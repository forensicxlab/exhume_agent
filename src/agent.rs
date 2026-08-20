const SKILL_SCHEMA: &str = include_str!("skills/schema.md");
const SKILL_WORKFLOW: &str = include_str!("skills/workflow.md");
const SKILL_DELEGATION: &str = include_str!("skills/delegation.md");

use crate::config::AgentConfig;
use crate::ensure_agent_tables;
use crate::paths;
use crate::policy::{AgentOptions, AgentPolicy};
use crate::tools::detect_fs::DetectFilesystemTool;
use crate::tools::extract_file::ExtractFileTool;
use crate::tools::list_dir::ListDirTool;
use crate::tools::notes::SaveInvestigationNoteTool;
use crate::tools::partitions::ListPartitionsTool;
use crate::tools::query_index::QueryIndexTool;
use crate::tools::query_sqlite::QuerySqliteFileTool;
use crate::tools::report::UpdateDigitalReportTool;
use crate::tools::shell::ShellTool;
use crate::tools::specialists::{
    DelegateAudioSpecialist, DelegateImageSpecialist, DelegateSqliteSpecialist,
};
use crate::ui::UiHandle;
use anyhow::{anyhow, Result};
use rig::{
    agent::{HookAction, PromptHook, ToolCallHookAction},
    client::CompletionClient,
    completion::{
        message::{AssistantContent, ReasoningContent},
        request::{CompletionModel, CompletionResponse},
        Chat,
    },
    message::Message,
    providers::{ollama, openai},
    tool::ToolDyn,
};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AgentToolContext {
    pub evidence_id: i64,
    pub session_id: String,
    pub image_path: String,
    pub db_path: std::path::PathBuf,
    pub extraction_dir: std::path::PathBuf,
    pub pool: Arc<SqlitePool>,
    pub ui: Option<UiHandle>,
}

pub trait AgentToolProvider: Send + Sync {
    fn tools(&self, context: &AgentToolContext) -> Vec<Box<dyn ToolDyn>>;
}

#[derive(Clone)]
pub struct ExhumeAgent {
    config: AgentConfig,
    image_path: String,
    db_path: std::path::PathBuf,
    pool: Arc<SqlitePool>,
    extraction_dir: std::path::PathBuf,
    is_folder: bool,
    is_logical: bool,
    reporting_enabled: bool,
    ui: Option<UiHandle>,
    options: AgentOptions,
    tool_providers: Vec<Arc<dyn AgentToolProvider>>,
}

#[derive(Clone)]
struct LoggingReasoningHook {
    ui: Option<UiHandle>,
    grounding: GroundingLedger,
}

#[derive(Clone, Debug)]
struct GroundingEvidence {
    event_id: String,
    tool_name: String,
    result: String,
}

#[derive(Default)]
struct GroundingState {
    call_event_ids: HashMap<String, String>,
    evidence: Vec<GroundingEvidence>,
    successful_delegation: bool,
    successful_report_update: bool,
}

#[derive(Clone, Default)]
struct GroundingLedger {
    state: Arc<Mutex<GroundingState>>,
}

impl GroundingLedger {
    fn record_call(&self, execution_id: &str, event_id: String) {
        if let Ok(mut state) = self.state.lock() {
            state
                .call_event_ids
                .insert(execution_id.to_string(), event_id);
        }
    }

    fn call_event_id(&self, execution_id: &str) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.call_event_ids.get(execution_id).cloned())
    }

    fn record_result(&self, event_id: String, tool_name: &str, result: &str) {
        if !tool_result_succeeded(result) {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            if tool_name.starts_with("delegate_") {
                state.successful_delegation = true;
            }
            if tool_name == "update_digital_report" {
                state.successful_report_update = true;
            }
            if is_supporting_tool(tool_name) || tool_name == "update_digital_report" {
                state.evidence.push(GroundingEvidence {
                    event_id,
                    tool_name: tool_name.to_string(),
                    result: result.to_string(),
                });
            }
        }
    }

    fn snapshot(&self) -> GroundingSnapshot {
        self.state
            .lock()
            .map(|state| GroundingSnapshot {
                evidence: state.evidence.clone(),
                successful_delegation: state.successful_delegation,
                successful_report_update: state.successful_report_update,
            })
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct GroundingSnapshot {
    evidence: Vec<GroundingEvidence>,
    successful_delegation: bool,
    successful_report_update: bool,
}

impl<M: CompletionModel> PromptHook<M> for LoggingReasoningHook {
    async fn on_completion_response(
        &self,
        _prompt: &Message,
        response: &CompletionResponse<M::Response>,
    ) -> HookAction {
        let mut has_reasoning = false;
        for item in response.choice.iter() {
            if let AssistantContent::Reasoning(reasoning) = item {
                if !has_reasoning {
                    self.log("Model reasoning");
                    has_reasoning = true;
                }
                if reasoning.content.is_empty() {
                    let id_hint = reasoning.id.as_deref().unwrap_or("unknown");
                    self.log(format!(
                        "Reasoning performed but not exposed by the API. id={}",
                        id_hint
                    ));
                } else {
                    for block in &reasoning.content {
                        match block {
                            ReasoningContent::Text { text, .. } => {
                                for line in text.lines() {
                                    self.log(format!("Reasoning: {}", line));
                                }
                            }
                            ReasoningContent::Summary(s) => {
                                self.log(format!("Reasoning summary: {}", s));
                            }
                            ReasoningContent::Encrypted(_) | ReasoningContent::Redacted { .. } => {
                                self.log(
                                    "[encrypted/redacted reasoning block — not human-readable]",
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        HookAction::Continue
    }

    async fn on_tool_call(
        &self,
        tool_name: &str,
        tool_call_id: Option<String>,
        internal_call_id: &str,
        args: &str,
    ) -> ToolCallHookAction {
        let args = truncate_for_event(args, 16_384);
        if let Some(ui) = &self.ui {
            let event_id = ui.tool_call(tool_name, tool_call_id, internal_call_id, args);
            if !event_id.is_empty() {
                self.grounding.record_call(internal_call_id, event_id);
            }
        } else {
            tracing::info!(tool = tool_name, arguments = %args, "Agent tool call");
        }
        ToolCallHookAction::Continue
    }

    async fn on_tool_result(
        &self,
        tool_name: &str,
        tool_call_id: Option<String>,
        internal_call_id: &str,
        _args: &str,
        result: &str,
    ) -> HookAction {
        let result = truncate_for_event(result, 64_000);
        if let Some(ui) = &self.ui {
            let parent_event_id = self.grounding.call_event_id(internal_call_id);
            let event_id = ui.tool_result(
                tool_name,
                tool_call_id,
                internal_call_id,
                parent_event_id.clone(),
                &result,
            );
            if parent_event_id.is_some()
                && !event_id.is_empty()
                && tool_result_succeeded(&result)
                && is_supporting_tool(tool_name)
            {
                ui.register_supporting_event(event_id.clone());
            }
            if parent_event_id.is_some() && !event_id.is_empty() {
                self.grounding.record_result(event_id, tool_name, &result);
            }
        } else {
            tracing::info!(tool = tool_name, "Agent tool completed");
        }
        HookAction::Continue
    }
}

impl LoggingReasoningHook {
    fn log(&self, message: impl Into<String>) {
        let message = message.into();
        if let Some(ui) = &self.ui {
            ui.log(message);
        } else {
            tracing::info!("{message}");
        }
    }
}

fn truncate_for_event(value: &str, max_chars: usize) -> String {
    let mut result: String = value.chars().take(max_chars).collect();
    if value.chars().count() > max_chars {
        result.push_str("\n[truncated]");
    }
    result
}

fn tool_result_succeeded(result: &str) -> bool {
    let lower = result.to_ascii_lowercase();
    if lower.contains("toolset error") {
        return false;
    }
    if lower.contains("specialisterror:") || lower.starts_with("error:") {
        return false;
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(result) {
        if value.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
            return false;
        }
        if value
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|exit_code| exit_code != 0)
        {
            return false;
        }
        if value
            .get("error")
            .is_some_and(|error| !error.is_null() && error.as_str() != Some(""))
        {
            return false;
        }
    }
    true
}

fn is_supporting_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "query_index"
            | "query_sqlite_file"
            | "shell"
            | "list_partitions"
            | "detect_filesystem"
            | "list_dir"
            | "extract_file"
            | "delegate_image_specialist"
            | "delegate_audio_specialist"
            | "delegate_sqlite_specialist"
    )
}

fn request_requires_grounding(prompt: &str) -> bool {
    let normalized = prompt.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    let conversational = [
        "hi",
        "hello",
        "hey",
        "thanks",
        "thank you",
        "help",
        "what can you do",
        "who are you",
    ];
    !conversational
        .iter()
        .any(|message| normalized == *message || normalized == format!("{message}!"))
}

fn response_hashes(response: &str) -> Vec<String> {
    response
        .split(|character: char| !character.is_ascii_hexdigit())
        .filter(|token| (32..=128).contains(&token.len()))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn response_monetary_values(response: &str) -> Vec<String> {
    const CURRENCIES: &[&str] = &[
        "usd", "eur", "gbp", "egp", "dollar", "dollars", "euro", "euros", "pound", "pounds",
    ];
    let tokens = response.split_whitespace().collect::<Vec<_>>();
    let mut values = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let lower = token
            .trim_matches(|character: char| {
                character.is_ascii_punctuation() && !matches!(character, '$' | '.' | ',')
            })
            .to_ascii_lowercase();
        let previous = index
            .checked_sub(1)
            .and_then(|previous| tokens.get(previous))
            .map(|token| {
                token
                    .trim_matches(|character: char| !character.is_alphabetic())
                    .to_ascii_lowercase()
            });
        let next = tokens.get(index + 1).map(|token| {
            token
                .trim_matches(|character: char| !character.is_alphabetic())
                .to_ascii_lowercase()
        });
        let has_symbol = token.contains(['$', '€', '£', '¥']);
        let has_currency_neighbor = previous
            .as_deref()
            .is_some_and(|value| CURRENCIES.contains(&value))
            || next
                .as_deref()
                .is_some_and(|value| CURRENCIES.contains(&value));
        if has_symbol || has_currency_neighbor {
            let number = lower
                .chars()
                .filter(|character| character.is_ascii_digit() || matches!(character, '.' | ','))
                .collect::<String>();
            if number.chars().any(|character| character.is_ascii_digit()) {
                values.push(number);
            }
        }
    }
    values
}

fn digits_only(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
}

fn numeric_values(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_digit() && !matches!(character, '.' | ','))
        .map(digits_only)
        .filter(|value| !value.is_empty())
        .collect()
}

fn strip_model_evidence_references(response: &str) -> String {
    let mut sanitized = response.to_string();
    while let Some(start) = sanitized.find("[[evidence:") {
        let Some(relative_end) = sanitized[start..].find("]]") else {
            break;
        };
        let end = start + relative_end + 2;
        sanitized.replace_range(start..end, "");
    }
    sanitized.trim_end().to_string()
}

fn observed_evidence_text(event: &GroundingEvidence) -> String {
    if event.tool_name != "delegate_sqlite_specialist" {
        return event.result.clone();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&event.result) else {
        return String::new();
    };
    value
        .get("queries")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|query| query.get("error").is_none_or(serde_json::Value::is_null))
        .filter_map(|query| query.get("result").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_grounded_response(
    response: &str,
    requires_grounding: bool,
    snapshot: &GroundingSnapshot,
) -> std::result::Result<(), Vec<String>> {
    let mut reasons = Vec::new();
    let supporting = snapshot
        .evidence
        .iter()
        .filter(|event| is_supporting_tool(&event.tool_name))
        .collect::<Vec<_>>();
    if requires_grounding && supporting.is_empty() {
        reasons.push("no successful forensic tool result".to_string());
    }

    let lower = response.to_ascii_lowercase();
    let claims_delegation = lower.contains("delegated")
        || lower.contains("specialist analysis complete")
        || lower.contains("specialist found");
    if claims_delegation && !snapshot.successful_delegation {
        reasons.push("delegation claimed without a successful specialist result".to_string());
    }
    let claims_report_update = lower.contains("report has been updated")
        || lower.contains("updated the report")
        || lower.contains("recorded in the report");
    if claims_report_update && !snapshot.successful_report_update {
        reasons.push("report update claimed without a successful report tool result".to_string());
    }

    for hash in response_hashes(response) {
        let observed = supporting.iter().any(|event| {
            observed_evidence_text(event)
                .to_ascii_lowercase()
                .contains(&hash)
        });
        if !observed {
            reasons.push(format!(
                "hash-like value {hash} does not occur in a successful tool result"
            ));
        }
    }
    for amount in response_monetary_values(response) {
        let amount_digits = digits_only(&amount);
        let observed = supporting.iter().any(|event| {
            let result = observed_evidence_text(event);
            result.contains(&amount)
                || (!amount_digits.is_empty() && numeric_values(&result).contains(&amount_digits))
        });
        if !observed {
            reasons.push(format!(
                "monetary value {amount} does not occur in a successful tool result"
            ));
        }
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

fn finalize_grounded_response(
    response: String,
    requires_grounding: bool,
    snapshot: &GroundingSnapshot,
) -> Result<String> {
    let mut response = strip_model_evidence_references(&response);
    if let Err(reasons) = validate_grounded_response(&response, requires_grounding, snapshot) {
        return Ok(format!(
            "I could not verify this result from completed forensic tools, so I will not present the draft as a finding. Grounding failure: {}",
            reasons.join("; ")
        ));
    }

    let references = snapshot
        .evidence
        .iter()
        .map(|event| format!("[[evidence:{}|{}]]", event.event_id, event.tool_name))
        .collect::<Vec<_>>();
    if !references.is_empty() {
        response.push_str("\n\n");
        response.push_str(&references.join(" "));
    }
    Ok(response)
}

/// Build a compact, token-efficient summary of the forensic index to orient the agent
/// at the start of each session without requiring exploratory tool calls.
async fn generate_index_summary(pool: &SqlitePool) -> String {
    use sqlx::Row;
    let mut parts: Vec<String> = Vec::new();

    // Partition overview
    if let Ok(rows) = sqlx::query(
        "SELECT kind, COUNT(*) as cnt, SUM(size_bytes) as total_bytes FROM partitions GROUP BY kind",
    )
    .fetch_all(pool)
    .await
    {
        if !rows.is_empty() {
            let desc: Vec<String> = rows
                .iter()
                .map(|r| {
                    let kind: String = r.get("kind");
                    let cnt: i64 = r.get("cnt");
                    let bytes: i64 = r.try_get("total_bytes").unwrap_or(0);
                    format!("{kind}×{cnt} ({:.1}GB)", bytes as f64 / 1_073_741_824.0)
                })
                .collect();
            parts.push(format!("Partitions: {}", desc.join(", ")));
        }
    }

    // File counts
    if let Ok(row) = sqlx::query(
        "SELECT COUNT(*) as total, \
         SUM(CASE WHEN is_dir=1 THEN 1 ELSE 0 END) as dirs, \
         SUM(CASE WHEN is_dir=0 THEN 1 ELSE 0 END) as files \
         FROM system_files",
    )
    .fetch_one(pool)
    .await
    {
        let total: i64 = row.try_get("total").unwrap_or(0);
        let dirs: i64 = row.try_get("dirs").unwrap_or(0);
        let files: i64 = row.try_get("files").unwrap_or(0);
        if total > 0 {
            parts.push(format!(
                "Files: {files} regular, {dirs} directories ({total} total)"
            ));
        }
    }

    // Timeline range (modified timestamps)
    if let Ok(row) = sqlx::query(
        "SELECT datetime(MIN(modified),'unixepoch') as earliest, \
                datetime(MAX(modified),'unixepoch') as latest \
         FROM system_files WHERE modified IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    {
        if let (Ok(earliest), Ok(latest)) = (
            row.try_get::<String, _>("earliest"),
            row.try_get::<String, _>("latest"),
        ) {
            parts.push(format!("Timeline (modified): {earliest} → {latest}"));
        }
    }

    // Top 8 file extensions
    if let Ok(rows) = sqlx::query(
        "SELECT LOWER(SUBSTR(name, INSTR(name,'.')+1)) as ext, COUNT(*) as cnt \
         FROM system_files WHERE is_dir=0 AND name LIKE '%.%' \
         GROUP BY ext ORDER BY cnt DESC LIMIT 8",
    )
    .fetch_all(pool)
    .await
    {
        if !rows.is_empty() {
            let exts: Vec<String> = rows
                .iter()
                .map(|r| {
                    let ext: String = r.try_get("ext").unwrap_or_default();
                    let cnt: i64 = r.try_get("cnt").unwrap_or(0);
                    format!(".{ext}({cnt})")
                })
                .collect();
            parts.push(format!("Top extensions: {}", exts.join(" ")));
        }
    }

    // Artifacts by category
    if let Ok(rows) = sqlx::query(
        "SELECT category, COUNT(*) as cnt FROM artifacts GROUP BY category ORDER BY cnt DESC LIMIT 6",
    )
    .fetch_all(pool)
    .await
    {
        if !rows.is_empty() {
            let cats: Vec<String> = rows
                .iter()
                .map(|r| {
                    let cat: String = r.try_get("category").unwrap_or_default();
                    let cnt: i64 = r.try_get("cnt").unwrap_or(0);
                    format!("{cat}:{cnt}")
                })
                .collect();
            parts.push(format!("Artifacts by category: {}", cats.join(", ")));
        }
    }

    // Signature anomalies (extension mismatch)
    if let Ok(row) = sqlx::query("SELECT COUNT(*) as cnt FROM system_files WHERE anomaly_flag = 1")
        .fetch_one(pool)
        .await
    {
        let cnt: i64 = row.try_get("cnt").unwrap_or(0);
        if cnt > 0 {
            parts.push(format!(
                "Signature anomalies (ext/magic mismatch): {cnt} files — query: SELECT name, absolute_path, sig_name, sig_exts FROM system_files WHERE anomaly_flag=1"
            ));
        }
    }

    // Previously analyzed by specialists
    if let Ok(row) = sqlx::query(
        "SELECT COUNT(DISTINCT file_id) as cnt FROM artifact_objects WHERE parser = 'ai_specialist'",
    )
    .fetch_one(pool)
    .await
    {
        let cnt: i64 = row.try_get("cnt").unwrap_or(0);
        if cnt > 0 {
            parts.push(format!(
                "Cached specialist analyses: {cnt} files already analyzed — delegate tools will return cached results automatically"
            ));
        }
    }

    // Outstanding investigation notes
    if let Ok(row) = sqlx::query("SELECT COUNT(*) as cnt FROM investigation_notes")
        .fetch_one(pool)
        .await
    {
        let cnt: i64 = row.try_get("cnt").unwrap_or(0);
        if cnt > 0 {
            parts.push(format!(
                "Investigation notes: {cnt} saved — query: SELECT * FROM investigation_notes ORDER BY significance DESC"
            ));
        }
    }

    // Detect folder evidence and surface base path for shell operations
    if let Ok(row) =
        sqlx::query("SELECT COUNT(*) as cnt FROM system_files WHERE host_path IS NOT NULL LIMIT 1")
            .fetch_one(pool)
            .await
    {
        let cnt: i64 = row.try_get("cnt").unwrap_or(0);
        if cnt > 0 {
            if let Ok(ev) = sqlx::query("SELECT path FROM evidence LIMIT 1")
                .fetch_one(pool)
                .await
            {
                let base: String = ev.try_get("path").unwrap_or_default();
                parts.push(format!(
                    "Evidence type: FOLDER — base path: {base}\n\
                     Path guidance: `absolute_path` is the logical forensic path (e.g. /Documents/file.txt). \
                     `host_path` is the real host path usable in shell commands (e.g. {base}/Documents/file.txt). \
                     ALWAYS use `host_path` for shell operations on this evidence."
                ));
            }
        }
    }

    if parts.is_empty() {
        return "Index not yet built — run filesystem discovery first.".to_string();
    }

    format!(
        "=== INDEX SUMMARY ===\n{}\n=====================",
        parts.join("\n")
    )
}

impl ExhumeAgent {
    pub fn new(
        config: AgentConfig,
        image_path: String,
        db_path: std::path::PathBuf,
        pool: Arc<SqlitePool>,
        is_logical: bool,
        reporting_enabled: bool,
        ui: Option<UiHandle>,
    ) -> Self {
        let evidence_id = ui.as_ref().map(UiHandle::evidence_id).unwrap_or(1);
        let session_id = ui
            .as_ref()
            .map(|handle| handle.session_id().to_string())
            .unwrap_or_else(|| "default".to_string());
        Self::new_with_options(
            config,
            image_path,
            db_path,
            pool,
            is_logical,
            reporting_enabled,
            ui,
            AgentOptions {
                session_id,
                evidence_id,
                policy: AgentPolicy::default(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        config: AgentConfig,
        image_path: String,
        db_path: std::path::PathBuf,
        pool: Arc<SqlitePool>,
        is_logical: bool,
        reporting_enabled: bool,
        ui: Option<UiHandle>,
        options: AgentOptions,
    ) -> Self {
        let is_folder = std::path::Path::new(&image_path).is_dir();
        let extraction_dir = paths::extraction_dir_for_db(&db_path);

        if let Err(e) = std::fs::create_dir_all(&extraction_dir) {
            tracing::warn!(
                path = %extraction_dir.display(),
                "Failed to create extraction directory: {e}"
            );
        }

        Self {
            config,
            image_path,
            db_path,
            pool,
            extraction_dir,
            is_folder,
            is_logical,
            reporting_enabled,
            ui,
            options,
            tool_providers: Vec::new(),
        }
    }

    pub fn with_tool_provider(mut self, provider: Arc<dyn AgentToolProvider>) -> Self {
        self.tool_providers.push(provider);
        self
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    pub fn policy(&self) -> &AgentPolicy {
        &self.options.policy
    }

    pub fn session_id(&self) -> &str {
        &self.options.session_id
    }

    pub fn evidence_id(&self) -> i64 {
        self.options.evidence_id
    }

    pub fn pool(&self) -> &Arc<SqlitePool> {
        &self.pool
    }

    pub fn ui(&self) -> Option<&UiHandle> {
        self.ui.as_ref()
    }

    pub fn reporting_enabled(&self) -> bool {
        self.reporting_enabled
    }

    pub async fn ensure_session(&self) -> Result<()> {
        ensure_agent_tables(&self.pool).await?;
        sqlx::query(
            r#"
            INSERT INTO agent_sessions (
                id, evidence_id, provider, model, reporting_enabled, status
            ) VALUES (?, ?, ?, ?, ?, 'idle')
            ON CONFLICT(id) DO UPDATE SET
                evidence_id = excluded.evidence_id,
                provider = excluded.provider,
                model = excluded.model,
                reporting_enabled = excluded.reporting_enabled,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&self.options.session_id)
        .bind(self.options.evidence_id)
        .bind(&self.config.provider)
        .bind(&self.config.model)
        .bind(self.reporting_enabled)
        .execute(&*self.pool)
        .await?;

        self.migrate_legacy_history().await?;
        Ok(())
    }

    async fn migrate_legacy_history(&self) -> Result<()> {
        if self.options.session_id != "default" {
            return Ok(());
        }

        let existing: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_messages WHERE session_id = ?")
                .bind(&self.options.session_id)
                .fetch_one(&*self.pool)
                .await
                .unwrap_or(0);
        if existing > 0 {
            return Ok(());
        }

        use sqlx::Row;
        let rows = sqlx::query("SELECT content FROM conversations ORDER BY id ASC")
            .fetch_all(&*self.pool)
            .await?;
        for row in rows {
            let content: String = row.get("content");
            let Ok(message) = serde_json::from_str::<Message>(&content) else {
                continue;
            };
            let role = match message {
                Message::User { .. } => "user",
                Message::Assistant { .. } => "assistant",
            };
            sqlx::query("INSERT INTO agent_messages (session_id, role, content) VALUES (?, ?, ?)")
                .bind(&self.options.session_id)
                .bind(role)
                .bind(content)
                .execute(&*self.pool)
                .await?;
        }
        sqlx::query("DELETE FROM conversations")
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    /// Load conversation history from the database
    pub async fn load_history(&self) -> Result<Vec<Message>> {
        self.ensure_session().await?;
        use sqlx::Row;
        let rows =
            sqlx::query("SELECT content FROM agent_messages WHERE session_id = ? ORDER BY id ASC")
                .bind(&self.options.session_id)
                .fetch_all(&*self.pool)
                .await
                .map_err(|e| anyhow!("Failed to load history: {}", e))?;

        let mut history = Vec::new();
        for row in rows {
            let content: String = row.get("content");
            if let Ok(msg) = serde_json::from_str::<Message>(&content) {
                history.push(msg);
            }
        }
        Ok(history)
    }

    /// Save a message to the database
    pub async fn save_message(&self, msg: &Message) -> Result<()> {
        self.save_message_for_turn(msg, self.ui.as_ref().and_then(UiHandle::current_turn_id))
            .await
    }

    pub async fn save_message_for_turn(
        &self,
        msg: &Message,
        turn_id: Option<String>,
    ) -> Result<()> {
        self.ensure_session().await?;
        let content = serde_json::to_string(msg)
            .map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
        let role = match msg {
            Message::User { .. } => "user",
            Message::Assistant { .. } => "assistant",
        };

        sqlx::query(
            "INSERT INTO agent_messages (session_id, turn_id, role, content) VALUES (?, ?, ?, ?)",
        )
        .bind(&self.options.session_id)
        .bind(turn_id)
        .bind(role)
        .bind(content)
        .execute(&*self.pool)
        .await
        .map_err(|e| anyhow!("Failed to save message: {}", e))?;
        Ok(())
    }

    /// Clear all conversation history from the database.
    pub async fn clear_history(&self) -> Result<()> {
        self.ensure_session().await?;
        sqlx::query("DELETE FROM agent_messages WHERE session_id = ?")
            .bind(&self.options.session_id)
            .execute(&*self.pool)
            .await
            .map_err(|e| anyhow!("Failed to clear history: {}", e))?;
        if self.options.session_id == "default" {
            sqlx::query("DELETE FROM conversations")
                .execute(&*self.pool)
                .await
                .map_err(|e| anyhow!("Failed to clear legacy history: {e}"))?;
        }
        Ok(())
    }

    /// Keep provider-native chat roles while applying the configured history bounds.
    fn build_chat_request(&self, history: &[Message]) -> Result<(String, Vec<Message>)> {
        let (latest, prior) = history
            .split_last()
            .ok_or_else(|| anyhow!("No user message in history to prompt with."))?;
        if !matches!(latest, Message::User { .. }) {
            return Err(anyhow!(
                "The latest conversation message is not from the user."
            ));
        }
        let prompt = message_text(latest);
        if prompt.trim().is_empty() {
            return Err(anyhow!("The latest user message is empty."));
        }

        let mut selected: Vec<Message> = Vec::new();
        let mut chars = 0usize;
        for msg in prior
            .iter()
            .rev()
            .take(self.options.policy.max_history_messages.max(1))
        {
            let text = message_text(msg);
            if text.trim().is_empty() {
                continue;
            }
            let remaining = self.options.policy.max_history_chars.saturating_sub(chars);
            if remaining == 0 {
                break;
            }
            if text.chars().count() > remaining {
                break;
            }
            chars += text.chars().count();
            selected.push(msg.clone());
        }
        selected.reverse();
        Ok((prompt, selected))
    }

    /// Helper to dynamically build the right rig::agent::Agent based on the config.
    pub async fn chat(&self, history: &[Message]) -> Result<String> {
        self.ensure_session().await?;
        let target_type = if self.is_folder {
            "local folder"
        } else if self.is_logical {
            "logical volume dump"
        } else {
            "disk image"
        };

        // Auto-generated index summary injected at session start to skip exploratory tool calls
        let index_summary = generate_index_summary(&self.pool).await;
        let skill_artifacts = exhume_indexer::ARTIFACTS_YAML;

        let layout_instructions = if self.is_folder || self.is_logical {
            "This is a single-volume evidence source. There is only one partition with ID 1. Do NOT use `list_partitions` — go directly to querying the index with `query_index`."
        } else {
            "When asked to examine the evidence, ALWAYS start by understanding the layout using `list_partitions`. You can then use the `detect_filesystem` tool on a specific partition to see what filesystem is formatted inside it."
        };

        let image_path = &self.image_path;
        let db_path = self.db_path.display();
        let extraction_dir = self.extraction_dir.display();
        let host_os = std::env::consts::OS;
        let shell_note = if self.options.policy.allow_shell {
            "The `shell` tool is enabled and executes on the investigator's host, with every command requiring explicit investigator approval. \
            When the investigator explicitly requests a host command, call `shell` in the current turn with the exact proposed command. \
            Never respond that you will run a command later, and never claim a command ran unless you received its `shell` tool result. \
            If approval is denied or execution fails, report that outcome accurately."
        } else {
            "The host shell capability is disabled for this session. Do not propose or attempt shell commands."
        };
        let reporting_note = if self.reporting_enabled {
            "A Digital Forensics Report has been initialized. For each material discovery, call `update_digital_report` before your final reply. Every report entry must include: what evidence was analysed, the analytical finding, why it matters, and ordered reproducibility steps that another examiner could follow if challenged in court."
        } else {
            "Digital report generation is disabled for this session. You may still explain your reasoning in chat, but do not rely on report persistence."
        };

        let preamble = format!(
            "You are the Exhume Autonomous Forensic Assistant.
            Your job is to assist digital forensic investigators.
            You have access to native forensic capability tools that interact with a {target_type}.
            The current {target_type} being investigated is: {image_path}
            The investigator is running on: {host_os}.

            {index_summary}

            {layout_instructions}
            You can traverse the file system inside a partition using the `list_dir` tool by passing its offset and size. For the root directory, omit the `file_id`. For subdirectories, provide the `file_id` returned by previous `list_dir` calls.
            You can extract the contents of a specific file using the `extract_file` tool by providing the `file_id` discovered via `list_dir`. Extracted files are dumped into a persistent `extracted/` directory next to the database for subsequent analysis.
            When providing a file for analysis (e.g., to a specialist or for your own content review), ALWAYS call `extract_file` first to ensure the file is available on the host filesystem.
            Use `query_sqlite_file` when the investigator needs a specific bounded read-only query against an SQLite evidence file.
            The persistent database path for this session is: {db_path}
            Extracted files are persisted under: {extraction_dir}

            {SKILL_SCHEMA}

            {SKILL_WORKFLOW}

            {skill_artifacts}

            Reporting: {reporting_note}

            {SKILL_DELEGATION}

            Host shell policy: {shell_note}"
        );

        // Resolve evidence_id from the database (fallback to 1)
        let evidence_id = self.options.evidence_id;

        let (prompt, chat_history) = self.build_chat_request(history)?;
        let requires_grounding = request_requires_grounding(&prompt);
        let grounding = GroundingLedger::default();
        if let Some(ui) = &self.ui {
            ui.log("Investigating evidence...");
        } else {
            tracing::info!("Investigating evidence");
        }

        // Macro to avoid duplicating tool registration across providers
        macro_rules! build_and_prompt {
            ($client:expr) => {{
                let agent = $client
                    .agent(&self.config.model)
                    .preamble(&preamble)
                    .default_max_turns(10)
                    .hook(LoggingReasoningHook {
                        ui: self.ui.clone(),
                        grounding: grounding.clone(),
                    })
                    .tools(self.build_tools(evidence_id))
                    .build();
                let mut response = agent
                    .chat(prompt.clone(), chat_history.clone())
                    .await
                    .map_err(|e| anyhow!(e))?;
                if let Err(reasons) =
                    validate_grounded_response(&response, requires_grounding, &grounding.snapshot())
                {
                    if let Some(ui) = &self.ui {
                        ui.log_with_level(
                            crate::ui::AgentLogLevel::Warning,
                            format!(
                                "Grounding gate rejected the draft; retrying with required tool evidence: {}",
                                reasons.join("; ")
                            ),
                        );
                    }
                    let mut retry_history = chat_history.clone();
                    retry_history.push(Message::user(prompt.clone()));
                    retry_history.push(Message::assistant(response));
                    let correction = format!(
                        "Your previous draft failed the forensic grounding gate: {}. \
                         Re-investigate now using the available tools. Do not state a hash, finding, \
                         delegation, or report update unless the corresponding tool completed successfully. \
                         Return only claims supported by the tool results.",
                        reasons.join("; ")
                    );
                    response = agent
                        .chat(correction, retry_history)
                        .await
                        .map_err(|e| anyhow!(e))?;
                }
                finalize_grounded_response(
                    response,
                    requires_grounding,
                    &grounding.snapshot(),
                )
            }};
        }

        match self.config.provider.as_str() {
            "openai" => {
                if let Some(endpoint) = self.config.openai_endpoint() {
                    let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                        .api_key(&self.config.api_key)
                        .base_url(&endpoint)
                        .build()
                        .map_err(|e| {
                            anyhow!("Failed to initialize OpenAI-compatible client: {e}")
                        })?;
                    build_and_prompt!(client)
                } else {
                    let client: openai::Client = openai::Client::new(&self.config.api_key)
                        .map_err(|e| anyhow!("Failed to initialize OpenAI client: {}", e))?;
                    build_and_prompt!(client)
                }
            }
            "ollama" => {
                let client: ollama::Client = {
                    let mut builder = ollama::Client::builder();
                    if !self.config.endpoint.is_empty() {
                        builder = builder.base_url(&self.config.endpoint);
                    }
                    builder.api_key(rig::client::Nothing).build()?
                };
                build_and_prompt!(client)
            }
            "copilot" => {
                let llm_url = self.config.copilot_llm_endpoint()?;
                tracing::debug!(
                    "[copilot] orchestrator LLM → {} (model: {})",
                    llm_url,
                    self.config.model
                );
                let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                    .api_key("no-key")
                    .base_url(&llm_url)
                    .build()
                    .map_err(|e| anyhow!("Failed to initialize copilot client: {}", e))?;
                build_and_prompt!(client)
            }
            _ => Err(anyhow!("Unsupported provider: {}", self.config.provider)),
        }
    }

    fn build_tools(&self, evidence_id: i64) -> Vec<Box<dyn ToolDyn>> {
        let mut tools: Vec<Box<dyn ToolDyn>> = vec![
            Box::new(ListPartitionsTool::new(
                self.image_path.clone(),
                self.ui.clone(),
            )),
            Box::new(DetectFilesystemTool::new(
                self.image_path.clone(),
                self.pool.clone(),
                self.ui.clone(),
            )),
            Box::new(ListDirTool::new(
                self.image_path.clone(),
                self.pool.clone(),
                self.ui.clone(),
            )),
            Box::new(ExtractFileTool::new(
                self.image_path.clone(),
                self.extraction_dir.clone(),
                self.pool.clone(),
                self.ui.clone(),
            )),
            Box::new(QueryIndexTool::new(
                self.db_path.clone(),
                self.ui.clone(),
                self.options.policy.clone(),
            )),
            Box::new(QuerySqliteFileTool::new(
                self.image_path.clone(),
                self.extraction_dir.clone(),
                self.pool.clone(),
                self.ui.clone(),
                self.options.policy.clone(),
            )),
            Box::new(SaveInvestigationNoteTool::new(
                self.pool.clone(),
                self.ui.clone(),
            )),
            Box::new(DelegateImageSpecialist::new(
                self.pool.clone(),
                evidence_id,
                self.config.clone(),
                self.image_path.clone(),
                self.extraction_dir.clone(),
                self.ui.clone(),
            )),
            Box::new(DelegateAudioSpecialist::new(
                self.pool.clone(),
                evidence_id,
                self.config.clone(),
                self.image_path.clone(),
                self.extraction_dir.clone(),
                self.ui.clone(),
            )),
            Box::new(DelegateSqliteSpecialist::new(
                self.pool.clone(),
                evidence_id,
                self.config.clone(),
                self.image_path.clone(),
                self.extraction_dir.clone(),
                self.ui.clone(),
            )),
            Box::new(UpdateDigitalReportTool::new(
                self.pool.clone(),
                self.reporting_enabled,
                self.ui.clone(),
            )),
        ];

        if self.options.policy.allow_shell {
            tools.push(Box::new(ShellTool::new(
                self.options.policy.clone(),
                self.ui.clone(),
            )));
        }

        let context = AgentToolContext {
            evidence_id,
            session_id: self.options.session_id.clone(),
            image_path: self.image_path.clone(),
            db_path: self.db_path.clone(),
            extraction_dir: self.extraction_dir.clone(),
            pool: self.pool.clone(),
            ui: self.ui.clone(),
        };
        for provider in &self.tool_providers {
            tools.extend(provider.tools(&context));
        }

        tools
    }
}

pub fn message_text(msg: &Message) -> String {
    let value = serde_json::to_value(msg).unwrap_or_default();
    let mut chunks = Vec::new();
    collect_message_text(&value, &mut chunks);
    if chunks.is_empty() {
        value.to_string()
    } else {
        chunks.join("\n")
    }
}

fn collect_message_text(value: &serde_json::Value, chunks: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) if !text.trim().is_empty() => chunks.push(text.clone()),
        serde_json::Value::Array(items) => {
            items
                .iter()
                .for_each(|item| collect_message_text(item, chunks));
        }
        serde_json::Value::Object(map) => {
            if let Some(text) = map
                .get("text")
                .and_then(serde_json::Value::as_str)
                .filter(|text| !text.trim().is_empty())
            {
                chunks.push(text.to_string());
            } else {
                map.values()
                    .for_each(|item| collect_message_text(item, chunks));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod grounding_tests {
    use super::{
        tool_result_succeeded, validate_grounded_response, GroundingEvidence, GroundingSnapshot,
    };

    fn snapshot(result: &str) -> GroundingSnapshot {
        GroundingSnapshot {
            evidence: vec![GroundingEvidence {
                event_id: "event-1".to_string(),
                tool_name: "shell".to_string(),
                result: result.to_string(),
            }],
            successful_delegation: false,
            successful_report_update: false,
        }
    }

    fn sqlite_snapshot(summary: &str, query_result: &str) -> GroundingSnapshot {
        GroundingSnapshot {
            evidence: vec![GroundingEvidence {
                event_id: "event-sqlite".to_string(),
                tool_name: "delegate_sqlite_specialist".to_string(),
                result: serde_json::json!({
                    "summary": summary,
                    "queries": [{
                        "query_id": "query-1",
                        "result": query_result,
                        "error": null
                    }]
                })
                .to_string(),
            }],
            successful_delegation: true,
            successful_report_update: false,
        }
    }

    #[test]
    fn rejects_forensic_answer_without_a_tool_result() {
        let reasons =
            validate_grounded_response("The victim owes 2500.", true, &Default::default())
                .expect_err("ungrounded response must fail");
        assert!(reasons
            .iter()
            .any(|reason| reason.contains("no successful forensic tool result")));
    }

    #[test]
    fn rejects_hash_not_observed_in_tool_output() {
        let invented = "a3d5c709e5e45a8d2e1f7c8babc1234567890abcdef1234567890abcdef1234";
        assert!(validate_grounded_response(
            &format!("SHA-256: {invented}"),
            true,
            &snapshot("command completed without a hash"),
        )
        .is_err());
        assert!(validate_grounded_response(
            &format!("SHA-256: {invented}"),
            true,
            &snapshot(&format!("hash={invented}")),
        )
        .is_ok());
    }

    #[test]
    fn rejects_unobserved_debt_amount() {
        assert!(validate_grounded_response(
            "The victim owes $2500.",
            true,
            &snapshot("The message states 250,000 EGP."),
        )
        .is_err());
        assert!(validate_grounded_response(
            "The victim owes 250,000 EGP.",
            true,
            &snapshot("The message states 250,000 EGP."),
        )
        .is_ok());
    }

    #[test]
    fn sqlite_summary_cannot_ground_a_value_absent_from_query_rows() {
        let snapshot = sqlite_snapshot("The debt is $2500.", "body=250,000 EGP");
        assert!(validate_grounded_response("The debt is $2500.", true, &snapshot).is_err());
        assert!(validate_grounded_response("The debt is 250,000 EGP.", true, &snapshot).is_ok());
    }

    #[test]
    fn structured_tool_errors_are_not_successful() {
        assert!(!tool_result_succeeded(
            r#"{"result":"","error":"no such table"}"#
        ));
        assert!(!tool_result_succeeded(
            r#"{"success":false,"error":"denied"}"#
        ));
        assert!(!tool_result_succeeded(
            r#"{"exit_code":127,"stdout":"","stderr":"not found"}"#
        ));
        assert!(tool_result_succeeded(
            r#"{"result":"one row","error":null}"#
        ));
    }
}
