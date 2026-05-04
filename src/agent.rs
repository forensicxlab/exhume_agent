use crate::config::AgentConfig;
use crate::ensure_agent_tables;
use crate::paths;
use crate::report;
use crate::tools::detect_fs::DetectFilesystemTool;
use crate::tools::extract_file::ExtractFileTool;
use crate::tools::list_dir::ListDirTool;
use crate::tools::notes::SaveInvestigationNoteTool;
use crate::tools::partitions::ListPartitionsTool;
use crate::tools::query_index::QueryIndexTool;
use crate::tools::report::UpdateDigitalReportTool;
use crate::tools::shell::ShellTool;
use crate::tools::specialists::{
    DelegateAudioSpecialist, DelegateImageSpecialist, DelegateSqliteSpecialist,
};
use crate::ui::UiHandle;
use anyhow::{anyhow, Result};
use colored::Colorize;
use rig::{
    agent::{HookAction, PromptHook},
    client::CompletionClient,
    completion::{
        message::{AssistantContent, ReasoningContent},
        request::{CompletionModel, CompletionResponse},
        Prompt,
    },
    message::Message,
    providers::{ollama, openai},
};
use sqlx::SqlitePool;
use std::sync::Arc;

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
}

/// A PromptHook that prints reasoning blocks emitted by the model on each agent turn.
/// This surfaces chain-of-thought from models that support explicit reasoning tokens
/// (e.g. OpenAI o1/o3, DeepSeek-R1, Anthropic extended-thinking).
/// For standard models the hook is a silent no-op.
#[derive(Clone)]
struct ReasoningHook;

#[derive(Clone)]
struct LoggingReasoningHook {
    ui: Option<UiHandle>,
}

impl<M: CompletionModel> PromptHook<M> for ReasoningHook {
    async fn on_completion_response(
        &self,
        _prompt: &Message,
        response: &CompletionResponse<M::Response>,
    ) -> HookAction {
        let mut has_reasoning = false;
        for item in response.choice.iter() {
            if let AssistantContent::Reasoning(reasoning) = item {
                if !has_reasoning {
                    println!(
                        "\n  {} {}\n",
                        "🧠".yellow(),
                        "Model Reasoning".yellow().bold()
                    );
                    has_reasoning = true;
                }
                if reasoning.content.is_empty() {
                    // OpenAI Chat Completions API does not expose reasoning token content
                    // for o-series models — reasoning is performed server-side only.
                    let id_hint = reasoning.id.as_deref().unwrap_or("unknown");
                    println!(
                        "    {} (id: {})",
                        "Reasoning performed — content not exposed by the API (Chat Completions limitation).".dimmed().italic(),
                        id_hint.dimmed()
                    );
                } else {
                    for block in &reasoning.content {
                        match block {
                            ReasoningContent::Text { text, .. } => {
                                for line in text.lines() {
                                    println!("    {}", line.dimmed().italic());
                                }
                            }
                            ReasoningContent::Summary(s) => {
                                println!("    {}", s.dimmed().italic());
                            }
                            ReasoningContent::Encrypted(_) | ReasoningContent::Redacted { .. } => {
                                println!(
                                    "    {}",
                                    "[encrypted/redacted reasoning block — not human-readable]"
                                        .dimmed()
                                        .italic()
                                );
                            }
                            _ => {} // non-exhaustive enum — ignore unknown future variants
                        }
                    }
                }
                println!();
            }
        }
        HookAction::Continue
    }
}

impl<M: CompletionModel> PromptHook<M> for LoggingReasoningHook {
    async fn on_completion_response(
        &self,
        _prompt: &Message,
        response: &CompletionResponse<M::Response>,
    ) -> HookAction {
        let Some(ui) = &self.ui else {
            return <ReasoningHook as PromptHook<M>>::on_completion_response(
                &ReasoningHook,
                _prompt,
                response,
            )
            .await;
        };

        let mut has_reasoning = false;
        for item in response.choice.iter() {
            if let AssistantContent::Reasoning(reasoning) = item {
                if !has_reasoning {
                    ui.log("Model reasoning");
                    has_reasoning = true;
                }
                if reasoning.content.is_empty() {
                    let id_hint = reasoning.id.as_deref().unwrap_or("unknown");
                    ui.log(format!(
                        "Reasoning performed but not exposed by the API. id={}",
                        id_hint
                    ));
                } else {
                    for block in &reasoning.content {
                        match block {
                            ReasoningContent::Text { text, .. } => {
                                for line in text.lines() {
                                    ui.log(format!("Reasoning: {}", line));
                                }
                            }
                            ReasoningContent::Summary(s) => {
                                ui.log(format!("Reasoning summary: {}", s));
                            }
                            ReasoningContent::Encrypted(_) | ReasoningContent::Redacted { .. } => {
                                ui.log("[encrypted/redacted reasoning block — not human-readable]");
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        HookAction::Continue
    }
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
    if let Ok(row) =
        sqlx::query("SELECT COUNT(*) as cnt FROM system_files WHERE anomaly_flag = 1")
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
    if let Ok(row) =
        sqlx::query("SELECT COUNT(*) as cnt FROM investigation_notes")
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
    if let Ok(row) = sqlx::query(
        "SELECT COUNT(*) as cnt FROM system_files WHERE host_path IS NOT NULL LIMIT 1",
    )
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

    format!("=== INDEX SUMMARY ===\n{}\n=====================", parts.join("\n"))
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
        let is_folder = std::path::Path::new(&image_path).is_dir();
        let extraction_dir = paths::extraction_dir_for_db(&db_path);

        if let Err(e) = std::fs::create_dir_all(&extraction_dir) {
            eprintln!(
                "Warning: Failed to create extraction directory {:?}: {}",
                extraction_dir, e
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
        }
    }

    /// Extract text from rigorous Message content blocks via JSON to avoid exhaustive rigorous type mismatches
    fn extract_text_from_message(msg: &Message) -> String {
        serde_json::to_string(msg).unwrap_or_default()
    }

    /// Load conversation history from the database
    pub async fn load_history(&self) -> Result<Vec<Message>> {
        ensure_agent_tables(&self.pool).await?;
        use sqlx::Row;
        let rows = sqlx::query("SELECT content FROM conversations ORDER BY id ASC")
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
        ensure_agent_tables(&self.pool).await?;
        let content = serde_json::to_string(msg)
            .map_err(|e| anyhow!("Failed to serialize message: {}", e))?;

        sqlx::query("INSERT INTO conversations (content) VALUES (?)")
            .bind(content)
            .execute(&*self.pool)
            .await
            .map_err(|e| anyhow!("Failed to save message: {}", e))?;
        Ok(())
    }

    /// Clear all conversation history from the database.
    pub async fn clear_history(&self) -> Result<()> {
        ensure_agent_tables(&self.pool).await?;
        sqlx::query("DELETE FROM conversations")
            .execute(&*self.pool)
            .await
            .map_err(|e| anyhow!("Failed to clear history: {}", e))?;
        Ok(())
    }

    /// Dynamically discover the database schema from sqlite_master.
    async fn discover_schema(pool: &SqlitePool) -> Result<String> {
        use sqlx::Row;
        let rows = sqlx::query("SELECT sql FROM sqlite_master WHERE type IN ('table', 'view') AND sql IS NOT NULL ORDER BY name")
            .fetch_all(&*pool)
            .await
            .map_err(|e| anyhow!("Failed to query schema: {}", e))?;

        let mut ddl_lines = Vec::new();
        for row in rows {
            let sql: String = row.get("sql");
            if !sql.trim().is_empty() {
                ddl_lines.push(sql);
            }
        }

        if ddl_lines.is_empty() {
            Ok("(no tables found)".to_string())
        } else {
            Ok(ddl_lines.join("\n\n"))
        }
    }

    /// Build a flat conversation text from history for the prompt.
    fn build_conversation_text(history: &[Message]) -> Result<String> {
        let mut conversation = String::new();
        for msg in history {
            let text = Self::extract_text_from_message(msg);
            match msg {
                Message::User { .. } => conversation.push_str(&format!("User: {}\n", text)),
                Message::Assistant { .. } => {
                    conversation.push_str(&format!("Assistant: {}\n", text))
                }
            }
        }
        if conversation.is_empty() {
            return Err(anyhow!("No user message in history to prompt with."));
        }
        Ok(conversation)
    }

    /// Helper to dynamically build the right rig::agent::Agent based on the config.
    pub async fn chat(&self, history: &[Message]) -> Result<String> {
        ensure_agent_tables(&self.pool).await?;
        let target_type = if self.is_folder {
            "local folder"
        } else if self.is_logical {
            "logical volume dump"
        } else {
            "disk image"
        };

        // Dynamically discover the database schema for the preamble
        let schema_ddl = Self::discover_schema(&self.pool)
            .await
            .unwrap_or_else(|_| "(schema unavailable)".to_string());

        // Auto-generated index summary injected at session start to skip exploratory tool calls
        let index_summary = generate_index_summary(&self.pool).await;

        let layout_instructions = if self.is_folder || self.is_logical {
            "This is a single-volume evidence source. There is only one partition with ID 1. Do NOT use `list_partitions` — go directly to querying the index with `query_index`.".to_string()
        } else {
            "When asked to examine the evidence, ALWAYS start by understanding the layout using `list_partitions`. You can then use the `detect_filesystem` tool on a specific partition to see what filesystem is formatted inside it.".to_string()
        };

        let preamble = format!(
            "You are the Exhume Autonomous Forensic Assistant.
            Your job is to assist digital forensic investigators.
            You have access to native forensic capability tools that interact with a {target_type}.
            The current {target_type} being investigated is: {}
            The investigator is running on: macOS (Unix-like).

            {index_summary}

            {layout_instructions}
            You can then use the `detect_filesystem` tool on a specific partition to see what filesystem is formatted inside it.
            You can traverse the file system inside a partition using the `list_dir` tool by passing its offset and size. For the root directory, omit the `file_id`. For subdirectories, provide the `file_id` returned by previous `list_dir` calls.
            You can extract the contents of a specific file using the `extract_file` tool by providing the `file_id` discovered via `list_dir`. Extracted files are dumped into a persistent `extracted/` directory next to the database for subsequent analysis.

            When providing a file for analysis (e.g., to a specialist or for your own content review), ALWAYS call `extract_file` first to ensure the file is available on the host filesystem.
            The persistent database path for this session is: {}
            Extracted files are persisted under: {}

            Database Schema (live):
            {schema_ddl}

            Key column notes:
            - In `system_files`: `identifier` is the file_id used by all tools. `ftype` is 'File' or 'Directory'. `anomaly_flag=1` means the file extension does not match its magic-byte signature — a high-priority forensic indicator.
            - `absolute_path`: the logical forensic path within the evidence (e.g. `/Windows/System32/file.exe`). Used for artifact pattern matching and forensic navigation. NOT a valid host path on its own for folder evidence.
            - `host_path`: the real host filesystem path (e.g. `/my/path/EVIDENCE/Windows/System32/file.exe`). Populated only for folder evidence; NULL for disk image partitions. ALWAYS use `host_path` — never `absolute_path` — when constructing shell commands or telling the user where a file is located on the host.
            - `timeline` view: unified filesystem timestamps (created/modified/accessed) across all files. Columns: evidence_id, partition_id, identifier, absolute_path, name, sig_name, anomaly_flag, event_type, event_time (ISO), ts_unix. Use it for temporal correlation.
            - `investigation_notes` table: your persistent notepad. Use `save_investigation_note` to record findings; query with `SELECT * FROM investigation_notes ORDER BY significance DESC`.
            - `artifact_objects` with `parser='ai_specialist'`: cached specialist analysis results. Always check before delegating to avoid redundant model calls.
            - If a `system_files_fts` table exists, use FTS5: `SELECT * FROM system_files_fts WHERE system_files_fts MATCH 'keyword'`.

            Token-efficient investigation workflow:
            1. The INDEX SUMMARY above already tells you what's in the image — skip generic orientation queries.
            2. Use `query_index` with `SELECT COUNT(*)` first to gauge scale, then fetch rows with a targeted LIMIT.
            3. Query `artifact_objects` (parser, kind, text, json) before running specialists — results are cached.
            4. Use `SELECT ... FROM system_files WHERE anomaly_flag=1` to jump directly to suspicious files.
            5. Use `SELECT ... FROM timeline WHERE ts_unix BETWEEN ? AND ?` for temporal forensic correlation.
            6. Use `save_investigation_note` to persist findings as you work — avoids re-discovering the same evidence.
            7. Prefer `artifact_objects` and `artifacts` joins over raw filesystem traversal for known artifact types.

            IMPORTANT — query_index results: When you call `query_index`, the full result table is rendered directly on the user's terminal. DO NOT re-enumerate or re-list the individual rows in your final answer — the user can already see the table. Instead, summarise key findings, highlight notable items, and explain what the results mean for the investigation.

            Reporting:
            {}

            Multi-Agent Delegation:
            You act as the Lead Investigator. When you discover media files or databases, DO NOT assume `sig_mime` is populated yet. Query by signature when available, but fall back to filename/path heuristics such as `LOWER(name) LIKE '%.jpg'` or `LOWER(absolute_path) LIKE '%.sqlite'`. Once you identify a candidate, pass its `identifier` (as `file_id`) to the specialized AI delegation tools:
            - Use `delegate_image_specialist` for pictures (e.g., .png, .jpg).
            - Use `delegate_audio_specialist` for audio recordings (e.g., .wav, .mp3).
            - Use `delegate_sqlite_specialist` for SQLite databases (e.g., .sqlite, .db).
            Specialist tools automatically return cached results if the file was already analyzed — no extra query needed.

            System Interaction:
            You have access to the `shell` tool to execute commands on the host system. Use this for environment investigation, advanced file operations, or running external specialized forensic tools.
            The `shell` tool automatically prompts the user for manual approval (y/N) at the terminal level before execution. Do not ask for permission in the chat; simply call the tool when a command is necessary. Be precise with your commands.",
            self.image_path,
            self.db_path.display(),
            self.extraction_dir.display(),
            if self.reporting_enabled {
                "A Digital Forensics Report has been initialized. For each material discovery, call `update_digital_report` before your final reply. Every report entry must include: what evidence was analysed, the analytical finding, why it matters, and ordered reproducibility steps that another examiner could follow if challenged in court."
            } else {
                "Digital report generation is disabled for this session. You may still explain your reasoning in chat, but do not rely on report persistence."
            }
        );

        // Resolve evidence_id from the database (fallback to 1)
        let evidence_id = report::current_evidence_id(&self.pool).await.unwrap_or(1);

        let list_partitions = ListPartitionsTool::new(self.image_path.clone(), self.ui.clone());
        let detect_fs =
            DetectFilesystemTool::new(self.image_path.clone(), self.pool.clone(), self.ui.clone());
        let list_dir =
            ListDirTool::new(self.image_path.clone(), self.pool.clone(), self.ui.clone());
        let extract_file = ExtractFileTool::new(
            self.image_path.clone(),
            self.extraction_dir.clone(),
            self.pool.clone(),
            self.ui.clone(),
        );
        let query_index = QueryIndexTool::new(self.pool.clone(), self.ui.clone());
        let save_note = SaveInvestigationNoteTool::new(self.pool.clone(), self.ui.clone());
        let delegate_image = DelegateImageSpecialist::new(
            self.pool.clone(),
            evidence_id,
            self.config.clone(),
            self.image_path.clone(),
            self.extraction_dir.clone(),
            self.ui.clone(),
        );
        let delegate_audio = DelegateAudioSpecialist::new(
            self.pool.clone(),
            evidence_id,
            self.config.clone(),
            self.image_path.clone(),
            self.extraction_dir.clone(),
            self.ui.clone(),
        );
        let delegate_sqlite = DelegateSqliteSpecialist::new(
            self.pool.clone(),
            evidence_id,
            self.config.clone(),
            self.image_path.clone(),
            self.extraction_dir.clone(),
            self.ui.clone(),
        );
        let update_report = UpdateDigitalReportTool::new(
            self.pool.clone(),
            self.reporting_enabled,
            self.ui.clone(),
        );
        let shell = ShellTool::new(self.ui.clone());

        let conversation = Self::build_conversation_text(history)?;
        if let Some(ui) = &self.ui {
            ui.log("Investigating evidence...");
        } else {
            println!("  {} {}...", "💭".cyan(), "Investigating evidence".bold());
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
                    })
                    .tool(list_partitions)
                    .tool(detect_fs)
                    .tool(list_dir)
                    .tool(extract_file)
                    .tool(query_index)
                    .tool(save_note)
                    .tool(delegate_image)
                    .tool(delegate_audio)
                    .tool(delegate_sqlite)
                    .tool(update_report)
                    .tool(shell)
                    .build();
                agent.prompt(&conversation).await.map_err(|e| anyhow!(e))
            }};
        }

        match self.config.provider.as_str() {
            "openai" => {
                let client: openai::Client = openai::Client::new(&self.config.api_key)
                    .map_err(|e| anyhow!("Failed to initialize OpenAI client: {}", e))?;
                build_and_prompt!(client)
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
                // forensic-llm is an OpenAI-compatible vLLM server (Chat Completions) on port 8000
                let llm_url = format!("{}:8000/v1", self.config.endpoint.trim_end_matches('/'));
                tracing::debug!("[copilot] orchestrator LLM → {} (model: {})", llm_url, self.config.model);
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
}
