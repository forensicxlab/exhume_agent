use crate::config::AgentConfig;
use crate::ensure_agent_tables;
use crate::paths;
use crate::policy::{AgentOptions, AgentPolicy};
use crate::tools::detect_fs::DetectFilesystemTool;
use crate::tools::extract_file::ExtractFileTool;
use crate::tools::list_dir::ListDirTool;
use crate::tools::media::{media_destination, DescribeImageTool, TranscribeAudioTool};
use crate::tools::partitions::ListPartitionsTool;
use crate::tools::query_index::QueryIndexTool;
use crate::tools::query_sqlite::QuerySqliteFileTool;
use crate::tools::shell::ShellTool;
use crate::ui::UiHandle;
use anyhow::{anyhow, Result};
use rig::{message::Message, tool::ToolDyn};
use sqlx::SqlitePool;
use std::sync::Arc;

pub struct AgentToolContext {
    pub evidence_id: i64,
    pub session_id: String,
    pub image_path: String,
    pub db_path: std::path::PathBuf,
    pub extraction_dir: std::path::PathBuf,
    pub pool: Arc<SqlitePool>,
    pub ui: Option<UiHandle>,
    /// Host-only credentials. Do not include these in model inputs or case records.
    pub body_open_options: Arc<exhume_body::BodyOpenOptions>,
}

pub trait AgentToolProvider: Send + Sync {
    fn tools(&self, context: &AgentToolContext) -> Vec<Box<dyn ToolDyn>>;

    /// Trusted host adapters declare every processing destination. None disables the tool.
    /// Returning an empty list asserts that the implementation only reads local selected evidence.
    fn tool_destinations(
        &self,
        _tool_name: &str,
    ) -> Option<Vec<crate::investigation::ProcessingDestination>> {
        None
    }
}

#[derive(Clone)]
pub struct ExhumeAgent {
    pub(crate) config: AgentConfig,
    pub(crate) image_path: String,
    pub(crate) db_path: std::path::PathBuf,
    pub(crate) pool: Arc<SqlitePool>,
    pub(crate) extraction_dir: std::path::PathBuf,
    pub(crate) is_folder: bool,
    pub(crate) is_logical: bool,
    reporting_enabled: bool,
    pub(crate) ui: Option<UiHandle>,
    pub(crate) options: AgentOptions,
    pub(crate) investigation: Arc<tokio::sync::OnceCell<crate::investigation::InvestigationStore>>,
    tool_providers: Vec<Arc<dyn AgentToolProvider>>,
    body_open_options: Arc<exhume_body::BodyOpenOptions>,
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
        _reporting_enabled: bool,
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
            reporting_enabled: true,
            ui,
            options,
            investigation: Arc::new(tokio::sync::OnceCell::new()),
            tool_providers: Vec::new(),
            body_open_options: Arc::default(),
        }
    }

    pub fn with_tool_provider(mut self, provider: Arc<dyn AgentToolProvider>) -> Self {
        self.tool_providers.push(provider);
        self
    }

    /// Supply credentials for the selected image to every evidence-reading tool.
    /// They remain in host memory and are not part of the model configuration.
    pub fn with_body_open_options(mut self, options: Arc<exhume_body::BodyOpenOptions>) -> Self {
        self.body_open_options = options;
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
        let stored = sqlx::query(
            r#"
            INSERT INTO agent_sessions (
                id, evidence_id, provider, model, reporting_enabled, status
            ) VALUES (?, ?, ?, ?, ?, 'idle')
            ON CONFLICT(id) DO UPDATE SET
                provider = excluded.provider,
                model = excluded.model,
                reporting_enabled = excluded.reporting_enabled,
                updated_at = CURRENT_TIMESTAMP
            WHERE agent_sessions.evidence_id = excluded.evidence_id
            "#,
        )
        .bind(&self.options.session_id)
        .bind(self.options.evidence_id)
        .bind(&self.config.provider)
        .bind(&self.config.model)
        .bind(self.reporting_enabled)
        .execute(&*self.pool)
        .await?;
        if stored.rows_affected() != 1 {
            return Err(anyhow!(
                "This session belongs to another evidence source; select a different session ID"
            ));
        }

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
    pub(crate) fn build_chat_request(&self, history: &[Message]) -> Result<(String, Vec<Message>)> {
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

    /// Run one approved investigation step, or return an actionable pending proposal.
    pub async fn chat(&self, history: &[Message]) -> Result<String> {
        crate::runtime::chat(self, history, None).await
    }

    pub(crate) async fn chat_for_turn(&self, history: &[Message], turn_id: &str) -> Result<String> {
        crate::runtime::chat(self, history, Some(turn_id)).await
    }

    pub(crate) fn build_tools(&self, evidence_id: i64) -> Vec<Box<dyn ToolDyn>> {
        let mut tools: Vec<Box<dyn ToolDyn>> = vec![
            Box::new(
                ListPartitionsTool::new(self.image_path.clone(), self.ui.clone())
                    .with_body_open_options(self.body_open_options.clone()),
            ),
            Box::new(
                DetectFilesystemTool::new(
                    self.image_path.clone(),
                    self.pool.clone(),
                    self.ui.clone(),
                )
                .with_body_open_options(self.body_open_options.clone()),
            ),
            Box::new(
                ListDirTool::new(self.image_path.clone(), self.pool.clone(), self.ui.clone())
                    .with_body_open_options(self.body_open_options.clone()),
            ),
            Box::new(
                ExtractFileTool::new(
                    self.image_path.clone(),
                    self.extraction_dir.clone(),
                    self.pool.clone(),
                    self.ui.clone(),
                )
                .with_body_open_options(self.body_open_options.clone()),
            ),
            Box::new(QueryIndexTool::new(
                self.db_path.clone(),
                self.ui.clone(),
                self.options.policy.clone(),
            )),
            Box::new(
                QuerySqliteFileTool::new(
                    self.image_path.clone(),
                    self.extraction_dir.clone(),
                    self.pool.clone(),
                    self.ui.clone(),
                    self.options.policy.clone(),
                )
                .with_body_open_options(self.body_open_options.clone()),
            ),
        ];

        if media_destination(&self.config, "describe_image").is_ok() {
            tools.push(Box::new(
                DescribeImageTool::new(
                    self.pool.clone(),
                    evidence_id,
                    self.config.clone(),
                    self.image_path.clone(),
                    self.extraction_dir.clone(),
                )
                .with_body_open_options(self.body_open_options.clone()),
            ));
        }
        if media_destination(&self.config, "transcribe_audio").is_ok() {
            tools.push(Box::new(
                TranscribeAudioTool::new(
                    self.pool.clone(),
                    evidence_id,
                    self.config.clone(),
                    self.image_path.clone(),
                    self.extraction_dir.clone(),
                )
                .with_body_open_options(self.body_open_options.clone()),
            ));
        }

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
            body_open_options: self.body_open_options.clone(),
        };
        for provider in &self.tool_providers {
            tools.extend(provider.tools(&context));
        }

        tools
    }

    pub(crate) fn tool_destinations(
        &self,
        name: &str,
    ) -> Option<Vec<crate::investigation::ProcessingDestination>> {
        if matches!(name, "describe_image" | "transcribe_audio") {
            return media_destination(&self.config, name)
                .ok()
                .map(|destination| vec![destination]);
        }
        if matches!(
            name,
            "list_partitions"
                | "detect_filesystem"
                | "list_dir"
                | "extract_file"
                | "query_index"
                | "query_sqlite_file"
                | "shell"
        ) {
            return Some(vec![]);
        }
        self.tool_providers
            .iter()
            .find_map(|provider| provider.tool_destinations(name))
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
