use crate::config::AgentConfig;
use crate::tools::partitions::ListPartitionsTool;
use crate::tools::detect_fs::DetectFilesystemTool;
use crate::tools::list_dir::ListDirTool;
use crate::tools::extract_file::ExtractFileTool;
use crate::tools::query_index::QueryIndexTool;
use crate::tools::specialists::{DelegateImageSpecialist, DelegateAudioSpecialist, DelegateSqliteSpecialist};
use crate::tools::shell::ShellTool;
use anyhow::{Result, anyhow};
use colored::Colorize;
use rig::{
    agent::{PromptHook, HookAction},
    client::CompletionClient,
    completion::{
        message::{AssistantContent, ReasoningContent},
        request::{CompletionModel, CompletionResponse},
        Prompt,
    },
    message::Message,
    providers::{ollama, openai},
};
use std::sync::Arc;
use sqlx::SqlitePool;

pub struct ExhumeAgent {
    config: AgentConfig,
    image_path: String,
    pool: Arc<SqlitePool>,
    extraction_dir: std::path::PathBuf,
    is_folder: bool,
    is_logical: bool,
}

/// A PromptHook that prints reasoning blocks emitted by the model on each agent turn.
/// This surfaces chain-of-thought from models that support explicit reasoning tokens
/// (e.g. OpenAI o1/o3, DeepSeek-R1, Anthropic extended-thinking).
/// For standard models the hook is a silent no-op.
#[derive(Clone)]
struct ReasoningHook;

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
                                println!("    {}", "[encrypted/redacted reasoning block — not human-readable]".dimmed().italic());
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

impl ExhumeAgent {
    pub fn new(config: AgentConfig, image_path: String, pool: Arc<SqlitePool>, is_logical: bool) -> Self {
        let is_folder = std::path::Path::new(&image_path).is_dir();
        let db_path = if is_folder {
            format!("{}.exhume.sqlite", image_path.trim_end_matches('/'))
        } else {
            format!("{}.index.sqlite", image_path)
        };
        
        let extraction_dir = std::path::Path::new(&db_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("extracted");
        
        if let Err(e) = std::fs::create_dir_all(&extraction_dir) {
            eprintln!("Warning: Failed to create extraction directory {:?}: {}", extraction_dir, e);
        }

        Self { config, image_path, pool, extraction_dir, is_folder, is_logical }
    }

    /// Extract text from rigorous Message content blocks via JSON to avoid exhaustive rigorous type mismatches
    fn extract_text_from_message(msg: &Message) -> String {
        serde_json::to_string(msg).unwrap_or_default()
    }

    /// Load conversation history from the database
    pub async fn load_history(&self) -> Result<Vec<Message>> {
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
                Message::Assistant { .. } => conversation.push_str(&format!("Assistant: {}\n", text)),
            }
        }
        if conversation.is_empty() {
            return Err(anyhow!("No user message in history to prompt with."));
        }
        Ok(conversation)
    }

    /// Helper to dynamically build the right rig::agent::Agent based on the config.
    pub async fn chat(&self, history: &[Message]) -> Result<String> {
        let target_type = if self.is_folder {
            "local folder"
        } else if self.is_logical {
            "logical volume dump"
        } else {
            "disk image"
        };

        // Dynamically discover the database schema for the preamble
        let schema_ddl = Self::discover_schema(&self.pool).await.unwrap_or_else(|_| "(schema unavailable)".to_string());

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
            
            {layout_instructions}
            You can then use the `detect_filesystem` tool on a specific partition to see what filesystem is formatted inside it.
            You can traverse the file system inside a partition using the `list_dir` tool by passing its offset and size. For the root directory, omit the `file_id`. For subdirectories, provide the `file_id` returned by previous `list_dir` calls.
            You can extract the contents of a specific file using the `extract_file` tool by providing the `file_id` discovered via `list_dir`. Extracted files are dumped into a persistent `extracted/` directory next to the database for subsequent analysis.
            
            When providing a file for analysis (e.g., to a specialist or for your own content review), ALWAYS call `extract_file` first to ensure the file is available on the host filesystem.
            
            Database Schema:
            You can search the index using the `query_index` tool. The live schema is:
            {schema_ddl}
            
            Key column notes: In `system_files`, the `identifier` column is the file_id used by other tools. `ftype` is 'File' or 'Directory'. `metadata` is JSON.
            If a `system_files_fts` table exists, you can use FTS5 queries like: `SELECT * FROM system_files_fts WHERE system_files_fts MATCH 'keyword'`.
            
            Instead of manually traversing directories with `list_dir`, it is highly recommended to use `query_index` first to locate artifacts of interest, taking note of their `identifier` (`file_id`), or query `artifact_objects` directly to see results of past parser runs.
            
            IMPORTANT — query_index results: When you call `query_index`, the full result table is rendered directly on the user's terminal. DO NOT re-enumerate or re-list the individual rows in your final answer — the user can already see the table. Instead, summarise key findings, highlight notable items, and explain what the results mean for the investigation.
            
            Multi-Agent Delegation:
            You act as the Lead Investigator. When you discover media files or databases (e.g. by querying `SELECT absolute_path, identifier FROM system_files WHERE sig_mime LIKE 'image/%' LIMIT 5`), DO NOT extract them yourself. Instead, pass their `identifier` (as `file_id`) to the specialized AI delegation tools:
            - Use `delegate_image_specialist` for pictures (e.g., .png, .jpg).
            - Use `delegate_audio_specialist` for audio recordings (e.g., .wav, .mp3).
            - Use `delegate_sqlite_specialist` for SQLite databases (e.g., .sqlite, .db).
            The specialists will independently analyze these complex files, save their forensic structured findings into the database, and return a readable summary for you to build the overarching investigation story.
            
            System Interaction:
            You have access to the `shell` tool to execute commands on the host system. Use this for environment investigation, advanced file operations, or running external specialized forensic tools.
            The `shell` tool automatically prompts the user for manual approval (y/N) at the terminal level before execution. Do not ask for permission in the chat; simply call the tool when a command is necessary. Be precise with your commands.",
            self.image_path
        );

        // Resolve evidence_id from the database (fallback to 1)
        let evidence_id: i64 = sqlx::query_scalar("SELECT DISTINCT evidence_id FROM system_files LIMIT 1")
            .fetch_optional(&*self.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(1);

        let list_partitions = ListPartitionsTool::new(self.image_path.clone());
        let detect_fs = DetectFilesystemTool::new(self.image_path.clone(), self.pool.clone());
        let list_dir = ListDirTool::new(self.image_path.clone(), self.pool.clone());
        let extract_file = ExtractFileTool::new(self.image_path.clone(), self.extraction_dir.clone(), self.pool.clone());
        let query_index = QueryIndexTool::new(self.pool.clone());
        let delegate_image = DelegateImageSpecialist::new(self.pool.clone(), evidence_id, self.config.clone(), self.image_path.clone(), self.extraction_dir.clone());
        let delegate_audio = DelegateAudioSpecialist::new(self.pool.clone(), evidence_id, self.config.clone(), self.image_path.clone(), self.extraction_dir.clone());
        let delegate_sqlite = DelegateSqliteSpecialist::new(self.pool.clone(), evidence_id, self.config.clone(), self.image_path.clone(), self.extraction_dir.clone());
        let shell = ShellTool;

        let conversation = Self::build_conversation_text(history)?;
        println!("  {} {}...", "💭".cyan(), "Investigating evidence".bold());

        // Macro to avoid duplicating tool registration across providers
        macro_rules! build_and_prompt {
            ($client:expr) => {{
                let agent = $client
                    .agent(&self.config.model)
                    .preamble(&preamble)
                    .default_max_turns(10)
                    .hook(ReasoningHook)
                    .tool(list_partitions)
                    .tool(detect_fs)
                    .tool(list_dir)
                    .tool(extract_file)
                    .tool(query_index)
                    .tool(delegate_image)
                    .tool(delegate_audio)
                    .tool(delegate_sqlite)
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
            _ => Err(anyhow!("Unsupported provider: {}", self.config.provider)),
        }
    }
}
