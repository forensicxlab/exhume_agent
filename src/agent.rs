use crate::config::AgentConfig;
use crate::tools::partitions::ListPartitionsTool;
use crate::tools::detect_fs::DetectFilesystemTool;
use crate::tools::list_dir::ListDirTool;
use crate::tools::extract_file::ExtractFileTool;
use crate::tools::query_index::QueryIndexTool;
use anyhow::{Result, anyhow};
use rig::{
    agent::Agent,
    completion::{CompletionModel, Prompt},
    client::CompletionClient,
    message::Message,
    providers::{ollama, openai},
};
use std::sync::Arc;
use sqlx::SqlitePool;

pub struct ExhumeAgent {
    config: AgentConfig,
    image_path: String,
    pool: Arc<SqlitePool>,
}

impl ExhumeAgent {
    pub fn new(config: AgentConfig, image_path: String, pool: Arc<SqlitePool>) -> Self {
        Self { config, image_path, pool }
    }

    /// Extract text from rigorous Message content blocks via JSON to avoid exhaustive rigorous type mismatches
    fn extract_text_from_message(msg: &Message) -> String {
        serde_json::to_string(msg).unwrap_or_default()
    }

    /// Helper to dynamically build the right rig::agent::Agent based on the config.
    pub async fn chat(&self, history: &[Message]) -> Result<String> {
        let preamble = format!(
            "You are the Exhume Autonomous Forensic Assistant.
            Your job is to assist digital forensic investigators.
            You have access to native forensic capability tools that interact with a disk image.
            The current disk image being investigated is: {}
            
            When asked to examine the disk, ALWAYS start by listing the partitions to understand the layout.
            Use the `list_partitions` tool for this. Note down the partition IDs and their offsets.
            You can then use the `detect_filesystem` tool on a specific partition to see what filesystem is formatted inside it.
            You can traverse the file system inside a partition using the `list_dir` tool by passing its offset and size. For the root directory, omit the `file_id`. For subdirectories, provide the `file_id` returned by previous `list_dir` calls.
            You can extract the contents of a specific file using the `extract_file` tool by providing the `file_id` discovered via `list_dir`.
            You can quickly search the entire filesystem index using the `query_index` tool by writing SQL queries against the local `system_files` table. The `system_files` table contains `absolute_path`, `name`, `ftype`, `size`, `identifier` (which is the file_id), and other metadata.
            Instead of manually traversing directories with `list_dir`, it is highly recommended to use `query_index` first to locate artifacts of interest, taking note of their `identifier` (`file_id`), and then extracting them with `extract_file`.",
            self.image_path
        );

        let list_partitions = ListPartitionsTool::new(self.image_path.clone());
        let detect_fs = DetectFilesystemTool::new(self.image_path.clone());
        let list_dir = ListDirTool::new(self.image_path.clone());
        let extract_file = ExtractFileTool::new(self.image_path.clone());
        let query_index = QueryIndexTool::new(self.pool.clone());

        match self.config.provider.as_str() {
            "openai" => {
                let client: openai::Client = openai::Client::new(&self.config.api_key)
                    .map_err(|e| anyhow!("Failed to initialize OpenAI client: {}", e))?;
                let agent = client
                    .agent(&self.config.model)
                    .preamble(&preamble)
                    .default_max_turns(10)
                    .tool(list_partitions)
                    .tool(detect_fs)
                    .tool(list_dir.clone())
                    .tool(extract_file.clone())
                    .tool(query_index.clone())
                    .build();

                let mut conversation = String::new();
                for msg in history {
                    let text = Self::extract_text_from_message(msg);
                    match msg {
                        Message::User { .. } => conversation.push_str(&format!("User: {}\n", text)),
                        Message::Assistant { .. } => conversation.push_str(&format!("Assistant: {}\n", text)),
                        _ => {}
                    }
                }

                if conversation.is_empty() {
                    return Err(anyhow!("No user message in history to prompt with."));
                }

                let response = agent.prompt(&conversation).await?;
                Ok(response)
            }
            "ollama" => {
                let mut builder = ollama::Client::builder();
                if !self.config.endpoint.is_empty() {
                    builder = builder.base_url(&self.config.endpoint);
                }
                
                // Ollama in rig 0.31 requires a dummy API key wrapper 
                let client: ollama::Client = builder.api_key(rig::client::Nothing).build()?;
                let agent = client
                    .agent(&self.config.model)
                    .preamble(&preamble)
                    .default_max_turns(10)
                    .tool(list_partitions)
                    .tool(detect_fs)
                    .tool(list_dir)
                    .tool(extract_file)
                    .tool(query_index)
                    .build();

                let mut conversation = String::new();
                for msg in history {
                    let text = Self::extract_text_from_message(msg);
                    match msg {
                        Message::User { .. } => conversation.push_str(&format!("User: {}\n", text)),
                        Message::Assistant { .. } => conversation.push_str(&format!("Assistant: {}\n", text)),
                        _ => {}
                    }
                }

                let response = agent.prompt(&conversation).await?;
                Ok(response)
            }
            _ => Err(anyhow!("Unsupported provider: {}", self.config.provider)),
        }
    }
}
