use crate::evidence_io;
use exhume_filesystem::Filesystem;
use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon};
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use colored::Colorize;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ListDirArgs {
    pub offset: u64,
    pub partition_size: u64,
    pub partition_id: Option<i64>,
    pub file_id: Option<u64>,
}

#[derive(Serialize)]
pub struct DirEntryInfo {
    pub file_id: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Serialize)]
pub struct ListDirOutput {
    pub entries: Vec<DirEntryInfo>,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("ListDirError: {0}")]
pub struct ListDirError(pub String);

#[derive(Clone)]
pub struct ListDirTool {
    image_path: String,
    pool: Arc<SqlitePool>,
}

impl ListDirTool {
    pub fn new(image_path: String, pool: Arc<SqlitePool>) -> Self {
        Self { image_path, pool }
    }
}

impl Tool for ListDirTool {
    const NAME: &'static str = "list_dir";

    type Args = ListDirArgs;
    type Output = ListDirOutput;
    type Error = ListDirError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Lists the contents of a directory within a specific partition.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "offset": {
                        "type": "integer",
                        "description": "The absolute byte offset where the partition starts."
                    },
                    "partition_size": {
                        "type": "integer",
                        "description": "The absolute size in bytes of the partition."
                    },
                    "partition_id": {
                        "type": "integer",
                        "description": "The partition ID from the index database. If provided, offset/partition_size are ignored and resolved automatically."
                    },
                    "file_id": {
                        "type": "integer",
                        "description": "The file ID of the directory to list. Leave this empty/omitted to list the root directory."
                    }
                },
                "required": ["offset", "partition_size"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("  {} {} (id: {})...", "🛠️".magenta(), "Listing directory".bold(), args.file_id.unwrap_or(0));

        let mut fs = if let Some(pid) = args.partition_id {
            evidence_io::open_filesystem(&self.image_path, pid, &*self.pool)
                .await
                .map_err(|e| ListDirError(e.to_string()))?
        } else {
            use exhume_body::Body;
            use exhume_filesystem::detected_fs::detect_filesystem;
            let body = Body::new(self.image_path.clone(), "auto");
            detect_filesystem(&body, args.offset, args.partition_size, None)
                .map_err(|e| ListDirError(format!("Could not mount partition: {}", e)))?
        };

        let target_id = args.file_id.unwrap_or_else(|| fs.get_root_file_id());

        let dir_file = match fs.get_file(target_id) {
            Ok(f) => f,
            Err(e) => {
                return Ok(ListDirOutput {
                    entries: vec![],
                    error: Some(format!("Failed to read directory with id {}: {}", target_id, e)),
                });
            }
        };

        match fs.list_dir(&dir_file) {
            Ok(entries) => {
                let mut results = Vec::new();
                for entry in entries {
                    if let Ok(file) = fs.get_file(entry.file_id()) {
                        results.push(DirEntryInfo {
                            file_id: entry.file_id(),
                            name: entry.name().to_string(),
                            is_dir: file.is_dir(),
                            size: file.size(),
                        });
                    } else {
                        results.push(DirEntryInfo {
                            file_id: entry.file_id(),
                            name: entry.name().to_string(),
                            is_dir: false,
                            size: 0,
                        });
                    }
                }

                Ok(ListDirOutput {
                    entries: results,
                    error: None,
                })
            }
            Err(e) => Ok(ListDirOutput {
                entries: vec![],
                error: Some(format!("Failed to list directory: {}", e)),
            }),
        }
    }
}
