use crate::evidence_io;
use crate::ui::UiHandle;
use colored::Colorize;
use exhume_filesystem::Filesystem;
use log::error;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ExtractFileArgs {
    pub offset: u64,
    pub partition_size: u64,
    pub partition_id: Option<i64>,
    pub file_id: u64,
    pub max_bytes: Option<usize>,
}

#[derive(Serialize)]
pub struct ExtractFileOutput {
    pub content_utf8: Option<String>,
    pub size_read: usize,
    pub is_truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("ExtractFileError: {0}")]
pub struct ExtractFileError(pub String);

#[derive(Clone)]
pub struct ExtractFileTool {
    image_path: String,
    extraction_dir: std::path::PathBuf,
    pool: Arc<SqlitePool>,
    ui: Option<UiHandle>,
}

impl ExtractFileTool {
    pub fn new(
        image_path: String,
        extraction_dir: std::path::PathBuf,
        pool: Arc<SqlitePool>,
        ui: Option<UiHandle>,
    ) -> Self {
        Self {
            image_path,
            extraction_dir,
            pool,
            ui,
        }
    }
}

impl Tool for ExtractFileTool {
    const NAME: &'static str = "extract_file";

    type Args = ExtractFileArgs;
    type Output = ExtractFileOutput;
    type Error = ExtractFileError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Reads the contents of a file located within a specific partition."
                .to_string(),
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
                        "description": "The file ID of the file to read within the filesystem."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Optional maximum number of bytes to read. Defaults to 8192 bytes. Keep this small to avoid filling up the context window."
                    }
                },
                "required": ["offset", "partition_size", "file_id"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if let Some(ui) = &self.ui {
            ui.log(format!(
                "Extracting file content for file_id={}...",
                args.file_id
            ));
        } else {
            println!(
                "  {} {} (id: {})...",
                "🛠️".magenta(),
                "Extracting file content".bold(),
                args.file_id
            );
        }

        let mut fs = if let Some(pid) = args.partition_id {
            evidence_io::open_filesystem(&self.image_path, pid, &*self.pool)
                .await
                .map_err(|e| ExtractFileError(e.to_string()))?
        } else {
            use exhume_body::Body;
            use exhume_filesystem::detected_fs::detect_filesystem;
            let body = Body::new(self.image_path.clone(), "auto");
            detect_filesystem(&body, args.offset, args.partition_size, None)
                .map_err(|e| ExtractFileError(format!("Could not mount partition: {}", e)))?
        };

        let file = match fs.get_file(args.file_id) {
            Ok(f) => f,
            Err(e) => {
                return Ok(ExtractFileOutput {
                    content_utf8: None,
                    size_read: 0,
                    is_truncated: false,
                    error: Some(format!("Failed to find file {}: {}", args.file_id, e)),
                });
            }
        };

        let max_len = args.max_bytes.unwrap_or(8192);

        match fs.read_file_content(&file) {
            Ok(data) => {
                // Persistent dump to host filesystem
                let dump_filename = format!("file_{}", args.file_id);
                let dump_path = self.extraction_dir.join(dump_filename);

                if let Err(e) = std::fs::write(&dump_path, &data) {
                    error!("Failed to dump file to host: {}", e);
                }

                let actual_len = data.len();
                let is_truncated = actual_len > max_len;
                let display_data = if is_truncated {
                    &data[..max_len]
                } else {
                    &data
                };

                let content_utf8 = match String::from_utf8(display_data.to_vec()) {
                    Ok(s) => Some(s),
                    Err(_) => Some(String::from_utf8_lossy(display_data).into_owned()),
                };

                let msg = format!(
                    "File ID {} extracted to host at: {:?}. ({} bytes read)",
                    args.file_id, dump_path, actual_len
                );
                if let Some(ui) = &self.ui {
                    ui.log(msg);
                } else {
                    println!("  {} {}", "💾".green(), msg);
                }

                Ok(ExtractFileOutput {
                    content_utf8,
                    size_read: actual_len,
                    is_truncated,
                    error: None,
                })
            }
            Err(e) => Ok(ExtractFileOutput {
                content_utf8: None,
                size_read: 0,
                is_truncated: false,
                error: Some(format!("Failed to read file: {}", e)),
            }),
        }
    }
}
