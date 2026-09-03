use crate::evidence_io;
use crate::ui::UiHandle;
use exhume_filesystem::Filesystem;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub sha256: Option<String>,
    pub dump_path: Option<String>,
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
            tracing::info!(file_id = args.file_id, "Extracting file content");
        }

        let max_len = args.max_bytes.unwrap_or(8192).clamp(1, 1_048_576);
        if let Some(partition_id) = args.partition_id {
            let extracted = evidence_io::extract_file_bytes(
                &self.pool,
                &self.image_path,
                args.file_id,
                partition_id,
                &self.extraction_dir,
            )
            .await
            .map_err(|error| ExtractFileError(error.to_string()))?;
            return Ok(output_from_data(
                &extracted.content,
                max_len,
                extracted.sha256,
                extracted.dump_path,
            ));
        }

        use exhume_body::Body;
        use exhume_filesystem::detected_fs::detect_filesystem;
        let body = Body::try_new(self.image_path.clone(), "auto").map_err(|error| {
            ExtractFileError(format!(
                "Unable to open evidence source '{}': {error}",
                self.image_path
            ))
        })?;
        let mut fs = detect_filesystem(&body, args.offset, args.partition_size, None)
            .map_err(|e| ExtractFileError(format!("Could not mount partition: {}", e)))?;

        let file = match fs.get_file(args.file_id) {
            Ok(f) => f,
            Err(e) => {
                return Ok(ExtractFileOutput {
                    content_utf8: None,
                    size_read: 0,
                    is_truncated: false,
                    sha256: None,
                    dump_path: None,
                    error: Some(format!("Failed to find file {}: {}", args.file_id, e)),
                });
            }
        };

        match fs.read_file_content(&file) {
            Ok(data) => {
                let sha256 = hex::encode(Sha256::digest(&data));
                let scoped_dir = self.extraction_dir.join("unindexed");
                std::fs::create_dir_all(&scoped_dir)
                    .map_err(|error| ExtractFileError(error.to_string()))?;
                let dump_path =
                    scoped_dir.join(format!("{}_{}_{}", args.file_id, &sha256[..12], "file"));

                std::fs::write(&dump_path, &data).map_err(|error| {
                    ExtractFileError(format!("Failed to persist extracted file: {error}"))
                })?;

                let msg = format!(
                    "File ID {} extracted to host at: {:?}. ({} bytes read)",
                    args.file_id,
                    dump_path,
                    data.len()
                );
                if let Some(ui) = &self.ui {
                    ui.log(msg);
                } else {
                    tracing::info!("{msg}");
                }

                Ok(output_from_data(&data, max_len, sha256, dump_path))
            }
            Err(e) => Ok(ExtractFileOutput {
                content_utf8: None,
                size_read: 0,
                is_truncated: false,
                sha256: None,
                dump_path: None,
                error: Some(format!("Failed to read file: {}", e)),
            }),
        }
    }
}

fn output_from_data(
    data: &[u8],
    max_len: usize,
    sha256: String,
    dump_path: std::path::PathBuf,
) -> ExtractFileOutput {
    let is_truncated = data.len() > max_len;
    let display_data = &data[..data.len().min(max_len)];
    ExtractFileOutput {
        content_utf8: Some(String::from_utf8_lossy(display_data).into_owned()),
        size_read: data.len(),
        is_truncated,
        sha256: Some(sha256),
        dump_path: Some(dump_path.display().to_string()),
        error: None,
    }
}
