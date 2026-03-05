use exhume_body::Body;
use exhume_filesystem::detected_fs::detect_filesystem;
use exhume_filesystem::Filesystem;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ExtractFileArgs {
    pub offset: u64,
    pub partition_size: u64,
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
}

impl ExtractFileTool {
    pub fn new(image_path: String) -> Self {
        Self { image_path }
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
            description: "Reads the contents of a file located within a specific partition.".to_string(),
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
        let body = Body::new(self.image_path.clone(), "auto");

        let mut fs = match detect_filesystem(&body, args.offset, args.partition_size, None) {
            Ok(fs) => fs,
            Err(e) => {
                return Ok(ExtractFileOutput {
                    content_utf8: None,
                    size_read: 0,
                    is_truncated: false,
                    error: Some(format!("Could not mount partition: {}", e)),
                });
            }
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

        match fs.read_file_prefix(&file, max_len + 1) {
            Ok(data) => {
                let is_truncated = data.len() > max_len;
                let actual_data = if is_truncated { &data[..max_len] } else { &data };

                // Try to parse as UTF-8 string for easy reading by the LLM
                let content_utf8 = match String::from_utf8(actual_data.to_vec()) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        // Fallback to lossy if it's mostly text with some bad chars, 
                        // but if it's completely binary, the LLM will just get messy printable string.
                        Some(String::from_utf8_lossy(actual_data).into_owned())
                    }
                };

                Ok(ExtractFileOutput {
                    content_utf8,
                    size_read: actual_data.len(),
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
