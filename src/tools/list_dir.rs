use exhume_body::Body;
use exhume_filesystem::detected_fs::detect_filesystem;
use exhume_filesystem::filesystem::{DirectoryCommon, FileCommon};
use exhume_filesystem::Filesystem;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ListDirArgs {
    pub offset: u64,
    pub partition_size: u64,
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
}

impl ListDirTool {
    pub fn new(image_path: String) -> Self {
        Self { image_path }
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
        let body = Body::new(self.image_path.clone(), "auto");

        let mut fs = match detect_filesystem(&body, args.offset, args.partition_size, None) {
            Ok(fs) => fs,
            Err(e) => {
                return Ok(ListDirOutput {
                    entries: vec![],
                    error: Some(format!("Could not mount partition: {}", e)),
                });
            }
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
                // To keep the reply compact for the LLM, we resolve file sizes for dirs where we can,
                // but for speed we might not get full sizes.
                let mut results = Vec::new();
                for entry in entries {
                    // Try to get the actual file to reliably determine is_dir and size
                    // Since DetectedDir doesn't have is_dir/size in DirectoryCommon 
                    // (it only has file_id() and name()), we fetch the file.
                    if let Ok(file) = fs.get_file(entry.file_id()) {
                        results.push(DirEntryInfo {
                            file_id: entry.file_id(),
                            name: entry.name().to_string(),
                            is_dir: file.is_dir(),
                            size: file.size(),
                        });
                    } else {
                        // Fallback if get_file fails for some reason
                         results.push(DirEntryInfo {
                            file_id: entry.file_id(),
                            name: entry.name().to_string(),
                            is_dir: false, // Defaulting for fallback
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
