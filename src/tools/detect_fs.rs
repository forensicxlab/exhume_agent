use exhume_body::Body;
use exhume_filesystem::detected_fs::detect_filesystem;
use exhume_filesystem::Filesystem;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DetectFilesystemArgs {
    pub offset: u64,
    pub partition_size: u64,
}

#[derive(Serialize)]
pub struct DetectFilesystemOutput {
    pub fs_type: String,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("DetectFilesystemError: {0}")]
pub struct DetectFilesystemError(pub String);

pub struct DetectFilesystemTool {
    image_path: String,
}

impl DetectFilesystemTool {
    pub fn new(image_path: String) -> Self {
        Self { image_path }
    }
}

impl Tool for DetectFilesystemTool {
    const NAME: &'static str = "detect_filesystem";

    type Args = DetectFilesystemArgs;
    type Output = DetectFilesystemOutput;
    type Error = DetectFilesystemError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Detects the underlying filesystem type (like NTFS, Ext, APFS, exFAT) on a given partition offset and size.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "offset": {
                        "type": "integer",
                        "description": "The absolute byte offset (first_sector * sector_size) where the partition starts"
                    },
                    "partition_size": {
                        "type": "integer",
                        "description": "The absolute size in bytes (size_sectors * sector_size) of the partition"
                    }
                },
                "required": ["offset", "partition_size"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let body = Body::new(self.image_path.clone(), "auto");

        match detect_filesystem(&body, args.offset, args.partition_size, None) {
            Ok(fs) => Ok(DetectFilesystemOutput {
                fs_type: fs.filesystem_type(),
                error: None,
            }),
            Err(e) => Ok(DetectFilesystemOutput {
                fs_type: "Unknown".to_string(),
                error: Some(e.to_string()),
            }),
        }
    }
}
