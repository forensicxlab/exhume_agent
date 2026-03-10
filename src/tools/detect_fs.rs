use crate::evidence_io;
use exhume_filesystem::Filesystem;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use colored::Colorize;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct DetectFilesystemArgs {
    pub offset: u64,
    pub partition_size: u64,
    pub partition_id: Option<i64>,
}

#[derive(Serialize)]
pub struct DetectFilesystemOutput {
    pub fs_type: String,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("DetectFilesystemError: {0}")]
pub struct DetectFilesystemError(pub String);

#[derive(Clone)]
pub struct DetectFilesystemTool {
    image_path: String,
    pool: Arc<SqlitePool>,
}

impl DetectFilesystemTool {
    pub fn new(image_path: String, pool: Arc<SqlitePool>) -> Self {
        Self { image_path, pool }
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
            description: "Detects the underlying filesystem type (like NTFS, Ext, APFS, exFAT) on a given partition.".to_string(),
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
                    }
                },
                "required": ["offset", "partition_size"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("  {} {} (offset: {})...", "🛠️".magenta(), "Detecting filesystem".bold(), args.offset);

        let fs_res = if let Some(pid) = args.partition_id {
            evidence_io::open_filesystem(&self.image_path, pid, &*self.pool)
                .await
                .map_err(|e| DetectFilesystemError(e.to_string()))
        } else {
            use exhume_body::Body;
            use exhume_filesystem::detected_fs::detect_filesystem;
            let body = Body::new(self.image_path.clone(), "auto");
            detect_filesystem(&body, args.offset, args.partition_size, None)
                .map_err(|e| DetectFilesystemError(format!("Could not mount partition: {}", e)))
        };

        match fs_res {
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
