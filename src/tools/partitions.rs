use crate::ui::UiHandle;
use colored::Colorize;
use exhume_body::Body;
use exhume_partitions::Partitions;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ListPartitionsArgs {}

#[derive(Serialize)]
pub struct PartitionInfo {
    pub partition_type: String, // e.g. "MBR", "GPT"
    pub index: usize,
    pub first_sector: u64,
    pub size_sectors: u64,
    pub bootable: bool,
    pub type_name: String,
}

#[derive(Serialize)]
pub struct ListPartitionsOutput {
    pub sector_size: u32,
    pub partitions: Vec<PartitionInfo>,
}

#[derive(Debug, thiserror::Error)]
#[error("PartitionError: {0}")]
pub struct PartitionError(pub String);

pub struct ListPartitionsTool {
    image_path: String,
    ui: Option<UiHandle>,
}

impl ListPartitionsTool {
    pub fn new(image_path: String, ui: Option<UiHandle>) -> Self {
        Self { image_path, ui }
    }
}

impl Tool for ListPartitionsTool {
    const NAME: &'static str = "list_partitions";

    type Args = ListPartitionsArgs;
    type Output = ListPartitionsOutput;
    type Error = PartitionError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Scans the disk image for MBR or GPT partition tables and returns a list of partitions with their starting sectors and sizes.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        if let Some(ui) = &self.ui {
            ui.log("Listing partitions...");
        } else {
            println!("  {} {}...", "🛠️".magenta(), "Listing partitions".bold());
        }
        let mut body = Body::new(self.image_path.clone(), "auto");

        let sector_size = body.get_sector_size();
        let mut results = Vec::new();

        let parts = Partitions::new(&mut body).map_err(|e| PartitionError(e.to_string()))?;

        if let Some(gpt) = parts.gpt {
            for (i, entry) in gpt.partition_entries.iter().enumerate() {
                results.push(PartitionInfo {
                    partition_type: "GPT".to_string(),
                    index: i + 1,
                    first_sector: entry.starting_lba,
                    size_sectors: entry.size_sectors / sector_size as u64,
                    bootable: false,
                    type_name: entry.description.clone(),
                });
            }
        } else if let Some(mbr) = parts.mbr {
            for (i, entry) in mbr.partition_table.iter().enumerate() {
                if entry.size_sectors > 0 {
                    results.push(PartitionInfo {
                        partition_type: "MBR".to_string(),
                        index: i + 1,
                        first_sector: entry.start_lba as u64,
                        size_sectors: entry.size_sectors as u64,
                        bootable: entry.boot_indicator == 0x80,
                        type_name: entry.description.clone(),
                    });
                }
            }
        }

        Ok(ListPartitionsOutput {
            sector_size: sector_size as u32,
            partitions: results,
        })
    }
}
