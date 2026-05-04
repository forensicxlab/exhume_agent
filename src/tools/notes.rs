use crate::ui::UiHandle;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct SaveNoteArgs {
    pub note: String,
    /// Forensic significance 0–100. Use >50 for material findings.
    pub significance: Option<i64>,
    /// `identifier` from system_files (the file_id used by other tools).
    pub file_id: Option<i64>,
    /// Human-readable path for context (optional, stored for readability).
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct SaveNoteOutput {
    pub note_id: i64,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("SaveNoteError: {0}")]
pub struct SaveNoteError(pub String);

#[derive(Clone)]
pub struct SaveInvestigationNoteTool {
    pool: Arc<SqlitePool>,
    ui: Option<UiHandle>,
}

impl SaveInvestigationNoteTool {
    pub fn new(pool: Arc<SqlitePool>, ui: Option<UiHandle>) -> Self {
        Self { pool, ui }
    }
}

impl Tool for SaveInvestigationNoteTool {
    const NAME: &'static str = "save_investigation_note";

    type Args = SaveNoteArgs;
    type Output = SaveNoteOutput;
    type Error = SaveNoteError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Persist a forensic finding or hypothesis to the investigation_notes \
                table. Use this to record material discoveries, mark files as reviewed, or \
                annotate items for the final report. Notes survive session restarts and can \
                be queried later with: \
                SELECT * FROM investigation_notes ORDER BY significance DESC, created_at DESC. \
                The significance field (0–100) mirrors the specialist score scale: \
                0–30 low, 31–60 medium, 61–100 high/critical."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The forensic finding or hypothesis to record."
                    },
                    "significance": {
                        "type": "integer",
                        "description": "Forensic significance 0–100. Omit or use 0 for routine observations.",
                        "minimum": 0,
                        "maximum": 100
                    },
                    "file_id": {
                        "type": "integer",
                        "description": "The identifier (file_id) from system_files this note relates to, if any."
                    },
                    "path": {
                        "type": "string",
                        "description": "Human-readable file path for context (optional)."
                    }
                },
                "required": ["note"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        use colored::Colorize;
        let significance = args.significance.unwrap_or(0).clamp(0, 100);

        if let Some(ui) = &self.ui {
            ui.log(format!(
                "Saving investigation note (significance={significance}): {}",
                &args.note
            ));
        } else {
            println!(
                "  {} {} [sig={}]: {}",
                "🛠️".magenta(),
                "Saving investigation note".bold(),
                significance,
                args.note.dimmed()
            );
        }

        let row = sqlx::query(
            r#"INSERT INTO investigation_notes (file_id, path, note, significance)
               VALUES (?, ?, ?, ?)
               RETURNING id"#,
        )
        .bind(args.file_id)
        .bind(&args.path)
        .bind(&args.note)
        .bind(significance)
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| SaveNoteError(e.to_string()))?;

        use sqlx::Row;
        let note_id: i64 = row.get(0);

        Ok(SaveNoteOutput {
            note_id,
            message: format!("Note saved (id={note_id}, significance={significance})."),
        })
    }
}
