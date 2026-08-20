use crate::report::{self, ReportUpdateInput};
use crate::ui::UiHandle;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct UpdateDigitalReportArgs {
    pub section: String,
    pub title: String,
    pub summary: String,
    pub details_markdown: String,
    pub methodology_steps: Vec<String>,
    pub supporting_evidence: Vec<String>,
}

#[derive(Serialize)]
pub struct UpdateDigitalReportOutput {
    pub success: bool,
    pub export_path: Option<String>,
    pub supporting_event_ids: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("UpdateDigitalReportError: {0}")]
pub struct UpdateDigitalReportError(pub String);

#[derive(Clone)]
pub struct UpdateDigitalReportTool {
    pool: Arc<SqlitePool>,
    enabled: bool,
    ui: Option<UiHandle>,
}

impl UpdateDigitalReportTool {
    pub fn new(pool: Arc<SqlitePool>, enabled: bool, ui: Option<UiHandle>) -> Self {
        Self { pool, enabled, ui }
    }
}

impl Tool for UpdateDigitalReportTool {
    const NAME: &'static str = "update_digital_report";

    type Args = UpdateDigitalReportArgs;
    type Output = UpdateDigitalReportOutput;
    type Error = UpdateDigitalReportError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Append a court-oriented finding to the persisted Digital Forensics Report. The host automatically attaches successful forensic tool-event IDs from the current turn and rejects ungrounded updates.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "description": "Report section label, for example 'Analysis', 'Timeline', 'User Activity', or 'File System Findings'."
                    },
                    "title": {
                        "type": "string",
                        "description": "Short finding title."
                    },
                    "summary": {
                        "type": "string",
                        "description": "One concise paragraph describing the significance of the finding."
                    },
                    "details_markdown": {
                        "type": "string",
                        "description": "Markdown details explaining the finding, evidence analyzed, and investigative interpretation."
                    },
                    "methodology_steps": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Ordered steps that another examiner could follow to reproduce the result."
                    },
                    "supporting_evidence": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Relevant file paths, file identifiers, SQL queries, extracted artefacts, or command references."
                    }
                },
                "required": ["section", "title", "summary", "details_markdown", "methodology_steps", "supporting_evidence"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if !self.enabled {
            return Ok(UpdateDigitalReportOutput {
                success: false,
                export_path: None,
                supporting_event_ids: Vec::new(),
                error: Some("Reporting is disabled for this session.".to_string()),
            });
        }

        let supporting_event_ids = self
            .ui
            .as_ref()
            .map(UiHandle::supporting_event_ids)
            .unwrap_or_default();
        if supporting_event_ids.is_empty() {
            return Ok(UpdateDigitalReportOutput {
                success: false,
                export_path: None,
                supporting_event_ids,
                error: Some(
                    "Report update rejected: no successful forensic tool event exists in the current turn."
                        .to_string(),
                ),
            });
        }
        let mut supporting_evidence = args.supporting_evidence;
        supporting_evidence.extend(
            supporting_event_ids
                .iter()
                .map(|event_id| format!("Agent tool event: {event_id}")),
        );

        report::append_report_update(
            &self.pool,
            ReportUpdateInput {
                section: args.section,
                title: args.title,
                summary: args.summary,
                details_markdown: args.details_markdown,
                methodology_steps: args.methodology_steps,
                supporting_evidence,
            },
        )
        .await
        .map_err(|e| UpdateDigitalReportError(e.to_string()))?;

        let evidence_id = report::current_evidence_id(&self.pool)
            .await
            .map_err(|e| UpdateDigitalReportError(e.to_string()))?;
        let export_path = sqlx::query_scalar::<_, String>(
            "SELECT export_path FROM digital_reports WHERE evidence_id = ?",
        )
        .bind(evidence_id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| UpdateDigitalReportError(e.to_string()))?
        .unwrap_or_default();

        if let Some(ui) = &self.ui {
            ui.log(format!("Digital report updated: {}", export_path));
            ui.report_updated_at(Some(export_path.clone()));
        }

        Ok(UpdateDigitalReportOutput {
            success: true,
            export_path: Some(export_path),
            supporting_event_ids,
            error: None,
        })
    }
}
