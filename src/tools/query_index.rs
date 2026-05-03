use crate::ui::UiHandle;
use prettytable::{format, Cell, Row, Table};
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::{Column, Row as SqlRow, SqlitePool};
use std::sync::Arc;

const MAX_ROWS: usize = 100;

/// Columns that are printed for the human investigator but excluded from the LLM's context
/// because they contain large binary / raw data that consumes tokens without adding reasoning value.
const LLM_EXCLUDED_COLS: &[&str] = &["metadata", "display"];

/// Maximum characters per cell value returned to the LLM. Values beyond this are truncated.
const LLM_MAX_CELL: usize = 300;

#[derive(Deserialize)]
pub struct QueryIndexArgs {
    pub sql: String,
}

#[derive(Serialize)]
pub struct QueryIndexOutput {
    /// Compact text table returned to the LLM (prettytable format).
    pub result: String,
    pub row_count: usize,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("QueryIndexError: {0}")]
pub struct QueryIndexError(pub String);

#[derive(Clone)]
pub struct QueryIndexTool {
    pool: Arc<SqlitePool>,
    ui: Option<UiHandle>,
}

impl QueryIndexTool {
    pub fn new(pool: Arc<SqlitePool>, ui: Option<UiHandle>) -> Self {
        Self { pool, ui }
    }
}

impl Tool for QueryIndexTool {
    const NAME: &'static str = "query_index";

    type Args = QueryIndexArgs;
    type Output = QueryIndexOutput;
    type Error = QueryIndexError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Execute a read-only SQL query against the local SQLite forensic index.
            Available tables:
            - `system_files`: [id, evidence_id, partition_id, identifier (file_id), absolute_path, name, ftype, size, created, modified, accessed, sig_name, sig_mime, sig_exts, metadata, display]
            - `artifacts`: [id, file_id, name, description, parser, tag, category]
            - `artifact_objects`: [id, artifact_id, file_id, parser, kind, text, json]
            - `partitions`: [id, evidence_id, kind, first_byte_addr, size_sectors, sector_size, size_bytes, fvek, description]
            Results are rendered as a table for both the user and returned as text for your analysis.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "The SQL SELECT statement to execute."
                    }
                },
                "required": ["sql"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        use colored::Colorize;
        if let Some(ui) = &self.ui {
            ui.log(format!("Querying file index: {}", args.sql));
        } else {
            println!(
                "  {} {} SQL: {}",
                "🛠️".magenta(),
                "Querying file index —".bold(),
                args.sql.dimmed()
            );
        }

        let sql = args.sql.trim();
        if !sql.to_uppercase().starts_with("SELECT") {
            return Ok(QueryIndexOutput {
                result: String::new(),
                row_count: 0,
                truncated: false,
                error: Some("Only SELECT queries are allowed.".to_string()),
            });
        }

        let rows_res = sqlx::query(sql).fetch_all(&*self.pool).await;

        match rows_res {
            Ok(sql_rows) => {
                if sql_rows.is_empty() {
                    if let Some(ui) = &self.ui {
                        ui.log("Query returned 0 rows.");
                    } else {
                        println!("  {} No rows returned.\n", "📋".cyan());
                    }
                    return Ok(QueryIndexOutput {
                        result: "Query returned 0 rows.".to_string(),
                        row_count: 0,
                        truncated: false,
                        error: None,
                    });
                }

                let total_rows = sql_rows.len();
                let is_truncated = total_rows > MAX_ROWS;
                let display_rows = if is_truncated {
                    &sql_rows[..MAX_ROWS]
                } else {
                    &sql_rows[..]
                };

                // Collect column names from the first row
                let col_names: Vec<String> = sql_rows[0]
                    .columns()
                    .iter()
                    .map(|c| c.name().to_string())
                    .collect();

                // ── Helper: read one cell as a String ────────────────────
                let read_cell = |row: &sqlx::sqlite::SqliteRow, col: &str| -> String {
                    if let Ok(v) = row.try_get::<String, _>(col) {
                        v
                    } else if let Ok(v) = row.try_get::<i64, _>(col) {
                        v.to_string()
                    } else if let Ok(v) = row.try_get::<f64, _>(col) {
                        v.to_string()
                    } else if let Ok(v) = row.try_get::<bool, _>(col) {
                        v.to_string()
                    } else {
                        "NULL".to_string()
                    }
                };

                // ── Full table printed to the terminal (all columns, no truncation) ──
                let mut full_table = Table::new();
                full_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                full_table.set_titles(Row::new(
                    col_names.iter().map(|n| Cell::new(n).style_spec("bFc")).collect(),
                ));
                for row in display_rows {
                    full_table.add_row(Row::new(
                        col_names.iter().map(|c| Cell::new(&read_cell(row, c))).collect(),
                    ));
                }

                if let Some(ui) = &self.ui {
                    ui.log(full_table.to_string());
                    if is_truncated {
                        ui.log(format!(
                            "Showing {} of {} total rows. Use LIMIT/WHERE to refine.",
                            MAX_ROWS, total_rows
                        ));
                    } else {
                        ui.log(format!("{} row(s) returned.", total_rows));
                    }
                } else {
                    println!();
                    full_table.printstd();
                    if is_truncated {
                        println!(
                            "  {} Showing {} of {} total rows. Use LIMIT/WHERE to refine.\n",
                            "⚠️".yellow(),
                            MAX_ROWS.to_string().bold(),
                            total_rows.to_string().bold()
                        );
                    } else {
                        println!(
                            "  {} {} row(s) returned.\n",
                            "📋".cyan(),
                            total_rows.to_string().bold()
                        );
                    }
                }

                // ── Slim table returned to the LLM (heavy columns stripped, values capped) ──
                let llm_cols: Vec<&String> = col_names
                    .iter()
                    .filter(|n| !LLM_EXCLUDED_COLS.contains(&n.as_str()))
                    .collect();

                let mut llm_table = Table::new();
                llm_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                llm_table.set_titles(Row::new(
                    llm_cols.iter().map(|n| Cell::new(n).style_spec("bFc")).collect(),
                ));
                for row in display_rows {
                    llm_table.add_row(Row::new(
                        llm_cols
                            .iter()
                            .map(|c| {
                                let val = read_cell(row, c);
                                let truncated = if val.len() > LLM_MAX_CELL {
                                    format!("{}…", &val[..LLM_MAX_CELL])
                                } else {
                                    val
                                };
                                Cell::new(&truncated)
                            })
                            .collect(),
                    ));
                }

                let excluded_note = if !LLM_EXCLUDED_COLS.iter().all(|e| !col_names.iter().any(|c| c == e)) {
                    let present: Vec<&str> = LLM_EXCLUDED_COLS
                        .iter()
                        .filter(|e| col_names.iter().any(|c| c.as_str() == **e))
                        .copied()
                        .collect();
                    format!(" (columns omitted from context: {})", present.join(", "))
                } else {
                    String::new()
                };

                let truncation_note = if is_truncated {
                    format!(
                        "\n[TRUNCATED: showing {} of {} rows — add LIMIT/WHERE to narrow results.]",
                        MAX_ROWS, total_rows
                    )
                } else {
                    String::new()
                };

                Ok(QueryIndexOutput {
                    result: format!(
                        "{} row(s) returned. Columns: [{}]{}\n\n{}{}",
                        total_rows,
                        llm_cols.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", "),
                        excluded_note,
                        llm_table.to_string(),
                        truncation_note
                    ),
                    row_count: total_rows,
                    truncated: is_truncated,
                    error: None,
                })
            }
            Err(e) => Ok(QueryIndexOutput {
                result: String::new(),
                row_count: 0,
                truncated: false,
                error: Some(e.to_string()),
            }),
        }
    }
}
