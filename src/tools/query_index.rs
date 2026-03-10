use prettytable::{Cell, Row, Table, format};
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::{Column, Row as SqlRow, SqlitePool};
use std::sync::Arc;

const MAX_ROWS: usize = 100;

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
}

impl QueryIndexTool {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
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
            - `mbr_partition_entries`, `gpt_partition_entries`, `logical_partition_entries`: [id, first_byte_addr, size_sectors, fvek]
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
        println!(
            "  {} {} SQL: {}",
            "🛠️".magenta(),
            "Querying file index —".bold(),
            args.sql.dimmed()
        );

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
                    println!("  {} No rows returned.\n", "📋".cyan());
                    return Ok(QueryIndexOutput {
                        result: "Query returned 0 rows.".to_string(),
                        row_count: 0,
                        truncated: false,
                        error: None,
                    });
                }

                let total_rows = sql_rows.len();
                let is_truncated = total_rows > MAX_ROWS;
                let display_rows = if is_truncated { &sql_rows[..MAX_ROWS] } else { &sql_rows[..] };

                // Collect column names from the first row
                let col_names: Vec<String> = sql_rows[0]
                    .columns()
                    .iter()
                    .map(|c| c.name().to_string())
                    .collect();

                // Build prettytable
                let mut table = Table::new();
                table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

                // Header row
                let header_cells: Vec<Cell> = col_names
                    .iter()
                    .map(|name| Cell::new(name).style_spec("bFc"))
                    .collect();
                table.set_titles(Row::new(header_cells));

                // Data rows
                for row in display_rows {
                    let cells: Vec<Cell> = col_names
                        .iter()
                        .map(|col_name| {
                            // Try to get value as string first, then fallback to other types
                            // SQLite and sqlx can be flexible, but we need a string for the table.
                            let val_str = if let Ok(v) = row.try_get::<String, _>(col_name.as_str()) {
                                v
                            } else if let Ok(v) = row.try_get::<i64, _>(col_name.as_str()) {
                                v.to_string()
                            } else if let Ok(v) = row.try_get::<f64, _>(col_name.as_str()) {
                                v.to_string()
                            } else if let Ok(v) = row.try_get::<bool, _>(col_name.as_str()) {
                                v.to_string()
                            } else {
                                "NULL".to_string()
                            };

                            Cell::new(&val_str)
                        })
                        .collect();
                    table.add_row(Row::new(cells));
                }

                // Print the coloured table for the user
                println!();
                table.printstd();

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

                // Return a plain-text version of the table to the LLM so it can reason about the data
                let plain_table = table.to_string();
                let truncation_note = if is_truncated {
                    format!("\n[TRUNCATED: Showing {} of {} rows. Add LIMIT or WHERE clauses to narrow results.]", MAX_ROWS, total_rows)
                } else {
                    String::new()
                };
                Ok(QueryIndexOutput {
                    result: format!(
                        "{} row(s) returned. Columns: [{}]\n\n{}{}",
                        total_rows,
                        col_names.join(", "),
                        plain_table,
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
