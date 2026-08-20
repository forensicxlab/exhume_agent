use crate::evidence_io::extract_file_bytes;
use crate::policy::AgentPolicy;
use crate::tools::query_index::validate_read_query;
use crate::ui::UiHandle;
use futures_util::TryStreamExt;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Column, Row, SqlitePool};
use std::sync::Arc;
use std::time::Duration;

const MAX_SQLITE_FILE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CELL_CHARS: usize = 500;

#[derive(Deserialize)]
pub struct QuerySqliteFileArgs {
    pub file_id: u64,
    pub partition_id: i64,
    pub sql: String,
    pub max_rows: Option<usize>,
}

#[derive(Serialize)]
pub struct QuerySqliteFileOutput {
    pub file_name: String,
    pub source_sha256: String,
    pub result: String,
    pub row_count: usize,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("QuerySqliteFileError: {0}")]
pub struct QuerySqliteFileError(pub String);

#[derive(Clone)]
pub struct QuerySqliteFileTool {
    image_path: String,
    extraction_dir: std::path::PathBuf,
    evidence_pool: Arc<SqlitePool>,
    ui: Option<UiHandle>,
    policy: AgentPolicy,
}

impl QuerySqliteFileTool {
    pub fn new(
        image_path: String,
        extraction_dir: std::path::PathBuf,
        evidence_pool: Arc<SqlitePool>,
        ui: Option<UiHandle>,
        policy: AgentPolicy,
    ) -> Self {
        Self {
            image_path,
            extraction_dir,
            evidence_pool,
            ui,
            policy,
        }
    }
}

impl Tool for QuerySqliteFileTool {
    const NAME: &'static str = "query_sqlite_file";

    type Args = QuerySqliteFileArgs;
    type Output = QuerySqliteFileOutput;
    type Error = QuerySqliteFileError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Extract a SQLite evidence file and execute one bounded read-only query. \
                Use the system_files identifier and partition_id. The extracted database is opened immutable and cannot be modified."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_id": {
                        "type": "integer",
                        "description": "The identifier from system_files."
                    },
                    "partition_id": {
                        "type": "integer",
                        "description": "The partition containing the SQLite file."
                    },
                    "sql": {
                        "type": "string",
                        "description": "One SELECT, WITH ... SELECT, or EXPLAIN SELECT statement."
                    },
                    "max_rows": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": self.policy.max_query_rows
                    }
                },
                "required": ["file_id", "partition_id", "sql"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let sql = match validate_read_query(&args.sql) {
            Ok(sql) => sql,
            Err(error) => return Ok(error_output("", "", error)),
        };
        if let Some(ui) = &self.ui {
            ui.log(format!(
                "Extracting and querying SQLite file_id={} partition_id={}",
                args.file_id, args.partition_id
            ));
        }
        let indexed_size = sqlx::query_scalar::<_, i64>(
            "SELECT size FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1",
        )
        .bind(args.file_id as i64)
        .bind(args.partition_id)
        .fetch_optional(&*self.evidence_pool)
        .await
        .map_err(|error| QuerySqliteFileError(error.to_string()))?
        .unwrap_or(0);
        if indexed_size > MAX_SQLITE_FILE_BYTES as i64 {
            return Ok(error_output(
                "",
                "",
                "SQLite evidence file exceeds the 512MB interactive-query limit.",
            ));
        }

        let extracted = extract_file_bytes(
            &self.evidence_pool,
            &self.image_path,
            args.file_id,
            args.partition_id,
            &self.extraction_dir,
        )
        .await
        .map_err(|error| QuerySqliteFileError(error.to_string()))?;
        if extracted.content.len() > MAX_SQLITE_FILE_BYTES {
            return Ok(error_output(
                &extracted.file_name,
                &extracted.sha256,
                "SQLite evidence file exceeds the 512MB interactive-query limit.",
            ));
        }
        if !extracted.content.starts_with(b"SQLite format 3\0") {
            return Ok(error_output(
                &extracted.file_name,
                &extracted.sha256,
                "The selected file does not have a SQLite 3 header.",
            ));
        }

        let options = SqliteConnectOptions::new()
            .filename(&extracted.dump_path)
            .read_only(true)
            .create_if_missing(false)
            .immutable(true)
            .busy_timeout(Duration::from_secs(self.policy.query_timeout_secs.max(1)));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|error| QuerySqliteFileError(error.to_string()))?;
        let max_rows = args
            .max_rows
            .unwrap_or(50)
            .clamp(1, self.policy.max_query_rows.max(1));
        let timeout = Duration::from_secs(self.policy.query_timeout_secs.max(1));
        let query = async {
            let mut stream = sqlx::query(&sql).fetch(&pool);
            let mut rows = Vec::with_capacity(max_rows.saturating_add(1));
            while rows.len() <= max_rows {
                match stream.try_next().await {
                    Ok(Some(row)) => rows.push(row),
                    Ok(None) => break,
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok::<_, String>(rows)
        };
        let mut rows = match tokio::time::timeout(timeout, query).await {
            Ok(Ok(rows)) => rows,
            Ok(Err(error)) => {
                pool.close().await;
                return Ok(error_output(&extracted.file_name, &extracted.sha256, error));
            }
            Err(_) => {
                pool.close().await;
                return Ok(error_output(
                    &extracted.file_name,
                    &extracted.sha256,
                    format!("Query exceeded the {} second timeout.", timeout.as_secs()),
                ));
            }
        };
        pool.close().await;

        let truncated = rows.len() > max_rows;
        rows.truncate(max_rows);
        let result = if rows.is_empty() {
            "Query returned 0 rows.".to_string()
        } else {
            render_rows(&rows)
        };
        Ok(QuerySqliteFileOutput {
            file_name: extracted.file_name,
            source_sha256: extracted.sha256,
            result,
            row_count: rows.len(),
            truncated,
            error: None,
        })
    }
}

fn render_rows(rows: &[SqliteRow]) -> String {
    let columns: Vec<String> = rows[0]
        .columns()
        .iter()
        .map(|column| column.name().to_string())
        .collect();
    let mut output = format!("Columns: [{}]\n", columns.join(", "));
    for (index, row) in rows.iter().enumerate() {
        let values: Vec<String> = columns
            .iter()
            .map(|column| format!("{column}={}", read_cell(row, column)))
            .collect();
        output.push_str(&format!("{}: {}\n", index + 1, values.join(" | ")));
    }
    output
}

fn read_cell(row: &SqliteRow, column: &str) -> String {
    let value = if let Ok(value) = row.try_get::<String, _>(column) {
        value
    } else if let Ok(value) = row.try_get::<i64, _>(column) {
        value.to_string()
    } else if let Ok(value) = row.try_get::<f64, _>(column) {
        value.to_string()
    } else if let Ok(value) = row.try_get::<Vec<u8>, _>(column) {
        format!("<{} bytes>", value.len())
    } else {
        "NULL".to_string()
    };
    let mut chars = value.chars();
    let mut result: String = chars.by_ref().take(MAX_CELL_CHARS).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result.replace(['\n', '\r'], " ")
}

fn error_output(
    file_name: impl Into<String>,
    source_sha256: impl Into<String>,
    error: impl Into<String>,
) -> QuerySqliteFileOutput {
    QuerySqliteFileOutput {
        file_name: file_name.into(),
        source_sha256: source_sha256.into(),
        result: String::new(),
        row_count: 0,
        truncated: false,
        error: Some(error.into()),
    }
}
