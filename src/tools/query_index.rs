use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::{Column, Row, SqlitePool, TypeInfo};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct QueryIndexArgs {
    pub sql: String,
}

#[derive(Serialize)]
pub struct QueryIndexOutput {
    pub rows: serde_json::Value,
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
            description: "Execute a read-only SQL query against the local SQLite evidence index. The main table is `system_files` with columns: id, evidence_id, partition_id, identifier (file_id), absolute_path, name, ftype, size, created, modified, accessed, permissions, owner, group, metadata, display.".to_string(),
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
        let sql = args.sql.trim();
        if !sql.to_uppercase().starts_with("SELECT") {
            return Ok(QueryIndexOutput {
                rows: serde_json::Value::Null,
                error: Some("Only SELECT queries are allowed.".to_string()),
            });
        }

        let rows_res = sqlx::query(sql).fetch_all(&*self.pool).await;

        match rows_res {
            Ok(sql_rows) => {
                let mut results = Vec::new();
                for row in sql_rows {
                    let mut map = serde_json::Map::new();
                    for col in row.columns() {
                        let val = match col.type_info().name() {
                            "INTEGER" => {
                                if let Ok(v) = row.try_get::<i64, _>(col.name()) {
                                    serde_json::json!(v)
                                } else {
                                    serde_json::Value::Null
                                }
                            }
                            "TEXT" | "VARCHAR" | "STRING" => {
                                if let Ok(v) = row.try_get::<String, _>(col.name()) {
                                    serde_json::json!(v)
                                } else {
                                    serde_json::Value::Null
                                }
                            }
                            "REAL" | "FLOAT" | "DOUBLE" => {
                                if let Ok(v) = row.try_get::<f64, _>(col.name()) {
                                    serde_json::json!(v)
                                } else {
                                    serde_json::Value::Null
                                }
                            }
                            "BOOLEAN" => {
                                if let Ok(v) = row.try_get::<bool, _>(col.name()) {
                                    serde_json::json!(v)
                                } else {
                                    serde_json::Value::Null
                                }
                            }
                            // Fallback to text
                            _ => {
                                if let Ok(v) = row.try_get::<String, _>(col.name()) {
                                    serde_json::json!(v)
                                } else {
                                    serde_json::Value::Null
                                }
                            }
                        };
                        map.insert(col.name().to_string(), val);
                    }
                    results.push(serde_json::Value::Object(map));
                }

                Ok(QueryIndexOutput {
                    rows: serde_json::Value::Array(results),
                    error: None,
                })
            }
            Err(e) => Ok(QueryIndexOutput {
                rows: serde_json::Value::Null,
                error: Some(e.to_string()),
            }),
        }
    }
}
