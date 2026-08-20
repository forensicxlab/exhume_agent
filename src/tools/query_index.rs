use crate::policy::AgentPolicy;
use crate::ui::UiHandle;
use futures_util::TryStreamExt;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Column, Row, SqlitePool};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

const LLM_DEFAULT_MAX_ROWS: usize = 50;
const LLM_EXCLUDED_COLS: &[&str] = &["metadata", "display"];
const LLM_MAX_CELL_CHARS: usize = 300;

#[derive(Deserialize)]
pub struct QueryIndexArgs {
    pub sql: String,
    pub max_rows: Option<usize>,
}

#[derive(Serialize)]
pub struct QueryIndexOutput {
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
    db_path: PathBuf,
    pool: Arc<OnceCell<SqlitePool>>,
    ui: Option<UiHandle>,
    policy: AgentPolicy,
}

impl QueryIndexTool {
    pub fn new(db_path: PathBuf, ui: Option<UiHandle>, policy: AgentPolicy) -> Self {
        Self {
            db_path,
            pool: Arc::new(OnceCell::new()),
            ui,
            policy,
        }
    }

    async fn read_pool(&self) -> Result<&SqlitePool, QueryIndexError> {
        self.pool
            .get_or_try_init(|| async {
                let url = format!("sqlite:{}", self.db_path.display());
                let options = SqliteConnectOptions::from_str(&url)
                    .map_err(|error| QueryIndexError(error.to_string()))?
                    .read_only(true)
                    .create_if_missing(false)
                    .busy_timeout(Duration::from_secs(self.policy.query_timeout_secs.max(1)));
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options)
                    .await
                    .map_err(|error| QueryIndexError(error.to_string()))
            })
            .await
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
            description: "Execute one read-only SQL query against the local SQLite forensic index. \
                Use COUNT queries before broad result queries and add WHERE/LIMIT clauses. \
                Primary tables are system_files, partitions, artifacts, artifact_objects, and investigation_notes."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "One SELECT, WITH ... SELECT, or EXPLAIN SELECT statement."
                    },
                    "max_rows": {
                        "type": "integer",
                        "description": format!(
                            "Maximum rows returned, capped at {}.",
                            self.policy.max_query_rows
                        ),
                        "minimum": 1,
                        "maximum": self.policy.max_query_rows
                    }
                },
                "required": ["sql"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let sql = match validate_read_query(&args.sql) {
            Ok(sql) => sql,
            Err(error) => return Ok(error_output(error)),
        };

        if let Some(ui) = &self.ui {
            ui.log(format!("Querying forensic index: {sql}"));
        } else {
            tracing::info!(query = %sql, "Querying forensic index");
        }

        let limit = args
            .max_rows
            .unwrap_or(LLM_DEFAULT_MAX_ROWS)
            .clamp(1, self.policy.max_query_rows.max(1));
        let timeout = Duration::from_secs(self.policy.query_timeout_secs.max(1));
        let pool = self.read_pool().await?;

        let fetch = async {
            let mut stream = sqlx::query(&sql).fetch(pool);
            let mut rows = Vec::with_capacity(limit.saturating_add(1));
            while rows.len() <= limit {
                match stream.try_next().await {
                    Ok(Some(row)) => rows.push(row),
                    Ok(None) => break,
                    Err(error) => return Err(QueryIndexError(error.to_string())),
                }
            }
            Ok::<_, QueryIndexError>(rows)
        };

        let mut rows = match tokio::time::timeout(timeout, fetch).await {
            Ok(Ok(rows)) => rows,
            Ok(Err(error)) => return Ok(error_output(error.to_string())),
            Err(_) => {
                return Ok(error_output(format!(
                    "Query exceeded the {} second timeout",
                    timeout.as_secs()
                )))
            }
        };

        let truncated = rows.len() > limit;
        rows.truncate(limit);
        if rows.is_empty() {
            return Ok(QueryIndexOutput {
                result: "Query returned 0 rows.".to_string(),
                row_count: 0,
                truncated: false,
                error: None,
            });
        }

        let columns: Vec<String> = rows[0]
            .columns()
            .iter()
            .map(|column| column.name().to_string())
            .filter(|name| !LLM_EXCLUDED_COLS.contains(&name.as_str()))
            .collect();
        let table = render_markdown_table(&rows, &columns);
        let truncation_note = truncated.then(|| {
            format!(
                "\n[RESULT CAPPED: showing the first {limit} rows. Refine the query to inspect more.]"
            )
        });
        let result = format!(
            "{} row(s) returned. Columns: [{}]\n\n{}{}",
            rows.len(),
            columns.join(", "),
            table,
            truncation_note.unwrap_or_default()
        );

        if let Some(ui) = &self.ui {
            ui.log(result.clone());
        }

        Ok(QueryIndexOutput {
            result,
            row_count: rows.len(),
            truncated,
            error: None,
        })
    }
}

pub fn validate_read_query(sql: &str) -> Result<String, String> {
    let sql = sql.trim();
    if sql.is_empty() {
        return Err("SQL query cannot be empty.".to_string());
    }
    if contains_multiple_statements(sql) {
        return Err("Only one SQL statement is allowed.".to_string());
    }
    let sql = sql.strip_suffix(';').unwrap_or(sql).trim().to_string();
    let tokens = unquoted_sql_tokens(&sql);
    let first = tokens.first().map(String::as_str).unwrap_or_default();
    if !matches!(first, "SELECT" | "WITH" | "EXPLAIN") {
        return Err(
            "Only SELECT, WITH ... SELECT, or EXPLAIN SELECT queries are allowed.".to_string(),
        );
    }
    const WRITE_TOKENS: &[&str] = &[
        "ALTER", "ATTACH", "CREATE", "DELETE", "DETACH", "DROP", "INSERT", "PRAGMA", "REINDEX",
        "REPLACE", "UPDATE", "VACUUM",
    ];
    if let Some(token) = tokens
        .iter()
        .find(|token| WRITE_TOKENS.contains(&token.as_str()))
    {
        return Err(format!(
            "SQL token '{token}' is not allowed in a read-only query."
        ));
    }
    Ok(sql)
}

fn unquoted_sql_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(character) = chars.next() {
        if let Some(current_quote) = quote {
            if character == current_quote {
                if chars.peek() == Some(&current_quote) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            push_token(&mut tokens, &mut token);
            quote = Some(character);
            continue;
        }
        if character == '-' && chars.peek() == Some(&'-') {
            push_token(&mut tokens, &mut token);
            chars.next();
            for comment_character in chars.by_ref() {
                if comment_character == '\n' {
                    break;
                }
            }
            continue;
        }
        if character == '/' && chars.peek() == Some(&'*') {
            push_token(&mut tokens, &mut token);
            chars.next();
            let mut previous = '\0';
            for comment_character in chars.by_ref() {
                if previous == '*' && comment_character == '/' {
                    break;
                }
                previous = comment_character;
            }
            continue;
        }
        if character.is_ascii_alphanumeric() || character == '_' {
            token.push(character.to_ascii_uppercase());
        } else {
            push_token(&mut tokens, &mut token);
        }
    }
    push_token(&mut tokens, &mut token);
    tokens
}

fn push_token(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

fn contains_multiple_statements(sql: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut semicolons = Vec::new();
    for (index, ch) in sql.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if ch == current {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
        } else if ch == ';' {
            semicolons.push(index);
        }
    }
    semicolons
        .iter()
        .any(|index| !sql[index + 1..].trim().is_empty())
}

fn render_markdown_table(rows: &[SqliteRow], columns: &[String]) -> String {
    let mut output = String::new();
    output.push('|');
    for column in columns {
        output.push(' ');
        output.push_str(&escape_markdown(column));
        output.push_str(" |");
    }
    output.push('\n');
    output.push('|');
    for _ in columns {
        output.push_str(" --- |");
    }
    output.push('\n');
    for row in rows {
        output.push('|');
        for column in columns {
            output.push(' ');
            output.push_str(&escape_markdown(&read_cell(row, column)));
            output.push_str(" |");
        }
        output.push('\n');
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
    } else if let Ok(value) = row.try_get::<bool, _>(column) {
        value.to_string()
    } else if let Ok(value) = row.try_get::<Vec<u8>, _>(column) {
        format!("<{} bytes>", value.len())
    } else {
        "NULL".to_string()
    };
    truncate_chars(&value, LLM_MAX_CELL_CHARS)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn error_output(error: impl Into<String>) -> QueryIndexOutput {
    QueryIndexOutput {
        result: String::new(),
        row_count: 0,
        truncated: false,
        error: Some(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{contains_multiple_statements, truncate_chars, validate_read_query};

    #[test]
    fn allows_single_read_queries() {
        assert!(validate_read_query("SELECT * FROM system_files;").is_ok());
        assert!(validate_read_query("WITH recent AS (SELECT 1) SELECT * FROM recent").is_ok());
    }

    #[test]
    fn rejects_multiple_or_write_queries() {
        assert!(contains_multiple_statements(
            "SELECT 1; DELETE FROM system_files"
        ));
        assert!(validate_read_query("DELETE FROM system_files").is_err());
        assert!(validate_read_query("WITH doomed AS (SELECT 1) DELETE FROM system_files").is_err());
        assert!(validate_read_query("SELECT ';' AS value;").is_ok());
        assert!(validate_read_query("SELECT 'DELETE' AS harmless").is_ok());
    }

    #[test]
    fn truncates_unicode_at_character_boundaries() {
        assert_eq!(truncate_chars("évidence", 3), "évi…");
    }
}
