use crate::config::AgentConfig;
use crate::db_helpers::{ensure_ai_artifact, store_specialist_result};
use crate::evidence_io::{extract_file_bytes, ExtractedFile};
use crate::tools::query_index::validate_read_query;
use crate::ui::{SpecialistKind, SpecialistUpdate, UiHandle};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::TryStreamExt;
use log::debug;
use rig::client::CompletionClient;
use rig::completion::{Prompt, ToolDefinition};
use rig::providers::{ollama, openai};
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Column, Row};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

const SPECIALIST_TOOL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+objective-query-v1");

#[derive(Deserialize)]
pub struct DelegateArgs {
    pub file_id: u64,
    pub partition_id: i64,
    pub objective: String,
}

#[derive(Serialize, Debug, Error)]
#[error("SpecialistError: {message}")]
pub struct SpecialistError {
    pub message: String,
}

/// Result of a completed specialist job: feeds both the `Finished` UI event
/// and the exact tool output string returned to the orchestrator LLM.
struct SpecialistOutcome {
    file_name: String,
    score: Option<i64>,
    summary: String,
    cached: bool,
    output: String,
}

/// Emits structured specialist progress to the TUI, falling back to stdout
/// when running headless. The `call()` wrappers guarantee the event protocol:
/// one `Started`, any number of `Stage`s, then exactly one terminal event.
struct SpecialistProgress {
    ui: Option<UiHandle>,
    kind: SpecialistKind,
}

impl SpecialistProgress {
    fn new(ui: &Option<UiHandle>, kind: SpecialistKind) -> Self {
        Self {
            ui: ui.clone(),
            kind,
        }
    }

    fn started(&self, file_id: u64) {
        match &self.ui {
            Some(ui) => ui.specialist(self.kind, SpecialistUpdate::Started { file_id }),
            None => tracing::info!(
                specialist = self.kind.label(),
                file_id,
                "Delegating to specialist"
            ),
        }
    }

    fn stage<S: Into<String>>(&self, msg: S) {
        let msg = msg.into();
        match &self.ui {
            Some(ui) => ui.specialist(
                self.kind,
                SpecialistUpdate::Stage {
                    message: msg.clone(),
                },
            ),
            None => tracing::info!(specialist = self.kind.label(), "{msg}"),
        }
    }

    fn finished(&self, outcome: &SpecialistOutcome) {
        match &self.ui {
            Some(ui) => ui.specialist(
                self.kind,
                SpecialistUpdate::Finished {
                    file_name: outcome.file_name.clone(),
                    score: outcome.score,
                    summary: outcome.summary.clone(),
                    cached: outcome.cached,
                },
            ),
            None => tracing::info!(
                specialist = self.kind.label(),
                file = %outcome.file_name,
                cached = outcome.cached,
                score = outcome.score,
                "Specialist finished"
            ),
        }
    }

    fn failed(&self, error: &str) {
        match &self.ui {
            Some(ui) => ui.specialist(
                self.kind,
                SpecialistUpdate::Failed {
                    error: error.to_string(),
                },
            ),
            None => tracing::error!(specialist = self.kind.label(), error, "Specialist failed"),
        }
    }
}

fn fmt_bytes(len: usize) -> String {
    if len >= 1_048_576 {
        format!("{:.1} MB", len as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KB", len as f64 / 1024.0)
    }
}

const SPECIALIST_QUERY_MAX_ROWS: usize = 100;
const SPECIALIST_QUERY_TIMEOUT_SECS: u64 = 10;
const SPECIALIST_CELL_MAX_CHARS: usize = 500;
const SPECIALIST_QUERY_RESULT_MAX_CHARS: usize = 6_000;
const SPECIALIST_QUERY_MAX_COUNT: usize = 6;

#[derive(Clone, Deserialize)]
struct SpecialistQueryArgs {
    sql: String,
    max_rows: Option<usize>,
}

#[derive(Clone, Serialize)]
struct SpecialistQueryRecord {
    query_id: String,
    sql: String,
    result: String,
    row_count: usize,
    truncated: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Error)]
#[error("SpecialistQueryError: {message}")]
struct SpecialistQueryError {
    message: String,
}

#[derive(Clone)]
struct SpecialistSqlQueryTool {
    pool: Arc<sqlx::SqlitePool>,
    objective: String,
    records: Arc<Mutex<Vec<SpecialistQueryRecord>>>,
}

impl SpecialistSqlQueryTool {
    fn new(pool: Arc<sqlx::SqlitePool>, objective: String) -> Self {
        Self {
            pool,
            objective,
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn records(&self) -> Vec<SpecialistQueryRecord> {
        self.records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }

    fn has_successful_query(&self) -> bool {
        self.records().iter().any(|record| record.error.is_none())
    }

    fn record(&self, record: SpecialistQueryRecord) -> SpecialistQueryRecord {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
        record
    }
}

impl Tool for SpecialistSqlQueryTool {
    const NAME: &'static str = "query_delegated_sqlite";

    type Args = SpecialistQueryArgs;
    type Output = SpecialistQueryRecord;
    type Error = SpecialistQueryError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: format!(
                "Execute one bounded read-only query against the delegated immutable SQLite database. \
                 Use it to answer this objective: {}",
                self.objective
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "One SELECT, WITH ... SELECT, or EXPLAIN SELECT statement."
                    },
                    "max_rows": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": SPECIALIST_QUERY_MAX_ROWS
                    }
                },
                "required": ["sql"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let query_id = crate::ui::unique_id("specialist-query");
        if self.records().len() >= SPECIALIST_QUERY_MAX_COUNT {
            return Ok(self.record(SpecialistQueryRecord {
                query_id,
                sql: args.sql,
                result: String::new(),
                row_count: 0,
                truncated: false,
                error: Some(format!(
                    "The specialist query limit of {SPECIALIST_QUERY_MAX_COUNT} was reached."
                )),
            }));
        }
        if args.sql.chars().count() > 10_000 {
            return Ok(self.record(SpecialistQueryRecord {
                query_id,
                sql: String::new(),
                result: String::new(),
                row_count: 0,
                truncated: false,
                error: Some("SQL exceeds the 10,000 character limit.".to_string()),
            }));
        }
        let sql = match validate_read_query(&args.sql) {
            Ok(sql) => sql,
            Err(error) => {
                return Ok(self.record(SpecialistQueryRecord {
                    query_id,
                    sql: args.sql,
                    result: String::new(),
                    row_count: 0,
                    truncated: false,
                    error: Some(error),
                }))
            }
        };
        let max_rows = args
            .max_rows
            .unwrap_or(50)
            .clamp(1, SPECIALIST_QUERY_MAX_ROWS);
        let fetch = async {
            let mut stream = sqlx::query(&sql).fetch(&*self.pool);
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
        let mut rows =
            match tokio::time::timeout(Duration::from_secs(SPECIALIST_QUERY_TIMEOUT_SECS), fetch)
                .await
            {
                Ok(Ok(rows)) => rows,
                Ok(Err(error)) => {
                    return Ok(self.record(SpecialistQueryRecord {
                        query_id,
                        sql,
                        result: String::new(),
                        row_count: 0,
                        truncated: false,
                        error: Some(error),
                    }))
                }
                Err(_) => {
                    return Ok(self.record(SpecialistQueryRecord {
                        query_id,
                        sql,
                        result: String::new(),
                        row_count: 0,
                        truncated: false,
                        error: Some(format!(
                            "Query exceeded the {SPECIALIST_QUERY_TIMEOUT_SECS} second timeout."
                        )),
                    }))
                }
            };
        let rows_truncated = rows.len() > max_rows;
        rows.truncate(max_rows);
        let (result, content_truncated) = render_specialist_rows(&rows);
        Ok(self.record(SpecialistQueryRecord {
            query_id,
            sql,
            result,
            row_count: rows.len(),
            truncated: rows_truncated || content_truncated,
            error: None,
        }))
    }
}

fn render_specialist_rows(rows: &[SqliteRow]) -> (String, bool) {
    if rows.is_empty() {
        return ("Query returned 0 rows.".to_string(), false);
    }
    let columns = rows[0]
        .columns()
        .iter()
        .take(30)
        .map(|column| column.name().to_string())
        .collect::<Vec<_>>();
    let mut output = format!("Columns: [{}]\n", columns.join(", "));
    for (index, row) in rows.iter().enumerate() {
        let values = columns
            .iter()
            .map(|column| {
                let value = if let Ok(value) = row.try_get::<String, _>(column.as_str()) {
                    value
                } else if let Ok(value) = row.try_get::<i64, _>(column.as_str()) {
                    value.to_string()
                } else if let Ok(value) = row.try_get::<f64, _>(column.as_str()) {
                    value.to_string()
                } else if let Ok(value) = row.try_get::<Vec<u8>, _>(column.as_str()) {
                    format!("<{} bytes>", value.len())
                } else {
                    "NULL".to_string()
                };
                let mut chars = value.chars();
                let mut value = chars
                    .by_ref()
                    .take(SPECIALIST_CELL_MAX_CHARS)
                    .collect::<String>();
                if chars.next().is_some() {
                    value.push('…');
                }
                format!("{column}={}", value.replace(['\n', '\r'], " "))
            })
            .collect::<Vec<_>>();
        output.push_str(&format!("{}: {}\n", index + 1, values.join(" | ")));
    }
    let content_truncated = output.chars().count() > SPECIALIST_QUERY_RESULT_MAX_CHARS;
    (
        output
            .chars()
            .take(SPECIALIST_QUERY_RESULT_MAX_CHARS)
            .collect(),
        content_truncated,
    )
}

fn validate_sqlite_findings(
    verdict: &serde_json::Value,
    query_records: &[SpecialistQueryRecord],
) -> Result<(), SpecialistError> {
    let findings = verdict
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| SpecialistError {
            message: "SQLite specialist result must contain a findings array.".to_string(),
        })?;
    for finding in findings {
        let statement = finding
            .get("finding")
            .and_then(serde_json::Value::as_str)
            .filter(|statement| !statement.trim().is_empty())
            .ok_or_else(|| SpecialistError {
                message: "Each SQLite finding must contain a non-empty finding statement."
                    .to_string(),
            })?;
        let query_ids = finding
            .get("query_ids")
            .and_then(serde_json::Value::as_array)
            .filter(|query_ids| !query_ids.is_empty())
            .ok_or_else(|| SpecialistError {
                message: format!("SQLite finding '{statement}' has no supporting query IDs."),
            })?;
        for query_id in query_ids {
            let Some(query_id) = query_id.as_str() else {
                return Err(SpecialistError {
                    message: format!(
                        "SQLite finding '{statement}' contains a non-string query ID."
                    ),
                });
            };
            if !query_records
                .iter()
                .any(|record| record.query_id == query_id && record.error.is_none())
            {
                return Err(SpecialistError {
                    message: format!(
                        "SQLite finding '{statement}' references unknown or failed query ID '{query_id}'."
                    ),
                });
            }
        }
        if !finding
            .get("limitations")
            .is_some_and(serde_json::Value::is_string)
        {
            return Err(SpecialistError {
                message: format!(
                    "SQLite finding '{statement}' must state its limitations (an empty string is allowed)."
                ),
            });
        }
    }
    Ok(())
}

/// Extract (score, summary) from a stored specialist verdict JSON blob.
fn parse_verdict(raw: &str) -> Option<(Option<i64>, String)> {
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    let summary = val.get("summary")?.as_str()?.to_string();
    let score = val.get("score").and_then(|s| s.as_i64());
    Some((score, summary))
}

/// Build the outcome for a cached `artifact_objects` hit. The verdict JSON is
/// the source of truth for score/summary; `text` (transcription/schema, NULL
/// for images) is only a fallback if the JSON is unreadable.
fn cached_outcome(row: &sqlx::sqlite::SqliteRow, specialist_word: &str) -> SpecialistOutcome {
    use sqlx::Row;
    let file_name: String = row.try_get("name").unwrap_or_default();
    let raw_json: String = row.try_get("json").unwrap_or_default();
    let (score, summary) =
        parse_verdict(&raw_json).unwrap_or_else(|| (None, row.try_get("text").unwrap_or_default()));
    let output = if specialist_word.eq_ignore_ascii_case("sqlite") {
        raw_json
    } else {
        format!(
            "[CACHED] {} Specialist Analysis for '{}'. Summary: {}. Stored verdict: {}",
            specialist_word, file_name, summary, raw_json
        )
    };
    SpecialistOutcome {
        file_name,
        score,
        summary,
        cached: true,
        output,
    }
}

fn objective_sha256(objective: &str) -> String {
    hex::encode(Sha256::digest(objective.trim().as_bytes()))
}

fn cache_is_current(row: &sqlx::sqlite::SqliteRow, config: &AgentConfig, objective: &str) -> bool {
    let raw_json: String = row.try_get("json").unwrap_or_default();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw_json) else {
        return false;
    };
    let Some(provenance) = value.get("_provenance") else {
        return false;
    };
    let objective_hash = objective_sha256(objective);
    provenance
        .get("tool_version")
        .and_then(|value| value.as_str())
        == Some(SPECIALIST_TOOL_VERSION)
        && provenance.get("provider").and_then(|value| value.as_str())
            == Some(config.provider.as_str())
        && provenance.get("model").and_then(|value| value.as_str()) == Some(config.model.as_str())
        && provenance
            .get("objective_sha256")
            .and_then(|value| value.as_str())
            == Some(objective_hash.as_str())
}

fn with_provenance(
    mut verdict: serde_json::Value,
    config: &AgentConfig,
    extracted: &ExtractedFile,
    specialist: &str,
    objective: &str,
) -> serde_json::Value {
    if !verdict.is_object() {
        verdict = serde_json::json!({ "result": verdict });
    }
    if let Some(object) = verdict.as_object_mut() {
        object.insert(
            "_provenance".to_string(),
            serde_json::json!({
                "specialist": specialist,
                "objective": objective,
                "objective_sha256": objective_sha256(objective),
                "tool_version": SPECIALIST_TOOL_VERSION,
                "provider": config.provider,
                "model": config.model,
                "source_sha256": extracted.sha256,
                "evidence_id": extracted.evidence_id,
                "partition_id": extracted.partition_id,
                "database_file_id": extracted.database_file_id,
                "identifier": extracted.dump_path.file_name().and_then(|name| name.to_str()),
            }),
        );
    }
    verdict
}

/// Helper to build a specialist sub-agent prompt using the configured provider.
async fn specialist_prompt(
    config: &AgentConfig,
    preamble: &str,
    prompt_text: &str,
) -> Result<String, SpecialistError> {
    match config.provider.as_str() {
        "openai" => {
            if let Some(endpoint) = config.openai_endpoint() {
                let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                    .api_key(&config.api_key)
                    .base_url(&endpoint)
                    .build()
                    .map_err(|e| SpecialistError {
                        message: format!("Failed to initialize OpenAI-compatible client: {e}"),
                    })?;
                let agent = client.agent(&config.model).preamble(preamble).build();
                agent
                    .prompt(prompt_text)
                    .await
                    .map_err(|e| SpecialistError {
                        message: format!("Specialist LLM call failed: {e}"),
                    })
            } else {
                let client: openai::Client =
                    openai::Client::new(&config.api_key).map_err(|e| SpecialistError {
                        message: format!("Failed to initialize OpenAI client: {}", e),
                    })?;
                let agent = client.agent(&config.model).preamble(preamble).build();
                agent
                    .prompt(prompt_text)
                    .await
                    .map_err(|e| SpecialistError {
                        message: format!("Specialist LLM call failed: {e}"),
                    })
            }
        }
        "ollama" => {
            let mut builder = ollama::Client::builder();
            if !config.endpoint.is_empty() {
                builder = builder.base_url(&config.endpoint);
            }
            let client: ollama::Client =
                builder
                    .api_key(rig::client::Nothing)
                    .build()
                    .map_err(|e| SpecialistError {
                        message: format!("Failed to initialize Ollama client: {}", e),
                    })?;
            let agent = client.agent(&config.model).preamble(preamble).build();
            agent
                .prompt(prompt_text)
                .await
                .map_err(|e| SpecialistError {
                    message: format!("Specialist LLM call failed: {}", e),
                })
        }
        "copilot" => {
            // forensic-llm is an OpenAI-compatible vLLM server (Chat Completions) on port 8000
            let llm_url = config
                .copilot_llm_endpoint()
                .map_err(|error| SpecialistError {
                    message: error.to_string(),
                })?;
            debug!(
                "[copilot] specialist LLM → {} (model: {})",
                llm_url, config.model
            );
            let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                .api_key("no-key")
                .base_url(&llm_url)
                .build()
                .map_err(|e| SpecialistError {
                    message: format!("Failed to initialize copilot client: {}", e),
                })?;
            let agent = client.agent(&config.model).preamble(preamble).build();
            agent
                .prompt(prompt_text)
                .await
                .map_err(|e| SpecialistError {
                    message: format!("Specialist LLM call failed: {}", e),
                })
        }
        other => Err(SpecialistError {
            message: format!("Unsupported specialist provider: {}", other),
        }),
    }
}

async fn sqlite_specialist_prompt(
    config: &AgentConfig,
    preamble: &str,
    prompt_text: &str,
    query_tool: SpecialistSqlQueryTool,
) -> Result<String, SpecialistError> {
    macro_rules! run_with_client {
        ($client:expr) => {{
            let agent = $client
                .agent(&config.model)
                .preamble(preamble)
                .default_max_turns(8)
                .tool(query_tool.clone())
                .build();
            let mut response = agent
                .prompt(prompt_text)
                .await
                .map_err(|e| SpecialistError {
                    message: format!("SQLite specialist LLM call failed: {e}"),
                })?;
            if !query_tool.has_successful_query() {
                response = agent
                    .prompt(format!(
                        "You have not completed the delegated investigation. You MUST call \
                         query_delegated_sqlite with at least one valid read-only query before \
                         answering. Original task:\n{prompt_text}"
                    ))
                    .await
                    .map_err(|e| SpecialistError {
                        message: format!("SQLite specialist retry failed: {e}"),
                    })?;
            }
            if !query_tool.has_successful_query() {
                Err(SpecialistError {
                    message:
                        "SQLite specialist returned without executing a successful read-only query."
                            .to_string(),
                })
            } else {
                Ok(response)
            }
        }};
    }

    match config.provider.as_str() {
        "openai" => {
            if let Some(endpoint) = config.openai_endpoint() {
                let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                    .api_key(&config.api_key)
                    .base_url(&endpoint)
                    .build()
                    .map_err(|e| SpecialistError {
                        message: format!("Failed to initialize OpenAI-compatible client: {e}"),
                    })?;
                run_with_client!(client)
            } else {
                let client: openai::Client =
                    openai::Client::new(&config.api_key).map_err(|e| SpecialistError {
                        message: format!("Failed to initialize OpenAI client: {e}"),
                    })?;
                run_with_client!(client)
            }
        }
        "ollama" => {
            let mut builder = ollama::Client::builder();
            if !config.endpoint.is_empty() {
                builder = builder.base_url(&config.endpoint);
            }
            let client: ollama::Client =
                builder
                    .api_key(rig::client::Nothing)
                    .build()
                    .map_err(|e| SpecialistError {
                        message: format!("Failed to initialize Ollama client: {e}"),
                    })?;
            run_with_client!(client)
        }
        "copilot" => {
            let llm_url = config
                .copilot_llm_endpoint()
                .map_err(|error| SpecialistError {
                    message: error.to_string(),
                })?;
            let client: openai::CompletionsClient = openai::CompletionsClient::builder()
                .api_key("no-key")
                .base_url(&llm_url)
                .build()
                .map_err(|e| SpecialistError {
                    message: format!("Failed to initialize copilot client: {e}"),
                })?;
            run_with_client!(client)
        }
        other => Err(SpecialistError {
            message: format!("Unsupported SQLite specialist provider: {other}"),
        }),
    }
}

/// Send a base64-encoded image to the dfi-copilot image2text service and return the description.
async fn copilot_image_describe(
    url: &str,
    image_base64: &str,
    file_name: &str,
) -> Result<String, SpecialistError> {
    debug!("[copilot] image2text POST {} (file: '{}')", url, file_name);
    let body = serde_json::json!({
        "image_base64": image_base64,
        "prompt": "You are a forensic image analyst. Describe this image in forensic detail. \
                   Identify all visible people, objects, text, locations, timestamps, and activities. \
                   Note anything that may be relevant to a criminal or civil investigation."
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| SpecialistError {
            message: format!("Failed to build image2text client: {error}"),
        })?;
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| SpecialistError {
            message: format!("image2text: connection to {} failed: {}", url, e),
        })?;

    let status = resp.status();
    debug!("[copilot] image2text response status: {}", status);
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SpecialistError {
            message: format!(
                "image2text returned HTTP {} for '{}': {}",
                status, file_name, body
            ),
        });
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| SpecialistError {
        message: format!("image2text response parse failed ({}): {}", url, e),
    })?;
    debug!("[copilot] image2text raw response: {}", json);
    json.get("text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SpecialistError {
            message: format!(
                "image2text returned no 'text' field for '{}'. Full response: {}",
                file_name, json
            ),
        })
}

/// Send an audio file to the dfi-copilot audio2text service and return the transcription text.
async fn copilot_audio_transcribe(
    url: &str,
    audio_bytes: Vec<u8>,
    ext: &str,
    file_name: &str,
) -> Result<String, SpecialistError> {
    debug!(
        "[copilot] audio2text POST {} (file: '{}', {} bytes, ext: {})",
        url,
        file_name,
        audio_bytes.len(),
        ext
    );
    let mime = format!("audio/{}", ext);
    let part = reqwest::multipart::Part::bytes(audio_bytes)
        .file_name(format!("audio.{}", ext))
        .mime_str(&mime)
        .map_err(|e| SpecialistError {
            message: format!("Failed to build multipart for '{}': {}", file_name, e),
        })?;
    let form = reqwest::multipart::Form::new().part("file", part);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|error| SpecialistError {
            message: format!("Failed to build audio2text client: {error}"),
        })?;
    let resp = client
        .post(url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| SpecialistError {
            message: format!("audio2text: connection to {} failed: {}", url, e),
        })?;

    let status = resp.status();
    debug!("[copilot] audio2text response status: {}", status);
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(SpecialistError {
            message: format!(
                "audio2text returned HTTP {} for '{}': {}",
                status, file_name, body
            ),
        });
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| SpecialistError {
        message: format!("audio2text response parse failed ({}): {}", url, e),
    })?;
    debug!("[copilot] audio2text raw response: {}", json);
    json.get("text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SpecialistError {
            message: format!(
                "audio2text returned no 'text' field for '{}'. Full response: {}",
                file_name, json
            ),
        })
}

/// Helper to build a specialist vision prompt using OpenAI (vision requires OpenAI).
async fn specialist_vision_prompt(
    config: &AgentConfig,
    preamble: &str,
    message: rig::completion::Message,
) -> Result<String, SpecialistError> {
    // Vision analysis requires OpenAI with gpt-4o regardless of configured provider
    let api_key = if config.api_key.is_empty() {
        return Err(SpecialistError {
            message: "OpenAI API Key is missing. Vision model requires a valid OpenAI Key."
                .to_string(),
        });
    } else {
        &config.api_key
    };

    let client: openai::Client = openai::Client::new(api_key).map_err(|e| SpecialistError {
        message: format!("Failed to initialize OAI client: {}", e),
    })?;
    let agent = client.agent("gpt-4o").preamble(preamble).build();
    agent.prompt(message).await.map_err(|e| SpecialistError {
        message: format!("Vision Analysis failed: {}", e),
    })
}

// ──────────────────────── Image Specialist ────────────────────────

#[derive(Clone)]
pub struct DelegateImageSpecialist {
    pub evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
    pub evidence_id: i64,
    pub config: AgentConfig,
    pub image_path: String,
    pub extraction_dir: std::path::PathBuf,
    pub ui: Option<UiHandle>,
}

impl DelegateImageSpecialist {
    pub fn new(
        evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
        evidence_id: i64,
        config: AgentConfig,
        image_path: String,
        extraction_dir: std::path::PathBuf,
        ui: Option<UiHandle>,
    ) -> Self {
        Self {
            evidence_pool,
            evidence_id,
            config,
            image_path,
            extraction_dir,
            ui,
        }
    }
}

impl Tool for DelegateImageSpecialist {
    const NAME: &'static str = "delegate_image_specialist";

    type Args = DelegateArgs;
    type Output = String;
    type Error = SpecialistError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Delegates an image file (e.g. .jpg, .png) to the Image Specialist. The specialist analyzes the picture visually to uncover suspect activities, saves the result into the database, and returns a summary.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_id": {
                        "type": "integer",
                        "description": "The unique 'identifier' integer of the image file. (Retrieved from system_files)"
                    },
                    "partition_id": {
                        "type": "integer",
                        "description": "The ID of the partition containing the image file."
                    },
                    "objective": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4000,
                        "description": "The explicit investigative question the specialist must answer from this file."
                    }
                },
                "required": ["file_id", "partition_id", "objective"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if args.objective.trim().is_empty() || args.objective.chars().count() > 4_000 {
            return Err(SpecialistError {
                message: "An explicit investigation objective of 1-4,000 characters is required."
                    .to_string(),
            });
        }
        let progress = SpecialistProgress::new(&self.ui, SpecialistKind::Image);
        progress.started(args.file_id);
        match self.run(&args, &progress).await {
            Ok(outcome) => {
                progress.finished(&outcome);
                Ok(outcome.output)
            }
            Err(e) => {
                progress.failed(&e.message);
                Err(e)
            }
        }
    }
}

impl DelegateImageSpecialist {
    async fn run(
        &self,
        args: &DelegateArgs,
        progress: &SpecialistProgress,
    ) -> Result<SpecialistOutcome, SpecialistError> {
        // Return cached result if this file was already analyzed in a prior session
        if let Ok(Some(cached)) = sqlx::query(
            r#"SELECT sf.name, ao.text, ao.json
               FROM artifact_objects ao
               JOIN system_files sf ON sf.id = ao.file_id
               WHERE sf.identifier = ? AND sf.partition_id = ?
                 AND ao.parser = 'ai_specialist' AND ao.kind = 'Image Analysis'
               ORDER BY ao.id DESC
               LIMIT 1"#,
        )
        .bind(args.file_id as i64)
        .bind(args.partition_id)
        .fetch_optional(&*self.evidence_pool)
        .await
        {
            if !cache_is_current(&cached, &self.config, &args.objective) {
                progress.stage("Cached image verdict is stale; recomputing...");
            } else {
                return Ok(cached_outcome(&cached, "Image"));
            }
        }

        progress.stage("Extracting file from evidence...");
        let extracted = extract_file_bytes(
            &self.evidence_pool,
            &self.image_path,
            args.file_id,
            args.partition_id,
            &self.extraction_dir,
        )
        .await
        .map_err(|e| SpecialistError {
            message: e.to_string(),
        })?;
        let content = &extracted.content;
        let file_name = &extracted.file_name;
        let absolute_path = &extracted.absolute_path;

        progress.stage(format!(
            "Extracted '{}' ({})",
            file_name,
            fmt_bytes(content.len())
        ));

        if content.len() > 20_000_000 {
            return Err(SpecialistError {
                message: "Image file is too large to process visually (>20MB).".to_string(),
            });
        }

        let ext = std::path::Path::new(&absolute_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let mime_type = match ext.as_str() {
            "png" => "image/png",
            "gif" => "image/gif",
            "webp" => "image/webp",
            _ => "image/jpeg",
        };

        let base64_data = BASE64.encode(content);

        let preamble = "You are an AI Image Specialist. Your job is to deeply analyze images for forensic evidence. \
            Focus on uncovering hidden intent, suspects, illegal objects, metadata, or sensitive communication.\
            Produce a structured JSON output with exactly two keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise 1-2 sentence description explaining the forensic significance.\
            Do not include any markdown format tags like ```json.";

        let response = if self.config.provider == "copilot" {
            // Two-step pipeline: Qwen-VL describes the image, forensic-llm scores it
            progress.stage("Vision model describing image...");
            let endpoint =
                self.config
                    .copilot_image_endpoint()
                    .map_err(|error| SpecialistError {
                        message: error.to_string(),
                    })?;
            let description = copilot_image_describe(&endpoint, &base64_data, file_name).await?;
            progress.stage("Scoring description with forensic LLM...");
            specialist_prompt(
                &self.config,
                preamble,
                &format!(
                        "Investigation objective: {}\nFile: {}\nVisual description produced by a vision model:\n{}",
                    args.objective, file_name, description
                ),
            )
            .await?
        } else {
            let data_uri = format!("data:{};base64,{}", mime_type, base64_data);
            let image_message = rig::completion::Message::User {
                content: rig::one_or_many::OneOrMany::many(vec![
                    rig::completion::message::UserContent::text(format!(
                        "Analyze this extracted evidence image for this objective: {}",
                        args.objective
                    )),
                    rig::completion::message::UserContent::image_url(data_uri, None, None),
                ])
                .unwrap(),
            };
            progress.stage("Sending image to GPT-4o vision...");
            specialist_vision_prompt(&self.config, preamble, image_message).await?
        };
        let cleaned = response
            .trim()
            .trim_start_matches("```json")
            .trim_end_matches("```")
            .trim();

        let val: serde_json::Value = serde_json::from_str(cleaned).unwrap_or_else(|_| {
            serde_json::json!({
                "score": 0,
                "summary": format!("Failed to parse specialist JSON: {}", cleaned)
            })
        });
        let val = with_provenance(val, &self.config, &extracted, "image", &args.objective);

        progress.stage("Saving verdict to database...");
        if let Ok(art_id) = ensure_ai_artifact(
            &self.evidence_pool,
            self.evidence_id,
            args.partition_id,
            extracted.database_file_id,
            "AI Image Analysis",
        )
        .await
        {
            let _ = store_specialist_result(
                &self.evidence_pool,
                self.evidence_id,
                args.partition_id,
                extracted.database_file_id,
                art_id,
                file_name,
                "Image Analysis",
                None,
                &val,
            )
            .await;
        }

        let score = val.get("score").and_then(|s| s.as_i64());
        let summary = val
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("No summary provided")
            .to_string();
        let output = format!(
            "Image Specialist Analysis Complete for '{}'. Summary: {}",
            file_name, summary
        );
        Ok(SpecialistOutcome {
            file_name: file_name.clone(),
            score,
            summary,
            cached: false,
            output,
        })
    }
}

// ──────────────────────── Audio Specialist ────────────────────────

#[derive(Clone)]
pub struct DelegateAudioSpecialist {
    pub evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
    pub evidence_id: i64,
    pub config: AgentConfig,
    pub image_path: String,
    pub extraction_dir: std::path::PathBuf,
    pub ui: Option<UiHandle>,
}

impl DelegateAudioSpecialist {
    pub fn new(
        evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
        evidence_id: i64,
        config: AgentConfig,
        image_path: String,
        extraction_dir: std::path::PathBuf,
        ui: Option<UiHandle>,
    ) -> Self {
        Self {
            evidence_pool,
            evidence_id,
            config,
            image_path,
            extraction_dir,
            ui,
        }
    }
}

impl Tool for DelegateAudioSpecialist {
    const NAME: &'static str = "delegate_audio_specialist";

    type Args = DelegateArgs;
    type Output = String;
    type Error = SpecialistError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Delegates an audio file (.wav, .mp3, etc.) to the Audio Specialist. The specialist transcribes the audio, analyzes the dialogue for suspect activity, saves the result into the database, and returns a summary.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_id": {
                        "type": "integer",
                        "description": "The unique 'identifier' integer of the audio file."
                    },
                    "partition_id": {
                        "type": "integer",
                        "description": "The ID of the partition containing the audio file."
                    },
                    "objective": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4000,
                        "description": "The explicit investigative question the specialist must answer from this file."
                    }
                },
                "required": ["file_id", "partition_id", "objective"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if args.objective.trim().is_empty() || args.objective.chars().count() > 4_000 {
            return Err(SpecialistError {
                message: "An explicit investigation objective of 1-4,000 characters is required."
                    .to_string(),
            });
        }
        let progress = SpecialistProgress::new(&self.ui, SpecialistKind::Audio);
        progress.started(args.file_id);
        match self.run(&args, &progress).await {
            Ok(outcome) => {
                progress.finished(&outcome);
                Ok(outcome.output)
            }
            Err(e) => {
                progress.failed(&e.message);
                Err(e)
            }
        }
    }
}

impl DelegateAudioSpecialist {
    async fn run(
        &self,
        args: &DelegateArgs,
        progress: &SpecialistProgress,
    ) -> Result<SpecialistOutcome, SpecialistError> {
        // Return cached result if this file was already analyzed in a prior session
        if let Ok(Some(cached)) = sqlx::query(
            r#"SELECT sf.name, ao.text, ao.json
               FROM artifact_objects ao
               JOIN system_files sf ON sf.id = ao.file_id
               WHERE sf.identifier = ? AND sf.partition_id = ?
                 AND ao.parser = 'ai_specialist' AND ao.kind = 'Audio Analysis'
               ORDER BY ao.id DESC
               LIMIT 1"#,
        )
        .bind(args.file_id as i64)
        .bind(args.partition_id)
        .fetch_optional(&*self.evidence_pool)
        .await
        {
            if !cache_is_current(&cached, &self.config, &args.objective) {
                progress.stage("Cached audio verdict is stale; recomputing...");
            } else {
                return Ok(cached_outcome(&cached, "Audio"));
            }
        }

        progress.stage("Extracting file from evidence...");
        let extracted = extract_file_bytes(
            &self.evidence_pool,
            &self.image_path,
            args.file_id,
            args.partition_id,
            &self.extraction_dir,
        )
        .await
        .map_err(|e| SpecialistError {
            message: e.to_string(),
        })?;
        let content = &extracted.content;
        let file_name = &extracted.file_name;
        let absolute_path = &extracted.absolute_path;

        progress.stage(format!(
            "Extracted '{}' ({})",
            file_name,
            fmt_bytes(content.len())
        ));
        if content.len() > 100_000_000 {
            return Err(SpecialistError {
                message: "Audio file is too large to transcribe safely (>100MB).".to_string(),
            });
        }

        let ext = std::path::Path::new(&absolute_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("wav")
            .to_lowercase();

        let transcription = if self.config.provider == "copilot" {
            progress.stage("Transcribing audio via audio2text service...");
            let endpoint =
                self.config
                    .copilot_audio_endpoint()
                    .map_err(|error| SpecialistError {
                        message: error.to_string(),
                    })?;
            copilot_audio_transcribe(&endpoint, content.clone(), &ext, file_name).await?
        } else {
            if self.config.api_key.is_empty() {
                return Err(SpecialistError {
                    message: "OpenAI API Key is missing. Whisper transcription requires a valid OpenAI Key."
                        .to_string(),
                });
            }

            progress.stage("Transcribing with OpenAI Whisper...");
            use std::io::Write;

            let temp_file_builder = tempfile::Builder::new()
                .suffix(&format!(".{}", ext))
                .tempfile();
            let mut temp_file = temp_file_builder.map_err(|e| SpecialistError {
                message: format!("Failed to create temp file: {}", e),
            })?;
            temp_file.write_all(content).map_err(|e| SpecialistError {
                message: format!("Failed to write to temp file: {}", e),
            })?;
            temp_file.flush().map_err(|_| SpecialistError {
                message: "Failed to flush temp audio file".to_string(),
            })?;

            let path_buf = temp_file.path().to_path_buf();
            let api_key_clone = self.config.api_key.clone();

            let res = tokio::task::spawn_blocking(
                move || -> Result<reqwest::blocking::Response, String> {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(Duration::from_secs(300))
                        .build()
                        .map_err(|error| error.to_string())?;
                    let form = match reqwest::blocking::multipart::Form::new()
                        .text("model", "whisper-1")
                        .file("file", &path_buf)
                    {
                        Ok(f) => f,
                        Err(e) => return Err(e.to_string()),
                    };
                    client
                        .post("https://api.openai.com/v1/audio/transcriptions")
                        .bearer_auth(api_key_clone)
                        .multipart(form)
                        .send()
                        .map_err(|e| e.to_string())
                },
            )
            .await
            .map_err(|e| SpecialistError {
                message: format!("Tokio blocking error: {}", e),
            })?;

            match res {
                Ok(r) => {
                    let json: serde_json::Value = r.json().unwrap_or_default();
                    if let Some(text) = json.get("text").and_then(|v| v.as_str()) {
                        text.to_string()
                    } else if let Some(error) = json
                        .get("error")
                        .and_then(|v| v.get("message"))
                        .and_then(|v| v.as_str())
                    {
                        return Err(SpecialistError {
                            message: format!("Whisper API Error: {}", error),
                        });
                    } else {
                        return Err(SpecialistError {
                            message: "Transcription failed, no text returned.".to_string(),
                        });
                    }
                }
                Err(e) => {
                    return Err(SpecialistError {
                        message: format!("Reqwest failed for Whisper: {}", e),
                    })
                }
            }
        };

        let preamble = "You are an AI Audio Specialist. You will receive a raw dialogue transcription. \
            Analyze the dialogue for forensic evidence. Focus on identifying criminal plotting, confessions, or illegal activity.\
            Produce a structured JSON output with exactly two keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise 1-2 sentence description explaining the forensic significance.\
            Do not include any markdown format tags like ```json.";

        progress.stage(format!(
            "Transcription received ({} chars)",
            transcription.chars().count()
        ));
        let transcription_for_model: String = transcription.chars().take(100_000).collect();
        progress.stage("Analyzing transcription with forensic LLM...");
        let response = specialist_prompt(
            &self.config,
            preamble,
            &format!(
                "Investigation objective: {}\nFile: {}\nTranscription:\n{}",
                args.objective, file_name, transcription_for_model
            ),
        )
        .await?;
        let cleaned = response
            .trim()
            .trim_start_matches("```json")
            .trim_end_matches("```")
            .trim();

        let val: serde_json::Value = serde_json::from_str(cleaned).unwrap_or_else(|_| {
            serde_json::json!({
                "score": 0,
                "summary": format!("Failed to parse specialist JSON: {}", cleaned),
                "transcription": transcription_for_model
            })
        });
        let val = with_provenance(val, &self.config, &extracted, "audio", &args.objective);

        progress.stage("Saving verdict to database...");
        if let Ok(art_id) = ensure_ai_artifact(
            &self.evidence_pool,
            self.evidence_id,
            args.partition_id,
            extracted.database_file_id,
            "AI Audio Analysis",
        )
        .await
        {
            let mut db_val = val.clone();
            if let Some(obj) = db_val.as_object_mut() {
                obj.insert(
                    "transcription".to_string(),
                    serde_json::json!(transcription),
                );
            }
            let _ = store_specialist_result(
                &self.evidence_pool,
                self.evidence_id,
                args.partition_id,
                extracted.database_file_id,
                art_id,
                file_name,
                "Audio Analysis",
                Some(&transcription),
                &db_val,
            )
            .await;
        }

        let score = val.get("score").and_then(|s| s.as_i64());
        let summary = val
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("No summary provided")
            .to_string();
        let output = format!(
            "Audio Specialist Analysis Complete for '{}'. Summary: {}",
            file_name, summary
        );
        Ok(SpecialistOutcome {
            file_name: file_name.clone(),
            score,
            summary,
            cached: false,
            output,
        })
    }
}

// ──────────────────────── SQLite Specialist ────────────────────────

#[derive(Clone)]
pub struct DelegateSqliteSpecialist {
    pub evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
    pub evidence_id: i64,
    pub config: AgentConfig,
    pub image_path: String,
    pub extraction_dir: std::path::PathBuf,
    pub ui: Option<UiHandle>,
}

impl DelegateSqliteSpecialist {
    pub fn new(
        evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
        evidence_id: i64,
        config: AgentConfig,
        image_path: String,
        extraction_dir: std::path::PathBuf,
        ui: Option<UiHandle>,
    ) -> Self {
        Self {
            evidence_pool,
            evidence_id,
            config,
            image_path,
            extraction_dir,
            ui,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_sqlite_findings, SpecialistQueryArgs, SpecialistSqlQueryTool};
    use rig::tool::Tool;
    use std::sync::Arc;

    #[tokio::test]
    async fn delegated_sqlite_query_tool_is_bounded_and_read_only() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("open sqlite");
        sqlx::query("CREATE TABLE messages(body TEXT)")
            .execute(&pool)
            .await
            .expect("create table");
        sqlx::query("INSERT INTO messages(body) VALUES ('250,000 EGP')")
            .execute(&pool)
            .await
            .expect("insert row");

        let tool = SpecialistSqlQueryTool::new(
            Arc::new(pool.clone()),
            "Determine the debt amount".to_string(),
        );
        let result = tool
            .call(SpecialistQueryArgs {
                sql: "SELECT body FROM messages".to_string(),
                max_rows: Some(20),
            })
            .await
            .expect("query call");
        assert_eq!(result.row_count, 1);
        assert!(result.result.contains("250,000 EGP"));
        assert!(result.error.is_none());
        assert!(validate_sqlite_findings(
            &serde_json::json!({
                "findings": [{
                    "finding": "The debt is 250,000 EGP.",
                    "query_ids": [result.query_id],
                    "limitations": ""
                }]
            }),
            &tool.records(),
        )
        .is_ok());
        assert!(validate_sqlite_findings(
            &serde_json::json!({
                "findings": [{
                    "finding": "Unsupported finding",
                    "query_ids": ["made-up-query"],
                    "limitations": ""
                }]
            }),
            &tool.records(),
        )
        .is_err());

        let rejected = tool
            .call(SpecialistQueryArgs {
                sql: "DELETE FROM messages".to_string(),
                max_rows: None,
            })
            .await
            .expect("validation response");
        assert!(rejected.error.is_some());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
            .fetch_one(&pool)
            .await
            .expect("count rows");
        assert_eq!(count, 1);
    }
}

impl Tool for DelegateSqliteSpecialist {
    const NAME: &'static str = "delegate_sqlite_specialist";

    type Args = DelegateArgs;
    type Output = String;
    type Error = SpecialistError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Delegates a SQLite database file to an objective-driven DB Specialist. The specialist must execute bounded read-only queries against the extracted immutable database before returning findings.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_id": {
                        "type": "integer",
                        "description": "The unique 'identifier' integer of the SQLite file."
                    },
                    "partition_id": {
                        "type": "integer",
                        "description": "The ID of the partition containing the SQLite file."
                    },
                    "objective": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4000,
                        "description": "A concrete investigative question with the facts or fields the specialist must recover."
                    }
                },
                "required": ["file_id", "partition_id", "objective"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if args.objective.trim().is_empty() || args.objective.chars().count() > 4_000 {
            return Err(SpecialistError {
                message: "An explicit investigation objective of 1-4,000 characters is required."
                    .to_string(),
            });
        }
        let progress = SpecialistProgress::new(&self.ui, SpecialistKind::Sqlite);
        progress.started(args.file_id);
        match self.run(&args, &progress).await {
            Ok(outcome) => {
                progress.finished(&outcome);
                Ok(outcome.output)
            }
            Err(e) => {
                progress.failed(&e.message);
                Err(e)
            }
        }
    }
}

impl DelegateSqliteSpecialist {
    async fn run(
        &self,
        args: &DelegateArgs,
        progress: &SpecialistProgress,
    ) -> Result<SpecialistOutcome, SpecialistError> {
        // Return cached result if this file was already analyzed in a prior session
        if let Ok(Some(cached)) = sqlx::query(
            r#"SELECT sf.name, ao.text, ao.json
               FROM artifact_objects ao
               JOIN system_files sf ON sf.id = ao.file_id
               WHERE sf.identifier = ? AND sf.partition_id = ?
                 AND ao.parser = 'ai_specialist' AND ao.kind = 'Database Analysis'
               ORDER BY ao.id DESC
               LIMIT 1"#,
        )
        .bind(args.file_id as i64)
        .bind(args.partition_id)
        .fetch_optional(&*self.evidence_pool)
        .await
        {
            if !cache_is_current(&cached, &self.config, &args.objective) {
                progress.stage("Cached SQLite verdict is stale; recomputing...");
            } else {
                return Ok(cached_outcome(&cached, "Sqlite"));
            }
        }

        progress.stage("Extracting file from evidence...");
        let extracted = extract_file_bytes(
            &self.evidence_pool,
            &self.image_path,
            args.file_id,
            args.partition_id,
            &self.extraction_dir,
        )
        .await
        .map_err(|e| SpecialistError {
            message: e.to_string(),
        })?;
        let content = &extracted.content;
        let file_name = &extracted.file_name;

        progress.stage(format!(
            "Extracted '{}' ({})",
            file_name,
            fmt_bytes(content.len())
        ));
        if !content.starts_with(b"SQLite format 3\0") {
            return Err(SpecialistError {
                message: "The delegated file does not have a SQLite 3 header.".to_string(),
            });
        }

        progress.stage("Reading database schema...");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&extracted.dump_path)
            .read_only(true)
            .create_if_missing(false)
            .immutable(true);
        let temp_pool = Arc::new(
            sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .map_err(|e| SpecialistError {
                    message: format!("Failed to open extracted SQLite DB read-only: {}", e),
                })?,
        );

        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT name, sql FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 100",
        )
        .fetch_all(&*temp_pool)
        .await
        .map_err(|e| SpecialistError {
            message: format!("Failed to extract schema from sqlite: {}", e),
        })?;

        let mut schema_blobs = Vec::new();
        for row in rows {
            let _ = row.try_get::<String, _>("name");
            if let Ok(sql) = row.try_get::<String, _>("sql") {
                if !sql.trim().is_empty() {
                    schema_blobs.push(sql);
                }
            }
        }
        let full_schema = schema_blobs.join("\n\n");

        if full_schema.is_empty() {
            return Err(SpecialistError {
                message: "The delegated SQLite database has no readable user tables.".to_string(),
            });
        }
        progress.stage(format!("Schema read ({} tables)", schema_blobs.len()));

        let analysis_input: String = format!(
            "Investigation objective:\n{}\n\nDatabase schema:\n{}",
            args.objective, full_schema
        )
        .chars()
        .take(40_000)
        .collect();

        let preamble = "You are an AI Forensic Database Specialist with a read-only SQL query tool scoped to one extracted evidence database.\
            Answer the explicit investigation objective. Inspect the schema, then execute enough focused SQL queries to support every finding.\
            Never infer a record value that was not returned by your query tool. Include the relevant specialist query IDs in the summary.\
            Produce a structured JSON object with these keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise answer to the investigation objective, including relevant query IDs.\
            - `findings`: An array of objects with `finding`, `query_ids`, and `limitations`.\
            Do not include any markdown format tags like ```json.";

        progress.stage("Querying database for the delegated objective...");
        let query_tool = SpecialistSqlQueryTool::new(temp_pool.clone(), args.objective.clone());
        let response = sqlite_specialist_prompt(
            &self.config,
            preamble,
            &format!("File: {}\n{}", file_name, analysis_input),
            query_tool.clone(),
        )
        .await?;
        temp_pool.close().await;
        let query_records = query_tool.records();
        let cleaned = response
            .trim()
            .trim_start_matches("```json")
            .trim_end_matches("```")
            .trim();

        let val: serde_json::Value =
            serde_json::from_str(cleaned).map_err(|error| SpecialistError {
                message: format!("SQLite specialist returned invalid JSON: {error}"),
            })?;
        if val
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|summary| summary.trim().is_empty())
        {
            return Err(SpecialistError {
                message: "SQLite specialist result must contain a non-empty summary.".to_string(),
            });
        }
        validate_sqlite_findings(&val, &query_records)?;
        let mut val = with_provenance(val, &self.config, &extracted, "sqlite", &args.objective);
        if let Some(object) = val.as_object_mut() {
            object.insert("status".to_string(), serde_json::json!("completed"));
            object.insert(
                "queries".to_string(),
                serde_json::to_value(&query_records).unwrap_or_default(),
            );
        }

        progress.stage("Saving verdict to database...");
        if let Ok(art_id) = ensure_ai_artifact(
            &self.evidence_pool,
            self.evidence_id,
            args.partition_id,
            extracted.database_file_id,
            "AI Database Analysis",
        )
        .await
        {
            let mut db_val = val.clone();
            if let Some(obj) = db_val.as_object_mut() {
                obj.insert("schema".to_string(), serde_json::json!(analysis_input));
            }
            let _ = store_specialist_result(
                &self.evidence_pool,
                self.evidence_id,
                args.partition_id,
                extracted.database_file_id,
                art_id,
                file_name,
                "Database Analysis",
                Some(&analysis_input),
                &db_val,
            )
            .await;
        }

        let score = val.get("score").and_then(|s| s.as_i64());
        let summary = val
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("No summary provided")
            .to_string();
        let output = val.to_string();
        Ok(SpecialistOutcome {
            file_name: file_name.clone(),
            score,
            summary,
            cached: false,
            output,
        })
    }
}
