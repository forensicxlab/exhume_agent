use crate::config::AgentConfig;
use crate::db_helpers::{ensure_ai_artifact, store_specialist_result};
use crate::evidence_io::extract_file_bytes;
use log::error;
use rig::client::CompletionClient;
use rig::completion::{Prompt, ToolDefinition};
use rig::providers::{ollama, openai};
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use colored::Colorize;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Deserialize)]
pub struct DelegateArgs {
    pub file_id: u64,
    pub partition_id: i64,
}

#[derive(Serialize, Debug, Error)]
#[error("SpecialistError: {message}")]
pub struct SpecialistError {
    pub message: String,
}

/// Helper to build a specialist sub-agent prompt using the configured provider.
async fn specialist_prompt(config: &AgentConfig, preamble: &str, prompt_text: &str) -> Result<String, SpecialistError> {
    match config.provider.as_str() {
        "openai" => {
            let client: openai::Client = openai::Client::new(&config.api_key)
                .map_err(|e| SpecialistError { message: format!("Failed to initialize OpenAI client: {}", e) })?;
            let agent = client.agent(&config.model).preamble(preamble).build();
            agent.prompt(prompt_text).await
                .map_err(|e| SpecialistError { message: format!("Specialist LLM call failed: {}", e) })
        }
        "ollama" => {
            let mut builder = ollama::Client::builder();
            if !config.endpoint.is_empty() {
                builder = builder.base_url(&config.endpoint);
            }
            let client: ollama::Client = builder.api_key(rig::client::Nothing).build()
                .map_err(|e| SpecialistError { message: format!("Failed to initialize Ollama client: {}", e) })?;
            let agent = client.agent(&config.model).preamble(preamble).build();
            agent.prompt(prompt_text).await
                .map_err(|e| SpecialistError { message: format!("Specialist LLM call failed: {}", e) })
        }
        other => Err(SpecialistError { message: format!("Unsupported specialist provider: {}", other) }),
    }
}

/// Helper to build a specialist vision prompt using OpenAI (vision requires OpenAI).
async fn specialist_vision_prompt(config: &AgentConfig, preamble: &str, message: rig::completion::Message) -> Result<String, SpecialistError> {
    // Vision analysis requires OpenAI with gpt-4o regardless of configured provider
    let api_key = if config.api_key.is_empty() {
        return Err(SpecialistError { message: "OpenAI API Key is missing. Vision model requires a valid OpenAI Key.".to_string() });
    } else {
        &config.api_key
    };

    let client: openai::Client = openai::Client::new(api_key)
        .map_err(|e| SpecialistError { message: format!("Failed to initialize OAI client: {}", e) })?;
    let agent = client.agent("gpt-4o").preamble(preamble).build();
    agent.prompt(message).await
        .map_err(|e| SpecialistError { message: format!("Vision Analysis failed: {}", e) })
}

// ──────────────────────── Image Specialist ────────────────────────

#[derive(Clone)]
pub struct DelegateImageSpecialist {
    pub evidence_pool: std::sync::Arc<sqlx::SqlitePool>,
    pub evidence_id: i64,
    pub config: AgentConfig,
    pub image_path: String,
    pub extraction_dir: std::path::PathBuf,
}

impl DelegateImageSpecialist {
    pub fn new(evidence_pool: std::sync::Arc<sqlx::SqlitePool>, evidence_id: i64, config: AgentConfig, image_path: String, extraction_dir: std::path::PathBuf) -> Self {
        Self { evidence_pool, evidence_id, config, image_path, extraction_dir }
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
                    }
                },
                "required": ["file_id", "partition_id"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("  {} {} (id: {})...", "🛠️".magenta(), "Delegating to Image Specialist".bold(), args.file_id);
        let (content, file_name, absolute_path, _dump_path) = extract_file_bytes(
            &*self.evidence_pool, &self.image_path, args.file_id, args.partition_id, &self.extraction_dir
        ).await.map_err(|e| SpecialistError { message: e.to_string() })?;

        if content.len() > 20_000_000 {
            return Err(SpecialistError { message: "Image file is too large to process visually (>20MB).".to_string() });
        }

        let ext = std::path::Path::new(&absolute_path).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let mime_type = match ext.as_str() {
            "png" => "image/png",
            "gif" => "image/gif",
            "webp" => "image/webp",
            _ => "image/jpeg",
        };

        let base64_data = BASE64.encode(&content);
        let data_uri = format!("data:{};base64,{}", mime_type, base64_data);

        let preamble = "You are an AI Image Specialist. Your job is to deeply analyze images for forensic evidence. \
            Focus on uncovering hidden intent, suspects, illegal objects, metadata, or sensitive communication.\
            Produce a structured JSON output with exactly two keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise 1-2 sentence description explaining the forensic significance.\
            Do not include any markdown format tags like ```json.";

        let image_message = rig::completion::Message::User { 
            content: rig::one_or_many::OneOrMany::many(
                vec![
                    rig::completion::message::UserContent::text("Analyze this extracted evidence image."),
                    rig::completion::message::UserContent::image_url(data_uri, None, None)
                ]
            ).unwrap()
        };

        let response = specialist_vision_prompt(&self.config, preamble, image_message).await?;
        let cleaned = response.trim().trim_start_matches("```json").trim_end_matches("```").trim();
        
        let val: serde_json::Value = serde_json::from_str(cleaned).unwrap_or_else(|_| {
            serde_json::json!({
                "score": 0,
                "summary": format!("Failed to parse specialist JSON: {}", cleaned)
            })
        });

        use sqlx::Row;
        let db_id_res = sqlx::query("SELECT id FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1")
            .bind(args.file_id as i64)
            .bind(args.partition_id)
            .fetch_one(&*self.evidence_pool).await;

        if let Ok(row) = db_id_res {
            let file_db_id: i64 = row.get("id");
            if let Ok(art_id) = ensure_ai_artifact(&*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, "AI Image Analysis").await {
                let _ = store_specialist_result(
                    &*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, art_id, &file_name, "Image Analysis", None, &val
                ).await;
            }
        }

        let summary = val.get("summary").and_then(|s| s.as_str()).unwrap_or("No summary provided");
        Ok(format!("Image Specialist Analysis Complete for '{}'. Summary: {}", file_name, summary))
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
}

impl DelegateAudioSpecialist {
    pub fn new(evidence_pool: std::sync::Arc<sqlx::SqlitePool>, evidence_id: i64, config: AgentConfig, image_path: String, extraction_dir: std::path::PathBuf) -> Self {
        Self { evidence_pool, evidence_id, config, image_path, extraction_dir }
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
                    }
                },
                "required": ["file_id", "partition_id"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("  {} {} (id: {})...", "🛠️".magenta(), "Delegating to Audio Specialist".bold(), args.file_id);
        let (content, file_name, absolute_path, _dump_path) = extract_file_bytes(
            &*self.evidence_pool, &self.image_path, args.file_id, args.partition_id, &self.extraction_dir
        ).await.map_err(|e| SpecialistError { message: e.to_string() })?;

        if self.config.api_key.is_empty() {
            return Err(SpecialistError { message: "OpenAI API Key is missing. Whisper transcription requires a valid OpenAI Key.".to_string() });
        }

        use std::io::Write;
        
        let ext = std::path::Path::new(&absolute_path).extension().and_then(|e| e.to_str()).unwrap_or("wav").to_lowercase();
        let temp_file_builder = tempfile::Builder::new().suffix(&format!(".{}", ext)).tempfile();
        let mut temp_file = temp_file_builder.map_err(|e| SpecialistError { message: format!("Failed to create temp file: {}", e) })?;
        
        temp_file.write_all(&content).map_err(|e| SpecialistError { message: format!("Failed to write to temp file: {}", e) })?;
        temp_file.flush().map_err(|_| SpecialistError { message: "Failed to flush temp audio file".to_string() })?;

        let path_buf = temp_file.path().to_path_buf();
        let api_key_clone = self.config.api_key.clone();
        
        let res = tokio::task::spawn_blocking(move || -> Result<reqwest::blocking::Response, String> {
            let client = reqwest::blocking::Client::new();
            let form = match reqwest::blocking::multipart::Form::new()
                .text("model", "whisper-1")
                .file("file", &path_buf) {
                    Ok(f) => f,
                    Err(e) => return Err(e.to_string()),
                };

            client
                .post("https://api.openai.com/v1/audio/transcriptions")
                .bearer_auth(api_key_clone)
                .multipart(form)
                .send()
                .map_err(|e| e.to_string())
        }).await.map_err(|e| SpecialistError { message: format!("Tokio blocking error: {}", e) })?;

        let transcription = match res {
            Ok(r) => {
                let json: serde_json::Value = r.json().unwrap_or_default();
                if let Some(text) = json.get("text").and_then(|v| v.as_str()) {
                    text.to_string()
                } else if let Some(error) = json.get("error").and_then(|v| v.get("message")).and_then(|v| v.as_str()) {
                    return Err(SpecialistError { message: format!("Whisper API Error: {}", error) });
                } else {
                    return Err(SpecialistError { message: "Transcription failed, no text returned.".to_string() });
                }
            },
            Err(e) => return Err(SpecialistError { message: format!("Reqwest failed for Whisper: {}", e) })
        };

        let preamble = "You are an AI Audio Specialist. You will receive a raw dialogue transcription. \
            Analyze the dialogue for forensic evidence. Focus on identifying criminal plotting, confessions, or illegal activity.\
            Produce a structured JSON output with exactly two keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise 1-2 sentence description explaining the forensic significance.\
            Do not include any markdown format tags like ```json.";

        let response = specialist_prompt(&self.config, preamble, &format!("File: {}\nTranscription:\n{}", file_name, transcription)).await?;
        let cleaned = response.trim().trim_start_matches("```json").trim_end_matches("```").trim();
        
        let val: serde_json::Value = serde_json::from_str(cleaned).unwrap_or_else(|_| {
            serde_json::json!({
                "score": 0,
                "summary": format!("Failed to parse specialist JSON: {}", cleaned),
                "transcription": transcription
            })
        });

        use sqlx::Row;
        let db_id_res = sqlx::query("SELECT id FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1")
            .bind(args.file_id as i64)
            .bind(args.partition_id)
            .fetch_one(&*self.evidence_pool).await;

        if let Ok(row) = db_id_res {
            let file_db_id: i64 = row.get("id");
            if let Ok(art_id) = ensure_ai_artifact(&*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, "AI Audio Analysis").await {
                let mut db_val = val.clone();
                if let Some(obj) = db_val.as_object_mut() {
                    obj.insert("transcription".to_string(), serde_json::json!(transcription));
                }
                let _ = store_specialist_result(
                    &*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, art_id, &file_name, "Audio Analysis", Some(&transcription), &db_val
                ).await;
            }
        }

        let summary = val.get("summary").and_then(|s| s.as_str()).unwrap_or("No summary provided");
        Ok(format!("Audio Specialist Analysis Complete for '{}'. Summary: {}", file_name, summary))
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
}

impl DelegateSqliteSpecialist {
    pub fn new(evidence_pool: std::sync::Arc<sqlx::SqlitePool>, evidence_id: i64, config: AgentConfig, image_path: String, extraction_dir: std::path::PathBuf) -> Self {
        Self { evidence_pool, evidence_id, config, image_path, extraction_dir }
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
            description: "Delegates a SQLite database file (.sqlite, .db) to the DB Specialist. The specialist connects dynamically to the DB, extracts its schema, analyzes it for forensic relevance, saves the result into the database, and returns a summary.".to_string(),
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
                    }
                },
                "required": ["file_id", "partition_id"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("  {} {} (id: {})...", "🛠️".magenta(), "Delegating to SQLite Specialist".bold(), args.file_id);
        let (content, file_name, _, dump_path) = extract_file_bytes(
            &*self.evidence_pool, &self.image_path, args.file_id, args.partition_id, &self.extraction_dir
        ).await.map_err(|e| SpecialistError { message: e.to_string() })?;

        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().map_err(|e| SpecialistError { message: format!("Failed to create temp file: {}", e) })?;
        temp_file.write_all(&content).map_err(|e| SpecialistError { message: format!("Failed to write to temp file: {}", e) })?;
        temp_file.flush().map_err(|_| SpecialistError { message: "Failed to flush temp sqlite file".to_string() })?;

        let db_path = dump_path.display().to_string();
        let uri = format!("sqlite://{}", db_path);

        let temp_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&uri)
            .await
            .map_err(|e| SpecialistError { message: format!("Failed to open temp extracted sqlite DB: {}", e) })?;

        use sqlx::Row;
        let rows = sqlx::query("SELECT sql FROM sqlite_master WHERE type='table'")
            .fetch_all(&temp_pool)
            .await
            .map_err(|e| SpecialistError { message: format!("Failed to extract schema from sqlite: {}", e) })?;

        let mut schema_blobs = Vec::new();
        for row in rows {
            if let Ok(sql) = row.try_get::<String, _>("sql") {
                if !sql.trim().is_empty() {
                    schema_blobs.push(sql);
                }
            }
        }
        let full_schema = schema_blobs.join("\n\n");

        if full_schema.is_empty() {
            return Ok(format!("Sqlite Specialist Analysis Complete for '{}'. Result: Empty schema or unreadable DB.", file_name));
        }

        let schema_trimmed: String = full_schema.chars().take(25_000).collect();

        let preamble = "You are an AI Forensic Database Specialist. You will receive the extracted SQL schema of a suspect database.\
            Analyze the tables and columns to deduce what type of application this database belongs to (e.g. Chrome History, Signal Messages, App Config) and whether it holds high forensic value.\
            Produce a structured JSON output with exactly two keys:\
            - `score`: An integer from 0 to 100 representing forensic severity.\
            - `summary`: A concise 1-2 sentence description explaining the forensic significance of this database structure.\
            Do not include any markdown format tags like ```json.";

        let response = specialist_prompt(&self.config, preamble, &format!("File: {}\nSchema:\n{}", file_name, schema_trimmed)).await?;
        let cleaned = response.trim().trim_start_matches("```json").trim_end_matches("```").trim();
        
        let val: serde_json::Value = serde_json::from_str(cleaned).unwrap_or_else(|_| {
            serde_json::json!({
                "score": 0,
                "summary": format!("Failed to parse specialist JSON: {}", cleaned),
                "schema_preview": schema_trimmed
            })
        });

        let db_id_res = sqlx::query("SELECT id FROM system_files WHERE identifier = ? AND partition_id = ? LIMIT 1")
            .bind(args.file_id as i64)
            .bind(args.partition_id)
            .fetch_one(&*self.evidence_pool).await;

        if let Ok(row) = db_id_res {
            let file_db_id: i64 = row.get("id");
            if let Ok(art_id) = ensure_ai_artifact(&*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, "AI Database Analysis").await {
                let mut db_val = val.clone();
                if let Some(obj) = db_val.as_object_mut() {
                    obj.insert("schema_preview".to_string(), serde_json::json!(schema_trimmed));
                }
                let _ = store_specialist_result(
                    &*self.evidence_pool, self.evidence_id, args.partition_id, file_db_id, art_id, &file_name, "Database Analysis", Some(&schema_trimmed), &db_val
                ).await;
            }
        }

        let summary = val.get("summary").and_then(|s| s.as_str()).unwrap_or("No summary provided");
        Ok(format!("Sqlite Specialist Analysis Complete for '{}'. Summary: {}", file_name, summary))
    }
}
