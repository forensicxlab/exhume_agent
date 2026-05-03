use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    pub endpoint: String,
    pub api_key: String,
}

impl AgentConfig {
    pub fn from_environment_or_args(
        arg_provider: Option<String>,
        arg_model: Option<String>,
        arg_endpoint: Option<String>,
    ) -> Result<Self> {
        let provider = arg_provider
            .or_else(|| env::var("AGENT_PROVIDER").ok())
            .unwrap_or_else(|| "ollama".to_string());

        let model = arg_model
            .or_else(|| env::var("AGENT_MODEL").ok())
            .unwrap_or_else(|| {
                if provider == "copilot" {
                    "forensic-qwen".to_string()
                } else {
                    "llama3".to_string()
                }
            });

        let endpoint = arg_endpoint
            .or_else(|| env::var("AGENT_ENDPOINT").ok())
            .unwrap_or_else(|| {
                if provider == "ollama" {
                    "http://127.0.0.1:11434/api".to_string()
                } else if provider == "openai" {
                    "https://api.openai.com/v1".to_string()
                } else if provider == "copilot" {
                    "http://10.0.0.198".to_string()
                } else {
                    "".to_string()
                }
            });

        let api_key = env::var("AGENT_API_KEY")
            .unwrap_or_else(|_| env::var("OPENAI_API_KEY").unwrap_or_default());

        if provider == "openai" && api_key.is_empty() {
            anyhow::bail!("OpenAI API key is missing. Set AGENT_API_KEY or OPENAI_API_KEY environment variable.");
        }

        // Ensure the endpoint always has a protocol so HTTP clients don't fail silently.
        let endpoint = if !endpoint.is_empty()
            && !endpoint.starts_with("http://")
            && !endpoint.starts_with("https://")
        {
            format!("http://{}", endpoint)
        } else {
            endpoint
        };

        Ok(Self {
            provider,
            model,
            endpoint,
            api_key,
        })
    }
}
