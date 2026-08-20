use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    pub endpoint: String,
    pub api_key: String,
    #[serde(default)]
    pub llm_endpoint: Option<String>,
    #[serde(default)]
    pub image_endpoint: Option<String>,
    #[serde(default)]
    pub audio_endpoint: Option<String>,
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
        let llm_endpoint = env::var("AGENT_LLM_ENDPOINT").ok();
        let image_endpoint = env::var("AGENT_IMAGE_ENDPOINT").ok();
        let audio_endpoint = env::var("AGENT_AUDIO_ENDPOINT").ok();

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
            llm_endpoint,
            image_endpoint,
            audio_endpoint,
        })
    }

    pub fn openai_endpoint(&self) -> Option<String> {
        self.llm_endpoint
            .clone()
            .or_else(|| (!self.endpoint.trim().is_empty()).then(|| self.endpoint.clone()))
    }

    pub fn copilot_llm_endpoint(&self) -> Result<String> {
        self.service_endpoint(self.llm_endpoint.as_deref(), 8000, "/v1")
    }

    pub fn copilot_image_endpoint(&self) -> Result<String> {
        self.service_endpoint(self.image_endpoint.as_deref(), 8001, "/v1/describe")
    }

    pub fn copilot_audio_endpoint(&self) -> Result<String> {
        self.service_endpoint(self.audio_endpoint.as_deref(), 8002, "/v1/transcribe")
    }

    fn service_endpoint(
        &self,
        explicit: Option<&str>,
        default_port: u16,
        default_path: &str,
    ) -> Result<String> {
        if let Some(explicit) = explicit.filter(|value| !value.trim().is_empty()) {
            return Ok(normalize_endpoint(explicit));
        }

        let mut url = reqwest::Url::parse(&normalize_endpoint(&self.endpoint))
            .map_err(|error| anyhow::anyhow!("Invalid agent endpoint: {error}"))?;
        url.set_port(Some(default_port))
            .map_err(|_| anyhow::anyhow!("Agent endpoint cannot accept a port"))?;
        url.set_path(default_path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url.to_string().trim_end_matches('/').to_string())
    }
}

fn normalize_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}
