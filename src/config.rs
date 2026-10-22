use crate::auth::AuthMode;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    pub endpoint: String,
    #[serde(default, skip_serializing)]
    pub api_key: String,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub runtime_path: Option<String>,
    #[serde(default)]
    pub llm_endpoint: Option<String>,
    #[serde(default)]
    pub image_endpoint: Option<String>,
    #[serde(default)]
    pub audio_endpoint: Option<String>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("endpoint", &self.endpoint)
            .field("auth_mode", &self.auth_mode)
            .field("account_id", &self.account_id)
            .field("api_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AgentConfig {
    pub fn from_environment_or_args(
        arg_provider: Option<String>,
        arg_model: Option<String>,
        arg_endpoint: Option<String>,
    ) -> Result<Self> {
        Self::from_environment_or_args_with_auth(arg_provider, arg_model, arg_endpoint, None)
    }

    pub fn from_environment_or_args_with_auth(
        arg_provider: Option<String>,
        arg_model: Option<String>,
        arg_endpoint: Option<String>,
        arg_auth_mode: Option<AuthMode>,
    ) -> Result<Self> {
        let provider = arg_provider
            .or_else(|| env::var("AGENT_PROVIDER").ok())
            .unwrap_or_else(|| "ollama".to_string());
        let auth_mode = match (
            arg_auth_mode,
            env::var("AGENT_AUTH_MODE").unwrap_or_default().as_str(),
        ) {
            (Some(mode), _) => mode,
            (None, "" | "api_key") => AuthMode::ApiKey,
            (None, "subscription") => AuthMode::Subscription,
            _ => anyhow::bail!("AGENT_AUTH_MODE must be api_key or subscription"),
        };

        let model = arg_model
            .or_else(|| env::var("AGENT_MODEL").ok())
            .unwrap_or_else(|| {
                match provider.as_str() {
                    "copilot" => "forensic-qwen",
                    "openai" | "mistral" | "claude" | "anthropic" => "",
                    _ => "llama3",
                }
                .to_string()
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
                } else if provider == "mistral" {
                    "https://api.mistral.ai/v1".to_string()
                } else if provider == "claude" || provider == "anthropic" {
                    "https://api.anthropic.com/v1".to_string()
                } else {
                    "".to_string()
                }
            });

        let api_key = if auth_mode == AuthMode::Subscription {
            String::new()
        } else {
            env::var("AGENT_API_KEY").unwrap_or_else(|_| {
                env::var(match provider.as_str() {
                    "mistral" => "MISTRAL_API_KEY",
                    "claude" | "anthropic" => "ANTHROPIC_API_KEY",
                    _ => "OPENAI_API_KEY",
                })
                .unwrap_or_default()
            })
        };
        let llm_endpoint = env::var("AGENT_LLM_ENDPOINT").ok();
        let image_endpoint = env::var("AGENT_IMAGE_ENDPOINT").ok();
        let audio_endpoint = env::var("AGENT_AUDIO_ENDPOINT").ok();

        if auth_mode == AuthMode::ApiKey
            && matches!(
                provider.as_str(),
                "openai" | "mistral" | "claude" | "anthropic"
            )
            && api_key.is_empty()
        {
            anyhow::bail!(
                "Provider API key is missing. Set AGENT_API_KEY/the provider key, or explicitly select subscription authentication."
            );
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
            auth_mode,
            account_id: env::var("AGENT_ACCOUNT_ID").ok(),
            runtime_path: env::var("AGENT_RUNTIME_PATH").ok(),
            llm_endpoint,
            image_endpoint,
            audio_endpoint,
        })
    }

    /// Inference destination to approve before sending case material. Native Claude
    /// routing is opaque; its logical destination is never asserted as a public API URL.
    pub fn processing_destination(&self) -> Result<String> {
        if self.auth_mode == AuthMode::Subscription {
            return Ok(match self.provider.as_str() {
                "openai" => "https://api.openai.com/v1",
                "mistral" => "https://api.mistral.ai/v1",
                "claude" | "anthropic" => "native://claude-code",
                _ => anyhow::bail!("Subscription authentication is unsupported for this provider"),
            }
            .to_string());
        }
        if self.provider == "copilot" {
            return self.copilot_llm_endpoint();
        }
        if self.provider == "ollama" {
            let mut url = reqwest::Url::parse(&self.endpoint)?;
            if url.path().trim_matches('/').is_empty() {
                url.set_path("/api");
            }
            return Ok(url.to_string().trim_end_matches('/').to_string());
        }
        self.openai_endpoint()
            .ok_or_else(|| anyhow::anyhow!("Provider endpoint is required"))
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

#[cfg(test)]
mod tests {
    use super::*;
    fn legacy_config() -> AgentConfig {
        serde_json::from_value(serde_json::json!({"provider":"openai","model":"test","endpoint":"https://api.openai.com/v1","api_key":"a-sensitive-test-key"})).unwrap()
    }
    #[test]
    fn api_keys_are_not_serialized_or_debugged() {
        let c = legacy_config();
        assert!(!serde_json::to_string(&c)
            .unwrap()
            .contains("a-sensitive-test-key"));
        assert!(!format!("{c:?}").contains("a-sensitive-test-key"));
        assert_eq!(c.auth_mode, AuthMode::ApiKey);
    }
    #[test]
    fn subscription_destinations_are_pinned() {
        let mut c = legacy_config();
        c.auth_mode = AuthMode::Subscription;
        c.endpoint = "https://unapproved.invalid/v1".into();
        c.llm_endpoint = Some("https://other.invalid/v1".into());
        assert_eq!(
            c.processing_destination().unwrap(),
            "https://api.openai.com/v1"
        );
        c.provider = "mistral".into();
        assert_eq!(
            c.processing_destination().unwrap(),
            "https://api.mistral.ai/v1"
        );
    }
    #[test]
    fn ollama_base_urls_resolve_to_actual_api_destination() {
        let mut c = legacy_config();
        c.provider = "ollama".into();
        c.endpoint = "http://localhost:11434".into();
        assert_eq!(
            c.processing_destination().unwrap(),
            "http://localhost:11434/api"
        );
        c.endpoint = "http://localhost:11434/api".into();
        assert_eq!(
            c.processing_destination().unwrap(),
            "http://localhost:11434/api"
        );
    }
}
