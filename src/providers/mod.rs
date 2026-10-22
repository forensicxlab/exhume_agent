//! Model transports return proposed calls; they never execute Exhume tools.
mod http;
pub mod runtimes;

use crate::{auth::AuthMode, config::AgentConfig};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderMessage {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub tool_calls: Vec<ProviderToolCall>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    /// Complete Responses output (including reasoning) to replay without losing context.
    #[serde(default)]
    pub continuation: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderTool {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderRequest {
    pub instructions: String,
    pub messages: Vec<ProviderMessage>,
    pub tools: Vec<ProviderTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProvenance {
    pub provider: String,
    pub model: String,
    pub authentication: AuthMode,
    pub account_id: Option<String>,
    pub destination: String,
    pub usage_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub text: String,
    pub tool_calls: Vec<ProviderToolCall>,
    pub provenance: ProviderProvenance,
    #[serde(default)]
    pub continuation: Vec<Value>,
}

pub async fn complete(config: &AgentConfig, request: &ProviderRequest) -> Result<ProviderResponse> {
    if config.model.trim().is_empty() {
        bail!("Select a model before starting inference");
    }
    let response = match (config.provider.as_str(), config.auth_mode) {
        ("openai", AuthMode::Subscription) => http::chatgpt(config, request).await,
        ("claude" | "anthropic", AuthMode::Subscription) => runtimes::claude(config, request).await,
        ("mistral", AuthMode::Subscription) => http::mistral_account(config, request).await,
        ("ollama", AuthMode::ApiKey) => http::chat(config, request, true).await,
        ("openai" | "mistral" | "copilot", AuthMode::ApiKey) => {
            http::chat(config, request, false).await
        }
        ("claude" | "anthropic", AuthMode::ApiKey) => http::anthropic(config, request).await,
        _ => bail!("Unsupported provider/authentication combination; no fallback was attempted"),
    }?;
    let mut ids = std::collections::BTreeSet::new();
    for call in &response.tool_calls {
        if call.id.is_empty()
            || !ids.insert(&call.id)
            || !call.arguments.is_object()
            || !request.tools.iter().any(|tool| tool.name == call.name)
        {
            bail!("Provider returned duplicate, malformed or unavailable tool requests; no tools executed");
        }
    }
    Ok(response)
}

fn provenance(config: &AgentConfig, actual_model: &str) -> Result<ProviderProvenance> {
    Ok(ProviderProvenance {
        provider: config.provider.clone(),
        model: actual_model.to_string(),
        authentication: config.auth_mode,
        account_id: config.account_id.clone(),
        destination: config.processing_destination()?,
        usage_source: match (config.provider.as_str(), config.auth_mode) {
            ("openai", AuthMode::Subscription) => "chatgpt_plan",
            ("mistral", AuthMode::Subscription) => "mistral_account_api_allowance_or_payg",
            ("claude" | "anthropic", AuthMode::Subscription) => "claude_native_account",
            ("ollama" | "copilot", _) => "local_or_configured_service",
            _ => "api_key",
        }
        .into(),
    })
}

#[cfg(test)]
fn parse_envelope(text: &str, config: &AgentConfig, model: &str) -> Result<ProviderResponse> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        text: String,
        tool_calls: Vec<ProviderToolCall>,
    }
    let result: Envelope = serde_json::from_str(text).map_err(|_| {
        anyhow::anyhow!("Provider returned an invalid decision envelope; no tools executed")
    })?;
    for call in &result.tool_calls {
        if call.id.is_empty() || call.name.is_empty() || !call.arguments.is_object() {
            bail!("Provider returned an invalid proposed tool call; no tools executed");
        }
    }
    Ok(ProviderResponse {
        text: result.text,
        tool_calls: result.tool_calls,
        provenance: provenance(config, model)?,
        continuation: vec![],
    })
}
