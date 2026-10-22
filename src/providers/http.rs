use super::*;
use crate::auth;
use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

async fn body(response: reqwest::Response) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let guidance = match status {
            401 | 403 => "Reconnect the selected account or check its authorization",
            429 => "Usage or rate limit reached; pause and review the selected account",
            _ => "Provider request failed",
        };
        bail!("{guidance} (HTTP {status}); no provider, account or billing fallback was attempted");
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            anyhow!("Provider response stream was interrupted; no complete result is available")
        })?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            bail!("Provider response exceeded the bounded transport limit; no truncated response was accepted");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
async fn json_body(response: reqwest::Response) -> Result<Value> {
    serde_json::from_slice(&body(response).await?)
        .map_err(|_| anyhow!("Provider returned invalid JSON"))
}
fn tool_functions(request: &ProviderRequest) -> Vec<Value> {
    request.tools.iter().map(|t|json!({"type":"function","function":{"name":t.name,"description":t.description,"parameters":t.parameters}})).collect()
}
fn call_name_for_id<'a>(request: &'a ProviderRequest, id: &str) -> Option<&'a str> {
    request
        .messages
        .iter()
        .flat_map(|m| &m.tool_calls)
        .find(|c| c.id == id)
        .map(|c| c.name.as_str())
}
fn chat_messages(request: &ProviderRequest, ollama: bool) -> Vec<Value> {
    let mut messages = vec![json!({"role":"system","content":request.instructions})];
    for m in &request.messages {
        let mut item = json!({"role":m.role,"content":m.content});
        if !m.tool_calls.is_empty() {
            item["tool_calls"]=Value::Array(m.tool_calls.iter().map(|c| {
                if ollama { json!({"function":{"name":c.name,"arguments":c.arguments}}) }
                else { json!({"id":c.id,"type":"function","function":{"name":c.name,"arguments":c.arguments.to_string()}}) }
            }).collect());
        }
        if let Some(id) = &m.tool_call_id {
            if ollama {
                item["tool_name"] = json!(call_name_for_id(request, id).unwrap_or("unknown"));
            } else {
                item["tool_call_id"] = json!(id);
            }
        }
        messages.push(item);
    }
    messages
}
pub(super) async fn chat(
    config: &AgentConfig,
    request: &ProviderRequest,
    ollama: bool,
) -> Result<ProviderResponse> {
    chat_with_key(config, request, ollama, &config.api_key).await
}
pub(super) async fn mistral_account(
    config: &AgentConfig,
    request: &ProviderRequest,
) -> Result<ProviderResponse> {
    let key = auth::mistral_api_key(config.account_id.as_deref()).await?;
    chat_with_key(config, request, false, &key).await
}
async fn chat_with_key(
    config: &AgentConfig,
    request: &ProviderRequest,
    ollama: bool,
    key: &str,
) -> Result<ProviderResponse> {
    let endpoint = config.processing_destination()?;
    let url = format!(
        "{}/{}",
        endpoint.trim_end_matches('/'),
        if ollama { "chat" } else { "chat/completions" }
    );
    let mut payload =
        json!({"model":config.model,"messages":chat_messages(request,ollama),"stream":false});
    if !request.tools.is_empty() {
        payload["tools"] = json!(tool_functions(request));
    }
    let mut call = auth::http_client()?.post(&url).json(&payload);
    if !key.is_empty() {
        call = call.bearer_auth(key);
    }
    let response = json_body(
        call.send()
            .await
            .map_err(|_| anyhow!("Provider transport failed; no fallback was attempted"))?,
    )
    .await?;
    parse_chat_response(&response, config, request.messages.len(), ollama)
}
fn parse_chat_response(
    value: &Value,
    config: &AgentConfig,
    round: usize,
    ollama: bool,
) -> Result<ProviderResponse> {
    let message = if ollama {
        if value["done"] != true || value.get("error").is_some() {
            bail!("Ollama did not report successful completion");
        }
        &value["message"]
    } else {
        let choice = value["choices"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow!("Provider response omitted choices"))?;
        if !matches!(
            choice["finish_reason"].as_str(),
            Some("stop" | "tool_calls")
        ) {
            bail!("Provider response was incomplete or refused; no partial tool calls accepted");
        }
        &choice["message"]
    };
    let mut tool_calls = vec![];
    if let Some(calls) = message["tool_calls"].as_array() {
        for (i, c) in calls.iter().enumerate() {
            let function = &c["function"];
            let name = function["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("Provider tool call has no name"))?;
            let arguments = if let Some(s) = function["arguments"].as_str() {
                serde_json::from_str(s)
                    .map_err(|_| anyhow!("Provider tool arguments are invalid JSON"))?
            } else {
                function["arguments"].clone()
            };
            if !arguments.is_object() {
                bail!("Provider tool arguments must be an object");
            }
            let id = if ollama {
                c["id"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("ollama-{round}-{i}"))
            } else {
                c["id"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Provider tool call omitted its ID"))?
                    .to_string()
            };
            tool_calls.push(ProviderToolCall {
                id,
                name: name.to_string(),
                arguments,
            });
        }
    }
    let model = value["model"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Provider did not identify the actual response model"))?;
    Ok(ProviderResponse {
        text: message["content"].as_str().unwrap_or_default().to_string(),
        tool_calls,
        provenance: provenance(config, model)?,
        continuation: vec![],
    })
}
fn responses_payload(config: &AgentConfig, request: &ProviderRequest) -> Value {
    let mut input = vec![];
    for m in &request.messages {
        if !m.continuation.is_empty() {
            input.extend(m.continuation.clone());
            continue;
        }
        if let Some(id) = &m.tool_call_id {
            input.push(json!({"type":"function_call_output","call_id":id,"output":m.content}));
            continue;
        }
        if !m.content.is_empty() {
            input.push(json!({"role":if m.role=="system" {"developer"} else {&m.role},"content":m.content}));
        }
        for c in &m.tool_calls {
            input.push(json!({"type":"function_call","call_id":c.id,"name":c.name,"namespace":"exhume","arguments":c.arguments.to_string()}));
        }
    }
    let mut payload = json!({"model":config.model,"instructions":request.instructions,"input":input,"store":false,"stream":true,"include":["reasoning.encrypted_content"]});
    if !request.tools.is_empty() {
        payload["tools"] = json!([{"type":"namespace","name":"exhume","description":"Investigator-authorized Exhume tools. Calls are validated and executed by Exhume.","tools":request.tools.iter().map(|t|json!({"type":"function","name":t.name,"description":t.description,"parameters":t.parameters,"strict":false})).collect::<Vec<_>>()}]);
        // This runtime requires a callable action or its structured checkpoint.
        // Responses defaults to auto, which also permits text-only replies.
        payload["tool_choice"] = json!("required");
    }
    payload
}
pub(super) async fn chatgpt(
    config: &AgentConfig,
    request: &ProviderRequest,
) -> Result<ProviderResponse> {
    let token = auth::access_token(config.account_id.as_deref()).await?;
    let response = auth::http_client()?
        .post("https://api.openai.com/v1/responses")
        .bearer_auth(token)
        .json(&responses_payload(config, request))
        .send()
        .await
        .map_err(|_| anyhow!("ChatGPT transport failed; no fallback was attempted"))?;
    let bytes = body(response).await?;
    parse_responses_stream(&bytes, config)
}
fn parse_responses_stream(bytes: &[u8], config: &AgentConfig) -> Result<ProviderResponse> {
    let text = std::str::from_utf8(bytes).map_err(|_| anyhow!("Invalid provider event stream"))?;
    let normalized = text.replace("\r\n", "\n");
    let mut completed = None;
    let mut protocol = ResponseProtocolMetadata::default();
    let mut streamed = StreamedOutput::default();
    for event in normalized.split("\n\n") {
        let data = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:").map(str::trim_start))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let value: Value =
            serde_json::from_str(&data).map_err(|_| anyhow!("Invalid provider event JSON"))?;
        protocol.record_event(&value);
        match value["type"].as_str() {
            Some("error"|"response.failed"|"response.incomplete")=>bail!("ChatGPT reported an unsuccessful response; no partial result or tool call accepted"),
            Some("response.completed")=>{if completed.is_some(){bail!("Duplicate completed provider response");}completed=Some(value["response"].clone());},
            Some("response.output_item.added" | "response.output_item.done") => {
                if completed.is_some() {
                    bail!("Provider output arrived after response completion");
                }
                streamed.record(&value)?;
            }
            _=>{}
        }
    }
    let response = completed.ok_or_else(|| {
        anyhow!("ChatGPT stream ended without response.completed; no partial result accepted")
    })?;
    if response["status"] != "completed" {
        bail!("ChatGPT final response status was not completed");
    }
    let final_output = response["output"]
        .as_array()
        .ok_or_else(|| anyhow!("ChatGPT response omitted output"))?;
    let output = streamed.reconcile(final_output)?;
    let mut text = String::new();
    let mut tool_calls = vec![];
    let mut call_ids = std::collections::BTreeSet::new();
    for item in &output {
        if item
            .get("status")
            .is_some_and(|status| !status.is_null() && status != "completed")
        {
            bail!("Provider output item did not complete successfully");
        }
        match item["type"].as_str() {
            Some("message") => {
                if let Some(content) = item["content"].as_array() {
                    for part in content {
                        if part["type"] == "output_text" {
                            text.push_str(part["text"].as_str().unwrap_or_default());
                        } else if part["type"] == "refusal" {
                            bail!("Provider refused this request");
                        }
                    }
                }
            }
            Some("function_call") => {
                if let Some(namespace) = item["namespace"].as_str() {
                    if namespace != "exhume" {
                        bail!("Unexpected provider tool namespace");
                    }
                }
                let id = item["call_id"]
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| anyhow!("Provider call ID is missing"))?
                    .to_string();
                if !call_ids.insert(id.clone()) {
                    bail!("Provider returned duplicate tool call IDs");
                }
                let raw_name = item["name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Provider call name is missing"))?;
                let name = raw_name
                    .strip_prefix("exhume.")
                    .unwrap_or(raw_name)
                    .to_string();
                if name.trim().is_empty() {
                    bail!("Provider call name is empty");
                }
                let arguments: Value = serde_json::from_str(
                    item["arguments"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Provider call arguments are missing"))?,
                )
                .map_err(|_| anyhow!("Provider returned invalid tool arguments"))?;
                if !arguments.is_object() {
                    bail!("Provider call arguments must be an object");
                }
                tool_calls.push(ProviderToolCall {
                    id,
                    name,
                    arguments,
                });
            }
            Some("reasoning") => {}
            _ => bail!("Provider returned an unsupported output operation"),
        }
    }
    let model = response["model"]
        .as_str()
        .ok_or_else(|| anyhow!("Provider did not identify its response model"))?;
    if text.trim().is_empty() && tool_calls.is_empty() {
        bail!(
            "ChatGPT completed without visible text or callable actions; protocol_metadata={}",
            protocol.summary(&response, final_output)
        );
    }
    Ok(ProviderResponse {
        text,
        tool_calls,
        provenance: provenance(config, model)?,
        continuation: output,
    })
}

/// A successful final envelope can omit items already delivered by SSE. Only
/// whole output_item.done records are eligible for replay/execution; deltas and
/// added items never become executable output, even after response.completed.
#[derive(Default)]
struct StreamedOutput {
    added: BTreeMap<u64, (String, String)>,
    done: BTreeMap<u64, Value>,
}

fn output_identity(item: &Value) -> Result<(&str, &str)> {
    let id = item["id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Stream output item omitted its ID"))?;
    let kind = item["type"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Stream output item omitted its type"))?;
    Ok((id, kind))
}

impl StreamedOutput {
    fn record(&mut self, event: &Value) -> Result<()> {
        let index = event["output_index"]
            .as_u64()
            .filter(|index| *index < 4096)
            .ok_or_else(|| anyhow!("Stream output index is missing or out of bounds"))?;
        let item = &event["item"];
        let (id, kind) = output_identity(item)?;
        if event["type"] == "response.output_item.added" {
            if self.done.contains_key(&index)
                || self.added.insert(index, (id.into(), kind.into())).is_some()
            {
                bail!("Duplicate or out-of-order stream output item");
            }
        } else {
            if self
                .added
                .get(&index)
                .is_some_and(|(added_id, added_kind)| added_id != id || added_kind != kind)
            {
                bail!("Stream output identity changed before completion");
            }
            // Reasoning items may omit status. Executable calls and messages
            // must explicitly be complete in the streamed fallback.
            if (kind == "function_call" || kind == "message") && item["status"] != "completed"
                || item
                    .get("status")
                    .is_some_and(|status| !status.is_null() && status != "completed")
            {
                bail!("Stream output item did not complete successfully");
            }
            if self.done.insert(index, item.clone()).is_some() {
                bail!("Duplicate completed stream output item");
            }
        }
        Ok(())
    }

    fn reconcile(self, final_output: &[Value]) -> Result<Vec<Value>> {
        if !final_output.is_empty() {
            // Never concatenate two copies of a call or choose between conflicting
            // copies. A populated final envelope must agree with streamed items.
            for (index, item) in &self.done {
                if final_output.get(*index as usize) != Some(item) {
                    bail!("Completed response conflicts with streamed output");
                }
            }
            for (index, (id, kind)) in &self.added {
                let item = final_output.get(*index as usize).ok_or_else(|| {
                    anyhow!("Completed response omitted an announced output item")
                })?;
                if item["id"] != *id || item["type"] != *kind {
                    bail!("Completed response changed an announced output identity");
                }
            }
            return Ok(final_output.to_vec());
        }
        if self
            .added
            .keys()
            .any(|index| !self.done.contains_key(index))
        {
            bail!("Completed response omitted an unfinished stream output item");
        }
        let mut identities = std::collections::BTreeSet::new();
        for (expected, (index, item)) in self.done.iter().enumerate() {
            if *index != expected as u64 {
                bail!("Completed stream output has missing item indices");
            }
            if !identities.insert(output_identity(item)?.0) {
                bail!("Completed stream output has duplicate item IDs");
            }
        }
        Ok(self.done.into_values().collect())
    }
}

/// Only fixed protocol labels and counts enter diagnostics. Never copy provider
/// strings, tool arguments, text, reasoning, identifiers or the raw response.
#[derive(Default)]
struct ResponseProtocolMetadata {
    events: BTreeMap<&'static str, usize>,
    done_item_types: BTreeMap<&'static str, usize>,
    done_item_statuses: BTreeMap<&'static str, usize>,
    done_content_types: BTreeMap<&'static str, usize>,
}

fn count_label(counts: &mut BTreeMap<&'static str, usize>, label: &'static str) {
    *counts.entry(label).or_default() += 1;
}

fn protocol_item_type(item: &Value) -> &'static str {
    match item["type"].as_str() {
        Some("message") => "message",
        Some("function_call") => "function_call",
        Some("reasoning") => "reasoning",
        Some("custom_tool_call") => "custom_tool_call",
        Some("tool_search_call") => "tool_search_call",
        Some(_) => "other",
        None => "missing",
    }
}

fn protocol_status(item: &Value) -> &'static str {
    match item["status"].as_str() {
        Some("completed") => "completed",
        Some("in_progress") => "in_progress",
        Some("incomplete") => "incomplete",
        Some("failed") => "failed",
        Some("cancelled") => "cancelled",
        Some(_) => "other",
        None => "missing",
    }
}

fn count_content_types(item: &Value, counts: &mut BTreeMap<&'static str, usize>) {
    if let Some(parts) = item["content"].as_array() {
        for part in parts {
            count_label(
                counts,
                match part["type"].as_str() {
                    Some("output_text") => "output_text",
                    Some("refusal") => "refusal",
                    Some(_) => "other",
                    None => "missing",
                },
            );
        }
    }
}

impl ResponseProtocolMetadata {
    fn record_event(&mut self, event: &Value) {
        let label = match event["type"].as_str() {
            Some("response.created") => "response.created",
            Some("response.in_progress") => "response.in_progress",
            Some("response.completed") => "response.completed",
            Some("response.output_item.added") => "response.output_item.added",
            Some("response.output_item.done") => "response.output_item.done",
            Some("response.function_call_arguments.delta") => {
                "response.function_call_arguments.delta"
            }
            Some("response.function_call_arguments.done") => {
                "response.function_call_arguments.done"
            }
            Some("response.output_text.delta") => "response.output_text.delta",
            Some("response.output_text.done") => "response.output_text.done",
            Some(_) => "other",
            None => "missing",
        };
        count_label(&mut self.events, label);
        if label == "response.output_item.done" {
            let item = &event["item"];
            count_label(&mut self.done_item_types, protocol_item_type(item));
            count_label(&mut self.done_item_statuses, protocol_status(item));
            count_content_types(item, &mut self.done_content_types);
        }
    }

    fn summary(&self, response: &Value, output: &[Value]) -> Value {
        let mut final_item_types = BTreeMap::new();
        let mut final_item_statuses = BTreeMap::new();
        let mut final_content_types = BTreeMap::new();
        for item in output {
            count_label(&mut final_item_types, protocol_item_type(item));
            count_label(&mut final_item_statuses, protocol_status(item));
            count_content_types(item, &mut final_content_types);
        }
        let tool_choice = match response["tool_choice"].as_str() {
            Some("required") => "required",
            Some("auto") => "auto",
            Some("none") => "none",
            Some(_) => "other",
            None if response["tool_choice"].is_object() => "object",
            None => "missing",
        };
        json!({
            "events": self.events,
            "done_item_types": self.done_item_types,
            "done_item_statuses": self.done_item_statuses,
            "done_content_types": self.done_content_types,
            "final_item_types": final_item_types,
            "final_item_statuses": final_item_statuses,
            "final_content_types": final_content_types,
            "response_status": protocol_status(response),
            "tool_choice": tool_choice,
        })
    }
}
pub(super) async fn anthropic(
    config: &AgentConfig,
    request: &ProviderRequest,
) -> Result<ProviderResponse> {
    let mut messages = vec![];
    for m in &request.messages {
        if let Some(id) = &m.tool_call_id {
            messages.push(json!({"role":"user","content":[{"type":"tool_result","tool_use_id":id,"content":m.content}]}));
            continue;
        }
        let mut content = vec![];
        if !m.content.is_empty() {
            content.push(json!({"type":"text","text":m.content}));
        }
        for c in &m.tool_calls {
            content.push(json!({"type":"tool_use","id":c.id,"name":c.name,"input":c.arguments}));
        }
        messages.push(json!({"role":m.role,"content":content}));
    }
    let payload = json!({"model":config.model,"system":request.instructions,"messages":messages,"max_tokens":8192,"tools":request.tools.iter().map(|t|json!({"name":t.name,"description":t.description,"input_schema":t.parameters})).collect::<Vec<_>>()});
    let response = json_body(
        auth::http_client()?
            .post(format!(
                "{}/messages",
                config.processing_destination()?.trim_end_matches('/')
            ))
            .header("x-api-key", &config.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&payload)
            .send()
            .await
            .map_err(|_| anyhow!("Claude API transport failed; no fallback was attempted"))?,
    )
    .await?;
    if !matches!(
        response["stop_reason"].as_str(),
        Some("end_turn" | "tool_use")
    ) {
        bail!("Claude API returned an incomplete response");
    }
    let mut text = String::new();
    let mut tool_calls = vec![];
    for item in response["content"]
        .as_array()
        .ok_or_else(|| anyhow!("Claude API omitted response content"))?
    {
        if item["type"] == "text" {
            text.push_str(item["text"].as_str().unwrap_or_default());
        } else if item["type"] == "tool_use" {
            tool_calls.push(ProviderToolCall {
                id: item["id"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing tool ID"))?
                    .into(),
                name: item["name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing tool name"))?
                    .into(),
                arguments: item["input"].clone(),
            });
        }
    }
    let model = response["model"]
        .as_str()
        .ok_or_else(|| anyhow!("Claude API omitted actual model"))?;
    Ok(ProviderResponse {
        text,
        tool_calls,
        provenance: provenance(config, model)?,
        continuation: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> AgentConfig {
        AgentConfig {
            provider: "openai".into(),
            model: "test-model".into(),
            endpoint: "https://api.openai.com/v1".into(),
            api_key: "secret".into(),
            auth_mode: AuthMode::Subscription,
            account_id: Some("test-account".into()),
            runtime_path: None,
            llm_endpoint: None,
            image_endpoint: None,
            audio_endpoint: None,
        }
    }
    #[test]
    fn stream_delta_is_not_success_and_late_error_is_not_hidden() {
        let delta =
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"looks successful\"}\n\n";
        assert!(parse_responses_stream(delta, &config()).is_err());
        let mut bytes = vec![b' '; 70000];
        bytes.extend_from_slice(b"data: {\"type\":\"response.failed\"}\n\n");
        assert!(parse_responses_stream(&bytes, &config()).is_err());
    }
    #[test]
    fn completed_response_preserves_calls_and_reasoning() {
        let output = json!([{"type":"reasoning","id":"r","encrypted_content":"opaque"},{"type":"function_call","namespace":"exhume","call_id":"c","name":"list_dir","arguments":"{}"}]);
        let event = json!({"type":"response.completed","response":{"status":"completed","model":"actual-model","output":output}});
        let result =
            parse_responses_stream(format!("data: {event}\r\n\r\n").as_bytes(), &config()).unwrap();
        assert_eq!(result.tool_calls[0].name, "list_dir");
        assert_eq!(result.continuation.len(), 2);
        assert_eq!(result.provenance.model, "actual-model");
    }
    #[test]
    fn empty_final_output_retains_completed_stream_calls_and_reasoning_in_order() {
        let call = streamed_call();
        let reasoning = json!({"id":"r","type":"reasoning","encrypted_content":"opaque"});
        let response = parse_events(&[
            json!({"type":"response.output_item.added","output_index":1,"item":{"id":"fc","type":"function_call","status":"in_progress"}}),
            json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"ignored incomplete delta"}),
            done_item(1, call.clone()),
            done_item(0, reasoning.clone()),
            complete(json!([])),
        ]).unwrap();
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "query_index");
        assert_eq!(response.tool_calls[0].arguments, json!({"sql":"SELECT 1"}));
        assert_eq!(response.continuation, vec![reasoning, call]);
        assert_eq!(response.provenance.model, "actual-model");
    }

    fn streamed_call() -> Value {
        json!({"id":"fc","type":"function_call","status":"completed","namespace":"exhume",
            "call_id":"call-1","name":"query_index","arguments":"{\"sql\":\"SELECT 1\"}"})
    }
    fn done_item(index: u64, item: Value) -> Value {
        json!({"type":"response.output_item.done","output_index":index,"item":item})
    }
    fn complete(output: Value) -> Value {
        json!({"type":"response.completed","response":{"status":"completed","model":"actual-model","tool_choice":"required","output":output}})
    }
    fn parse_events(events: &[Value]) -> Result<ProviderResponse> {
        let stream = events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>();
        parse_responses_stream(stream.as_bytes(), &config())
    }

    #[test]
    fn populated_final_output_is_not_duplicated_and_conflicts_fail_closed() {
        let call = streamed_call();
        let response =
            parse_events(&[done_item(0, call.clone()), complete(json!([call.clone()]))]).unwrap();
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.continuation.len(), 1);
        let mut conflict = call.clone();
        conflict["arguments"] = json!("{\"sql\":\"SELECT 2\"}");
        assert!(parse_events(&[done_item(0, call), complete(json!([conflict]))]).is_err());
    }

    #[test]
    fn successful_envelope_cannot_complete_an_unfinished_output_item() {
        for status in ["in_progress", "incomplete", "failed", "PRIVATE-status"] {
            let mut call = streamed_call();
            call["status"] = json!(status);
            let error = parse_events(&[complete(json!([call]))])
                .unwrap_err()
                .to_string();
            assert_eq!(error, "Provider output item did not complete successfully");
        }
    }

    #[test]
    fn incomplete_ambiguous_or_failed_streams_cannot_supply_calls() {
        let call = streamed_call();
        let done = done_item(0, call.clone());
        let finish = complete(json!([]));
        let mut pending = call.clone();
        pending["status"] = json!("in_progress");
        let added =
            json!({"type":"response.output_item.added","output_index":0,"item":pending.clone()});
        let mut different = call.clone();
        different["id"] = json!("different-item");
        let mut duplicate_call = call.clone();
        duplicate_call["id"] = json!("different-item");
        let cases = vec![
            vec![done.clone()],
            vec![done.clone(), json!({"type":"response.failed"})],
            vec![done.clone(), finish.clone(), json!({"type":"error"})],
            vec![done.clone(), finish.clone(), finish.clone()],
            vec![finish.clone(), done.clone()],
            vec![done.clone(), done.clone(), finish.clone()],
            vec![done_item(1, call.clone()), finish.clone()],
            vec![added.clone(), finish.clone()],
            vec![done_item(0, pending), finish.clone()],
            vec![added.clone(), done_item(0, different), finish.clone()],
            vec![done.clone(), done_item(1, call.clone()), finish.clone()],
            vec![done.clone(), done_item(1, duplicate_call), finish.clone()],
            vec![
                added,
                json!({"type":"response.function_call_arguments.done","output_index":0,"arguments":"{}"}),
                finish.clone(),
            ],
        ];
        for (index, events) in cases.iter().enumerate() {
            assert!(
                parse_events(events).is_err(),
                "unsafe stream fixture {index} was accepted"
            );
        }
    }

    #[test]
    fn streamed_calls_keep_namespace_json_and_refusal_validation() {
        for (field, value) in [
            ("namespace", json!("other")),
            ("arguments", json!("{broken")),
            ("arguments", json!("[]")),
            ("call_id", json!("")),
            ("name", json!("exhume.")),
        ] {
            let mut call = streamed_call();
            call[field] = value;
            assert!(parse_events(&[done_item(0, call), complete(json!([]))]).is_err());
        }
        let refusal = json!({"id":"msg","type":"message","status":"completed","content":[{"type":"refusal","refusal":"no"}]});
        assert!(parse_events(&[done_item(0, refusal), complete(json!([]))]).is_err());
        let message = json!({"id":"msg","type":"message","status":"completed","content":[{"type":"output_text","text":"Checkpoint requires review."}]});
        assert_eq!(
            parse_events(&[done_item(0, message), complete(json!([]))])
                .unwrap()
                .text,
            "Checkpoint requires review."
        );
    }
    #[test]
    fn reasoning_only_diagnostics_are_bounded_and_exclude_provider_content() {
        let event = json!({"type":"response.completed","response":{
            "status":"completed","model":"PRIVATE-model","tool_choice":"PRIVATE-choice",
            "output":[
                {"type":"reasoning","id":"PRIVATE-id","encrypted_content":"PRIVATE-encrypted","summary":[{"text":"PRIVATE-reasoning"}]},
                {"type":"message","status":"completed","content":[{"type":"PRIVATE-type","text":"PRIVATE-text"}]}
            ]
        }});
        let error = parse_responses_stream(format!("data: {event}\n\n").as_bytes(), &config())
            .unwrap_err()
            .to_string();
        let metadata: Value =
            serde_json::from_str(error.split_once("protocol_metadata=").unwrap().1).unwrap();
        assert_eq!(metadata["final_item_types"]["reasoning"], 1);
        assert_eq!(metadata["final_content_types"]["other"], 1);
        assert_eq!(metadata["tool_choice"], "other");
        assert!(!error.contains("PRIVATE"));
        assert!(error.len() < 2048);
    }
    #[test]
    fn visible_text_without_tools_remains_a_valid_provider_response() {
        let event = json!({"type":"response.completed","response":{
            "status":"completed","model":"actual-model","output":[
                {"type":"message","content":[{"type":"output_text","text":"Please choose a step."}]}
            ]
        }});
        let response =
            parse_responses_stream(format!("data: {event}\n\n").as_bytes(), &config()).unwrap();
        assert_eq!(response.text, "Please choose a step.");
        assert!(response.tool_calls.is_empty());
    }
    #[test]
    fn subscription_payload_uses_preview_contract_and_full_replay() {
        let request = ProviderRequest {
            instructions: "instruction".into(),
            messages: vec![
                ProviderMessage {
                    role: "assistant".into(),
                    continuation: vec![json!({"type":"reasoning","id":"r"})],
                    ..Default::default()
                },
                ProviderMessage {
                    role: "tool".into(),
                    content: "observed".into(),
                    tool_call_id: Some("call".into()),
                    ..Default::default()
                },
            ],
            tools: vec![ProviderTool {
                name: "read".into(),
                description: "read".into(),
                parameters: json!({"type":"object"}),
            }],
        };
        let payload = responses_payload(&config(), &request);
        assert_eq!(payload["store"], false);
        assert_eq!(payload["stream"], true);
        assert_eq!(payload["tools"][0]["type"], "namespace");
        assert_eq!(payload["tool_choice"], "required");
        assert_eq!(payload["input"][1]["type"], "function_call_output");
        assert!(payload.get("temperature").is_none());
        let without_tools = responses_payload(&config(), &ProviderRequest::default());
        assert!(without_tools.get("tool_choice").is_none());
    }
    #[test]
    fn transport_does_not_accept_truncated_tool_arguments() {
        let value = json!({"model":"actual","choices":[{"finish_reason":"length","message":{"content":"claim","tool_calls":[]}}]});
        assert!(parse_chat_response(&value, &config(), 0, false).is_err());
    }
}
