//! Official, unmodified provider runtimes own their account credentials.
//! No runtime receives evidence paths or permission to execute forensic tools.
use super::*;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const MAX_RUNTIME_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug, Clone, Copy)]
pub enum RuntimeAuthAction {
    Login,
    Logout,
    Status,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAccountStatus {
    pub provider: String,
    pub connected: bool,
    pub authentication: String,
    pub account_label: Option<String>,
    pub account_id: Option<String>,
    pub detail: String,
}

pub fn runtime_directory(provider: &str) -> Result<PathBuf> {
    let name = match provider {
        "claude" | "anthropic" => "claude",
        "mistral" => "vibe",
        _ => bail!("No native account runtime for this provider"),
    };
    Ok(crate::auth::auth_directory()?.join("runtimes").join(name))
}
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn clean_command(binary: &str, provider: &str) -> Result<Command> {
    let mut command = Command::new(binary);
    command.env_clear();
    for key in [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "SystemRoot",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "TERM",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(v) = std::env::var_os(key) {
            command.env(key, v);
        }
    }
    let dir = runtime_directory(provider)?;
    create_private_dir(&dir)?;
    command.env(
        if provider == "mistral" {
            "VIBE_HOME"
        } else {
            "CLAUDE_CONFIG_DIR"
        },
        dir,
    );
    command.kill_on_drop(true);
    Ok(command)
}
fn binary(config: &AgentConfig) -> &str {
    config
        .runtime_path
        .as_deref()
        .unwrap_or(if config.provider == "mistral" {
            "vibe-acp"
        } else {
            "claude"
        })
}

/// Invoke only after the user selects a Connect/Disconnect action. The runtime retains
/// every native authentication method. Exhume does not read its credential files.
pub fn native_auth_command(config: &AgentConfig, action: RuntimeAuthAction) -> Result<Command> {
    let mut command = clean_command(binary(config), &config.provider)?;
    match config.provider.as_str() {
        "claude" | "anthropic" => {
            command.args([
                "auth",
                match action {
                    RuntimeAuthAction::Login => "login",
                    RuntimeAuthAction::Logout => "logout",
                    RuntimeAuthAction::Status => "status",
                },
            ]);
        }
        "mistral" => match action {
            RuntimeAuthAction::Login => {
                command.arg("--setup");
            }
            RuntimeAuthAction::Logout => bail!(
                "Vibe does not document a noninteractive logout command. Disconnect it in the native account settings and revoke the Vibe credential in Mistral Studio; Exhume does not delete or extract its credentials."
            ),
            RuntimeAuthAction::Status => bail!(
                "Vibe ACP does not expose verifiable subscription account status. Inspect the native Vibe account settings."
            ),
        },
        _ => bail!("Unsupported native account provider"),
    }
    command.current_dir(runtime_directory(&config.provider)?);
    Ok(command)
}
async fn bounded_read(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if result.len() + n > MAX_RUNTIME_BYTES {
            bail!("Native runtime exceeded its output bound");
        }
        result.extend_from_slice(&chunk[..n]);
    }
    Ok(result)
}
async fn capture(
    mut command: Command,
    input: Option<String>,
) -> Result<(std::process::ExitStatus, Vec<u8>)> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context(
        "Official account runtime is unavailable; install it or configure its executable path",
    )?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Runtime input unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Runtime output unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Runtime diagnostic output unavailable"))?;
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        let write = async {
            if let Some(input) = input {
                stdin.write_all(input.as_bytes()).await?;
            }
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let (_, stdout, _stderr) =
            tokio::try_join!(write, bounded_read(stdout), bounded_read(stderr))?;
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>((status, stdout))
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            bail!("Native runtime timed out; no complete result accepted")
        }
    }
}

pub async fn native_account_status(config: &AgentConfig) -> Result<RuntimeAccountStatus> {
    let command = native_auth_command(config, RuntimeAuthAction::Status)?;
    let (status, bytes) = capture(command, None).await?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("Native runtime returned invalid account status"))?;
    let method = value["authMethod"].as_str().unwrap_or("unknown");
    let label = value["email"].as_str().filter(|s| !s.is_empty());
    let identity = value["accountUuid"].as_str().or(label);
    let account_id = identity.map(|id| {
        use sha2::{Digest, Sha256};
        let binding = format!("{}:{}", id, value["orgId"].as_str().unwrap_or_default());
        format!(
            "claude-{}",
            &hex::encode(Sha256::digest(binding.as_bytes()))[..24]
        )
    });
    let connected = status.success()
        && method == "claude.ai"
        && value["loggedIn"].as_bool() != Some(false)
        && account_id.is_some();
    Ok(RuntimeAccountStatus {provider:config.provider.clone(),connected,authentication:method.to_string(),account_label:label.map(str::to_owned),account_id,detail:if connected{"Native Claude account authentication is active"}else{"Subscription access and account identity are not confirmed; select a Claude account through the native login flow"}.to_string()})
}

const MAX_MANAGED_SETTINGS_BYTES: u64 = 1024 * 1024;
fn bounded_settings_file(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!(
            "Cannot read native managed settings; resolve the local policy before sending evidence"
        ),
    };
    if !file.metadata()?.is_file() {
        bail!("Native managed settings are not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANAGED_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANAGED_SETTINGS_BYTES {
        bail!("Native managed settings exceed the inspection bound");
    }
    Ok(Some(bytes))
}
fn verify_managed_value(value: &Value, requested_model: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Native managed settings must be a JSON object"))?;
    for (key, value) in object {
        if value.is_null() {
            continue;
        }
        let empty = value.as_object().is_some_and(|v| v.is_empty())
            || value.as_array().is_some_and(|v| v.is_empty());
        let compatible = match key.as_str() {
            "$schema"
            | "cleanupPeriodDays"
            | "availableModels"
            | "deniedModels"
            | "requiredMinimumVersion"
            | "disableAutoMode"
            | "disableBypassPermissionsMode"
            | "forceLoginOrgUUID"
            | "allowedProviders"
            | "blockedMarketplaces"
            | "strictKnownMarketplaces"
            | "deniedMcpServers"
            | "allowedMcpServers"
            | "allowManagedMcpServersOnly"
            | "allowManagedHooksOnly"
            | "allowManagedPermissionRulesOnly"
            | "forceRemoteSettingsRefresh"
            | "managedSourcesBehavior"
            | "maxEffortLevel" => true,
            "model" => value.as_str() == Some(requested_model),
            "disableAllHooks" | "disableClaudeAiConnectors" => value == &Value::Bool(true),
            "autoMemoryEnabled"
            | "syncClaudeAiSkills"
            | "syncClaudeAiPlugins"
            | "enableArtifact" => value == &Value::Bool(false),
            "forceLoginMethod" => value.as_str() == Some("claudeai"),
            "env"
            | "hooks"
            | "managedMcpServers"
            | "mcpServers"
            | "fallbackModel"
            | "extraKnownMarketplaces" => empty,
            "enabledPlugins" => value
                .as_object()
                .is_some_and(|v| v.values().all(|value| value == &Value::Bool(false))),
            "permissions" => value.as_object().is_some_and(|v| {
                v.iter().all(|(key, value)| match key.as_str() {
                    "deny" => value.is_array(),
                    "disableBypassPermissionsMode" => value.as_str() == Some("disable"),
                    "allow" | "ask" | "additionalDirectories" => {
                        value.as_array().is_some_and(|v| v.is_empty())
                    }
                    _ => false,
                })
            }),
            // Unknown keys can add execution or routing in newer runtimes. They require review.
            _ => false,
        };
        if !compatible {
            bail!(
                "Native managed setting '{key}' is incompatible or unverified for model-only Exhume use; no case data was sent"
            );
        }
    }
    Ok(())
}
fn verify_settings_directory(directory: &Path, requested_model: &str) -> Result<()> {
    for file in ["managed-settings.json", "managed-mcp.json"] {
        if let Some(bytes) = bounded_settings_file(&directory.join(file))? {
            let value: Value =
                serde_json::from_slice(&bytes).context("Invalid native managed settings JSON")?;
            verify_managed_value(&value, requested_model)?;
        }
    }
    let fragments = directory.join("managed-settings.d");
    let entries = match std::fs::read_dir(&fragments) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => bail!("Cannot inspect native managed settings fragments"),
    };
    for (index, entry) in entries.enumerate() {
        if index >= 64 {
            bail!("Native managed settings fragment count exceeds the inspection bound");
        }
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with('.'))
            || path.extension().and_then(|v| v.to_str()) != Some("json")
        {
            continue;
        }
        if let Some(bytes) = bounded_settings_file(&path)? {
            verify_managed_value(
                &serde_json::from_slice::<Value>(&bytes)
                    .context("Invalid native managed settings fragment")?,
                requested_model,
            )?;
        }
    }
    Ok(())
}
/// This is a local compatibility preflight, not an attestation of native routing.
/// Server-managed/OS policies may change during launch. This inspection cannot
/// enable inference; `native://claude-code` remains a reserved logical destination.
async fn verify_local_managed_settings(requested_model: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        verify_settings_directory(
            Path::new("/Library/Application Support/ClaudeCode"),
            requested_model,
        )?;
        for path in [
            "/Library/Managed Preferences/com.anthropic.claudecode.plist",
            "/Library/Preferences/com.anthropic.claudecode.plist",
        ] {
            if let Some(bytes) = bounded_settings_file(Path::new(path))? {
                // Conversion reads the exact bounded snapshot; no preferences or secrets are logged.
                let file = tempfile::NamedTempFile::new()?;
                std::fs::write(file.path(), bytes)?;
                let mut command = Command::new("/usr/bin/plutil");
                command
                    .env_clear()
                    .args(["-convert", "json", "-o", "-"])
                    .arg(file.path())
                    .kill_on_drop(true);
                let (exit, bytes) = capture(command, None).await?;
                if !exit.success() {
                    bail!("Cannot inspect native macOS managed preference policy");
                }
                verify_managed_value(
                    &serde_json::from_slice::<Value>(&bytes)
                        .context("Invalid managed preference document")?,
                    requested_model,
                )?;
            }
        }
    }
    #[cfg(target_os = "linux")]
    verify_settings_directory(Path::new("/etc/claude-code"), requested_model)?;
    #[cfg(target_os = "windows")]
    {
        let directory = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("ClaudeCode");
        verify_settings_directory(&directory, requested_model)?;
        // Native registry policy remains opaque to this adapter, like server-managed policy.
        // The case must approve the native runtime destination rather than an invented HTTPS origin.
    }
    Ok(())
}

#[cfg(test)]
fn claude_arguments(model: &str) -> Vec<String> {
    ["--restricted","--print","--output-format","stream-json","--verbose","--tools","","--disallowed-tools","*",
     "--permission-prompts","none","--strict-mcp-config","--mcp-config","{\"mcpServers\":{}}","--setting-sources","",
     "--settings","{\"disableAllHooks\":true,\"autoMemoryEnabled\":false,\"enabledPlugins\":{},\"permissions\":{\"deny\":[\"*\"]}}",
     "--disable-slash-commands","--no-chrome","--no-session-persistence","--max-turns","1","--model",model]
        .into_iter().map(str::to_owned).collect()
}
pub(super) async fn claude(
    config: &AgentConfig,
    _request: &ProviderRequest,
) -> Result<ProviderResponse> {
    verify_local_managed_settings(&config.model).await?;
    bail!(
        "Claude account inference is unavailable: official runtime controls cannot guarantee that managed startup hooks/plugins are disabled before evidence is received. No native inference process was launched and no case data was sent. Login/status/logout remain available. Select a separately approved Claude API-key connection, or request the effective-policy attestation feature in docs/account-authentication.md. No fallback was attempted."
    )
}

// Keep the candidate protocol verification covered by synthetic regression fixtures.
// These parsers cannot enable inference until the pre-launch policy gap above is closed.
#[cfg(test)]
fn parse_claude_output(
    exit_success: bool,
    bytes: &[u8],
    config: &AgentConfig,
) -> Result<ProviderResponse> {
    if !exit_success {
        bail!("Claude Code exited unsuccessfully; no partial result accepted");
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow!("Claude Code returned invalid output encoding"))?;
    let mut models = std::collections::BTreeSet::new();
    let mut result = None;
    let mut init_seen = false;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let event: Value = serde_json::from_str(line)
            .map_err(|_| anyhow!("Claude Code returned an invalid structured event"))?;
        match event["type"].as_str() {
            Some("system") if event["subtype"] == "init" => {
                init_seen = true;
                let tools = event["tools"].as_array().ok_or_else(|| {
                    anyhow!("Claude runtime did not report its tool configuration")
                })?;
                if !tools.is_empty() {
                    bail!(
                        "Claude runtime enabled native tools; this runtime is incompatible with Exhume approval enforcement"
                    );
                }
            }
            Some("assistant") => {
                if let Some(model) = event["message"]["model"].as_str() {
                    models.insert(model.to_string());
                }
                if event["message"]["content"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|c| c["type"] == "tool_use"))
                {
                    bail!("Native runtime attempted an executable tool; result rejected");
                }
            }
            Some("result") => {
                if result.is_some() {
                    bail!("Duplicate Claude final result");
                }
                result = Some(event);
            }
            Some("hook_started" | "hook_response" | "tool_progress") => {
                bail!("Native runtime activated a hook or tool; result rejected")
            }
            _ => {}
        }
    }
    if !init_seen {
        bail!("Claude runtime omitted initialization verification");
    }
    let result = result.ok_or_else(|| anyhow!("Claude runtime ended without a final result"))?;
    if result["is_error"] != false || result["subtype"] != "success" {
        bail!("Claude runtime reported an unsuccessful final result");
    }
    if let Some(usage) = result["modelUsage"].as_object() {
        for model in usage.keys() {
            models.insert(model.clone());
        }
    }
    if models.len() != 1 {
        bail!(
            "Claude runtime did not report one unambiguous inference model; no fallback accepted"
        );
    }
    let model = models.into_iter().next().unwrap();
    let mut response = parse_envelope(
        result["result"]
            .as_str()
            .ok_or_else(|| anyhow!("Claude result omitted decision text"))?,
        config,
        &model,
    )?;
    response.provenance.account_id = config.account_id.clone();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn config() -> AgentConfig {
        AgentConfig {
            provider: "claude".into(),
            model: "test".into(),
            endpoint: "https://api.anthropic.com/v1".into(),
            api_key: String::new(),
            auth_mode: AuthMode::Subscription,
            account_id: None,
            runtime_path: None,
            llm_endpoint: None,
            image_endpoint: None,
            audio_endpoint: None,
        }
    }
    #[test]
    fn managed_execution_routing_and_fallback_overrides_are_rejected() {
        for value in [
            json!({"env":{"ANTHROPIC_BASE_URL":"https://other.invalid"}}),
            json!({"hooks":{"SessionStart":[{}]}}),
            json!({"policyHelper":"run"}),
            json!({"fallbackModel":["other"]}),
            json!({"model":"other"}),
        ] {
            assert!(verify_managed_value(&value, "selected").is_err());
        }
        assert!(verify_managed_value(
            &json!({"permissions":{"deny":["*"]},"disableAllHooks":true}),
            "selected"
        )
        .is_ok());
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("managed-settings.d")).unwrap();
        std::fs::write(
            dir.path().join("managed-settings.d/10-policy.json"),
            b"{\"enabledPlugins\":{\"plugin\":true}}",
        )
        .unwrap();
        assert!(verify_settings_directory(dir.path(), "selected").is_err());
    }
    #[tokio::test]
    async fn claude_inference_cannot_launch_an_unverified_runtime() {
        let mut c = config();
        c.runtime_path = Some("/this/must/never/run".into());
        assert!(claude(&c, &ProviderRequest::default()).await.is_err());
    }
    #[test]
    fn candidate_native_flags_remove_tools_and_persistence() {
        let args = claude_arguments("test");
        assert!(args.windows(2).any(|v| v == ["--tools", ""]));
        assert!(args.contains(&"--restricted".into()));
        assert!(args.contains(&"--no-session-persistence".into()));
        assert!(!args
            .iter()
            .any(|a| a.contains("bypassPermissions") || a == "--bare"));
    }
    #[test]
    fn exit_zero_without_success_result_is_failure() {
        let text=b"{\"type\":\"system\",\"subtype\":\"init\",\"tools\":[]}\n{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"unauthorized\"}\n";
        assert!(parse_claude_output(true, text, &config()).is_err());
    }
    #[test]
    fn rejects_native_tools_even_with_plausible_final_text() {
        let text = b"{\"type\":\"system\",\"subtype\":\"init\",\"tools\":[\"Read\"]}\n";
        assert!(parse_claude_output(true, text, &config()).is_err());
    }
    #[test]
    fn valid_native_result_returns_only_proposals() {
        let text = format!(
            "{}\n{}\n{}\n",
            json!({"type":"system","subtype":"init","tools":[]}),
            json!({"type":"assistant","message":{"model":"actual","content":[{"type":"text","text":"result"}]}}),
            json!({"type":"result","subtype":"success","is_error":false,"result":"{\"text\":\"Observation needs a read\",\"tool_calls\":[{\"id\":\"a\",\"name\":\"list_dir\",\"arguments\":{}}]}"})
        );
        let result = parse_claude_output(true, text.as_bytes(), &config()).unwrap();
        assert_eq!(result.tool_calls[0].name, "list_dir");
        assert_eq!(result.provenance.model, "actual");
    }
}
