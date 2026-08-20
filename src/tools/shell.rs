use crate::policy::AgentPolicy;
use crate::ui::UiHandle;
use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Deserialize)]
pub struct ShellArgs {
    pub command: String,
}

#[derive(Serialize)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("ShellError: {0}")]
pub struct ShellError(pub String);

#[derive(Clone)]
pub struct ShellTool {
    policy: AgentPolicy,
    ui: Option<UiHandle>,
}

impl ShellTool {
    pub fn new(policy: AgentPolicy, ui: Option<UiHandle>) -> Self {
        Self { policy, ui }
    }
}

impl Tool for ShellTool {
    const NAME: &'static str = "shell";

    type Args = ShellArgs;
    type Output = ShellOutput;
    type Error = ShellError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description:
                "Execute a bounded shell command on the host after explicit investigator approval. \
                Use only extracted host-side files, never the original evidence source."
                    .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command proposed for execution."
                    }
                },
                "required": ["command"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        if !self.policy.allow_shell {
            return Ok(denied_output(
                "Shell capability is disabled for this session.",
            ));
        }
        if args.command.trim().is_empty() {
            return Ok(denied_output("Shell command cannot be empty."));
        }

        let allowed = if let Some(ui) = &self.ui {
            ui.log(format!("Agent requested shell execution: {}", args.command));
            let working_dir = self
                .policy
                .shell_working_dir
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "process working directory".to_string());
            ui.request_approval(format!(
                "Allow this host shell command?\n\nWorking directory: {working_dir}\n\n{}",
                args.command,
            ))
            .await
        } else {
            tracing::warn!(command = %args.command, "Shell request denied because no approval UI is attached");
            false
        };
        if !allowed {
            return Ok(denied_output("Shell execution denied by the investigator."));
        }

        let mut command = if cfg!(target_os = "windows") {
            let mut command = Command::new("powershell");
            command.arg("-NoProfile").arg("-Command").arg(&args.command);
            command
        } else {
            let mut command = Command::new("sh");
            command.arg("-c").arg(&args.command);
            command
        };
        if let Some(working_dir) = &self.policy.shell_working_dir {
            command.current_dir(working_dir);
        }
        command.env_clear();
        for key in [
            "PATH",
            "HOME",
            "USERPROFILE",
            "TMPDIR",
            "TEMP",
            "TMP",
            "SystemRoot",
            "COMSPEC",
            "PATHEXT",
            "LANG",
            "LC_ALL",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command.env("NO_COLOR", "1");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|error| ShellError(format!("Failed to start shell command: {error}")))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ShellError("Failed to capture shell stdout".to_string()))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| ShellError("Failed to capture shell stderr".to_string()))?;
        let max_bytes = self.policy.max_shell_output_bytes.max(1);

        let operation = async {
            let read_stdout = read_bounded(&mut stdout, max_bytes);
            let read_stderr = read_bounded(&mut stderr, max_bytes);
            let (stdout, stderr, status) = tokio::join!(read_stdout, read_stderr, child.wait());
            Ok::<_, ShellError>((
                stdout.map_err(|error| ShellError(error.to_string()))?,
                stderr.map_err(|error| ShellError(error.to_string()))?,
                status.map_err(|error| ShellError(error.to_string()))?,
            ))
        };
        let timeout = Duration::from_secs(self.policy.shell_timeout_secs.max(1));
        let ((stdout, stdout_truncated), (stderr, stderr_truncated), status) =
            match tokio::time::timeout(timeout, operation).await {
                Ok(result) => result?,
                Err(_) => {
                    let _ = child.kill().await;
                    return Ok(ShellOutput {
                        stdout: String::new(),
                        stderr: String::new(),
                        exit_code: None,
                        truncated: false,
                        error: Some(format!(
                            "Shell command exceeded the {} second timeout and was terminated.",
                            timeout.as_secs()
                        )),
                    });
                }
            };

        Ok(ShellOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: status.code(),
            truncated: stdout_truncated || stderr_truncated,
            error: None,
        })
    }
}

async fn read_bounded(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    max_bytes: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::with_capacity(max_bytes.min(8192));
    let mut limited = reader.take(max_bytes as u64 + 1);
    limited.read_to_end(&mut output).await?;
    let truncated = output.len() > max_bytes;
    output.truncate(max_bytes);
    Ok((output, truncated))
}

fn denied_output(message: &str) -> ShellOutput {
    ShellOutput {
        stdout: String::new(),
        stderr: message.to_string(),
        exit_code: None,
        truncated: false,
        error: Some("Access denied".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{ShellArgs, ShellTool};
    use crate::policy::AgentPolicy;
    use crate::ui::{UiEvent, UiHandle};
    use rig::tool::Tool;

    #[tokio::test]
    async fn shell_is_disabled_by_default() {
        let tool = ShellTool::new(AgentPolicy::default(), None);
        let output = tool
            .call(ShellArgs {
                command: "echo should-not-run".to_string(),
            })
            .await
            .expect("tool output");
        assert_eq!(output.error.as_deref(), Some("Access denied"));
        assert!(output.stdout.is_empty());
    }

    #[tokio::test]
    async fn approved_shell_command_runs_in_the_configured_directory() {
        let directory = tempfile::tempdir().expect("temporary shell directory");
        let policy = AgentPolicy {
            allow_shell: true,
            shell_working_dir: Some(directory.path().to_path_buf()),
            ..AgentPolicy::default()
        };
        let (ui, mut receiver) = UiHandle::channel_with_context("shell-test", 1, 16);
        let tool = ShellTool::new(policy, Some(ui));
        let command = if cfg!(target_os = "windows") {
            "Write-Output shell-ok"
        } else {
            "printf shell-ok"
        };

        let execution = tokio::spawn(async move {
            tool.call(ShellArgs {
                command: command.to_string(),
            })
            .await
        });
        while let Some(event) = receiver.recv().await {
            if let UiEvent::ApprovalRequest { request, .. } = event {
                request
                    .responder
                    .send(true)
                    .expect("shell approval receiver");
                break;
            }
        }

        let output = execution.await.expect("shell task").expect("shell command");
        assert!(output.stdout.contains("shell-ok"));
        assert_eq!(output.exit_code, Some(0));
        assert!(output.error.is_none());
    }
}
