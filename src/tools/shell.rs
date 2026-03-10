use rig::completion::ToolDefinition;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::process::Command;
use colored::Colorize;

#[derive(Deserialize)]
pub struct ShellArgs {
    pub command: String,
}

#[derive(Serialize)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("ShellError: {0}")]
pub struct ShellError(pub String);

#[derive(Clone, Default)]
pub struct ShellTool;

impl Tool for ShellTool {
    const NAME: &'static str = "shell";

    type Args = ShellArgs;
    type Output = ShellOutput;
    type Error = ShellError;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description: "Executes a shell command on the host system. Use this for environment investigation, file system operations, or running external forensic tools. ALL commands require explicit user confirmation (y/N) before execution.".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute."
                    }
                },
                "required": ["command"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        println!("\n  {} {} {}", "⚠️".yellow(), "AGENT REQUESTS SHELL EXECUTION:".bold().yellow(), args.command.cyan());
        print!("  Allow execution? (y/N): ");
        io::stdout().flush().map_err(|e| ShellError(e.to_string()))?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| ShellError(e.to_string()))?;

        if input.trim().to_lowercase() != "y" {
            println!("  {} {}", "❌".red(), "Execution denied by user.".bold().red());
            return Ok(ShellOutput {
                stdout: String::new(),
                stderr: "Execution denied by user.".to_string(),
                exit_code: None,
                error: Some("Access Denied".to_string()),
            });
        }

        println!("  {} {}...", "🚀".green(), "Executing".bold().green());

        let command = args.command.clone();
        let output = tokio::task::spawn_blocking(move || {
            if cfg!(target_os = "windows") {
                Command::new("powershell")
                    .arg("-Command")
                    .arg(&command)
                    .output()
            } else {
                Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .output()
            }
        })
        .await
        .map_err(|e| ShellError(format!("Spawn blocking failed: {}", e)))?;

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let exit_code = out.status.code();

                Ok(ShellOutput {
                    stdout,
                    stderr,
                    exit_code,
                    error: None,
                })
            }
            Err(e) => Ok(ShellOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: None,
                error: Some(format!("Failed to execute command: {}", e)),
            }),
        }
    }
}
