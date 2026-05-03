use crate::agent::ExhumeAgent;
use crate::report::ReportMode;
use crate::ui::{ApprovalRequest, UiEvent};
use anyhow::Result;
use colored::Colorize;
use rig::message::Message;
use sqlx::SqlitePool;
use std::{
    io::Write,
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

pub async fn run(
    agent: ExhumeAgent,
    _pool: Arc<SqlitePool>,
    report_mode: ReportMode,
    mut ui_rx: mpsc::UnboundedReceiver<UiEvent>,
) -> Result<()> {
    // Replay persisted history
    let mut history = agent.load_history().await.unwrap_or_default();
    for msg in &history {
        print_message(msg);
    }

    if report_mode.enabled {
        println!(
            "  {} Report will be written to: {}\n",
            "📄".cyan(),
            report_mode.export_path.display()
        );
    }

    loop {
        // Drain stale events between turns (e.g. leftover log lines)
        drain_logs(&mut ui_rx);

        print!("{} ", ">>>".bold().yellow());
        std::io::stdout().flush()?;

        let mut raw = String::new();
        if std::io::stdin().read_line(&mut raw)? == 0 {
            // EOF — exit cleanly
            break;
        }
        let input = raw.trim().to_string();

        if input.is_empty() {
            continue;
        }
        if input.eq_ignore_ascii_case("exit") || input.eq_ignore_ascii_case("quit") {
            break;
        }

        // Persist and display the user turn
        let user_msg = Message::user(input.clone());
        agent.save_message(&user_msg).await?;
        history.push(user_msg);
        println!();
        print_labeled(" USER ", &input, Color::BrightBlue);

        // Spawn the agent in the background
        let (tx, rx) = oneshot::channel::<Result<String, String>>();
        let history_snap = history.clone();
        let agent_bg = agent.clone();
        tokio::spawn(async move {
            let result = match agent_bg.chat(&history_snap).await {
                Ok(text) => match agent_bg.save_message(&Message::assistant(text.clone())).await {
                    Ok(_) => Ok(text),
                    Err(e) => Err(e.to_string()),
                },
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(result);
        });

        // Drive the waiting loop: stream logs and handle approval while the agent runs
        let response = wait_for_turn(rx, &mut ui_rx).await;

        match response {
            Ok(text) => {
                history.push(Message::assistant(text.clone()));
                print_labeled(" ASSISTANT ", &text, Color::BrightGreen);
            }
            Err(e) => {
                print_labeled(" ERROR ", &e, Color::Red);
            }
        }
    }

    Ok(())
}

/// Poll the oneshot receiver while forwarding log and approval events from the UI channel.
async fn wait_for_turn(
    mut rx: oneshot::Receiver<Result<String, String>>,
    ui_rx: &mut mpsc::UnboundedReceiver<UiEvent>,
) -> Result<String, String> {
    loop {
        // Drain UI events first so logs appear promptly
        loop {
            match ui_rx.try_recv() {
                Ok(UiEvent::Log(line)) => {
                    println!("  {} {}", "⚙".cyan(), line.dimmed());
                }
                Ok(UiEvent::ApprovalRequest(req)) => {
                    handle_approval(req);
                }
                Ok(UiEvent::ReportUpdated) => {} // written to disk; nothing to render
                Err(_) => break,
            }
        }

        // Check if the agent finished
        match rx.try_recv() {
            Ok(result) => return result,
            Err(oneshot::error::TryRecvError::Closed) => {
                return Err("Agent task closed unexpectedly.".to_string());
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;
    }
}

/// Print a y/N approval prompt and send the user's answer back to the waiting tool.
/// Blocking stdin read is safe here: the agent task is suspended waiting for the oneshot,
/// and the Tokio multi-thread runtime keeps other tasks running on separate threads.
fn handle_approval(req: ApprovalRequest) {
    println!(
        "\n  {} {}",
        " APPROVAL REQUIRED ".black().on_red().bold(),
        req.prompt
    );
    print!("  Allow? [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    let approved = std::io::stdin()
        .read_line(&mut input)
        .map(|_| matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
        .unwrap_or(false);
    let _ = req.responder.send(approved);
    if approved {
        println!("  {}", "Approved.".green());
    } else {
        println!("  {}", "Denied.".red());
    }
    println!();
}

fn drain_logs(ui_rx: &mut mpsc::UnboundedReceiver<UiEvent>) {
    while let Ok(UiEvent::Log(line)) = ui_rx.try_recv() {
        println!("  {} {}", "⚙".cyan(), line.dimmed());
    }
}

// ── Rendering helpers ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Color {
    BrightBlue,
    BrightGreen,
    Red,
}

fn print_labeled(label: &str, body: &str, color: Color) {
    let styled = match color {
        Color::BrightBlue => label.black().on_bright_blue().bold().to_string(),
        Color::BrightGreen => label.black().on_bright_green().bold().to_string(),
        Color::Red => label.black().on_red().bold().to_string(),
    };
    println!("{}", styled);
    for line in body.lines() {
        println!("{}", line);
    }
    println!();
}

fn print_message(msg: &Message) {
    match msg {
        Message::User { .. } => print_labeled(" USER ", &extract_text(msg), Color::BrightBlue),
        Message::Assistant { .. } => {
            print_labeled(" ASSISTANT ", &extract_text(msg), Color::BrightGreen)
        }
    }
}

fn extract_text(message: &Message) -> String {
    let value = serde_json::to_value(message).unwrap_or_default();
    let mut chunks = Vec::new();
    collect_text(&value, &mut chunks);
    if chunks.is_empty() {
        value.to_string()
    } else {
        chunks.join("\n")
    }
}

fn collect_text(value: &serde_json::Value, chunks: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            if !text.trim().is_empty() {
                chunks.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_text(item, chunks);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(|v| v.as_str()) {
                if !text.trim().is_empty() {
                    chunks.push(text.to_string());
                }
            } else {
                for v in map.values() {
                    collect_text(v, chunks);
                }
            }
        }
        _ => {}
    }
}
