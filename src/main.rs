use clap::Parser;
use colored::*;
use dotenvy::dotenv;
use exhume_agent::agent::ExhumeAgent;
use exhume_agent::config::AgentConfig;
use exhume_agent::paths;
use exhume_agent::report::{self, ReportMode};
use exhume_agent::tui;
use exhume_agent::ui::UiHandle;
use exhume_body::Body;
use std::io::Write;
use std::process::exit;

pub mod index;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the disk image (EWF, raw, etc.)
    #[arg(short, long, conflicts_with = "folder")]
    image: Option<String>,

    /// Path to a local folder to analyze
    #[arg(short, long, conflicts_with = "image")]
    folder: Option<String>,

    /// LLM Provider (openai, ollama, anthropic, etc.)
    #[arg(short, long, env = "AGENT_PROVIDER")]
    provider: Option<String>,

    /// The specific model to use (e.g., gpt-4o, llama3)
    #[arg(short, long, env = "AGENT_MODEL")]
    model: Option<String>,

    /// API base endpoint (mostly for Ollama or OpenAI compatible proxies)
    #[arg(short, long, env = "AGENT_ENDPOINT")]
    endpoint: Option<String>,

    /// Treat the image as a single logical volume (no partition discovery)
    #[arg(short, long)]
    logical: bool,

    /// Override the default SQLite index database location
    #[arg(long, env = "EXHUME_DB_PATH")]
    db_path: Option<String>,

    /// Start a fresh conversation (clears chat history from the database)
    #[arg(short = 'n', long)]
    new_session: bool,
}

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if it exists
    dotenv().ok();

    // Initialize tracing to see rig's background actions (tools, prompts, etc)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();

    println!(
        "{}",
        "==============================================="
            .blue()
            .bold()
    );
    println!(
        "{}",
        " 🕵️  Exhume Agent - Autonomous Forensic Assistant"
            .blue()
            .bold()
    );
    println!(
        "{}",
        "===============================================\n"
            .blue()
            .bold()
    );

    let (target_path, is_folder) = match (args.image, args.folder) {
        (Some(img), None) => (img, false),
        (None, Some(fld)) => (fld, true),
        _ => {
            eprintln!(
                "{}",
                "Error: You must provide either --image <PATH> or --folder <PATH>".red()
            );
            exit(1);
        }
    };

    println!(
        "{} {}",
        if is_folder {
            "Target Folder:".bold()
        } else {
            "Target Image:".bold()
        },
        target_path
    );

    if !is_folder {
        // Verify the image can be opened
        let body_res = std::panic::catch_unwind(|| Body::new(target_path.clone(), "auto"));

        if body_res.is_err() {
            eprintln!(
                "{}",
                format!("Error: Failed to open image at {}", target_path).red()
            );
            exit(1);
        }
    } else if !std::path::Path::new(&target_path).is_dir() {
        eprintln!(
            "{}",
            format!("Error: {} is not a valid directory.", target_path).red()
        );
        exit(1);
    }

    let db_path = args
        .db_path
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| paths::default_db_path(&target_path, is_folder, args.logical));

    println!("{} {}", "Index Database:".bold(), db_path.display());

    // Attempt building config
    let config = AgentConfig::from_environment_or_args(args.provider, args.model, args.endpoint)?;

    println!("{} {}", "LLM Provider:".bold(), config.provider);
    println!("{} {}", "LLM Model:".bold(), config.model);

    // Initialize Index
    let pool = match index::init_index(&target_path, &db_path, is_folder, args.logical).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "{} Failed to initialize or open local index: {}",
                "Error:".red(),
                e
            );
            exit(1);
        }
    };
    println!();

    let pool = std::sync::Arc::new(pool);

    let agent_probe = ExhumeAgent::new(
        config.clone(),
        target_path.clone(),
        db_path.clone(),
        pool.clone(),
        args.logical,
        false,
        None,
    );
    let mut existing_messages = agent_probe.load_history().await.unwrap_or_default();

    if args.new_session && !existing_messages.is_empty() {
        println!(
            "{} Clearing {} message(s) from previous session.",
            "🗑️".yellow(),
            existing_messages.len()
        );
        let _ = agent_probe.clear_history().await;
        existing_messages.clear();
    } else if !existing_messages.is_empty() {
        println!(
            "{} Loaded {} messages from history.",
            "ℹ️".blue(),
            existing_messages.len()
        );
    }

    let report_mode = prompt_report_mode(
        &target_path,
        &db_path,
        is_folder,
        args.logical,
        pool.as_ref(),
    )
    .await?;

    let (ui, ui_rx) = UiHandle::channel();
    let agent = ExhumeAgent::new(
        config,
        target_path.clone(),
        db_path,
        pool.clone(),
        args.logical,
        report_mode.enabled,
        Some(ui),
    );

    println!(
        "{}",
        "Type your investigation query and press Enter. Type 'exit' to quit.".green()
    );
    println!(
        "\n{}",
        "===============================================\n".blue()
    );

    tui::run(agent, pool, report_mode, ui_rx).await?;

    Ok(())
}

async fn prompt_report_mode(
    target_path: &str,
    db_path: &std::path::Path,
    is_folder: bool,
    is_logical: bool,
    pool: &sqlx::SqlitePool,
) -> anyhow::Result<ReportMode> {
    let default_export_path =
        report::default_export_path(db_path, target_path, is_folder, is_logical);
    print!(
        "{} Start a persisted Digital Forensics Report now? [r]eport / [b]rowse only (default: b): ",
        "Prompt:".cyan().bold()
    );
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let wants_report = matches!(input.trim().to_ascii_lowercase().as_str(), "r" | "report");

    if wants_report {
        let mode =
            report::initialize_report(pool, db_path, target_path, is_folder, is_logical).await?;
        println!(
            "{} Report initialized and exported to {}",
            "Info:".yellow(),
            mode.export_path.display()
        );
        Ok(mode)
    } else {
        println!(
            "{} Browse-only mode selected. Reporting is disabled for this session.",
            "Info:".yellow()
        );
        Ok(ReportMode {
            enabled: false,
            export_path: default_export_path,
        })
    }
}
