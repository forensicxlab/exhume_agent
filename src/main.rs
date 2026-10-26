use clap::{CommandFactory, FromArgMatches, Parser};
use colored::*;
use dotenvy::dotenv;
use exhume_agent::agent::ExhumeAgent;
use exhume_agent::config::AgentConfig;
use exhume_agent::paths;
use exhume_agent::policy::{AgentOptions, AgentPolicy};
use exhume_agent::report::{self, ReportMode};
use exhume_agent::session::AgentSession;
use exhume_agent::tui;
use exhume_agent::ui::UiHandle;
use exhume_body::{credentials, Body};
use std::process::exit;

pub mod index;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Account action, without opening any evidence: login, status, refresh, logout, models
    #[arg(long)]
    auth: Option<String>,

    /// Authentication mode: api_key or subscription
    #[arg(long, value_parser = ["api_key", "subscription"])]
    auth_mode: Option<String>,

    /// Connected account identifier
    #[arg(long, env = "AGENT_ACCOUNT_ID")]
    account_id: Option<String>,

    /// Path to the official provider runtime (Claude Code or Vibe)
    #[arg(long, env = "AGENT_RUNTIME_PATH")]
    runtime_path: Option<String>,

    /// Path to the disk image (EWF, raw, etc.)
    #[arg(short, long, conflicts_with = "folder")]
    image: Option<String>,

    /// Path to a local folder to analyze
    #[arg(short, long, conflicts_with = "image")]
    folder: Option<String>,

    /// Model provider (openai, mistral, claude, ollama, or copilot)
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

    /// Allow the agent to request approved host shell commands
    #[arg(long, default_value_t = false)]
    allow_shell: bool,
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

    let matches = password_args(Args::command())
        .mut_arg("password_file", |arg| arg.requires("image"))
        .mut_arg("password_stdin", |arg| arg.requires("image"))
        .get_matches();
    let args = Args::from_arg_matches(&matches)?;
    if let Some(action) = args.auth.as_deref() {
        return account_action(&args, action).await;
    }

    println!(
        "{}",
        "==============================================="
            .blue()
            .bold()
    );
    println!(
        "{}",
        " 🕵️  Exhume Agent - Investigator-led Forensic Assistant"
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

    if !std::path::Path::new(&target_path).exists() {
        anyhow::bail!("Selected evidence source does not exist");
    }

    let body_open_options = std::sync::Arc::new(
        credentials::read_open_options(
            &target_path,
            "auto",
            matches
                .get_one::<String>("password_file")
                .map(String::as_str),
            matches.get_flag("password_stdin"),
        )
        .map_err(anyhow::Error::msg)?,
    );
    if !is_folder {
        // Authenticate before initializing the local case or starting a session.
        Body::open(target_path.clone(), "auto", &body_open_options)?;
    }

    let db_path = args
        .db_path
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| paths::default_db_path(&target_path, is_folder, args.logical));

    println!("{} {}", "Index Database:".bold(), db_path.display());

    // Attempt building config
    let mut config = AgentConfig::from_environment_or_args_with_auth(
        args.provider,
        args.model,
        args.endpoint,
        args.auth_mode.as_deref().map(|mode| {
            if mode == "subscription" {
                exhume_agent::auth::AuthMode::Subscription
            } else {
                exhume_agent::auth::AuthMode::ApiKey
            }
        }),
    )?;
    if args.account_id.is_some() {
        config.account_id = args.account_id;
    }
    if args.runtime_path.is_some() {
        config.runtime_path = args.runtime_path;
    }

    println!("{} {}", "LLM Provider:".bold(), config.provider);
    println!("{} {}", "LLM Model:".bold(), config.model);

    let provider = config.provider.clone();
    let model = config.model.clone();

    // Initialize Index
    let pool = match index::open_investigation_index(
        &target_path,
        &db_path,
        is_folder,
        args.logical,
    )
    .await
    {
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
    let evidence_id = report::current_evidence_id(pool.as_ref())
        .await
        .unwrap_or(1);
    let policy = AgentPolicy {
        allow_shell: args.allow_shell,
        shell_working_dir: Some(paths::extraction_dir_for_db(&db_path)),
        ..AgentPolicy::default()
    };
    let options = AgentOptions {
        session_id: "default".to_string(),
        evidence_id,
        policy: policy.clone(),
    };

    let agent_probe = ExhumeAgent::new_with_options(
        config.clone(),
        target_path.clone(),
        db_path.clone(),
        pool.clone(),
        args.logical,
        false,
        None,
        options.clone(),
    )
    .with_body_open_options(body_open_options.clone());
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

    let (ui, ui_rx) = UiHandle::channel_with_context("default", evidence_id, 512);
    let agent = ExhumeAgent::new_with_options(
        config,
        target_path.clone(),
        db_path,
        pool.clone(),
        args.logical,
        true,
        Some(ui),
        options,
    )
    .with_body_open_options(body_open_options);
    let session = AgentSession::open(agent).await?;
    let report_mode = ReportMode {
        enabled: true,
        export_path: session.investigation_snapshot().await?.report_path,
    };
    println!(
        "Automatic Markdown report: {}",
        report_mode.export_path.display()
    );

    println!(
        "{}",
        "Describe the case objective to prepare the first proposal. /help lists investigator commands. Type 'exit' to quit.".green()
    );
    println!(
        "\n{}",
        "===============================================\n".blue()
    );

    tui::run(
        session,
        pool,
        report_mode,
        ui_rx,
        target_path,
        provider,
        model,
    )
    .await?;

    Ok(())
}

async fn account_action(args: &Args, action: &str) -> anyhow::Result<()> {
    use exhume_agent::{auth, providers::runtimes};
    let provider = args
        .provider
        .clone()
        .or_else(|| std::env::var("AGENT_PROVIDER").ok())
        .unwrap_or_else(|| "openai".into());
    let config = AgentConfig {
        provider: provider.clone(),
        model: args.model.clone().unwrap_or_default(),
        endpoint: String::new(),
        api_key: String::new(),
        auth_mode: auth::AuthMode::Subscription,
        account_id: args.account_id.clone(),
        runtime_path: args.runtime_path.clone(),
        llm_endpoint: None,
        image_endpoint: None,
        audio_endpoint: None,
    };
    match (provider.as_str(), action) {
        ("openai", "login") => {
            let pending = auth::begin_chatgpt_sign_in(args.account_id.as_deref()).await?;
            open_browser(&pending.authorization_url)?;
            println!("Complete Sign in with ChatGPT in your browser.");
            println!(
                "{}",
                serde_json::to_string_pretty(&pending.complete().await?)?
            );
        }
        ("openai" | "mistral", "status") => println!(
            "{}",
            serde_json::to_string_pretty(&auth::account_status()?)?
        ),
        ("openai" | "mistral", "refresh") => println!(
            "{}",
            serde_json::to_string_pretty(&auth::refresh_account_status().await?)?
        ),
        ("openai", "logout") => {
            let id = args
                .account_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Select --account-id to disconnect"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&auth::disconnect_chatgpt(id).await?)?
            );
        }
        ("mistral", "logout") => {
            let id = args
                .account_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Select --account-id to disconnect"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&auth::disconnect_mistral(id)?)?
            );
        }
        ("mistral", "models") => {
            let id = args
                .account_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Select --account-id"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&auth::mistral_models(id).await?)?
            );
        }
        ("openai", "models") => {
            let id = args
                .account_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Select --account-id"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&auth::chatgpt_models(id).await?)?
            );
        }
        ("claude" | "anthropic" | "mistral", "login" | "logout") => {
            let operation = if action == "login" {
                runtimes::RuntimeAuthAction::Login
            } else {
                runtimes::RuntimeAuthAction::Logout
            };
            let status = runtimes::native_auth_command(&config, operation)?
                .status()
                .await?;
            if !status.success() {
                anyhow::bail!("Official runtime account action did not succeed");
            }
            if provider == "mistral" && action == "login" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &auth::import_mistral_runtime_credentials(
                            args.account_id.as_deref().unwrap_or("mistral-default")
                        )
                        .await?
                    )?
                );
            }
        }
        ("claude" | "anthropic", "status") => println!(
            "{}",
            serde_json::to_string_pretty(&runtimes::native_account_status(&config).await?)?
        ),
        _ => anyhow::bail!("Unsupported account action/provider combination"),
    }
    Ok(())
}

fn open_browser(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    let status = command.arg(url).status()?;
    if !status.success() {
        anyhow::bail!("Could not open the system browser");
    }
    Ok(())
}

/// Register this executable's mutually exclusive container-password sources.
fn password_args(command: clap::Command) -> clap::Command {
    command
        .arg(
            clap::Arg::new("password_file")
                .long("password-file")
                .global(true)
                .value_name("PATH")
                .conflicts_with("password_stdin")
                .help("Read the image container password from a file; remove one trailing line ending."),
        )
        .arg(
            clap::Arg::new("password_stdin")
                .long("password-stdin")
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help("Read the image container password from stdin; remove one trailing line ending."),
        )
}
