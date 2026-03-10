use clap::Parser;
use colored::*;
use dotenvy::dotenv;
use exhume_agent::agent::ExhumeAgent;
use exhume_agent::config::AgentConfig;
use exhume_body::Body;
use rig::message::Message;
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

    println!("{}", "===============================================".blue().bold());
    println!("{}", " 🕵️  Exhume Agent - Autonomous Forensic Assistant".blue().bold());
    println!("{}", "===============================================\n".blue().bold());

    let (target_path, is_folder) = match (args.image, args.folder) {
        (Some(img), None) => (img, false),
        (None, Some(fld)) => (fld, true),
        _ => {
            eprintln!("{}", "Error: You must provide either --image <PATH> or --folder <PATH>".red());
            exit(1);
        }
    };

    println!("{} {}", if is_folder { "Target Folder:".bold() } else { "Target Image:".bold() }, target_path);

    if !is_folder {
        // Verify the image can be opened
        let body_res = std::panic::catch_unwind(|| {
            Body::new(target_path.clone(), "auto")
        });
        
        if body_res.is_err() {
            eprintln!("{}", format!("Error: Failed to open image at {}", target_path).red());
            exit(1);
        }
    } else if !std::path::Path::new(&target_path).is_dir() {
        eprintln!("{}", format!("Error: {} is not a valid directory.", target_path).red());
        exit(1);
    }
    
    // Attempt building config
    let config = AgentConfig::from_environment_or_args(args.provider, args.model, args.endpoint)?;
    
    println!("{} {}", "LLM Provider:".bold(), config.provider);
    println!("{} {}", "LLM Model:".bold(), config.model);

    // Initialize Index
    let pool = match index::init_index(&target_path, is_folder, args.logical).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to initialize or open local index: {}", "Error:".red(), e);
            exit(1);
        }
    };
    println!();

    // Initialize the Agent Wrapper
    let agent = ExhumeAgent::new(config, target_path, std::sync::Arc::new(pool), args.logical);

    println!("{}", "Agent Initialized. Type 'exit' or 'quit' to stop.".green());

    let mut rl = rustyline::DefaultEditor::new()?;
    let mut history = agent.load_history().await.unwrap_or_default();

    if args.new_session && !history.is_empty() {
        println!("{} Clearing {} message(s) from previous session.", "🗑️".yellow(), history.len());
        let _ = agent.clear_history().await;
        history.clear();
    } else if !history.is_empty() {
        println!("{} Loaded {} messages from history.", "ℹ️".blue(), history.len());
    }

    println!("\n{}", "===============================================\n".blue());

    loop {
        let readline = rl.readline(&"User > ".bold().to_string());
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }
                
                if input.eq_ignore_ascii_case("exit") || input.eq_ignore_ascii_case("quit") {
                    println!("Exiting...");
                    break;
                }

                rl.add_history_entry(input)?;
                
                // Add user message to local history and database
                let user_msg = Message::user(input);
                let _ = agent.save_message(&user_msg).await;
                history.push(user_msg);
                
                println!();
                
                // Prompt Agent
                match agent.chat(&history).await {
                    Ok(response) => {
                        println!("{}\n{}\n", "Agent >".magenta().bold(), response);
                        let assistant_msg = Message::assistant(response);
                        let _ = agent.save_message(&assistant_msg).await;
                        history.push(assistant_msg);
                    }
                    Err(e) => {
                        eprintln!("{} {}\n", "Error:".red().bold(), e);
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) | Err(rustyline::error::ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}
