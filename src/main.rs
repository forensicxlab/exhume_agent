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
    #[arg(short, long)]
    image: Option<String>,

    /// LLM Provider (openai, ollama, anthropic, etc.)
    #[arg(short, long, env = "AGENT_PROVIDER")]
    provider: Option<String>,

    /// The specific model to use (e.g., gpt-4o, llama3)
    #[arg(short, long, env = "AGENT_MODEL")]
    model: Option<String>,

    /// API base endpoint (mostly for Ollama or OpenAI compatible proxies)
    #[arg(short, long, env = "AGENT_ENDPOINT")]
    endpoint: Option<String>,
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

    let image_path = match args.image {
        Some(path) => path,
        None => {
            eprintln!("{}", "Error: No disk image provided. Use --image <PATH>".red());
            exit(1);
        }
    };

    println!("{} {}", "Target Image:".bold(), image_path);

    // Verify the image can be opened
    let body_res = std::panic::catch_unwind(|| {
        Body::new(image_path.clone(), "auto")
    });
    
    if body_res.is_err() {
        eprintln!("{}", format!("Error: Failed to open image at {}", image_path).red());
        exit(1);
    }
    
    // Attempt building config
    let config = AgentConfig::from_environment_or_args(args.provider, args.model, args.endpoint)?;
    
    println!("{} {}", "LLM Provider:".bold(), config.provider);
    println!("{} {}", "LLM Model:".bold(), config.model);

    // Initialize Index
    let pool = match index::init_index(&image_path).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to initialize or open local index: {}", "Error:".red(), e);
            exit(1);
        }
    };
    println!();

    // Initialize the Agent Wrapper
    let agent = ExhumeAgent::new(config, image_path, std::sync::Arc::new(pool));

    println!("{}", "Agent Initialized. Type 'exit' or 'quit' to stop.".green());

    let mut rl = rustyline::DefaultEditor::new()?;
    let mut history: Vec<Message> = Vec::new();

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
                
                // Add user message to local history (or the agent could manage it entirely)
                let user_msg = Message::user(input);
                history.push(user_msg);
                
                println!();
                
                // Prompt Agent
                match agent.chat(&history).await {
                    Ok(response) => {
                        println!("{}\n{}\n", "Agent >".magenta().bold(), response);
                        history.push(Message::assistant(response));
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
