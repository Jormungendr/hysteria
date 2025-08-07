use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod client;
mod server;
mod config;

#[derive(Parser)]
#[command(name = "hysteria")]
#[command(about = "Hysteria 2 - A feature-packed proxy & relay tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as client
    Client {
        /// Configuration file path
        #[arg(short, long)]
        config: String,
    },
    /// Run as server
    Server {
        /// Configuration file path
        #[arg(short, long)]
        config: String,
    },
    /// Generate sample configuration
    GenConfig {
        /// Output file path
        #[arg(short, long, default_value = "config.yaml")]
        output: String,
        
        /// Configuration type (client or server)
        #[arg(short, long, default_value = "client")]
        r#type: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;
    
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(&cli.log_level, cli.verbose)?;
    
    info!("Starting Hysteria 2 CLI");
    
    match cli.command {
        Commands::Client { config } => {
            info!("Starting client with config: {}", config);
            client::run(config).await
        }
        Commands::Server { config } => {
            info!("Starting server with config: {}", config);
            server::run(config).await
        }
        Commands::GenConfig { output, r#type } => {
            info!("Generating {} configuration to: {}", r#type, output);
            config::generate_config(&output, &r#type).await
        }
    }
}

fn init_logging(level: &str, verbose: bool) -> Result<()> {
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new(level)
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))?;
    
    Ok(())
}