mod agent;
mod cmd;
mod config;
mod crypto;
mod decrypt;
mod error;
mod identity;
mod path;
mod recipients;
mod tty;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::error::RspassError;

#[derive(Parser, Debug)]
#[command(name = "rspass", version, about = "Minimal age-only secret manager")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to the config file. Overrides the default
    /// `$XDG_CONFIG_HOME/rspass/config.yaml` (or `~/.config/rspass/config.yaml`).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Decrypt a secret and print it to stdout.
    Show { path: String },
    /// Decrypt, edit, and re-encrypt a secret.
    Edit { path: String },
    /// List secrets as a tree (gopass-style).
    #[command(alias = "ls")]
    List { prefix: Option<String> },
    /// Manage the in-memory identity agent.
    Agent {
        #[command(subcommand)]
        op: cmd::agent::Op,
    },
    /// Internal: agent daemon entry point.
    #[command(name = "__agent-daemon", hide = true)]
    AgentDaemon,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match dispatch(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rspass: {e}");
            std::process::ExitCode::from(e.exit_code())
        }
    }
}

fn dispatch(cli: Cli) -> Result<(), RspassError> {
    tracing::debug!("dispatch: {:?}", cli.command);
    let config_path = cli.config;
    let load_config = || match &config_path {
        Some(p) => config::Config::load_from(p),
        None => config::Config::load(),
    };
    match cli.command {
        Command::Show { path } => {
            let config = load_config()?;
            cmd::show::run(&config, &path)
        }
        Command::Edit { path } => {
            let config = load_config()?;
            cmd::edit::run(&config, &path)
        }
        Command::List { prefix } => {
            let config = load_config()?;
            cmd::list::run(&config, prefix.as_deref())
        }
        Command::Agent { op } => {
            let config = load_config()?;
            cmd::agent::run(&config, op)
        }
        Command::AgentDaemon => {
            agent::server::run().map_err(|e| {
                // Daemon errors come from pre-accept-loop setup; map to the
                // generic CLI error → exit 1.
                RspassError::Io(std::io::Error::other(e.to_string()))
            })
        }
    }
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "warn" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
