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

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};

use crate::error::RspassError;

const HELP_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_SHA"), ")");

#[derive(Parser, Debug)]
#[command(
    name = "rspass",
    version = VERSION,
    about = "Minimal age-only secret manager",
    disable_help_subcommand = true,
    styles = HELP_STYLES
)]
struct Cli {
    /// Path to the config file. Overrides the default
    /// `$XDG_CONFIG_HOME/rspass/config.yaml` (or `~/.config/rspass/config.yaml`).
    #[arg(short, long, global = true, value_name = "PATH")]
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
    #[command(visible_alias = "ls")]
    List { prefix: Option<String> },
    /// Print the effective config as YAML (after `include:` resolution).
    Config,
    /// Manage the in-memory identity agent.
    #[command(disable_help_subcommand = true)]
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
    init_tracing();
    match dispatch(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rspass: {e}");
            std::process::ExitCode::from(e.exit_code())
        }
    }
}

fn dispatch(cli: Cli) -> Result<(), RspassError> {
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
        Command::Config => {
            let config = load_config()?;
            cmd::config::run(&config)
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

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
