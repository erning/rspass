// Modules below are exercised by unit tests now and consumed by the
// command handlers in later steps; the dead-code allow will be removed
// once `show` / `edit` are wired up.
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod path;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rspass", version, about = "Minimal age-only secret manager")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Decrypt a secret and print it to stdout.
    Show { path: String },
    /// Decrypt, edit, and re-encrypt a secret.
    Edit { path: String },
    /// Manage the in-memory identity agent.
    Agent {
        #[command(subcommand)]
        op: AgentOp,
    },
    /// Internal: agent daemon entry point.
    #[command(name = "__agent-daemon", hide = true)]
    AgentDaemon,
}

#[derive(Subcommand, Debug)]
enum AgentOp {
    Start,
    Stop,
    Status,
    Ls,
    Add { path: Option<String> },
    Rm { path: String },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match cli.command {
        Command::Show { .. } => todo!("show is implemented in step 3"),
        Command::Edit { .. } => todo!("edit is implemented in step 5"),
        Command::Agent { .. } => todo!("agent cli is implemented in step 7"),
        Command::AgentDaemon => todo!("agent daemon is implemented in step 6"),
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
