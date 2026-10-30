// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! wedge command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// wedge: web and application server.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the server.
    Run {
        /// Path to the master configuration file.
        #[arg(short, long, default_value = "wedge.toml")]
        config: PathBuf,
    },
    /// Load and validate the configuration, then exit.
    CheckConfig {
        /// Path to the master configuration file.
        #[arg(short, long, default_value = "wedge.toml")]
        config: PathBuf,
    },
    /// Print the configuration JSON Schema.
    Schema,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run { config } => run(&config),
        Command::CheckConfig { config } => match wedge_config::load(&config) {
            Ok(cfg) => {
                println!(
                    "{}: OK ({} listener(s), {} TLS listener(s), {} vhost(s))",
                    config.display(),
                    cfg.server.listen.len(),
                    cfg.server.listen_tls.len(),
                    cfg.vhost.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Command::Schema => {
            let schema = wedge_config::json_schema();
            match serde_json::to_string_pretty(&schema) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cannot render schema: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Loads the configuration and serves until SIGINT or SIGTERM (Ctrl+C on Windows).
fn run(config_path: &std::path::Path) -> ExitCode {
    init_logging();
    let config = match wedge_config::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start async runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let server = match wedge_core::Server::bind(&config).await {
            Ok(server) => server,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::FAILURE;
            }
        };
        for addr in server.local_addrs() {
            tracing::info!(%addr, "listening");
        }
        for addr in server.local_tls_addrs() {
            tracing::info!(%addr, "listening (TLS)");
        }
        server.run(shutdown_signal()).await;
        ExitCode::SUCCESS
    })
}

/// Logs to stderr. Filter with RUST_LOG (default info); JSON output with
/// WEDGE_LOG_FORMAT=json. Access lines use target `wedge::access`, so
/// `RUST_LOG=info,wedge::access=off` keeps only the error log.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    if std::env::var("WEDGE_LOG_FORMAT").is_ok_and(|v| v == "json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
