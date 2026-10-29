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
        Command::CheckConfig { config } => match wedge_config::load(&config) {
            Ok(cfg) => {
                println!(
                    "{}: OK ({} listener(s), {} vhost(s))",
                    config.display(),
                    cfg.server.listen.len(),
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
