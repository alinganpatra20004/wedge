// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! wedge command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod service;

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
    /// Ask a running server to reload its configuration (through the admin
    /// listener; needs `[server.admin]` with a `token`).
    Reload {
        /// Path to the master configuration file.
        #[arg(short, long, default_value = "wedge.toml")]
        config: PathBuf,
    },
    /// Print the configuration JSON Schema.
    Schema,
    /// Install, remove or run wedge as a Windows service.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
}

#[cfg(windows)]
#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Register the "wedge" service (run from an elevated prompt).
    Install {
        /// Path to the master configuration file.
        #[arg(short, long, default_value = "wedge.toml")]
        config: PathBuf,
    },
    /// Stop and remove the "wedge" service.
    Uninstall,
    /// Entry point used by the Service Control Manager.
    #[command(hide = true)]
    Run {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        log_file: PathBuf,
    },
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
        Command::Reload { config } => reload(&config),
        #[cfg(windows)]
        Command::Service { action } => {
            let result = match action {
                ServiceCommand::Install { config } => service::install(&config),
                ServiceCommand::Uninstall => service::uninstall(),
                ServiceCommand::Run { config, log_file } => service::run(config, log_file),
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
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
    if let Err(e) = init_logging(None) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    serve(config_path, shutdown_signal(), |_, _| {})
}

/// Loads the configuration, binds, and serves until `shutdown` completes.
/// `ready` receives the reloader and the runtime once the server listens.
fn serve(
    config_path: &std::path::Path,
    shutdown: impl std::future::Future<Output = ()>,
    ready: impl FnOnce(wedge_core::Reloader, tokio::runtime::Handle),
) -> ExitCode {
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
        let path = config_path.to_path_buf();
        let server = match wedge_core::Server::bind_reloadable(&config, Some(path)).await {
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
        if let Some(addr) = server.local_admin_addr() {
            tracing::info!(%addr, "admin listener (metrics)");
        }
        #[cfg(unix)]
        tokio::spawn(reload_on_sighup(server.reloader()));
        ready(server.reloader(), tokio::runtime::Handle::current());
        server.run(shutdown).await;
        ExitCode::SUCCESS
    })
}

/// Reloads on every SIGHUP. Errors are logged; the old config keeps serving.
#[cfg(unix)]
async fn reload_on_sighup(reloader: wedge_core::Reloader) {
    use tokio::signal::unix::{signal, SignalKind};
    let Ok(mut hangup) = signal(SignalKind::hangup()) else {
        tracing::warn!("cannot listen for SIGHUP; reload with `wedge reload` instead");
        return;
    };
    while hangup.recv().await.is_some() {
        if let Err(e) = reloader.reload().await {
            tracing::error!(error = %e, "reload failed; still serving the previous configuration");
        }
    }
}

/// Sends `POST /-/reload` to the admin listener named in the config, with
/// its token, and prints the server's answer.
fn reload(config_path: &std::path::Path) -> ExitCode {
    use std::io::{Read, Write};

    let config = match wedge_config::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(admin) = config.server.admin else {
        eprintln!("no [server.admin] section in {}", config_path.display());
        return ExitCode::FAILURE;
    };
    let Some(reference) = admin.token else {
        eprintln!("[server.admin] has no token, so reload over HTTP is off");
        return ExitCode::FAILURE;
    };
    let token = match reference.resolve() {
        Ok(token) => token,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(token) = std::str::from_utf8(token.expose()) else {
        eprintln!("admin token {reference} is not valid UTF-8");
        return ExitCode::FAILURE;
    };
    // A wildcard bind address is reached through loopback.
    let mut addr = admin.listen;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    let timeout = std::time::Duration::from_secs(30);
    let result = std::net::TcpStream::connect_timeout(&addr, timeout).and_then(|mut stream| {
        stream.set_read_timeout(Some(timeout))?;
        let request = format!(
            "POST /-/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes())?;
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        Ok(reply)
    });
    match result {
        Ok(reply) => {
            let ok = reply.starts_with("HTTP/1.1 200");
            let body = reply
                .split_once("\r\n\r\n")
                .map_or("", |(_, b)| b)
                .trim_end();
            if ok {
                println!("{body}");
                ExitCode::SUCCESS
            } else {
                let status = reply.lines().next().unwrap_or("no response");
                eprintln!("{status}\n{body}");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("cannot reach the admin listener at {addr}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Logs to stderr, or appends to `file` (used by the Windows service, which
/// has no console). Filter with RUST_LOG (default info); JSON output with
/// WEDGE_LOG_FORMAT=json. Access lines use target `wedge::access`, so
/// `RUST_LOG=info,wedge::access=off` keeps only the error log.
fn init_logging(file: Option<&std::path::Path>) -> Result<(), String> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json = std::env::var("WEDGE_LOG_FORMAT").is_ok_and(|v| v == "json");
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open log file {}: {e}", path.display()))?;
            let builder = builder
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false);
            if json {
                builder.json().init();
            } else {
                builder.init();
            }
        }
        None => {
            let builder = builder
                .with_writer(std::io::stderr)
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()));
            if json {
                builder.json().init();
            } else {
                builder.init();
            }
        }
    }
    Ok(())
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
