// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! wedge command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod service;
mod setup;

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
    /// Write a starter configuration and create the web folder with a
    /// default page.
    Init {
        /// Configuration file to write.
        #[arg(short, long, default_value = "wedge.toml")]
        config: PathBuf,
        /// Folder the site is served from (created if missing).
        #[arg(long, default_value = "www")]
        web_root: PathBuf,
        /// Port for the website.
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Port for the admin page, metrics and reload (loopback only).
        /// Leave it out to turn the admin listener off.
        #[arg(long)]
        admin_port: Option<u16>,
        /// Listen on every network interface, not only this computer.
        #[arg(long)]
        public: bool,
        /// Replace an existing configuration file (a backup is kept).
        #[arg(long)]
        force: bool,
    },
    /// Manage administrator accounts for the admin page.
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
    /// Install, remove, control or run wedge as a Windows service.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Create an account or change its password. The password is asked for
    /// without echo (or read from one line of standard input) and stored
    /// only as an Argon2id hash.
    SetPassword {
        /// The users file named by `[server.admin] users`.
        #[arg(long, required_unless_present = "config", conflicts_with = "config")]
        users_file: Option<PathBuf>,
        /// Or: the configuration file whose `[server.admin] users` names it.
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Account name.
        #[arg(long, default_value = "admin")]
        user: String,
        /// The password itself. Only for the Windows installer, which runs
        /// this as SYSTEM: on a command line it is visible to the system's
        /// administrators while the command runs.
        #[arg(long, hide = true)]
        password: Option<String>,
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
        /// Folder for wedge.log (default %ProgramData%\wedge\logs).
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Skip the check that only administrators can change wedge.exe and
        /// the folders above it (test setups only: other users may be able
        /// to replace the binary the service runs).
        #[arg(long)]
        allow_unprotected_path: bool,
    },
    /// Stop and remove the "wedge" service.
    Uninstall,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Stop and start the service.
    Restart,
    /// Show whether the service is running.
    Status,
    /// Ask the running service to reload its configuration.
    Reload,
    /// Delete an earlier installation's configuration, web content (only if
    /// wedge created the folder) and logs. Used by the installer.
    #[command(hide = true)]
    Purge {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        web_root: Option<PathBuf>,
        #[arg(long)]
        log_dir: Option<PathBuf>,
    },
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
        Command::Init {
            config,
            web_root,
            port,
            admin_port,
            public,
            force,
        } => report(setup::init(&setup::Init {
            config: &config,
            web_root: &web_root,
            port,
            admin_port,
            public,
            force,
        })),
        Command::Admin {
            action:
                AdminCommand::SetPassword {
                    users_file,
                    config,
                    user,
                    password,
                },
        } => report(
            setup::users_file(users_file, config.as_deref()).and_then(|file| {
                setup::set_password(&file, &user, password.map(zeroize::Zeroizing::new))
            }),
        ),
        #[cfg(windows)]
        Command::Service { action } => report(match action {
            ServiceCommand::Install {
                config,
                log_dir,
                allow_unprotected_path,
            } => service::install(&config, log_dir.as_deref(), allow_unprotected_path),
            ServiceCommand::Uninstall => service::uninstall(),
            ServiceCommand::Start => service::control(service::Control::Start),
            ServiceCommand::Stop => service::control(service::Control::Stop),
            ServiceCommand::Restart => service::control(service::Control::Restart),
            ServiceCommand::Status => service::control(service::Control::Status),
            ServiceCommand::Reload => service::control(service::Control::Reload),
            ServiceCommand::Purge {
                config,
                web_root,
                log_dir,
            } => service::purge(config.as_deref(), web_root.as_deref(), log_dir.as_deref()),
            ServiceCommand::Run { config, log_file } => service::run(config, log_file),
        }),
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

/// Prints an error, if any, and turns it into the exit code.
fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
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
/// has no console). Filter with RUST_LOG (default `info,rustls=error`); JSON
/// output with WEDGE_LOG_FORMAT=json. Access lines use target `wedge::access`,
/// so `RUST_LOG=info,wedge::access=off` keeps only the error log.
fn init_logging(file: Option<&std::path::Path>) -> Result<(), String> {
    // rustls warns about client mistakes (such as an IP address sent as SNI)
    // on every handshake; any client could fill the log with them. wedge logs
    // handshake failures itself at debug level and counts them in metrics.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,rustls=error"));
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
