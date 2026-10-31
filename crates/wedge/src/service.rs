// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Windows service: install, uninstall, and the entry point the Service
//! Control Manager starts (threat model T5.7, T5.8).
//!
//! The service runs as the virtual account `NT SERVICE\wedge`, not as
//! LocalSystem. Stop and shutdown stop the server gracefully; the
//! "parameter change" control (`sc control wedge paramchange`) reloads the
//! configuration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "wedge";
const ACCOUNT: &str = r"NT SERVICE\wedge";

/// The arguments the Service Control Manager starts wedge with.
pub(crate) fn launch_arguments(config: &Path, log_file: &Path) -> Vec<OsString> {
    vec![
        "service".into(),
        "run".into(),
        "--config".into(),
        config.as_os_str().to_owned(),
        "--log-file".into(),
        log_file.as_os_str().to_owned(),
    ]
}

/// `%ProgramData%\wedge\logs`.
fn log_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("wedge").join("logs")
}

/// Registers the service (needs an elevated prompt).
pub(crate) fn install(config: &Path) -> Result<(), String> {
    let config = std::path::absolute(config).map_err(|e| format!("{}: {e}", config.display()))?;
    wedge_config::load(&config).map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let logs = log_dir();
    std::fs::create_dir_all(&logs).map_err(|e| format!("{}: {e}", logs.display()))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("cannot open the service manager (run as Administrator): {e}"))?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "wedge web server".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: launch_arguments(&config, &logs.join("wedge.log")),
        dependencies: vec![],
        account_name: Some(ACCOUNT.into()),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("cannot create the service: {e}"))?;
    let _ = service.set_description("wedge web and application server");
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    let _ = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    });
    // T5.8: the account may write its logs and read the config, nothing more.
    let config_dir = config.parent().unwrap_or(Path::new("."));
    grant(&logs, "(OI)(CI)M")?;
    grant(config_dir, "(OI)(CI)RX")?;
    println!("installed service {NAME:?} running as {ACCOUNT}");
    println!("config: {}", config.display());
    println!("log:    {}", logs.join("wedge.log").display());
    println!("start it with: Start-Service {NAME}");
    Ok(())
}

/// Gives the service account `rights` on `path` with icacls.
fn grant(path: &Path, rights: &str) -> Result<(), String> {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg(format!("{ACCOUNT}:{rights}"))
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("icacls: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls could not grant {rights} on {}",
            path.display()
        ))
    }
}

/// Stops (if running) and removes the service.
pub(crate) fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("cannot open the service manager (run as Administrator): {e}"))?;
    let service = manager
        .open_service(
            NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| format!("cannot open service {NAME:?}: {e}"))?;
    if service
        .query_status()
        .is_ok_and(|s| s.current_state != ServiceState::Stopped)
    {
        let _ = service.stop();
    }
    service
        .delete()
        .map_err(|e| format!("cannot delete the service: {e}"))?;
    println!(
        "removed service {NAME:?}; logs remain in {}",
        log_dir().display()
    );
    Ok(())
}

/// Config and log paths for the service entry point, set before the
/// dispatcher starts.
static PATHS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
/// The running server's reloader, for the parameter-change control.
static READY: OnceLock<(wedge_core::Reloader, tokio::runtime::Handle)> = OnceLock::new();

/// Connects to the Service Control Manager and runs until it stops us.
pub(crate) fn run(config: PathBuf, log_file: PathBuf) -> Result<(), String> {
    let _ = PATHS.set((config, log_file));
    service_dispatcher::start(NAME, ffi_service_main)
        .map_err(|e| format!("not started by the Service Control Manager: {e}"))
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let Some((config, log_file)) = PATHS.get() else {
        return;
    };
    if crate::init_logging(Some(log_file)).is_err() {
        return;
    }
    if let Err(e) = run_service(config) {
        tracing::error!("{e}");
    }
}

fn run_service(config: &Path) -> Result<(), windows_service::Error> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().ok().and_then(|mut tx| tx.take()) {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::ParamChange => {
            if let Some((reloader, runtime)) = READY.get() {
                let reloader = reloader.clone();
                runtime.spawn(async move {
                    if let Err(e) = reloader.reload().await {
                        tracing::error!(error = %e, "reload failed; still serving the previous configuration");
                    }
                });
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state, accept, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
    };
    set(ServiceState::StartPending, ServiceControlAccept::empty(), 0)?;
    let code = crate::serve(
        config,
        async {
            let _ = stop_rx.await;
        },
        |reloader, runtime| {
            let _ = READY.set((reloader, runtime));
            let accept = ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PARAM_CHANGE;
            if let Err(e) = set(ServiceState::Running, accept, 0) {
                tracing::error!(error = %e, "cannot report the running state");
            }
        },
    );
    // ERROR_SERVICE_SPECIFIC_ERROR-style failure is reported as code 1.
    let failed = code != std::process::ExitCode::SUCCESS;
    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        u32::from(failed),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_arguments_name_config_and_log() {
        let args = launch_arguments(
            Path::new(r"C:\wedge\wedge.toml"),
            Path::new(r"C:\logs\w.log"),
        );
        let args: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "service",
                "run",
                "--config",
                r"C:\wedge\wedge.toml",
                "--log-file",
                r"C:\logs\w.log"
            ]
        );
    }
}
