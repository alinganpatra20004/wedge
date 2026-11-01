// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Windows service: install, uninstall, control, and the entry point the
//! Service Control Manager starts (threat model T5.7, T5.8, T6.7).
//!
//! The service runs as the virtual account `NT SERVICE\wedge`, not as
//! LocalSystem. Stop and shutdown stop the server gracefully; the
//! "parameter change" control (`wedge service reload`) reloads the
//! configuration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType, UserEventCode,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::acl;

const NAME: &str = "wedge";
const ACCOUNT: &str = r"NT SERVICE\wedge";
/// The user-defined control `wedge service reload` sends (the standard
/// parameter-change control, as `sc.exe control wedge paramchange` sends
/// it, reloads too; the service API only lets programs send codes 128-255).
const RELOAD_EVENT: u32 = 128;

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

/// `%ProgramData%\wedge\logs`, the log folder when none is given.
fn default_log_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("wedge").join("logs")
}

/// The running binary, in the ordinary `C:\...` form the Service Control
/// Manager starts reliably (canonicalize gives `\\?\C:\...`).
fn own_exe() -> Result<PathBuf, String> {
    // Used only as the path to register and to check: the administrator
    // chose to run this binary, and acl::check rejects user-writable places.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = std::fs::canonicalize(&exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    Ok(PathBuf::from(
        exe.as_os_str()
            .to_string_lossy()
            .trim_start_matches(r"\\?\"),
    ))
}

/// Registers the service (needs an elevated prompt). Unless
/// `allow_unprotected` is set, wedge.exe, its folder and every folder above
/// must be safe from ordinary users: a service whose executable (or a DLL
/// beside it) they can replace runs their code (binary planting, T6.7).
pub(crate) fn install(
    config: &Path,
    log_dir: Option<&Path>,
    allow_unprotected: bool,
) -> Result<(), String> {
    let config = std::path::absolute(config).map_err(|e| format!("{}: {e}", config.display()))?;
    let loaded = wedge_config::load(&config).map_err(|e| e.to_string())?;
    let exe = own_exe()?;
    if !allow_unprotected {
        acl::check(&exe).map_err(|e| {
            format!(
                "{e}\nInstall wedge.exe in a folder only administrators can change (the \
                 installer locks the folder it installs to), or pass \
                 --allow-unprotected-path for a test setup."
            )
        })?;
    }
    let logs = match log_dir {
        Some(dir) => std::path::absolute(dir).map_err(|e| e.to_string())?,
        None => default_log_dir(),
    };
    std::fs::create_dir_all(&logs).map_err(|e| format!("{}: {e}", logs.display()))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("cannot open the service manager (run as Administrator): {e}"))?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "wEdge web server".into(),
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
    let _ = service.set_description("wEdge web and application server");
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
    // T5.8: the account may write its logs and read its configuration and
    // sites, nothing more.
    let config_dir = config.parent().unwrap_or(Path::new("."));
    grant(&logs, "(OI)(CI)M")?;
    grant(config_dir, "(OI)(CI)RX")?;
    for root in loaded.vhost.iter().filter_map(|v| v.root.as_deref()) {
        if root.exists() {
            grant(root, "(OI)(CI)RX")?;
        }
    }
    if let Some(wedge_config::SecretRef::File(users)) =
        loaded.server.admin.as_ref().and_then(|a| a.users.as_ref())
    {
        if users.exists() {
            restrict_to_admins(users, true)?;
        }
    }
    println!("installed service {NAME:?} running as {ACCOUNT}");
    println!("config: {}", config.display());
    println!("log:    {}", logs.join("wedge.log").display());
    println!("start it with: wedge service start");
    Ok(())
}

/// Gives the service account `rights` on `path` with icacls.
fn grant(path: &Path, rights: &str) -> Result<(), String> {
    icacls(path, &["/grant", &format!("{ACCOUNT}:{rights}")])
}

/// Makes `path` readable and writable only by SYSTEM, Administrators and
/// its owner, plus read access for the service account when `service` is
/// set and the service exists. For the admin users file (T5.13).
pub(crate) fn restrict_to_admins(path: &Path, service: bool) -> Result<(), String> {
    // SIDs, not names: names are localized on non-English Windows.
    icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            "*S-1-3-4:F",
        ],
    )?;
    if service {
        // Fails until the service exists; `service install` grants it then.
        let _ = icacls(path, &["/grant", &format!("{ACCOUNT}:R")]);
    }
    Ok(())
}

fn icacls(path: &Path, args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new(system32("icacls.exe"))
        .arg(path)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("icacls: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls {} failed on {}",
            args.join(" "),
            path.display()
        ))
    }
}

/// A program in System32, by full path, so the search path cannot swap it.
pub(crate) fn system32(program: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(program)
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
        wait_for(&service, ServiceState::Stopped);
    }
    service
        .delete()
        .map_err(|e| format!("cannot delete the service: {e}"))?;
    println!("removed service {NAME:?}; configuration, sites and logs are kept");
    Ok(())
}

/// What `wedge service <control>` does.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Control {
    Start,
    Stop,
    Restart,
    Status,
    Reload,
}

/// Starts, stops, restarts, reloads or reports the service.
pub(crate) fn control(what: Control) -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("cannot open the service manager: {e}"))?;
    let access = match what {
        Control::Status => ServiceAccess::QUERY_STATUS,
        _ => {
            ServiceAccess::QUERY_STATUS
                | ServiceAccess::START
                | ServiceAccess::STOP
                | ServiceAccess::PAUSE_CONTINUE
        }
    };
    let service = manager.open_service(NAME, access).map_err(|e| {
        format!("cannot open service {NAME:?} (is it installed? controlling it needs an elevated prompt): {e}")
    })?;
    let state = || service.query_status().map(|s| s.current_state);
    match what {
        Control::Status => {}
        Control::Stop | Control::Restart => {
            if state().is_ok_and(|s| s != ServiceState::Stopped) {
                service
                    .stop()
                    .map_err(|e| format!("cannot stop the service: {e}"))?;
                if !wait_for(&service, ServiceState::Stopped) {
                    return Err("the service did not stop within 30 s".to_owned());
                }
            }
            if matches!(what, Control::Restart) {
                start(&service)?;
            }
        }
        Control::Start => {
            if state().is_ok_and(|s| s != ServiceState::Running) {
                start(&service)?;
            }
        }
        Control::Reload => {
            service
                .notify(UserEventCode::from_raw(RELOAD_EVENT).map_err(|e| e.to_string())?)
                .map_err(|e| format!("cannot signal the service (is it running?): {e}"))?;
            println!("asked the service to reload; the log says whether it worked");
            return Ok(());
        }
    }
    let now = state().map_err(|e| format!("cannot query the service: {e}"))?;
    println!("service {NAME:?}: {}", state_name(now));
    Ok(())
}

fn start(service: &windows_service::service::Service) -> Result<(), String> {
    service
        .start::<&str>(&[])
        .map_err(|e| format!("cannot start the service: {e}"))?;
    if wait_for(service, ServiceState::Running) {
        Ok(())
    } else {
        Err(format!(
            "the service did not start; see wedge.log in the log folder (default {})",
            default_log_dir().display()
        ))
    }
}

/// Polls until the service reaches `want` or 30 s pass.
fn wait_for(service: &windows_service::service::Service, want: ServiceState) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match service.query_status() {
            Ok(s) if s.current_state == want => return true,
            Ok(s) if want == ServiceState::Running && s.current_state == ServiceState::Stopped => {
                return false
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(250)),
            Err(_) => return false,
        }
    }
    false
}

fn state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "stopped",
        ServiceState::StartPending => "starting",
        ServiceState::StopPending => "stopping",
        ServiceState::Running => "running",
        ServiceState::ContinuePending => "resuming",
        ServiceState::PausePending => "pausing",
        ServiceState::Paused => "paused",
    }
}

/// Deletes what an earlier installation left: its configuration file with
/// `conf.d`, users file and backups; its web root only if `wedge init`
/// created it; `.log` files in its log folder. Used by the installer's
/// "uninstall the previous installation" choice when the administrator also
/// asks to delete the old data. Refuses system folders and drive roots.
pub(crate) fn purge(
    config: Option<&Path>,
    web_root: Option<&Path>,
    log_dir: Option<&Path>,
) -> Result<(), String> {
    if let Some(config) = config.filter(|c| c.is_file()) {
        let dir = config.parent().ok_or("config has no folder")?;
        refuse_protected(dir)?;
        let stem = config
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        remove_file(config)?;
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == crate::setup::USERS_FILE || name.starts_with(&format!("{stem}.bak-")) {
                remove_file(&entry.path())?;
            }
        }
        let conf_d = dir.join(wedge_config::CONF_DIR);
        if conf_d.is_dir() {
            std::fs::remove_dir_all(&conf_d).map_err(|e| format!("{}: {e}", conf_d.display()))?;
        }
        let _ = std::fs::remove_dir(dir);
        println!("deleted the configuration in {}", dir.display());
    }
    if let Some(root) = web_root.filter(|r| r.is_dir()) {
        refuse_protected(root)?;
        if root.join(crate::setup::CREATED_MARKER).exists() || is_legacy_data(root) {
            std::fs::remove_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
            println!("deleted the web content in {}", root.display());
        } else {
            println!(
                "kept {}: it existed before wedge was installed",
                root.display()
            );
        }
    }
    if let Some(logs) = log_dir.filter(|l| l.is_dir()) {
        refuse_protected(logs)?;
        for entry in std::fs::read_dir(logs)
            .map_err(|e| e.to_string())?
            .flatten()
        {
            if entry
                .path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("log"))
            {
                remove_file(&entry.path())?;
            }
        }
        let _ = std::fs::remove_dir(logs);
    }
    // The 0.1 installer's folder: remove it once it is empty.
    let _ = std::fs::remove_dir(legacy_data_dir());
    Ok(())
}

fn remove_file(path: &Path) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `%ProgramData%\wedge`, where the 0.1 installer put its data.
fn legacy_data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("wedge")
}

/// The 0.1 installer's web root, which predates the created-by marker.
fn is_legacy_data(root: &Path) -> bool {
    let plain = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    plain(root) == plain(&legacy_data_dir().join("www"))
}

/// Refuses to delete inside drive roots and well-known system folders.
fn refuse_protected(path: &Path) -> Result<(), String> {
    let path = std::path::absolute(path).map_err(|e| e.to_string())?;
    let plain = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    let target = plain(&path);
    let mut protected: Vec<String> = [
        "SystemRoot",
        "ProgramFiles",
        "ProgramW6432",
        "ProgramFiles(x86)",
        "ProgramData",
        "USERPROFILE",
        "PUBLIC",
    ]
    .iter()
    .filter_map(std::env::var_os)
    .map(|v| plain(Path::new(&v)))
    .collect();
    if let Some(users) = std::env::var_os("USERPROFILE")
        .as_deref()
        .map(Path::new)
        .and_then(Path::parent)
    {
        protected.push(plain(users));
    }
    let is_root = path.parent().is_none() || target.len() <= 3;
    if is_root || protected.contains(&target) {
        return Err(format!("refusing to delete in {}", path.display()));
    }
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

/// Starts a reload on the server's runtime; errors go to the log and the
/// previous configuration keeps serving.
fn reload_now() -> ServiceControlHandlerResult {
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
        ServiceControl::ParamChange => reload_now(),
        ServiceControl::UserEvent(code) if code.to_raw() == RELOAD_EVENT => reload_now(),
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
    // T6.7: refuse to run from a folder ordinary users can change. If the
    // check itself cannot run (for example PowerShell is blocked), say so
    // and continue: `service install` already checked the folder.
    match own_exe().and_then(|exe| acl::check(&exe).map_err(|e| e.to_string())) {
        Ok(()) => {}
        Err(e) if e.starts_with(acl::UNAVAILABLE) => tracing::warn!("{e}"),
        Err(e) => {
            tracing::error!("{e}; not starting");
            set(ServiceState::Stopped, ServiceControlAccept::empty(), 1)?;
            return Ok(());
        }
    }
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

    #[test]
    fn purge_refuses_roots_and_system_folders() {
        for path in [r"C:\", r"C:\Windows", r"C:\Program Files", r"C:\Users"] {
            assert!(refuse_protected(Path::new(path)).is_err(), "{path}");
        }
        assert!(refuse_protected(Path::new(r"C:\Program Files\wedge\conf")).is_ok());
    }

    #[test]
    fn purge_keeps_roots_it_did_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("conf").join("wedge.toml");
        let own = dir.path().join("own-site");
        let made = dir.path().join("made-site");
        let logs = dir.path().join("logs");
        for d in [config.parent().unwrap(), &own, &made, &logs] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::create_dir_all(config.parent().unwrap().join("conf.d")).unwrap();
        std::fs::write(&config, "x").unwrap();
        std::fs::write(config.with_file_name(crate::setup::USERS_FILE), "x").unwrap();
        std::fs::write(config.with_file_name("notes.txt"), "mine").unwrap();
        std::fs::write(own.join("index.html"), "mine").unwrap();
        std::fs::write(made.join(crate::setup::CREATED_MARKER), "").unwrap();
        std::fs::write(logs.join("wedge.log"), "log").unwrap();
        purge(Some(&config), Some(&own), Some(&logs)).unwrap();
        purge(None, Some(&made), None).unwrap();
        assert!(!config.exists());
        assert!(!config.with_file_name(crate::setup::USERS_FILE).exists());
        // Files wedge did not write stay, so the folder stays.
        assert!(config.with_file_name("notes.txt").exists());
        assert!(own.join("index.html").exists());
        assert!(!made.exists());
        assert!(!logs.exists());
    }
}
