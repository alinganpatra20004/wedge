// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! `wedge init` (a starter configuration) and `wedge admin set-password`
//! (administrator accounts). The Windows installer runs both.

use std::io::{BufRead, IsTerminal, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

use wedge_core::auth::{self, Users};
use zeroize::Zeroizing;

/// The users file `wedge init` points the admin listener at, next to the
/// configuration file.
pub(crate) const USERS_FILE: &str = "admin-users.txt";
/// Marks a web root that `wedge init` created, so a later purge may delete
/// it; folders that already existed are never purged.
pub(crate) const CREATED_MARKER: &str = ".wedge-created";

const DEFAULT_PAGE: &str = include_str!("../../../packaging/linux/www/index.html");

/// What `wedge init` writes.
pub(crate) struct Init<'a> {
    pub(crate) config: &'a Path,
    pub(crate) web_root: &'a Path,
    pub(crate) port: u16,
    /// Admin listener port; `None` leaves the admin listener off.
    pub(crate) admin_port: Option<u16>,
    /// Listen on every interface instead of loopback only.
    pub(crate) public: bool,
    /// Replace an existing file (it is kept as `<name>.bak-<time>`).
    pub(crate) force: bool,
}

/// Writes a configuration file and creates the web root with a default
/// page if it has none, then validates the result.
pub(crate) fn init(options: &Init<'_>) -> Result<(), String> {
    if options.port == 0 || options.admin_port == Some(0) {
        return Err("ports must be between 1 and 65535".to_owned());
    }
    if options.admin_port == Some(options.port) {
        return Err("the admin port must differ from the web port".to_owned());
    }
    let config = std::path::absolute(options.config).map_err(|e| e.to_string())?;
    let web_root = std::path::absolute(options.web_root).map_err(|e| e.to_string())?;
    let dir = config.parent().ok_or("the config path has no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if config.exists() {
        if !options.force {
            return Err(format!(
                "{} already exists; pass --force to replace it (a backup is kept)",
                config.display()
            ));
        }
        let backup = backup_name(&config);
        std::fs::rename(&config, &backup).map_err(|e| format!("{}: {e}", backup.display()))?;
        println!("kept the previous file as {}", backup.display());
    }
    // A missing or empty folder holds nothing but what wedge puts there, so
    // it is marked as wedge's; a folder with content stays the owner's.
    let empty = std::fs::read_dir(&web_root).map_or(true, |mut d| d.next().is_none());
    if empty {
        std::fs::create_dir_all(&web_root).map_err(|e| format!("{}: {e}", web_root.display()))?;
        std::fs::write(web_root.join(CREATED_MARKER), "created by wedge init\n")
            .map_err(|e| format!("{}: {e}", web_root.display()))?;
    }
    let index = web_root.join("index.html");
    if !index.exists() {
        std::fs::write(&index, DEFAULT_PAGE).map_err(|e| format!("{}: {e}", index.display()))?;
    }
    let text = config_text(options, &config, &web_root);
    std::fs::write(&config, text).map_err(|e| format!("{}: {e}", config.display()))?;
    wedge_config::load(&config)
        .map_err(|e| format!("the written configuration is invalid: {e}"))?;
    println!("wrote {}", config.display());
    let host = if options.public {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    for port in std::iter::once(options.port).chain(options.admin_port) {
        if TcpListener::bind(SocketAddr::from((host, port))).is_err() {
            eprintln!("warning: port {port} is in use now; wedge cannot start until it is free");
        }
    }
    if let Some(port) = options.admin_port {
        if !dir.join(USERS_FILE).exists() {
            println!(
                "next: create the administrator account with\n  wedge admin set-password --users-file \"{}\"",
                dir.join(USERS_FILE).display()
            );
        }
        println!("admin page: http://127.0.0.1:{port}/");
    }
    Ok(())
}

fn backup_name(path: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".bak-{secs}"));
    path.with_file_name(name)
}

fn config_text(options: &Init<'_>, config: &Path, web_root: &Path) -> String {
    let host = if options.public {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let check = format!("wedge check-config -c {}", config.display());
    let reload = if cfg!(windows) {
        "wedge service reload   (or use the admin page)"
    } else {
        "sudo systemctl reload wedge   (or use the admin page)"
    };
    let reach = if options.public {
        "wedge listens on every network interface; allow the port in the firewall."
    } else {
        "wedge listens on this computer only. To serve the network, change\n\
         # listen to [\"0.0.0.0:<port>\"] and allow the port in the firewall."
    };
    let mut text = format!(
        "# wEdge configuration, written by `wedge init`.\n\
         # Check changes with:  {check}\n\
         # then apply them:     {reload}\n\
         #\n\
         # {reach}\n\
         # Files in conf.d\\ (next to this file) are merged after this one.\n\
         # Every setting: docs/guide/configuration-reference.md\n\
         \n\
         [server]\n\
         listen = [\"{host}:{port}\"]\n\
         default_vhost = \"default\"\n",
        port = options.port
    );
    if let Some(port) = options.admin_port {
        text.push_str(&format!(
            "\n\
             # Admin page, metrics and reload: http://127.0.0.1:{port}/\n\
             # Loopback only; accounts are in {USERS_FILE} (`wedge admin set-password`).\n\
             [server.admin]\n\
             listen = \"127.0.0.1:{port}\"\n\
             users = \"file:{USERS_FILE}\"\n"
        ));
    }
    text.push_str(&format!(
        "\n\
         [[vhost]]\n\
         name = \"default\"\n\
         root = {}\n\
         \n\
         # Strict browser security headers for the default page. A real site\n\
         # usually needs these adjusted; see \"Response headers\" in\n\
         # docs/guide/security.md.\n\
         [vhost.headers]\n\
         \"Content-Security-Policy\" = \"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'\"\n\
         \"Permissions-Policy\" = \"camera=(), microphone=(), geolocation=(), payment=(), usb=()\"\n\
         \"Cross-Origin-Resource-Policy\" = \"same-origin\"\n",
        toml_string(&web_root.display().to_string())
    ));
    text
}

/// A TOML basic string: quotes, backslashes and control characters escaped.
fn toml_string(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The users file: given directly, or the `file:` reference in the
/// configuration's `[server.admin] users`.
pub(crate) fn users_file(
    direct: Option<PathBuf>,
    config: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(file) = direct {
        return Ok(file);
    }
    let config = config.ok_or("give --users-file or --config")?;
    let loaded = wedge_config::load(config).map_err(|e| e.to_string())?;
    match loaded.server.admin.and_then(|a| a.users) {
        Some(wedge_config::SecretRef::File(path)) => Ok(path),
        Some(other) => Err(format!(
            "[server.admin] users is {other}; give --users-file for a file to write"
        )),
        None => Err(format!(
            "{} has no [server.admin] users setting",
            config.display()
        )),
    }
}

/// Sets `user`'s password in `users_file`, creating the file if needed.
/// The password comes from `password` (the Windows installer), else is read
/// from the terminal without echo (asked twice), else from one stdin line.
pub(crate) fn set_password(
    users_file: &Path,
    user: &str,
    password: Option<Zeroizing<String>>,
) -> Result<(), String> {
    auth::validate_user(user)?;
    let password = match password {
        Some(p) => p,
        None => read_password()?,
    };
    let hash = auth::hash_password(&password)?;
    drop(password);
    let users_file = std::path::absolute(users_file).map_err(|e| e.to_string())?;
    let existing = match std::fs::metadata(&users_file) {
        Ok(meta) if meta.len() > wedge_config::MAX_SECRET_SIZE => {
            return Err(format!("{} is too large", users_file.display()));
        }
        Ok(_) => std::fs::read_to_string(&users_file)
            .map_err(|e| format!("{}: {e}", users_file.display()))?,
        Err(_) => String::new(),
    };
    let text = Users::with_user(&existing, user, &hash);
    Users::parse(&text).map_err(|e| format!("{}: {e}", users_file.display()))?;
    write_private(&users_file, &text)?;
    println!("set the password of {user:?} in {}", users_file.display());
    println!("a running wedge picks it up on its next reload");
    Ok(())
}

fn read_password() -> Result<Zeroizing<String>, String> {
    if std::io::stdin().is_terminal() {
        let first = Zeroizing::new(
            rpassword::prompt_password(format!(
                "New password (at least {} characters): ",
                auth::MIN_PASSWORD_CHARS
            ))
            .map_err(|e| e.to_string())?,
        );
        auth::validate_password(&first)?;
        let second =
            Zeroizing::new(rpassword::prompt_password("Repeat it: ").map_err(|e| e.to_string())?);
        if *first != *second {
            return Err("the two passwords differ".to_owned());
        }
        Ok(first)
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let trimmed = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
        Ok(trimmed)
    }
}

/// Replaces `path` with `text` through a temporary file in the same folder,
/// readable only by administrators and the service (T5.13).
fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("the users file path has no folder")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".tmp");
    let temp = dir.join(name);
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
    let mut file = options
        .open(&temp)
        .map_err(|e| format!("{}: {e}", temp.display()))?;
    #[cfg(windows)]
    crate::service::restrict_to_admins(&temp, true)?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", temp.display()))?;
    drop(file);
    std::fs::rename(&temp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_strings_are_escaped() {
        assert_eq!(toml_string(r"C:\sites\a"), r#""C:\\sites\\a""#);
        assert_eq!(toml_string("a\"b\n"), r#""a\"b\u000A""#);
    }

    #[test]
    fn init_writes_a_valid_config_and_default_page() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("conf").join("wedge.toml");
        let root = dir.path().join("site 'x'");
        let options = Init {
            config: &config,
            web_root: &root,
            port: 18080,
            admin_port: Some(19090),
            public: false,
            force: false,
        };
        init(&options).unwrap();
        assert_eq!(
            users_file(None, Some(&config)).unwrap(),
            config.with_file_name(USERS_FILE)
        );
        let loaded = wedge_config::load(&config).unwrap();
        assert_eq!(loaded.server.listen[0].to_string(), "127.0.0.1:18080");
        let admin = loaded.server.admin.unwrap();
        assert_eq!(admin.listen.to_string(), "127.0.0.1:19090");
        assert!(admin.users.unwrap().to_string().ends_with(USERS_FILE));
        assert_eq!(loaded.vhost[0].root.as_deref(), Some(root.as_path()));
        assert!(root.join("index.html").exists());
        assert!(root.join(CREATED_MARKER).exists());
        // A second run refuses, unless forced, and then keeps a backup.
        assert!(init(&options).is_err());
        init(&Init {
            force: true,
            public: true,
            admin_port: None,
            ..options
        })
        .unwrap();
        let loaded = wedge_config::load(&config).unwrap();
        assert_eq!(loaded.server.listen[0].to_string(), "0.0.0.0:18080");
        assert!(loaded.server.admin.is_none());
        let backups = std::fs::read_dir(config.parent().unwrap())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("wedge.toml.bak-")
            })
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn init_refuses_bad_ports_and_keeps_existing_roots_unmarked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("about.html"), "the owner's page").unwrap();
        let config = dir.path().join("wedge.toml");
        let same = Init {
            config: &config,
            web_root: dir.path(),
            port: 8080,
            admin_port: Some(8080),
            public: false,
            force: false,
        };
        assert!(init(&same).is_err());
        init(&Init {
            admin_port: Some(9090),
            port: 18081,
            ..same
        })
        .unwrap();
        // The root already had content: no marker, so a purge would keep it.
        assert!(!dir.path().join(CREATED_MARKER).exists());
        // An existing but empty folder (made by the installer) is marked.
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        init(&Init {
            config: &dir.path().join("second.toml"),
            web_root: &empty,
            admin_port: None,
            port: 18082,
            ..same
        })
        .unwrap();
        assert!(empty.join(CREATED_MARKER).exists());
    }

    #[test]
    fn set_password_creates_and_updates_the_users_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(USERS_FILE);
        let pw = |s: &str| Some(Zeroizing::new(s.to_owned()));
        assert!(set_password(&file, "admin", pw("short")).is_err());
        assert!(set_password(&file, "bad:name", pw("long enough password")).is_err());
        set_password(&file, "admin", pw("long enough password")).unwrap();
        set_password(&file, "ops", pw("another long password")).unwrap();
        set_password(&file, "admin", pw("a changed password!")).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("changed password"));
        assert_eq!(Users::parse(&text).unwrap().len(), 2);
    }
}
