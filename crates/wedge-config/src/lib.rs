// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Configuration loading for wedge.
//!
//! A deployment has one master file (`wedge.toml`) and an optional `conf.d/`
//! directory next to it. Every `*.toml` file in `conf.d/` is merged on top of
//! the master file in lexical file-name order:
//!
//! - tables are merged key by key, recursively;
//! - arrays (for example `[[vhost]]`) are appended;
//! - any other value in a later file replaces the earlier value.
//!
//! Unknown keys are rejected so that typos fail loudly instead of being ignored.

mod merge;
mod model;
mod schema;
mod secret;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub use model::{
    Config, Limits, ServerConfig, TlsSettings, TlsVersion, VhostTls, VirtualHost, RESERVED_HEADERS,
};
pub use schema::json_schema;
pub use secret::{Secret, SecretError, SecretRef, MAX_SECRET_SIZE};

/// Largest configuration file accepted, in bytes. Guards against accidental or
/// hostile huge inputs.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// Name of the directory, next to the master file, holding peripheral files.
pub const CONF_DIR: &str = "conf.d";

/// Errors raised while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than the {MAX_FILE_SIZE}-byte limit")]
    TooLarge { path: PathBuf },
    #[error("{path} is not valid UTF-8")]
    NotUtf8 { path: PathBuf },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("configuration does not match the schema:\n  {}", .errors.join("\n  "))]
    Schema { errors: Vec<String> },
    #[error("invalid configuration: {source}")]
    Invalid {
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("invalid configuration:\n  {}", .errors.join("\n  "))]
    Semantic { errors: Vec<String> },
}

/// Loads the master file at `master` and merges `conf.d/*.toml` beside it.
pub fn load(master: &Path) -> Result<Config, ConfigError> {
    let mut merged = read_table(master)?;
    let conf_dir = master
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CONF_DIR);
    for file in peripheral_files(&conf_dir)? {
        merge::merge(&mut merged, read_table(&file)?);
    }
    let mut config = from_table(merged)?;
    // Relative document roots are relative to the master file, not to the
    // working directory, so a config behaves the same wherever wedge starts.
    let base = master.parent().unwrap_or_else(|| Path::new("."));
    for vhost in &mut config.vhost {
        if vhost.root.is_relative() {
            vhost.root = base.join(&vhost.root);
        }
        if let Some(tls) = &mut vhost.tls {
            for reference in [&mut tls.cert, &mut tls.key] {
                if let SecretRef::File(path) = reference {
                    if path.is_relative() {
                        *path = base.join(&*path);
                    }
                }
            }
        }
    }
    Ok(config)
}

/// Parses a single configuration document without touching the filesystem.
pub fn from_str(text: &str) -> Result<Config, ConfigError> {
    let table = text
        .parse::<toml::Table>()
        .map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source: Box::new(e),
        })?;
    from_table(table)
}

/// Validates a merged document in three steps: JSON Schema (reports every
/// structural error at once), typed decoding (value formats such as socket
/// addresses), then cross-field rules.
fn from_table(table: toml::Table) -> Result<Config, ConfigError> {
    schema::validate(&table)?;
    let config: Config =
        toml::Value::Table(table)
            .try_into()
            .map_err(|e| ConfigError::Invalid {
                source: Box::new(e),
            })?;
    let errors = config.semantic_errors();
    if errors.is_empty() {
        Ok(config)
    } else {
        Err(ConfigError::Semantic { errors })
    }
}

/// Lists `*.toml` files in `dir`, sorted by file name. Hidden files and
/// non-files are skipped. A missing directory yields no files.
fn peripheral_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(ConfigError::Io {
                path: dir.to_path_buf(),
                source,
            })
        }
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        let hidden = name.to_string_lossy().starts_with('.');
        let is_toml = path.extension().is_some_and(|ext| ext == "toml");
        if !hidden && is_toml && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn read_table(path: &Path) -> Result<toml::Table, ConfigError> {
    let io_err = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = fs::File::open(path).map_err(io_err)?;
    // Read one byte past the limit so oversize files are detected even if the
    // file grows between a metadata check and the read.
    let mut bytes = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    let text = String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    text.parse::<toml::Table>().map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, text).unwrap();
        path
    }

    const MASTER: &str = r#"
        [server]
        listen = ["127.0.0.1:8080"]

        [[vhost]]
        name = "default"
        root = "/srv/www"
    "#;

    #[test]
    fn relative_roots_resolve_against_master_dir() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(
            dir.path(),
            "wedge.toml",
            "[[vhost]]
name = \"a\"
root = \"www\"
",
        );
        let cfg = load(&master).unwrap();
        assert_eq!(cfg.vhost[0].root, dir.path().join("www"));
    }

    #[test]
    fn loads_master_without_conf_d() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(dir.path(), "wedge.toml", MASTER);
        let cfg = load(&master).unwrap();
        assert_eq!(cfg.server.listen.len(), 1);
        assert_eq!(cfg.vhost.len(), 1);
        assert_eq!(cfg.vhost[0].name, "default");
    }

    #[test]
    fn merges_conf_d_in_lexical_order() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(dir.path(), "wedge.toml", MASTER);
        write(
            dir.path(),
            "conf.d/20-shop.toml",
            "[[vhost]]\nname = \"shop\"\nroot = \"/srv/shop\"\n",
        );
        write(
            dir.path(),
            "conf.d/10-blog.toml",
            "[[vhost]]\nname = \"blog\"\nroot = \"/srv/blog\"\n",
        );
        write(
            dir.path(),
            "conf.d/30-listen.toml",
            "[server]\nlisten = [\"0.0.0.0:80\"]\n",
        );
        let cfg = load(&master).unwrap();
        let names: Vec<_> = cfg.vhost.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["default", "blog", "shop"]);
        // Arrays append, so the listener from conf.d is added, not replaced.
        assert_eq!(cfg.server.listen.len(), 2);
    }

    #[test]
    fn skips_hidden_and_non_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(dir.path(), "wedge.toml", MASTER);
        write(dir.path(), "conf.d/.swap.toml", "not = [valid");
        write(dir.path(), "conf.d/notes.txt", "not toml at all [");
        assert_eq!(load(&master).unwrap().vhost.len(), 1);
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = from_str("[server]\nlisten = []\nlsiten = []\n").unwrap_err();
        assert!(matches!(err, ConfigError::Schema { .. }), "{err}");
        assert!(err.to_string().contains("lsiten"), "{err}");
    }

    #[test]
    fn reports_all_schema_errors_at_once() {
        let err =
            from_str("[server]\nlisten = 5\n[[vhost]]\nname = 1\nroot = \"/x\"\n").unwrap_err();
        let ConfigError::Schema { errors } = err else {
            panic!("expected schema error, got {err}");
        };
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors.iter().any(|e| e.starts_with("/server/listen")));
        assert!(errors.iter().any(|e| e.starts_with("/vhost/0/name")));
    }

    #[test]
    fn vhost_host_rules() {
        let shared = "[[vhost]]\nname = \"a\"\nroot = \"/x\"\nhosts = [\"x.com\"]\n\
                      [[vhost]]\nname = \"b\"\nroot = \"/y\"\nhosts = [\"X.com\"]\n";
        assert!(matches!(
            from_str(shared),
            Err(ConfigError::Semantic { .. })
        ));
        let bad_default =
            "[server]\ndefault_vhost = \"nope\"\n[[vhost]]\nname = \"a\"\nroot = \"/x\"\n";
        assert!(matches!(
            from_str(bad_default),
            Err(ConfigError::Semantic { .. })
        ));
        let bad_host = "[[vhost]]\nname = \"a\"\nroot = \"/x\"\nhosts = [\"a_b.com\"]\n";
        assert!(matches!(
            from_str(bad_host),
            Err(ConfigError::Semantic { .. })
        ));
        let good = "[server]\ndefault_vhost = \"a\"\n[[vhost]]\nname = \"a\"\nroot = \"/x\"\n\
                    hosts = [\"a.com\", \"*.a.com\"]\n";
        assert!(from_str(good).is_ok());
    }

    #[test]
    fn rejects_duplicate_vhost_names() {
        let text =
            "[[vhost]]\nname = \"a\"\nroot = \"/x\"\n[[vhost]]\nname = \"a\"\nroot = \"/y\"\n";
        let err = from_str(text).unwrap_err();
        assert!(matches!(err, ConfigError::Semantic { .. }), "{err}");
    }

    #[test]
    fn reports_file_path_on_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(dir.path(), "wedge.toml", MASTER);
        write(dir.path(), "conf.d/bad.toml", "[server\n");
        let err = load(&master).unwrap_err().to_string();
        assert!(err.contains("bad.toml"), "{err}");
    }

    #[test]
    fn rejects_oversize_file() {
        let dir = tempfile::tempdir().unwrap();
        let big = format!("# {}\n", "x".repeat(MAX_FILE_SIZE as usize));
        let master = write(dir.path(), "wedge.toml", &big);
        assert!(matches!(
            load(&master).unwrap_err(),
            ConfigError::TooLarge { .. }
        ));
    }

    #[test]
    fn rejects_non_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("wedge.toml");
        fs::write(&master, [0xff, 0xfe, b'a']).unwrap();
        assert!(matches!(
            load(&master).unwrap_err(),
            ConfigError::NotUtf8 { .. }
        ));
    }

    #[test]
    fn missing_master_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(&dir.path().join("absent.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn tls_settings_and_relative_cert_paths() {
        let dir = tempfile::tempdir().unwrap();
        let master = write(
            dir.path(),
            "wedge.toml",
            "[server]\nlisten_tls = [\"127.0.0.1:8443\"]\n[server.tls]\nmin_version = \"1.3\"\n\
             [[vhost]]\nname = \"a\"\nroot = \"www\"\n\
             [vhost.tls]\ncert = \"file:certs/a.pem\"\nkey = \"env:A_KEY\"\n",
        );
        let cfg = load(&master).unwrap();
        assert_eq!(cfg.server.tls.min_version, TlsVersion::V1_3);
        let tls = cfg.vhost[0].tls.as_ref().unwrap();
        assert_eq!(tls.cert, SecretRef::File(dir.path().join("certs/a.pem")));
        assert_eq!(tls.key, SecretRef::Env("A_KEY".into()));
    }

    #[test]
    fn tls_rules() {
        let vhost = "[[vhost]]\nname = \"a\"\nroot = \"/x\"\n";
        let no_cert = format!("[server]\nlisten_tls = [\"127.0.0.1:8443\"]\n{vhost}");
        let err = from_str(&no_cert).unwrap_err().to_string();
        assert!(err.contains("no vhost has a [vhost.tls]"), "{err}");
        let shared = format!(
            "[server]\nlisten = [\"127.0.0.1:8443\"]\nlisten_tls = [\"127.0.0.1:8443\"]\n{vhost}\
             [vhost.tls]\ncert = \"file:/c\"\nkey = \"file:/k\"\n"
        );
        let err = from_str(&shared).unwrap_err().to_string();
        assert!(err.contains("duplicate listen address"), "{err}");
        for bad in [
            "[server.tls]\nmin_version = \"1.1\"\n",
            "[[vhost]]\nname = \"a\"\nroot = \"/x\"\n[vhost.tls]\ncert = \"file:/c\"\n\
             key = \"-----BEGIN PRIVATE KEY-----\"\n",
        ] {
            let err = from_str(bad).unwrap_err();
            assert!(matches!(err, ConfigError::Schema { .. }), "{err}");
            assert!(!err.to_string().contains("BEGIN PRIVATE"), "{err}");
        }
    }

    #[test]
    fn rejects_invalid_listen_address() {
        let err = from_str("[server]\nlisten = [\"not-an-address\"]\n").unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    }
}
