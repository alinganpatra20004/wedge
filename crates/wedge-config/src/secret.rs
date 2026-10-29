// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Secrets are configured by reference only, never inline.
//!
//! A [`SecretRef`] is written in configuration as `"env:NAME"` (an environment
//! variable) or `"file:/path"` (a file, trailing newline stripped). Anything
//! else is rejected, so a literal password in a config file fails validation.
//! Resolved values live in [`Secret`], whose `Debug` output is redacted and
//! whose memory is zeroed on drop.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Largest secret file accepted, in bytes.
pub const MAX_SECRET_SIZE: u64 = 64 * 1024;

/// Where a secret comes from. Displaying it shows the reference, not the value.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum SecretRef {
    Env(String),
    File(PathBuf),
}

/// A resolved secret value.
pub struct Secret(Zeroizing<Vec<u8>>);

/// Errors raised while resolving a secret. Messages never contain the value.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret {0}: environment variable is not set or not valid UTF-8")]
    MissingEnv(SecretRef),
    #[error("secret {reference}: {source}")]
    Io {
        reference: SecretRef,
        #[source]
        source: std::io::Error,
    },
    #[error("secret {0}: larger than the {MAX_SECRET_SIZE}-byte limit")]
    TooLarge(SecretRef),
    #[error("secret {0}: value is empty")]
    Empty(SecretRef),
}

impl TryFrom<String> for SecretRef {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        // The input may itself be a pasted secret, so it is never echoed back.
        const HINT: &str = "secrets must be references: \"env:NAME\" or \"file:/path\"";
        if let Some(name) = text.strip_prefix("env:") {
            let mut chars = name.chars();
            let valid = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
            return if valid {
                Ok(Self::Env(name.to_owned()))
            } else {
                Err(format!("invalid environment variable name; {HINT}"))
            };
        }
        match text.strip_prefix("file:") {
            Some(path) if !path.is_empty() => Ok(Self::File(PathBuf::from(path))),
            _ => Err(HINT.to_owned()),
        }
    }
}

impl JsonSchema for SecretRef {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretRef".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^(env:[A-Za-z_][A-Za-z0-9_]*|file:.+)$",
            "description": "Secret reference: \"env:NAME\" or \"file:/path\". Inline values are not allowed."
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => write!(f, "env:{name}"),
            Self::File(path) => write!(f, "file:{}", path.display()),
        }
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({self})")
    }
}

impl SecretRef {
    /// Reads the secret value. Call at the point of use so rotated secrets are
    /// picked up on reload.
    pub fn resolve(&self) -> Result<Secret, SecretError> {
        let mut bytes = match self {
            Self::Env(name) => std::env::var(name)
                .map(|v| Zeroizing::new(v.into_bytes()))
                .map_err(|_| SecretError::MissingEnv(self.clone()))?,
            Self::File(path) => self.read_file(path)?,
        };
        while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            bytes.pop();
        }
        if bytes.is_empty() {
            return Err(SecretError::Empty(self.clone()));
        }
        Ok(Secret(bytes))
    }

    fn read_file(&self, path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let io_err = |source| SecretError::Io {
            reference: self.clone(),
            source,
        };
        let file = std::fs::File::open(path).map_err(io_err)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_SECRET_SIZE + 1)
            .read_to_end(&mut bytes)
            .map_err(io_err)?;
        if bytes.len() as u64 > MAX_SECRET_SIZE {
            return Err(SecretError::TooLarge(self.clone()));
        }
        Ok(bytes)
    }
}

impl Secret {
    /// The secret bytes. Avoid copying them into long-lived buffers.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<SecretRef, String> {
        SecretRef::try_from(text.to_owned())
    }

    #[test]
    fn parses_references() {
        assert_eq!(parse("env:DB_PASS"), Ok(SecretRef::Env("DB_PASS".into())));
        assert_eq!(
            parse("file:/run/secrets/key"),
            Ok(SecretRef::File("/run/secrets/key".into()))
        );
    }

    #[test]
    fn rejects_inline_values_without_echoing_them() {
        for bad in ["env:", "file:", ""] {
            assert!(parse(bad).is_err(), "{bad:?} accepted");
        }
        for secret_like in ["hunter2", "env:1BAD", "env:A-B"] {
            let err = parse(secret_like).unwrap_err();
            assert!(!err.contains(secret_like), "{err}");
        }
    }

    #[test]
    fn resolves_file_and_strips_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        std::fs::write(&path, "s3cret\r\n").unwrap();
        let secret = SecretRef::File(path).resolve().unwrap();
        assert_eq!(secret.expose(), b"s3cret");
    }

    #[test]
    fn debug_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        std::fs::write(&path, "s3cret").unwrap();
        let secret = SecretRef::File(path).resolve().unwrap();
        assert!(!format!("{secret:?}").contains("s3cret"));
    }

    #[test]
    fn missing_env_reports_name_only() {
        let reference = SecretRef::Env("WEDGE_TEST_SURELY_UNSET_VAR".into());
        let err = reference.resolve().unwrap_err().to_string();
        assert!(err.contains("env:WEDGE_TEST_SURELY_UNSET_VAR"), "{err}");
    }

    #[test]
    fn rejects_empty_and_oversize_files() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        assert!(matches!(
            SecretRef::File(empty).resolve(),
            Err(SecretError::Empty(_))
        ));
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'x'; MAX_SECRET_SIZE as usize + 1]).unwrap();
        assert!(matches!(
            SecretRef::File(big).resolve(),
            Err(SecretError::TooLarge(_))
        ));
    }
}
