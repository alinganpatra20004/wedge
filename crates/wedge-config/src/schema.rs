// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! JSON Schema for the configuration, derived from the typed model.
//!
//! The same schema is shipped as `schema/wedge.schema.json` for editors and
//! external tooling; a test keeps that file in sync with the model.

use std::sync::OnceLock;

use crate::{Config, ConfigError};

/// Returns the JSON Schema describing a merged configuration document.
pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(Config)).unwrap_or_default()
}

/// Compiles the schema once. The schema is generated from our own types, so a
/// compile failure is a programming error; it is still reported, not panicked.
fn validator() -> Result<&'static jsonschema::Validator, ConfigError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| jsonschema::validator_for(&json_schema()).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| ConfigError::Schema {
            errors: vec![format!("internal schema error: {e}")],
        })
}

/// Checks a merged document against the schema, collecting every error.
pub(crate) fn validate(table: &toml::Table) -> Result<(), ConfigError> {
    let instance = serde_json::to_value(table).map_err(|e| ConfigError::Schema {
        errors: vec![e.to_string()],
    })?;
    let errors: Vec<String> = validator()?
        .iter_errors(&instance)
        .flat_map(|e| describe(&e))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Schema { errors })
    }
}

/// Formats one error as `<json-pointer>: <message>`. Messages never contain
/// the offending value, because the field, or a table around it, may hold a
/// pasted secret (see `SecretRef`). An optional table (`anyOf` with `null`)
/// reports the errors inside the table instead.
fn describe(e: &jsonschema::ValidationError<'_>) -> Vec<String> {
    use jsonschema::error::ValidationErrorKind as Kind;
    let path = e.instance_path.to_string();
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    match &e.kind {
        Kind::Pattern { pattern } => {
            vec![format!(
                "{path}: value does not match the required format {pattern:?}"
            )]
        }
        Kind::AnyOf { context } => {
            let only_type = |errors: &Vec<jsonschema::ValidationError<'_>>| {
                errors.iter().all(|e| matches!(e.kind, Kind::Type { .. }))
            };
            let mut real = context.iter().filter(|branch| !only_type(branch));
            match (real.next(), real.next()) {
                (Some(branch), None) => branch.iter().flat_map(|e| describe(e)).collect(),
                _ => vec![format!("{path}: {}", e.masked())],
            }
        }
        _ => vec![format!("{path}: {}", e.masked())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_errors_do_not_echo_value() {
        let schema = serde_json::json!({"properties": {"p": {"pattern": "^env:"}}});
        let validator = jsonschema::validator_for(&schema).unwrap();
        let instance = serde_json::json!({"p": "hunter2"});
        let messages: Vec<String> = validator
            .iter_errors(&instance)
            .flat_map(|e| describe(&e))
            .collect();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].starts_with("/p: "), "{}", messages[0]);
        assert!(!messages[0].contains("hunter2"), "{}", messages[0]);
    }

    /// Type, enum and optional-table errors must not echo values either:
    /// a misplaced secret can sit in any string or table.
    #[test]
    fn no_error_kind_echoes_values() {
        let cases = [
            "[server]\nlisten = \"hunter2\"\n",
            "[server.tls]\nmin_version = \"hunter2\"\n",
            "[[vhost]]\nname = \"a\"\nroot = \"/x\"\ntls = \"hunter2\"\n",
            "[[vhost]]\nname = \"a\"\nroot = \"/x\"\n[vhost.tls]\ncert = \"file:/c\"\nkey = \"hunter2\"\n",
            "[[vhost]]\nname = \"a\"\nroot = \"/x\"\n[vhost.tls]\nkey = \"hunter2\"\nextra = 1\n",
        ];
        for text in cases {
            let table: toml::Table = text.parse().unwrap();
            let Err(ConfigError::Schema { errors }) = validate(&table) else {
                panic!("expected schema errors for {text}");
            };
            for message in &errors {
                assert!(!message.contains("hunter2"), "{message}");
            }
        }
        let table: toml::Table = cases[3].parse().unwrap();
        let Err(ConfigError::Schema { errors }) = validate(&table) else {
            unreachable!()
        };
        assert!(
            errors.iter().any(|e| e.starts_with("/vhost/0/tls/key: ")),
            "{errors:?}"
        );
    }

    const SHIPPED: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schema/wedge.schema.json"
    );

    /// Fails when the shipped schema drifts from the model. Regenerate with
    /// `WEDGE_BLESS=1 cargo test -p wedge-config`.
    #[test]
    fn shipped_schema_is_current() {
        let generated = serde_json::to_string_pretty(&json_schema()).unwrap() + "\n";
        if std::env::var_os("WEDGE_BLESS").is_some() {
            std::fs::write(SHIPPED, &generated).unwrap();
        }
        let shipped = std::fs::read_to_string(SHIPPED)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert_eq!(
            shipped, generated,
            "schema/wedge.schema.json is out of date"
        );
    }

    #[test]
    fn schema_compiles() {
        assert!(validator().is_ok());
    }
}
