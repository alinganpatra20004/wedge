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
        .map(|e| {
            let path = e.instance_path.to_string();
            let path = if path.is_empty() {
                "/".to_owned()
            } else {
                path
            };
            format!("{path}: {e}")
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Schema { errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
