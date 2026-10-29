// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Typed configuration model. Later phases extend these structs.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::Deserialize;

/// Complete, merged server configuration.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub vhost: Vec<VirtualHost>,
}

/// Process-wide server settings (`[server]`).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on, such as `"0.0.0.0:80"` or `"[::]:443"`.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
}

/// A virtual host (`[[vhost]]`).
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VirtualHost {
    /// Unique name used in logs and diagnostics.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    /// Directory served for this host.
    pub root: PathBuf,
}

impl Config {
    /// Cross-field rules that a schema cannot express. Empty means valid.
    pub(crate) fn semantic_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen = HashSet::new();
        for vhost in &self.vhost {
            if !seen.insert(vhost.name.as_str()) {
                errors.push(format!("duplicate vhost name {:?}", vhost.name));
            }
            if vhost.root.as_os_str().is_empty() {
                errors.push(format!("vhost {:?}: root must not be empty", vhost.name));
            }
        }
        let mut listen = HashSet::new();
        for addr in &self.server.listen {
            if !listen.insert(addr) {
                errors.push(format!("duplicate listen address {addr}"));
            }
        }
        errors
    }
}
