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
    /// Resource limits; the defaults are safe for an internet-facing server.
    #[serde(default)]
    pub limits: Limits,
}

/// Connection and request limits (`[server.limits]`). See the threat model,
/// entries T2.5 to T2.8.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Seconds allowed to receive a complete request head, including the wait
    /// for the next request on a kept-alive connection.
    #[schemars(range(min = 1, max = 300))]
    pub header_timeout_secs: u64,
    /// Seconds a connection may go without any bytes read or written before it
    /// is closed. Covers clients that connect and never send a request.
    #[schemars(range(min = 1, max = 3600))]
    pub idle_timeout_secs: u64,
    /// Seconds allowed for a handler to produce a response head.
    #[schemars(range(min = 1, max = 3600))]
    pub request_timeout_secs: u64,
    /// Seconds to let in-flight requests finish after a shutdown signal.
    #[schemars(range(min = 0, max = 3600))]
    pub shutdown_grace_secs: u64,
    /// Maximum simultaneous client connections across all listeners.
    #[schemars(range(min = 1, max = 1_000_000))]
    pub max_connections: usize,
    /// Maximum bytes buffered for an HTTP/1 request head, and maximum HTTP/2
    /// header list size.
    #[schemars(range(min = 8192, max = 1_048_576))]
    pub max_header_bytes: usize,
    /// Maximum number of request headers.
    #[schemars(range(min = 1, max = 1000))]
    pub max_headers: usize,
    /// Maximum request-target (URI) length in bytes.
    #[schemars(range(min = 256, max = 65_536))]
    pub max_uri_bytes: usize,
    /// Maximum concurrent HTTP/2 streams per connection.
    #[schemars(range(min = 1, max = 1000))]
    pub h2_max_concurrent_streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            header_timeout_secs: 10,
            idle_timeout_secs: 60,
            request_timeout_secs: 30,
            shutdown_grace_secs: 30,
            max_connections: 1024,
            max_header_bytes: 16 * 1024,
            max_headers: 100,
            max_uri_bytes: 8 * 1024,
            h2_max_concurrent_streams: 100,
        }
    }
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
