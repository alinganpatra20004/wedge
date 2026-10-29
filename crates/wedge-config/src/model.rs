// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Typed configuration model. Later phases extend these structs.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Complete, merged server configuration.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub vhost: Vec<VirtualHost>,
}

/// Process-wide server settings (`[server]`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on, such as `"0.0.0.0:80"` or `"[::]:443"`.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
}

/// A virtual host (`[[vhost]]`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VirtualHost {
    /// Unique name used in logs and diagnostics.
    pub name: String,
    /// Directory served for this host.
    pub root: PathBuf,
}
