// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Typed configuration model. Later phases extend these structs.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::Deserialize;

use crate::{IpNet, SecretRef};

/// Complete, merged server configuration.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub vhost: Vec<VirtualHost>,
    #[serde(default)]
    pub upstream: Vec<Upstream>,
}

/// A group of backend servers for the reverse proxy (`[[upstream]]`).
/// See the threat model, Phase 4.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Name that `[[vhost.proxy]]` routes refer to.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    /// Backend addresses as IP:port (no host names, so no DNS rebinding,
    /// T4.3). Requests go to healthy servers in turn.
    #[schemars(length(min = 1))]
    pub servers: Vec<SocketAddr>,
    /// Seconds allowed to open a TCP connection to a server.
    #[serde(default = "default_connect_timeout")]
    #[schemars(range(min = 1, max = 300))]
    pub connect_timeout_secs: u64,
    /// Seconds allowed for a server to send its response head.
    #[serde(default = "default_response_timeout")]
    #[schemars(range(min = 1, max = 3600))]
    pub response_timeout_secs: u64,
    /// Path probed with GET to check each server, such as `"/healthz"`.
    /// Without it, servers are only marked down when connections fail.
    #[serde(default)]
    pub health_path: Option<String>,
    /// Seconds between health checks.
    #[serde(default = "default_health_interval")]
    #[schemars(range(min = 1, max = 3600))]
    pub health_interval_secs: u64,
    /// Consecutive failures (checks or connection errors) that mark a server
    /// down. One success marks it up again.
    #[serde(default = "default_unhealthy_after")]
    #[schemars(range(min = 1, max = 100))]
    pub unhealthy_after: u32,
}

fn default_connect_timeout() -> u64 {
    5
}

fn default_response_timeout() -> u64 {
    30
}

fn default_health_interval() -> u64 {
    10
}

fn default_unhealthy_after() -> u32 {
    2
}

/// Sends requests under a path prefix to an upstream (`[[vhost.proxy]]`).
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyRoute {
    /// Path prefix starting with `/`, such as `"/api/"`. `"/api"` matches
    /// `/api` and `/api/...` but not `/apix`. The longest prefix wins.
    pub path: String,
    /// Name of the `[[upstream]]` that serves this route.
    pub upstream: String,
    /// Largest request body accepted, in bytes (T4.7).
    #[serde(default = "default_max_body")]
    #[schemars(range(min = 0, max = 4_294_967_296_u64))]
    pub max_body_bytes: u64,
}

fn default_max_body() -> u64 {
    10 * 1024 * 1024
}

/// Process-wide server settings (`[server]`).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on, such as `"0.0.0.0:80"` or `"[::]:443"`.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
    /// Addresses that accept TLS connections, such as `"[::]:443"`. Needs at
    /// least one vhost with a `[vhost.tls]` certificate.
    #[serde(default)]
    pub listen_tls: Vec<SocketAddr>,
    /// TLS protocol settings shared by all TLS listeners.
    #[serde(default)]
    pub tls: TlsSettings,
    /// Peers (such as a load balancer in front of wedge) whose
    /// `X-Forwarded-For` wedge extends instead of replacing (T4.6).
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Admin listener for metrics and reload. Off unless set.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// Debug capture of every request. For troubleshooting only; never in
    /// production. Restart-only.
    #[serde(default)]
    pub debug: DebugConfig,
    /// Name of the vhost that answers requests whose Host matches no vhost.
    /// When unset, such requests get 421 Misdirected Request.
    #[serde(default)]
    pub default_vhost: Option<String>,
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
    /// for the first byte of a new connection and for the next request on a
    /// kept-alive connection.
    #[schemars(range(min = 1, max = 300))]
    pub header_timeout_secs: u64,
    /// Seconds a connection may go without any bytes read or written before it
    /// is closed (for example, a client that stops reading a response).
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

/// The admin listener (`[server.admin]`): `GET /metrics` and
/// `POST /-/reload`. See the threat model, T5.1 to T5.6.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Address of the admin listener, such as `"127.0.0.1:9900"`. Keep it
    /// off public interfaces.
    pub listen: SocketAddr,
    /// Client addresses allowed to connect. Defaults to loopback only.
    #[serde(default = "default_admin_allow")]
    pub allow: Vec<IpNet>,
    /// Bearer token required for `POST /-/reload`, as a secret reference
    /// (`env:NAME` or `file:/path`). Without it, reload over HTTP is off.
    #[serde(default)]
    pub token: Option<SecretRef>,
}

fn default_admin_allow() -> Vec<IpNet> {
    ["127.0.0.0/8", "::1"]
        .into_iter()
        .filter_map(|s| IpNet::try_from(s.to_owned()).ok())
        .collect()
}

/// Debug capture (`[server.debug]`). See the threat model, T5.9 to T5.12.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DebugConfig {
    /// Write a capture log with each connection's bytes at every layer wedge
    /// sees (TCP, TLS, HTTP, routing), each step tagged with the source file
    /// that handled it.
    pub read_packet: bool,
    /// Capture log path; relative paths are relative to the master file.
    pub capture_file: PathBuf,
    /// Also record IP/TCP packet headers (sequence numbers, flags, window,
    /// retransmits) through pcap. Needs a build with the `packet-capture`
    /// feature, libpcap or Npcap, and root/admin or CAP_NET_RAW.
    pub tcp_headers: bool,
    /// Write credentials (`Authorization`, `Cookie`, `Set-Cookie`,
    /// `Proxy-Authorization` and `redact_headers`) unredacted. Breaks the
    /// "secrets never reach logs" rule while on.
    pub log_secrets: bool,
    /// More header names to redact, besides the built-in ones.
    pub redact_headers: Vec<String>,
    /// Bytes recorded per connection and direction; the rest is counted only.
    #[schemars(range(min = 0, max = 1_073_741_824))]
    pub max_bytes_per_connection: u64,
    /// Size at which the capture log is rotated.
    #[schemars(range(min = 65_536, max = 17_179_869_184_u64))]
    pub max_file_bytes: u64,
    /// Rotated files kept (`capture.log.1` ...).
    #[schemars(range(min = 1, max = 100))]
    pub keep_files: u32,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            read_packet: false,
            capture_file: PathBuf::from("capture.log"),
            tcp_headers: false,
            log_secrets: false,
            redact_headers: Vec::new(),
            max_bytes_per_connection: 64 * 1024,
            max_file_bytes: 100 * 1024 * 1024,
            keep_files: 5,
        }
    }
}

/// TLS protocol settings (`[server.tls]`). See the threat model, T3.1.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSettings {
    /// Lowest TLS version offered. Versions below 1.2 are not supported.
    pub min_version: TlsVersion,
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum TlsVersion {
    #[default]
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

/// A vhost's certificate (`[vhost.tls]`). Both values are secret references
/// (`env:NAME` or `file:/path`); relative file paths are relative to the
/// master configuration file.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VhostTls {
    /// PEM certificate chain, leaf certificate first.
    pub cert: SecretRef,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key: SecretRef,
    /// `Strict-Transport-Security` max-age on TLS responses; 0 turns HSTS off.
    #[serde(default = "default_hsts_max_age")]
    #[schemars(range(min = 0, max = 63_072_000))]
    pub hsts_max_age_secs: u64,
    /// Add `includeSubDomains` to HSTS. Only enable when every subdomain
    /// serves HTTPS.
    #[serde(default)]
    pub hsts_include_subdomains: bool,
    /// Answer plain-HTTP requests for this vhost with a 308 redirect to the
    /// first TLS listener.
    #[serde(default)]
    pub redirect_http: bool,
}

fn default_hsts_max_age() -> u64 {
    31_536_000
}

/// Response headers that `[vhost.headers]` may not set, because wedge
/// computes them or they control message framing.
pub const RESERVED_HEADERS: &[&str] = &[
    "connection",
    "content-encoding",
    "content-length",
    "content-range",
    "content-type",
    "date",
    "etag",
    "keep-alive",
    "last-modified",
    "location",
    "strict-transport-security",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "vary",
];

/// A virtual host (`[[vhost]]`).
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VirtualHost {
    /// Unique name used in logs and diagnostics.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    /// Directory served for this host. Optional when the vhost has proxy
    /// routes; requests that match no route then get 404.
    #[serde(default)]
    pub root: Option<PathBuf>,
    /// Reverse proxy routes, checked before static files.
    #[serde(default)]
    pub proxy: Vec<ProxyRoute>,
    /// Serve files reached through symbolic links. Off by default; even when
    /// on, the resolved file must still lie inside `root`.
    #[serde(default)]
    pub follow_symlinks: bool,
    /// Host names this vhost answers, such as `"example.com"` or
    /// `"*.example.com"` (any subdomain). Matching ignores case and port.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Extra response headers, such as `"Content-Security-Policy"`. A value
    /// replaces a default security header of the same name; an empty value
    /// removes it.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Certificate for TLS listeners. Without it, this vhost is not served on
    /// TLS listeners.
    #[serde(default)]
    pub tls: Option<VhostTls>,
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
            match &vhost.root {
                Some(root) if root.as_os_str().is_empty() => {
                    errors.push(format!("vhost {:?}: root must not be empty", vhost.name));
                }
                None if vhost.proxy.is_empty() => errors.push(format!(
                    "vhost {:?}: needs a root, a [[vhost.proxy]] route, or both",
                    vhost.name
                )),
                _ => {}
            }
            let mut prefixes = HashSet::new();
            for route in &vhost.proxy {
                if !valid_route_prefix(&route.path) {
                    errors.push(format!(
                        "vhost {:?}: proxy path {:?} must start with '/' and contain no \
                         empty, '.' or '..' segments, '%', '\\', '?' or '#'",
                        vhost.name, route.path
                    ));
                } else if !prefixes.insert(route.path.trim_end_matches('/')) {
                    errors.push(format!(
                        "vhost {:?}: proxy path {:?} is listed twice",
                        vhost.name, route.path
                    ));
                }
                if !self.upstream.iter().any(|u| u.name == route.upstream) {
                    errors.push(format!(
                        "vhost {:?}: proxy upstream {:?} is not defined",
                        vhost.name, route.upstream
                    ));
                }
            }
            for (name, value) in &vhost.headers {
                if let Some(problem) = header_problem(name, value) {
                    errors.push(format!(
                        "vhost {:?}: header {name:?}: {problem}",
                        vhost.name
                    ));
                }
            }
            let redirects = vhost.tls.as_ref().is_some_and(|t| t.redirect_http);
            if redirects && self.server.listen_tls.is_empty() {
                errors.push(format!(
                    "vhost {:?}: redirect_http needs a listen_tls address",
                    vhost.name
                ));
            }
        }
        let mut hosts = HashSet::new();
        for vhost in &self.vhost {
            for host in &vhost.hosts {
                if !valid_host_pattern(host) {
                    errors.push(format!(
                        "vhost {:?}: invalid host name {host:?}",
                        vhost.name
                    ));
                } else if !hosts.insert(host.to_ascii_lowercase()) {
                    errors.push(format!("host {host:?} is claimed by more than one vhost"));
                }
            }
        }
        if let Some(default) = &self.server.default_vhost {
            if !self.vhost.iter().any(|v| &v.name == default) {
                errors.push(format!("default_vhost {default:?} does not name a vhost"));
            }
        }
        let mut listen = HashSet::new();
        let admin = self.server.admin.as_ref().map(|a| &a.listen);
        for addr in self
            .server
            .listen
            .iter()
            .chain(&self.server.listen_tls)
            .chain(admin)
        {
            // Port 0 asks the OS for a free port, so those never collide.
            if addr.port() != 0 && !listen.insert(addr) {
                errors.push(format!("duplicate listen address {addr}"));
            }
        }
        if !self.server.listen_tls.is_empty() && self.vhost.iter().all(|v| v.tls.is_none()) {
            errors.push("listen_tls is set but no vhost has a [vhost.tls] certificate".into());
        }
        let mut names = HashSet::new();
        for upstream in &self.upstream {
            if !names.insert(upstream.name.as_str()) {
                errors.push(format!("duplicate upstream name {:?}", upstream.name));
            }
            for addr in &upstream.servers {
                if let Some(problem) = upstream_addr_problem(addr) {
                    errors.push(format!(
                        "upstream {:?}: server {addr}: {problem}",
                        upstream.name
                    ));
                }
            }
            if let Some(path) = &upstream.health_path {
                let valid = path.starts_with('/')
                    && path.len() <= 1024
                    && path
                        .bytes()
                        .all(|b| (b'!'..=b'~').contains(&b) && b != b'#');
                if !valid {
                    errors.push(format!(
                        "upstream {:?}: health_path must start with '/' and contain only \
                         visible ASCII",
                        upstream.name
                    ));
                }
            }
        }
        let debug = &self.server.debug;
        if !debug.read_packet && (debug.tcp_headers || debug.log_secrets) {
            errors
                .push("[server.debug] tcp_headers and log_secrets need read_packet = true".into());
        }
        for name in &debug.redact_headers {
            if header_problem(name, "").is_some_and(|p| p == "invalid header name") {
                errors.push(format!(
                    "[server.debug] redact_headers: invalid header name {name:?}"
                ));
            }
        }
        errors
    }
}

/// A proxy route prefix: starts with `/`, and has no empty (except a final
/// `/`), `.` or `..` segments and no characters that would make matching
/// ambiguous against encoded request paths (T4.13).
fn valid_route_prefix(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    path.len() <= 1024
        && path
            .bytes()
            .all(|b| (b'!'..=b'~').contains(&b) && !matches!(b, b'%' | b'\\' | b'?' | b'#'))
        && (rest.is_empty() || rest.split('/').all(|s| !matches!(s, "" | "." | "..")))
}

/// Why an upstream address is unusable (T4.2), if it is.
fn upstream_addr_problem(addr: &SocketAddr) -> Option<&'static str> {
    let ip = addr.ip();
    if addr.port() == 0 {
        return Some("port 0 is not a server port");
    }
    if ip.is_unspecified() {
        return Some("unspecified address (0.0.0.0 or ::) is not a server");
    }
    if ip.is_multicast() {
        return Some("multicast address is not a server");
    }
    if let std::net::IpAddr::V4(v4) = ip {
        if v4.is_broadcast() {
            return Some("broadcast address is not a server");
        }
    }
    None
}

/// Why a `[vhost.headers]` entry is unusable, if it is. Names must be RFC 9110
/// tokens; values must be visible ASCII, spaces or tabs (no CR/LF injection).
fn header_problem(name: &str, value: &str) -> Option<&'static str> {
    const TCHAR: &[u8] = b"!#$%&'*+-.^_`|~";
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || TCHAR.contains(&b))
    {
        return Some("invalid header name");
    }
    if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return Some("this header is managed by wedge and cannot be set");
    }
    if value.len() > 8192 {
        return Some("value is longer than 8192 bytes");
    }
    if !value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
    {
        return Some("value may contain only visible ASCII, spaces and tabs");
    }
    None
}

/// A DNS name (letters, digits, hyphens, dots; labels 1 to 63 bytes), an IP
/// literal, or `*.` followed by a DNS name.
fn valid_host_pattern(pattern: &str) -> bool {
    if pattern.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns() {
        for ok in [
            "example.com",
            "*.example.com",
            "localhost",
            "127.0.0.1",
            "::1",
            "a-b.c",
        ] {
            assert!(valid_host_pattern(ok), "{ok}");
        }
        for bad in [
            "",
            "*.",
            "a..b",
            "-a.com",
            "a_b.com",
            "*.*.com",
            "ex ample.com",
            "a.com:80",
        ] {
            assert!(!valid_host_pattern(bad), "{bad}");
        }
    }

    #[test]
    fn header_rules() {
        assert_eq!(
            header_problem("Content-Security-Policy", "default-src 'self'"),
            None
        );
        assert_eq!(header_problem("X-Frame-Options", ""), None);
        for (name, value) in [
            ("", "x"),
            ("Bad Name", "x"),
            ("X-A:", "x"),
            ("X-A", "a\r\nSet-Cookie: x=1"),
            ("X-A", "caf\u{e9}"),
            ("Content-Length", "0"),
            ("strict-transport-security", "max-age=0"),
            ("Transfer-Encoding", "chunked"),
        ] {
            assert!(header_problem(name, value).is_some(), "{name:?}: {value:?}");
        }
    }
}
