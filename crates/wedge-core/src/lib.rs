// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Core server for wedge: listeners, connection handling and request routing.

mod admin;
mod files;
mod headers;
mod idle;
mod metrics;
mod path;
mod proxy;
mod response;
mod server;
mod tls;
mod vhost;

pub use response::Body;
pub use server::{Server, ServerError};
pub use tls::TlsError;

/// Entry points for the fuzz targets in `fuzz/`. Not a stable API.
#[doc(hidden)]
pub mod fuzzing {
    /// Parses a raw request path and panics if an accepted path could escape
    /// a document root or reach a hidden file.
    pub fn check_request_path(raw: &str) {
        let Ok(safe) = crate::path::parse(raw) else {
            return;
        };
        for (index, segment) in safe.segments.iter().enumerate() {
            assert!(!segment.is_empty() && segment != "." && segment != "..");
            assert!(!segment.contains(['/', '\\', ':', '\0']), "{segment:?}");
            assert!(!segment.chars().any(char::is_control), "{segment:?}");
            assert!(
                !segment.starts_with('.') || (index == 0 && segment == ".well-known"),
                "{segment:?}"
            );
        }
    }

    /// Splits `input` at the first NUL into a request path and header lines
    /// (`name: value`), runs the proxy's path check and header sanitiser, and
    /// panics if an accepted path could resolve outside its route on the
    /// upstream (T4.13), or a hop-by-hop or client-forged forwarding header
    /// survives (T4.5, T4.6).
    pub fn check_proxy_request(input: &str) {
        use hyper::header::{HeaderMap, HeaderName, HeaderValue};

        let (raw_path, header_text) = input.split_once('\0').unwrap_or((input, ""));
        if crate::path::proxy_path_ok(raw_path) {
            for segment in raw_path[1..].split('/') {
                let decoded = crate::path::percent_decode(segment.as_bytes());
                assert!(decoded.is_some(), "accepted path must decode: {raw_path:?}");
                let decoded = decoded.unwrap_or_default();
                assert!(decoded != b"." && decoded != b"..", "{raw_path:?}");
                assert!(
                    !decoded.iter().any(|b| matches!(b, b'/' | b'\\' | 0)),
                    "{raw_path:?}"
                );
            }
        }

        let mut headers = HeaderMap::new();
        for line in header_text.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.trim().as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) else {
                continue;
            };
            headers.append(name, value);
        }
        let named: Vec<HeaderName> = headers
            .get_all(hyper::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
            .collect();
        crate::proxy::strip_hop_by_hop(&mut headers);
        let peer: std::net::SocketAddr = ([192, 0, 2, 1], 1234).into();
        crate::proxy::set_forwarding_headers(&mut headers, peer, false, false);

        const SET_BY_WEDGE: &[&str] = &["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"];
        for name in crate::proxy::HOP_BY_HOP
            .iter()
            .chain(&["x-real-ip", "forwarded"])
        {
            assert!(!headers.contains_key(*name), "{name} survived");
        }
        for name in &named {
            assert!(
                SET_BY_WEDGE.contains(&name.as_str()) || !headers.contains_key(name),
                "{name} named in Connection survived"
            );
        }
        let xff: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
        assert_eq!(
            xff,
            ["192.0.2.1"],
            "client-supplied X-Forwarded-For survived"
        );
        assert_eq!(headers.get_all("x-forwarded-proto").iter().count(), 1);
    }
}

/// Crate version, taken from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn fuzz_checks_hold_for_hostile_samples() {
        for input in [
            "/api/%2e%2e/admin\0Connection: X-Forwarded-For, x-a\nx-a: 1",
            "/api/x\0X-Forwarded-For: 6.6.6.6\nX-Forwarded-For: 7.7.7.7\nForwarded: for=x",
            "/api/x\0Connection: x-forwarded-proto\nX-Forwarded-Proto: https\nTE: trailers",
            "/\0Upgrade: h2c\nProxy-Connection: keep-alive\nX-Real-IP: 1.1.1.1",
            "relative\0",
        ] {
            fuzzing::check_proxy_request(input);
        }
    }
}
