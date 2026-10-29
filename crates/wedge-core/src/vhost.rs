// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Chooses the virtual host for a request from its Host header (HTTP/1) or
//! `:authority` (HTTP/2). The host is only ever compared against configured
//! names; it is never used to build a file path (threat model T2.16).

use std::collections::HashMap;

use hyper::header::{HeaderMap, HOST};
use hyper::Uri;
use wedge_config::Config;

/// Outcome of routing a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// Index into the configured vhosts.
    Vhost(usize),
    /// No vhost claims this host and no default is set: 421.
    Misdirected,
    /// Missing, repeated or malformed Host: 400.
    BadHost,
}

/// Host-name lookup table built once at startup.
#[derive(Debug, Default)]
pub(crate) struct Router {
    exact: HashMap<String, usize>,
    /// (".example.com", index), longest suffix first.
    wildcards: Vec<(String, usize)>,
    default: Option<usize>,
}

impl Router {
    pub(crate) fn new(config: &Config) -> Self {
        let mut router = Self::default();
        for (index, vhost) in config.vhost.iter().enumerate() {
            for host in &vhost.hosts {
                let host = host.to_ascii_lowercase();
                match host.strip_prefix('*') {
                    Some(suffix) => router.wildcards.push((suffix.to_owned(), index)),
                    None => {
                        router.exact.insert(host, index);
                    }
                }
            }
        }
        router
            .wildcards
            .sort_by_key(|w| std::cmp::Reverse(w.0.len()));
        router.default = config
            .server
            .default_vhost
            .as_ref()
            .and_then(|name| config.vhost.iter().position(|v| &v.name == name));
        router
    }

    pub(crate) fn route(&self, uri: &Uri, headers: &HeaderMap) -> Route {
        let Some(host) = request_host(uri, headers) else {
            return Route::BadHost;
        };
        if let Some(&index) = self.exact.get(&host) {
            return Route::Vhost(index);
        }
        for (suffix, index) in &self.wildcards {
            // "*.example.com" needs at least one label before the suffix.
            if host.len() > suffix.len() && host.ends_with(suffix.as_str()) {
                return Route::Vhost(*index);
            }
        }
        self.default.map_or(Route::Misdirected, Route::Vhost)
    }
}

/// Extracts and normalizes the request host: lower case, no port, no trailing
/// dot. Exactly one Host header is required unless the URI carries an
/// authority (HTTP/2, or HTTP/1 absolute-form).
fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(HOST).iter();
    let header = values.next();
    if values.next().is_some() {
        return None;
    }
    let raw = match (uri.authority(), header) {
        (Some(authority), _) => authority.host().to_owned(),
        (None, Some(value)) => {
            let authority: hyper::http::uri::Authority = value.to_str().ok()?.parse().ok()?;
            if authority.as_str().contains('@') {
                return None;
            }
            authority.host().to_owned()
        }
        (None, None) => return None,
    };
    let host = raw.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'[' | b']' | b':'));
    valid.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn router(default: Option<&str>) -> Router {
        let default = default.map_or(String::new(), |d| format!("default_vhost = {d:?}\n"));
        let text = format!(
            "[server]\n{default}\
             [[vhost]]\nname = \"main\"\nroot = \"/a\"\nhosts = [\"example.com\", \"www.example.com\"]\n\
             [[vhost]]\nname = \"apps\"\nroot = \"/b\"\nhosts = [\"*.apps.example.com\"]\n\
             [[vhost]]\nname = \"any\"\nroot = \"/c\"\nhosts = [\"*.example.com\"]\n"
        );
        Router::new(&wedge_config::from_str(&text).unwrap())
    }

    fn host(router: &Router, value: &str) -> Route {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(value).unwrap());
        router.route(&Uri::from_static("/"), &headers)
    }

    #[test]
    fn exact_and_wildcard_matching() {
        let r = router(None);
        assert_eq!(host(&r, "example.com"), Route::Vhost(0));
        assert_eq!(host(&r, "WWW.Example.COM:8443"), Route::Vhost(0));
        assert_eq!(host(&r, "example.com."), Route::Vhost(0));
        assert_eq!(host(&r, "x.apps.example.com"), Route::Vhost(1));
        assert_eq!(host(&r, "a.b.example.com"), Route::Vhost(2));
        // The bare suffix is not a subdomain of itself.
        assert_eq!(host(&r, "apps.example.com"), Route::Vhost(2));
    }

    #[test]
    fn unknown_host_uses_default_or_421() {
        assert_eq!(host(&router(None), "evil.test"), Route::Misdirected);
        assert_eq!(host(&router(Some("any")), "evil.test"), Route::Vhost(2));
        assert_eq!(host(&router(None), "notexample.com"), Route::Misdirected);
    }

    #[test]
    fn bad_hosts_are_rejected() {
        let r = router(Some("main"));
        assert_eq!(
            r.route(&Uri::from_static("/"), &HeaderMap::new()),
            Route::BadHost
        );
        assert_eq!(host(&r, "user@example.com"), Route::BadHost);
        assert_eq!(host(&r, "exa mple.com"), Route::BadHost);
        let mut two = HeaderMap::new();
        two.append(HOST, HeaderValue::from_static("example.com"));
        two.append(HOST, HeaderValue::from_static("evil.test"));
        assert_eq!(r.route(&Uri::from_static("/"), &two), Route::BadHost);
    }

    #[test]
    fn authority_in_uri_wins() {
        let r = router(None);
        let uri: Uri = "https://example.com/x".parse().unwrap();
        assert_eq!(r.route(&uri, &HeaderMap::new()), Route::Vhost(0));
    }
}
