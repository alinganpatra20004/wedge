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
        self.lookup(&host)
            .or(self.default)
            .map_or(Route::Misdirected, Route::Vhost)
    }

    /// The vhost that claims `host` (lower case, no port), ignoring the default.
    pub(crate) fn lookup(&self, host: &str) -> Option<usize> {
        if let Some(&index) = self.exact.get(host) {
            return Some(index);
        }
        // "*.example.com" needs at least one label before the suffix.
        self.wildcards
            .iter()
            .find(|(suffix, _)| host.len() > suffix.len() && host.ends_with(suffix.as_str()))
            .map(|&(_, index)| index)
    }

    /// The vhost for requests whose host no vhost claims.
    pub(crate) fn default_vhost(&self) -> Option<usize> {
        self.default
    }
}

/// Extracts and normalizes the request host: lower case, no port, no trailing
/// dot. Exactly one Host header is required unless the URI carries an
/// authority (HTTP/2, or HTTP/1 absolute-form).
pub(crate) fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(HOST).iter();
    let header = values.next();
    if values.next().is_some() {
        return None;
    }
    let authority = match (uri.authority(), header) {
        (Some(authority), _) => authority.clone(),
        (None, Some(value)) => value.to_str().ok()?.parse().ok()?,
        (None, None) => return None,
    };
    // RFC 9110 4.2.4 and 7.2: userinfo is an error, and a Host with an
    // invalid value (such as a port above 65535) gets 400.
    // (Authority::port() is None for an unparsable port, so check the text;
    // a ']' after the last ':' means it is inside an IPv6 literal.)
    let port_ok = match authority.as_str().rsplit_once(':') {
        Some((_, port)) if !port.contains(']') => port.is_empty() || port.parse::<u16>().is_ok(),
        _ => true,
    };
    if authority.as_str().contains('@') || !port_ok {
        return None;
    }
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
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
        assert_eq!(host(&r, "example.com:99999"), Route::BadHost);
        assert_eq!(host(&r, "example.com:8080"), Route::Vhost(0));
        assert_eq!(
            host(&r, "example.com:"),
            Route::Vhost(0),
            "empty port is allowed"
        );
        assert_eq!(host(&r, "[::1]"), Route::Vhost(0), "default vhost");
        assert_eq!(host(&r, "[::1]:8080"), Route::Vhost(0), "default vhost");
        assert_eq!(host(&r, "[::1]:99999"), Route::BadHost);
        for target in ["http://example.com:99999/", "http://user@example.com/"] {
            let uri: Uri = target.parse().unwrap();
            assert_eq!(r.route(&uri, &HeaderMap::new()), Route::BadHost, "{target}");
        }
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
