// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Response header policy and the HTTP to HTTPS redirect (threat model T3.11
//! to T3.13).
//!
//! Every response gets the default security headers. A vhost may replace or
//! remove them with `[vhost.headers]`. HSTS goes only on TLS responses, as
//! RFC 6797 §7.2 requires.

use hyper::header::{HeaderName, HeaderValue, LOCATION, STRICT_TRANSPORT_SECURITY};
use hyper::{Response, StatusCode, Uri};
use wedge_config::Config;

use crate::response::{self, Body};
use crate::vhost::Router;

/// Headers added to every response unless a vhost overrides them.
const DEFAULTS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "SAMEORIGIN"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
];

/// A header to set (`Some`) or remove (`None`).
type Rule = (HeaderName, Option<HeaderValue>);

/// Header rules for all vhosts, built once at startup.
pub(crate) struct Policy {
    defaults: Vec<Rule>,
    vhosts: Vec<VhostPolicy>,
    /// Port of the first TLS listener, for redirects; `None` means 443.
    https_port: Option<u16>,
}

struct VhostPolicy {
    rules: Vec<Rule>,
    hsts: Option<HeaderValue>,
    redirect_http: bool,
    /// First non-wildcard host name, used when the request's host is not
    /// one of this vhost's names (T3.12).
    canonical_host: Option<String>,
}

impl Policy {
    /// Fails only if a header that passed config validation is still rejected
    /// by the HTTP library, which would be a bug in that validation.
    pub(crate) fn new(config: &Config) -> Result<Self, String> {
        let defaults: Vec<Rule> = DEFAULTS
            .iter()
            .map(|(n, v)| {
                (
                    HeaderName::from_static(n),
                    Some(HeaderValue::from_static(v)),
                )
            })
            .collect();
        let mut vhosts = Vec::with_capacity(config.vhost.len());
        for vhost in &config.vhost {
            let mut rules = defaults.clone();
            for (name, value) in &vhost.headers {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| format!("vhost {:?}: bad header name {name:?}", vhost.name))?;
                let value = if value.is_empty() {
                    None
                } else {
                    Some(HeaderValue::from_str(value).map_err(|_| {
                        format!("vhost {:?}: bad value for header {name}", vhost.name)
                    })?)
                };
                rules.retain(|(existing, _)| *existing != name);
                rules.push((name, value));
            }
            let hsts = vhost
                .tls
                .as_ref()
                .filter(|t| t.hsts_max_age_secs > 0)
                .map(|t| {
                    let sub = if t.hsts_include_subdomains {
                        "; includeSubDomains"
                    } else {
                        ""
                    };
                    let text = format!("max-age={}{sub}", t.hsts_max_age_secs);
                    HeaderValue::from_str(&text).unwrap_or(HeaderValue::from_static("max-age=0"))
                });
            vhosts.push(VhostPolicy {
                rules,
                hsts,
                redirect_http: vhost.tls.as_ref().is_some_and(|t| t.redirect_http),
                canonical_host: vhost
                    .hosts
                    .iter()
                    .find(|h| !h.starts_with('*'))
                    .map(|h| h.to_ascii_lowercase()),
            });
        }
        let https_port = config
            .server
            .listen_tls
            .first()
            .map(std::net::SocketAddr::port)
            .filter(|&p| p != 443);
        Ok(Self {
            defaults,
            vhosts,
            https_port,
        })
    }

    /// The port to put in redirects, once the real bound port is known.
    pub(crate) fn set_https_port(&mut self, port: u16) {
        self.https_port = (port != 443).then_some(port);
    }

    /// Applies the header rules of `vhost` (or the defaults), and HSTS when
    /// the response goes out over TLS for `tls_vhost`.
    pub(crate) fn apply(
        &self,
        response: &mut Response<Body>,
        vhost: Option<usize>,
        tls_vhost: Option<usize>,
    ) {
        let rules = vhost
            .and_then(|i| self.vhosts.get(i))
            .map_or(&self.defaults, |v| &v.rules);
        let headers = response.headers_mut();
        for (name, value) in rules {
            match value {
                Some(value) => {
                    headers.insert(name.clone(), value.clone());
                }
                None => {
                    headers.remove(name);
                }
            }
        }
        if let Some(hsts) = tls_vhost
            .and_then(|i| self.vhosts.get(i))
            .and_then(|v| v.hsts.as_ref())
        {
            headers.insert(STRICT_TRANSPORT_SECURITY, hsts.clone());
        }
    }

    /// For a plain-HTTP request routed to `vhost`, the 308 redirect to HTTPS,
    /// if that vhost asks for one. The target host is the request's host only
    /// when it is one of the vhost's names, so a spoofed Host cannot turn
    /// this into an open redirect (T3.12).
    pub(crate) fn https_redirect(
        &self,
        router: &Router,
        vhost: usize,
        request_host: Option<&str>,
        uri: &Uri,
    ) -> Option<Response<Body>> {
        let policy = self.vhosts.get(vhost).filter(|v| v.redirect_http)?;
        let host = request_host
            .filter(|h| router.lookup(h) == Some(vhost))
            .or(policy.canonical_host.as_deref())?;
        let port = self.https_port.map_or(String::new(), |p| format!(":{p}"));
        let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
        let location = HeaderValue::from_str(&format!("https://{host}{port}{path}")).ok()?;
        let mut response = response::status(StatusCode::PERMANENT_REDIRECT);
        response.headers_mut().insert(LOCATION, location);
        Some(response)
    }
}
