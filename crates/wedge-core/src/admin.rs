// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Requests on the admin listener (threat model T5.1 to T5.3, T5.13 to
//! T5.16). The client address was already checked against `admin.allow`
//! before any HTTP was read.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::header::{
    HeaderValue, ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    LOCATION, REFERRER_POLICY, RETRY_AFTER, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use hyper::{Method, Request, Response, StatusCode};

use wedge_config::{Config, Secret};

use crate::metrics::Metrics;
use crate::proxy::Proxy;
use crate::response::{self, Body};

/// Answers `GET /metrics`; anything else here is 404 or 405.
pub(crate) fn respond(metrics: &Metrics, proxy: &Proxy, req: &Request<Incoming>) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET | &Method::HEAD, "/metrics") => {
            let text = metrics.render(&proxy.health_snapshot());
            let mut response = Response::new(response::full(text));
            let headers = response.headers_mut();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        (_, "/metrics") => response::status(StatusCode::METHOD_NOT_ALLOWED),
        _ => response::status(StatusCode::NOT_FOUND),
    }
}

/// Checks the request's method for a reload: only `POST`.
pub(crate) fn reload_method_rejection(req: &Request<Incoming>) -> Option<Response<Body>> {
    if req.method() == Method::POST {
        return None;
    }
    let mut response = response::status(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static("POST"));
    Some(response)
}

/// Whether the request carries the configured bearer token.
pub(crate) fn has_token(req: &Request<Incoming>, token: &Secret) -> bool {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.as_bytes().strip_prefix(b"Bearer "))
        .unwrap_or_default();
    constant_time_eq(token.expose(), presented)
}

/// Whether the request uses bearer authentication at all.
pub(crate) fn is_bearer(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"Bearer "))
}

/// 401 asking for a bearer token.
pub(crate) fn bearer_challenge() -> Response<Body> {
    let mut response = response::status(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// 401 asking the browser for the administrator name and password.
pub(crate) fn login_challenge() -> Response<Body> {
    let mut response = response::status(StatusCode::UNAUTHORIZED);
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"wedge admin\", charset=\"UTF-8\""),
    );
    response
}

/// 429 while an address is locked out after failed logins.
pub(crate) fn locked_out(wait: Duration) -> Response<Body> {
    let mut response = Response::new(response::full(
        "too many failed logins from this address; try again later\n",
    ));
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let seconds = wait.as_secs().max(1).to_string();
    if let Ok(value) = HeaderValue::from_str(&seconds) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// Compares in time that depends only on the length of `expected`, so the
/// token cannot be guessed byte by byte from response times.
fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    let mut diff = u8::from(expected.len() != presented.len());
    for (i, byte) in expected.iter().enumerate() {
        diff |= byte ^ presented.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// The request's host is an IP literal or `localhost`, never a DNS name that
/// an attacker could point at 127.0.0.1 (T5.3).
pub(crate) fn host_is_local(req: &Request<Incoming>) -> bool {
    request_host(req).is_some_and(|h| {
        let bare = h.trim_start_matches('[').trim_end_matches(']');
        h.eq_ignore_ascii_case("localhost") || bare.parse::<std::net::IpAddr>().is_ok()
    })
}

fn request_host(req: &Request<Incoming>) -> Option<String> {
    req.uri().host().map(str::to_owned).or_else(|| {
        let value = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
        let authority: hyper::http::uri::Authority = value.parse().ok()?;
        Some(authority.host().to_owned())
    })
}

/// T5.15: a state-changing request from a browser must come from the admin
/// page itself. Browsers send `Origin` (and `Sec-Fetch-Site`) on form posts,
/// and a page on another site cannot forge them; clients such as curl send
/// neither and are allowed.
pub(crate) fn same_origin(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    if let Some(site) = headers.get("sec-fetch-site") {
        if !matches!(site.as_bytes(), b"same-origin" | b"none") {
            return false;
        }
    }
    let Some(origin) = headers.get(hyper::header::ORIGIN) else {
        return true;
    };
    let Some(host) = headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(|rest| rest.eq_ignore_ascii_case(host))
}

/// One vhost as the status page lists it.
pub(crate) struct VhostInfo {
    name: String,
    hosts: String,
    serves: String,
}

impl VhostInfo {
    pub(crate) fn from_config(config: &Config) -> Vec<Self> {
        config
            .vhost
            .iter()
            .map(|v| {
                let mut serves = Vec::new();
                if let Some(root) = &v.root {
                    serves.push(format!("files from {}", root.display()));
                }
                for route in &v.proxy {
                    serves.push(format!(
                        "{} \u{2192} upstream {}",
                        route.path, route.upstream
                    ));
                }
                Self {
                    name: v.name.clone(),
                    hosts: if v.hosts.is_empty() {
                        "(any)".to_owned()
                    } else {
                        v.hosts.join(", ")
                    },
                    serves: serves.join("; "),
                }
            })
            .collect()
    }
}

/// What the status page shows.
pub(crate) struct Status<'a> {
    pub(crate) user: &'a str,
    pub(crate) uptime: Duration,
    pub(crate) listeners: &'a [(SocketAddr, &'static str)],
    pub(crate) vhosts: &'a [VhostInfo],
    pub(crate) metrics: &'a Metrics,
    pub(crate) proxy: &'a Proxy,
    /// The last reload's outcome, shown once after the Reload button.
    pub(crate) notice: Option<(bool, String)>,
}

const STYLE: &str = "\
body{font-family:system-ui,sans-serif;margin:0;color:#1d2330;background:#f5f6f8}\
header{background:#14365d;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}\
h1{font-size:20px;margin:0}main{max-width:960px;margin:0 auto;padding:16px 24px}\
section{background:#fff;border:1px solid #d9dde3;border-radius:6px;padding:12px 16px;margin:12px 0}\
h2{font-size:16px;margin:0 0 8px}table{border-collapse:collapse;width:100%}\
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef1;vertical-align:top}\
.ok{color:#1a7f37}.bad{color:#b42318}.note{padding:8px 12px;border-radius:4px;margin:12px 0}\
.note.ok{background:#e6f4ea}.note.bad{background:#fdecea}\
button{background:#14365d;color:#fff;border:0;border-radius:4px;padding:8px 16px;cursor:pointer}\
small{color:#5b6472}";

/// `GET /-/admin.css`.
pub(crate) fn stylesheet() -> Response<Body> {
    let mut response = Response::new(response::full(STYLE));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// `GET /`: the status page. Every value from configuration or requests is
/// HTML-escaped; the page loads nothing but its own stylesheet.
pub(crate) fn status_page(status: &Status<'_>) -> Response<Body> {
    let mut html = String::with_capacity(8192);
    let _ = write!(
        html,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>wEdge admin</title><link rel=\"stylesheet\" href=\"/-/admin.css\"></head><body>\
         <header><h1>wEdge admin</h1><span>Signed in as {}</span></header><main>",
        escape(status.user)
    );
    if let Some((ok, message)) = &status.notice {
        let class = if *ok { "ok" } else { "bad" };
        let _ = write!(
            html,
            "<div class=\"note {class}\">{}</div>",
            escape(message)
        );
    }
    let totals = status.metrics.totals();
    let _ = write!(
        html,
        "<section><h2>Server</h2><table>\
         <tr><th>Version</th><td>{}</td></tr>\
         <tr><th>Running for</th><td>{}</td></tr>\
         <tr><th>Open connections</th><td>{}</td></tr>\
         <tr><th>Connections since start</th><td>{}</td></tr>\
         <tr><th>Requests answered</th><td>{}</td></tr>\
         </table></section>",
        crate::VERSION,
        duration_text(status.uptime),
        totals.open_connections,
        totals.connections,
        totals.requests
    );
    html.push_str("<section><h2>Listeners</h2><table><tr><th>Address</th><th>Serves</th></tr>");
    for (addr, kind) in status.listeners {
        let _ = write!(html, "<tr><td>{addr}</td><td>{kind}</td></tr>");
    }
    html.push_str("</table></section>");
    html.push_str(
        "<section><h2>Virtual hosts</h2><table>\
         <tr><th>Name</th><th>Host names</th><th>Serves</th><th>Requests</th></tr>",
    );
    for (vhost, requests) in status.vhosts.iter().zip(&totals.per_vhost) {
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{requests}</td></tr>",
            escape(&vhost.name),
            escape(&vhost.hosts),
            escape(&vhost.serves)
        );
    }
    html.push_str("</table></section>");
    let servers = status.proxy.health_snapshot();
    if !servers.is_empty() {
        html.push_str(
            "<section><h2>Upstream servers</h2><table>\
             <tr><th>Upstream</th><th>Server</th><th>Health</th></tr>",
        );
        for (upstream, server, up) in &servers {
            let (class, text) = if *up { ("ok", "up") } else { ("bad", "down") };
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td class=\"{class}\">{text}</td></tr>",
                escape(upstream),
                escape(server)
            );
        }
        html.push_str("</table></section>");
    }
    html.push_str(
        "<section><h2>Configuration</h2>\
         <p>Edit the configuration file, then reload it here. A reload that fails keeps the \
         running configuration; listeners, limits and this admin section need a service \
         restart.</p>\
         <form method=\"post\" action=\"/-/reload\"><button type=\"submit\">Reload \
         configuration</button></form></section>\
         <p><small><a href=\"/metrics\">Prometheus metrics</a> \u{b7} \
         To sign out, close the browser.</small></p></main></body></html>",
    );
    let mut response = Response::new(response::full(html));
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    secure_page_headers(headers);
    response
}

/// Headers for every admin HTML response: no caching, no framing, no
/// scripts, forms only to this origin (T5.16).
fn secure_page_headers(headers: &mut hyper::HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
}

/// After the Reload button: back to the status page, which shows the result.
pub(crate) fn see_status_page() -> Response<Body> {
    let mut response = response::status(StatusCode::SEE_OTHER);
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    response
}

/// Whether the client is a browser that wants a page rather than text.
pub(crate) fn wants_html(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

fn duration_text(d: Duration) -> String {
    let secs = d.as_secs();
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    if days > 0 {
        format!("{days} d {hours} h {minutes} min")
    } else if hours > 0 {
        format!("{hours} h {minutes} min")
    } else {
        format!("{minutes} min {} s", secs % 60)
    }
}

/// Escapes text for HTML element content and quoted attributes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralises_markup() {
        assert_eq!(
            escape("<script>alert('x')</script>&\""),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;"
        );
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration_text(Duration::from_secs(59)), "0 min 59 s");
        assert_eq!(duration_text(Duration::from_secs(3_660)), "1 h 1 min");
        assert_eq!(duration_text(Duration::from_secs(90_061)), "1 d 1 h 1 min");
    }
}
