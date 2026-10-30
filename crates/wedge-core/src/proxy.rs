// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Reverse proxy (threat model T4.1 to T4.13).
//!
//! Every forwarded request is rebuilt by wedge's own HTTP/1.1 client, so raw
//! client bytes never reach an upstream (T4.4). Destinations come only from
//! configuration (T4.1). Servers are chosen round-robin among healthy ones;
//! active checks and connection failures move servers in and out (T4.11).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tokio::sync::watch;
use wedge_config::Config;

use crate::path;
use crate::response::{self, Body};

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1),
/// plus proxy credentials. Never forwarded in either direction (T4.5).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// All upstream pools and each vhost's proxy routes, built once at startup.
pub(crate) struct Proxy {
    pools: Vec<Arc<Pool>>,
    /// Indexed like the configured vhosts; longest prefix first.
    routes: Vec<Vec<Route>>,
}

/// A proxy route after validation.
pub(crate) struct Route {
    /// The configured prefix without its trailing `/`; empty for `/`.
    prefix: String,
    pool: usize,
    max_body_bytes: u64,
}

struct Pool {
    name: String,
    backends: Vec<Backend>,
    next: AtomicUsize,
    client: Client<HttpConnector, Body>,
    response_timeout: Duration,
    health_path: Option<String>,
    health_interval: Duration,
    unhealthy_after: u32,
    epoch: Instant,
}

struct Backend {
    addr: SocketAddr,
    /// Consecutive failures; the server is down at `unhealthy_after`.
    failures: AtomicU32,
    /// Milliseconds since the pool epoch of the last failure.
    last_failure_ms: AtomicU64,
}

impl Proxy {
    pub(crate) fn new(config: &Config) -> Self {
        let pools = config
            .upstream
            .iter()
            .map(|u| {
                let mut connector = HttpConnector::new();
                connector.set_connect_timeout(Some(Duration::from_secs(u.connect_timeout_secs)));
                connector.set_nodelay(true);
                connector.enforce_http(true);
                let client = Client::builder(TokioExecutor::new())
                    .timer(TokioTimer::new())
                    .pool_timer(TokioTimer::new())
                    .pool_idle_timeout(Duration::from_secs(30))
                    .pool_max_idle_per_host(32)
                    .build(connector);
                for addr in &u.servers {
                    if is_link_local(addr) {
                        tracing::warn!(
                            upstream = %u.name,
                            server = %addr,
                            "upstream is link-local (cloud metadata range)"
                        );
                    }
                }
                Arc::new(Pool {
                    name: u.name.clone(),
                    backends: u
                        .servers
                        .iter()
                        .map(|&addr| Backend {
                            addr,
                            failures: AtomicU32::new(0),
                            last_failure_ms: AtomicU64::new(0),
                        })
                        .collect(),
                    next: AtomicUsize::new(0),
                    client,
                    response_timeout: Duration::from_secs(u.response_timeout_secs),
                    health_path: u.health_path.clone(),
                    health_interval: Duration::from_secs(u.health_interval_secs),
                    unhealthy_after: u.unhealthy_after,
                    epoch: Instant::now(),
                })
            })
            .collect();
        let routes = config
            .vhost
            .iter()
            .map(|vhost| {
                let mut routes: Vec<Route> = vhost
                    .proxy
                    .iter()
                    .filter_map(|r| {
                        let pool = config.upstream.iter().position(|u| u.name == r.upstream)?;
                        Some(Route {
                            prefix: r.path.trim_end_matches('/').to_owned(),
                            pool,
                            max_body_bytes: r.max_body_bytes,
                        })
                    })
                    .collect();
                routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
                routes
            })
            .collect();
        Self { pools, routes }
    }

    /// The route of `vhost` whose prefix matches `path`: equal, or followed by
    /// `/`. So `/api` matches `/api` and `/api/x` but not `/apix`.
    pub(crate) fn route(&self, vhost: usize, path: &str) -> Option<&Route> {
        self.routes.get(vhost)?.iter().find(|r| {
            path.strip_prefix(r.prefix.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }

    /// Starts one health-check task per pool that has a `health_path`. They
    /// stop when `stop` changes.
    pub(crate) fn spawn_health_checks(&self, stop: &watch::Receiver<bool>) {
        for pool in &self.pools {
            if pool.health_path.is_some() {
                tokio::spawn(health_loop(Arc::clone(pool), stop.clone()));
            }
        }
    }

    /// Forwards `req` to the route's upstream and returns its response, or a
    /// generic 4xx/5xx that never names the upstream (T4.9).
    pub(crate) async fn forward(
        &self,
        route: &Route,
        req: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<Body> {
        let pool = &self.pools[route.pool];
        // T4.13: the upstream must resolve the same path wedge matched.
        if !path::proxy_path_ok(req.uri().path()) {
            return response::status(StatusCode::BAD_REQUEST);
        }
        let declared = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|n| n > route.max_body_bytes) {
            return close(response::status(StatusCode::PAYLOAD_TOO_LARGE));
        }
        let (parts, body) = req.into_parts();
        let has_body = declared.is_some_and(|n| n > 0)
            || parts.headers.contains_key(hyper::header::TRANSFER_ENCODING);
        // T4.11: only requests without a body and with a safe method are
        // retried, and only when no connection could be made.
        let retryable =
            !has_body && matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);

        let mut headers = parts.headers;
        strip_hop_by_hop(&mut headers);
        if !headers.contains_key(HOST) {
            // HTTP/2 clients send :authority instead of Host.
            if let Some(value) = parts
                .uri
                .authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
            {
                headers.insert(HOST, value);
            }
        }
        let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());

        let too_large = Arc::new(AtomicBool::new(false));
        let mut body = Some(if has_body {
            let flag = Arc::clone(&too_large);
            Limited::new(
                body,
                usize::try_from(route.max_body_bytes).unwrap_or(usize::MAX),
            )
            .map_err(move |e| {
                if e.downcast_ref::<LengthLimitError>().is_some() {
                    flag.store(true, Ordering::Relaxed);
                }
                std::io::Error::other(e)
            })
            .boxed()
        } else {
            response::empty()
        });

        let attempts = if retryable { pool.backends.len() } else { 1 };
        for _ in 0..attempts {
            let Some(backend) = pool.pick() else {
                tracing::warn!(upstream = %pool.name, "no healthy upstream server");
                return response::status(StatusCode::SERVICE_UNAVAILABLE);
            };
            let Ok(uri) = format!("http://{}{path_and_query}", backend.addr).parse::<hyper::Uri>()
            else {
                return response::status(StatusCode::BAD_REQUEST);
            };
            let mut upstream_req = Request::new(if retryable {
                response::empty()
            } else {
                body.take().unwrap_or_else(response::empty)
            });
            *upstream_req.method_mut() = parts.method.clone();
            *upstream_req.uri_mut() = uri;
            *upstream_req.version_mut() = Version::HTTP_11;
            *upstream_req.headers_mut() = headers.clone();

            let sent =
                tokio::time::timeout(pool.response_timeout, pool.client.request(upstream_req));
            match sent.await {
                Ok(Ok(upstream_res)) => {
                    pool.success(backend);
                    return into_client_response(upstream_res);
                }
                Ok(Err(e)) if e.is_connect() => {
                    pool.failure(backend);
                    tracing::warn!(
                        upstream = %pool.name,
                        server = %backend.addr,
                        %peer,
                        error = %e,
                        "upstream connect failed"
                    );
                }
                Ok(Err(e)) => {
                    if too_large.load(Ordering::Relaxed) {
                        return close(response::status(StatusCode::PAYLOAD_TOO_LARGE));
                    }
                    tracing::warn!(
                        upstream = %pool.name,
                        server = %backend.addr,
                        %peer,
                        error = %e,
                        "upstream request failed"
                    );
                    return response::status(StatusCode::BAD_GATEWAY);
                }
                Err(_) => {
                    tracing::warn!(
                        upstream = %pool.name,
                        server = %backend.addr,
                        %peer,
                        "upstream response timed out"
                    );
                    return response::status(StatusCode::GATEWAY_TIMEOUT);
                }
            }
        }
        response::status(StatusCode::BAD_GATEWAY)
    }
}

impl Pool {
    /// The next healthy server in turn. A server that is down only because of
    /// failed connections (no active checks) gets another try after the
    /// health interval, so it can recover.
    fn pick(&self) -> Option<&Backend> {
        let count = self.backends.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        (0..count)
            .map(|i| &self.backends[(start + i) % count])
            .find(|b| self.is_up(b))
    }

    fn is_up(&self, backend: &Backend) -> bool {
        if backend.failures.load(Ordering::Relaxed) < self.unhealthy_after {
            return true;
        }
        if self.health_path.is_some() {
            return false;
        }
        let since = self.now_ms() - backend.last_failure_ms.load(Ordering::Relaxed);
        u128::from(since) >= self.health_interval.as_millis()
    }

    fn success(&self, backend: &Backend) {
        if backend.failures.swap(0, Ordering::Relaxed) >= self.unhealthy_after {
            tracing::info!(upstream = %self.name, server = %backend.addr, "upstream server is up");
        }
    }

    fn failure(&self, backend: &Backend) {
        backend
            .last_failure_ms
            .store(self.now_ms(), Ordering::Relaxed);
        let failures = backend.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures == self.unhealthy_after {
            tracing::warn!(upstream = %self.name, server = %backend.addr, "upstream server is down");
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

async fn health_loop(pool: Arc<Pool>, mut stop: watch::Receiver<bool>) {
    let Some(path) = pool.health_path.clone() else {
        return;
    };
    let mut ticker = tokio::time::interval(pool.health_interval);
    let budget = pool.health_interval.min(pool.response_timeout);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = stop.changed() => return,
        }
        for backend in &pool.backends {
            let Ok(uri) = format!("http://{}{path}", backend.addr).parse::<hyper::Uri>() else {
                return;
            };
            let mut req = Request::new(response::empty());
            *req.uri_mut() = uri;
            let healthy = matches!(
                tokio::time::timeout(budget, pool.client.request(req)).await,
                Ok(Ok(res)) if res.status().is_success() || res.status().is_redirection()
            );
            if healthy {
                pool.success(backend);
            } else {
                pool.failure(backend);
            }
        }
    }
}

/// Removes hop-by-hop headers and every header that `Connection` names
/// (T4.5). Used on requests and responses.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

fn into_client_response(upstream: Response<Incoming>) -> Response<Body> {
    let (mut parts, body) = upstream.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, body.map_err(std::io::Error::other).boxed())
}

fn close(mut response: Response<Body>) -> Response<Body> {
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

/// 169.254.0.0/16 and fe80::/10, which include cloud metadata endpoints (T4.2).
fn is_link_local(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_and_connection_named_headers_are_removed() {
        let mut headers = HeaderMap::new();
        for (k, v) in [
            ("connection", "keep-alive, X-Secret-Token"),
            ("x-secret-token", "1"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("te", "trailers"),
            ("proxy-authorization", "Basic x"),
            ("x-kept", "yes"),
        ] {
            headers.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        strip_hop_by_hop(&mut headers);
        let left: Vec<_> = headers.keys().map(HeaderName::as_str).collect();
        assert_eq!(left, ["x-kept"]);
    }

    #[test]
    fn route_prefixes_match_on_segment_boundaries() {
        let config = wedge_config::from_str(
            "[[upstream]]\nname = \"u\"\nservers = [\"127.0.0.1:9\"]\n\
             [[vhost]]\nname = \"v\"\n\
             [[vhost.proxy]]\npath = \"/api\"\nupstream = \"u\"\n\
             [[vhost.proxy]]\npath = \"/api/v2/\"\nupstream = \"u\"\nmax_body_bytes = 1\n\
             [[vhost.proxy]]\npath = \"/\"\nupstream = \"u\"\nmax_body_bytes = 2\n",
        )
        .unwrap();
        let proxy = Proxy::new(&config);
        let limit = |path: &str| proxy.route(0, path).map(|r| r.max_body_bytes);
        let default = 10 * 1024 * 1024;
        assert_eq!(limit("/api"), Some(default));
        assert_eq!(limit("/api/x"), Some(default));
        assert_eq!(limit("/api/v2"), Some(1));
        assert_eq!(limit("/api/v2/x"), Some(1));
        assert_eq!(limit("/apix"), Some(2), "falls through to /");
        assert_eq!(limit("/"), Some(2));
    }
}
