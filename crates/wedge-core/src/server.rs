// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Listeners, the accept loop and per-connection protocol settings.
//!
//! Limits enforced here (threat model T2.5 to T2.8): a global connection cap,
//! a header read timeout, an idle timeout on the socket, header size and
//! count caps, a URI length cap, a per-request timeout, and HTTP/2 stream and
//! reset-flood limits. TLS listeners add a bounded handshake (T3.5) and the
//! SNI/Host check (T3.4).

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use wedge_config::{Config, Limits};

use crate::files::{self, Root};
use crate::headers::Policy;
use crate::idle::IdleTimeout;
use crate::response::{self, Body};
use crate::tls::{Tls, TlsError};
use crate::vhost::{request_host, Route, Router};

/// Errors that stop the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("no listen addresses configured")]
    NoListeners,
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("document root of vhost {vhost:?} is not accessible: {source}")]
    Root {
        vhost: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("invalid response header configuration: {0}")]
    Headers(String),
}

/// A server with its listeners bound, ready to run.
pub struct Server {
    /// Each listener with whether it terminates TLS.
    listeners: Vec<(TcpListener, bool)>,
    state: Arc<State>,
}

/// Shared, read-only state for all connections.
struct State {
    limits: Limits,
    roots: Vec<Root>,
    router: Router,
    tls: Option<Tls>,
    headers: Policy,
}

/// Per-connection facts passed to every request on it.
#[derive(Clone, Copy)]
struct Conn {
    peer: SocketAddr,
    /// For TLS connections, the vhost whose certificate was served.
    tls_vhost: Option<usize>,
}

impl Server {
    /// Loads certificates, then binds every configured listen address.
    pub async fn bind(config: &Config) -> Result<Self, ServerError> {
        if config.server.listen.is_empty() && config.server.listen_tls.is_empty() {
            return Err(ServerError::NoListeners);
        }
        let tls = Tls::from_config(config)?;
        let mut listeners = Vec::new();
        let plain = config.server.listen.iter().map(|a| (*a, false));
        let secure = config.server.listen_tls.iter().map(|a| (*a, true));
        for (addr, is_tls) in plain.chain(secure) {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| ServerError::Bind { addr, source })?;
            listeners.push((listener, is_tls));
        }
        let mut roots = Vec::new();
        for vhost in &config.vhost {
            let dir = tokio::fs::canonicalize(&vhost.root)
                .await
                .map_err(|source| ServerError::Root {
                    vhost: vhost.name.clone(),
                    source,
                })?;
            roots.push(Root {
                dir,
                follow_symlinks: vhost.follow_symlinks,
            });
        }
        let mut headers = Policy::new(config).map_err(ServerError::Headers)?;
        let first_tls_port = listeners
            .iter()
            .find(|(_, is_tls)| *is_tls)
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port());
        if let Some(port) = first_tls_port {
            headers.set_https_port(port);
        }
        Ok(Self {
            listeners,
            state: Arc::new(State {
                limits: config.server.limits.clone(),
                roots,
                router: Router::new(config),
                tls,
                headers,
            }),
        })
    }

    /// The bound plain-HTTP addresses (useful when a port of 0 was requested).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.addrs(false)
    }

    /// The bound TLS addresses.
    pub fn local_tls_addrs(&self) -> Vec<SocketAddr> {
        self.addrs(true)
    }

    fn addrs(&self, tls: bool) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter(|(_, is_tls)| *is_tls == tls)
            .filter_map(|(l, _)| l.local_addr().ok())
            .collect()
    }

    /// Serves until `shutdown` completes, then stops accepting and waits up
    /// to the configured grace period for open connections to finish.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let limits = &self.state.limits;
        let permits = Arc::new(Semaphore::new(limits.max_connections));
        let graceful = Arc::new(GracefulShutdown::new());
        let builder = Arc::new(protocol_builder(limits));
        let (stop_tx, stop_rx) = watch::channel(false);

        let mut accept_tasks = Vec::new();
        for (listener, is_tls) in self.listeners {
            accept_tasks.push(tokio::spawn(accept_loop(
                listener,
                is_tls,
                Arc::clone(&self.state),
                Arc::clone(&builder),
                Arc::clone(&permits),
                Arc::clone(&graceful),
                stop_rx.clone(),
            )));
        }

        shutdown.await;
        tracing::info!("shutdown requested; no longer accepting connections");
        let _ = stop_tx.send(true);
        for task in accept_tasks {
            let _ = task.await;
        }
        let grace = Duration::from_secs(limits.shutdown_grace_secs);
        // Every accept task has finished, so this is the last reference.
        let Some(graceful) = Arc::into_inner(graceful) else {
            return;
        };
        match tokio::time::timeout(grace, graceful.shutdown()).await {
            Ok(()) => tracing::info!("all connections closed"),
            Err(_) => tracing::warn!("grace period elapsed; dropping open connections"),
        }
    }
}

/// Builds the HTTP/1 + HTTP/2 connection settings from the limits.
fn protocol_builder(limits: &Limits) -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(limits.header_timeout_secs))
        .max_buf_size(limits.max_header_bytes)
        .max_headers(limits.max_headers);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.h2_max_concurrent_streams)
        .max_header_list_size(u32::try_from(limits.max_header_bytes).unwrap_or(u32::MAX))
        .max_pending_accept_reset_streams(Some(20))
        .max_local_error_reset_streams(Some(256))
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(limits.header_timeout_secs));
    builder
}

async fn accept_loop(
    listener: TcpListener,
    is_tls: bool,
    state: Arc<State>,
    builder: Arc<Builder<TokioExecutor>>,
    permits: Arc<Semaphore>,
    graceful: Arc<GracefulShutdown>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        // Wait for a free connection slot before accepting, so excess clients
        // queue in the kernel backlog instead of consuming memory here.
        let permit = tokio::select! {
            permit = Arc::clone(&permits).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return,
            },
            _ = stop.changed() => return,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Typically EMFILE or a reset during the handshake; back
                    // off briefly instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = stop.changed() => return,
        };
        let _ = stream.set_nodelay(true);
        let idle = Duration::from_secs(state.limits.idle_timeout_secs);
        let stream = IdleTimeout::new(stream, idle);
        let state = Arc::clone(&state);
        let builder = Arc::clone(&builder);
        // Taken now, so shutdown also waits for connections still handshaking.
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            match (&state.tls, is_tls) {
                (Some(tls), true) => {
                    // T3.5: the handshake shares the request-head time budget.
                    let budget = Duration::from_secs(state.limits.header_timeout_secs);
                    match tokio::time::timeout(budget, tls.acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let tls_vhost = tls.vhost_for(stream.get_ref().1.server_name());
                            let conn = Conn { peer, tls_vhost };
                            serve(&builder, stream, &state, conn, watcher).await;
                        }
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                }
                _ => {
                    let conn = Conn {
                        peer,
                        tls_vhost: None,
                    };
                    serve(&builder, stream, &state, conn, watcher).await;
                }
            }
            drop(permit);
        });
    }
}

/// Runs HTTP/1 or HTTP/2 on one connection until it closes.
async fn serve<I>(
    builder: &Builder<TokioExecutor>,
    io: I,
    state: &Arc<State>,
    conn: Conn,
    watcher: Watcher,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::clone(state);
    let service = service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(handle(&state, req, conn).await) }
    });
    let connection = builder
        .serve_connection(TokioIo::new(io), service)
        .into_owned();
    if let Err(e) = watcher.watch(connection).await {
        tracing::debug!(peer = %conn.peer, error = %e, "connection ended with error");
    }
}

/// Handles one request and writes its access log line.
async fn handle(state: &State, req: Request<Incoming>, conn: Conn) -> Response<Body> {
    let started = std::time::Instant::now();
    let entry = AccessEntry::new(&req, conn);
    let (mut response, vhost) = respond(state, req, conn).await;
    state.headers.apply(&mut response, vhost, conn.tls_vhost);
    entry.log(&response, started.elapsed());
    response
}

/// Applies request-level limits, then routes the request. Also returns the
/// vhost that answered, if any, for its response header policy.
async fn respond(
    state: &State,
    req: Request<Incoming>,
    conn: Conn,
) -> (Response<Body>, Option<usize>) {
    let limits = &state.limits;
    let uri_len = req.uri().path_and_query().map_or(0, |pq| pq.as_str().len());
    if uri_len > limits.max_uri_bytes {
        return (response::status(StatusCode::URI_TOO_LONG), None);
    }
    // No route accepts a request body yet (T2.7). Rejecting any
    // Transfer-Encoding also defeats CL.TE / TE.CL smuggling, because hyper
    // drops Content-Length when both are sent (T2.9). Phase 4 (proxy) relaxes
    // this per route.
    let headers = req.headers();
    let has_body = headers
        .get(hyper::header::CONTENT_LENGTH)
        .is_some_and(|v| v.as_bytes() != b"0");
    if headers.contains_key(hyper::header::TRANSFER_ENCODING) {
        return (close(response::status(StatusCode::BAD_REQUEST)), None);
    }
    if has_body {
        return (close(response::status(StatusCode::PAYLOAD_TOO_LARGE)), None);
    }
    let timeout = Duration::from_secs(limits.request_timeout_secs);
    match tokio::time::timeout(timeout, route(state, req, conn)).await {
        Ok(routed) => routed,
        Err(_) => (response::status(StatusCode::SERVICE_UNAVAILABLE), None),
    }
}

/// Dispatches a request to the vhost chosen by its Host.
async fn route(
    state: &State,
    req: Request<Incoming>,
    conn: Conn,
) -> (Response<Body>, Option<usize>) {
    match *req.method() {
        Method::GET | Method::HEAD => {
            if state.roots.is_empty() {
                return (response::status(StatusCode::NOT_FOUND), None);
            }
            match state.router.route(req.uri(), req.headers()) {
                // T3.4: Host must name the vhost whose certificate was served.
                Route::Vhost(index) if conn.tls_vhost.is_some_and(|t| t != index) => {
                    (response::status(StatusCode::MISDIRECTED_REQUEST), None)
                }
                Route::Vhost(index) => {
                    if conn.tls_vhost.is_none() {
                        let host = request_host(req.uri(), req.headers());
                        let redirect = state.headers.https_redirect(
                            &state.router,
                            index,
                            host.as_deref(),
                            req.uri(),
                        );
                        if let Some(redirect) = redirect {
                            return (redirect, Some(index));
                        }
                    }
                    let root = &state.roots[index];
                    let response =
                        files::serve(root, req.method(), req.uri().path(), req.headers()).await;
                    (response, Some(index))
                }
                Route::Misdirected => (response::status(StatusCode::MISDIRECTED_REQUEST), None),
                Route::BadHost => (close(response::status(StatusCode::BAD_REQUEST)), None),
            }
        }
        Method::OPTIONS => {
            let mut response = Response::new(response::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            (response, None)
        }
        _ => {
            let mut response = response::status(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            (response, None)
        }
    }
}

/// Marks a response so the connection closes after it is sent, discarding
/// any unread request body.
fn close(mut response: Response<Body>) -> Response<Body> {
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

/// Request fields captured for the access log before the request is consumed.
/// Only the path is logged, never the query string, which may carry tokens.
struct AccessEntry {
    peer: SocketAddr,
    tls: bool,
    method: String,
    path: String,
    version: hyper::Version,
    host: String,
    user_agent: String,
}

impl AccessEntry {
    fn new(req: &Request<Incoming>, conn: Conn) -> Self {
        let header = |name| {
            req.headers()
                .get(name)
                .map(|v: &hyper::header::HeaderValue| {
                    escape(&String::from_utf8_lossy(v.as_bytes()))
                })
                .unwrap_or_default()
        };
        Self {
            peer: conn.peer,
            tls: conn.tls_vhost.is_some(),
            method: escape(req.method().as_str()),
            path: escape(req.uri().path()),
            version: req.version(),
            host: header(hyper::header::HOST),
            user_agent: header(hyper::header::USER_AGENT),
        }
    }

    fn log(&self, response: &Response<Body>, elapsed: Duration) {
        let bytes = response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        tracing::info!(
            target: "wedge::access",
            peer = %self.peer,
            tls = self.tls,
            method = %self.method,
            path = %self.path,
            version = ?self.version,
            host = %self.host,
            status = response.status().as_u16(),
            bytes,
            duration_ms = elapsed.as_secs_f64() * 1000.0,
            user_agent = %self.user_agent,
        );
    }
}

/// Makes untrusted text safe for a log line (threat model T2.14): control
/// characters, quotes and backslashes become escapes, and the result is
/// capped at 512 characters so one request cannot flood the log.
fn escape(text: &str) -> String {
    const MAX: usize = 512;
    let mut out = String::with_capacity(text.len().min(MAX));
    for c in text.chars() {
        if out.len() >= MAX {
            out.push_str("...");
            break;
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn escape_neutralizes_log_injection() {
        assert_eq!(escape("/a\r\nFAKE 200"), "/a\\x0d\\x0aFAKE 200");
        assert_eq!(escape("\x1b[31mred"), "\\x1b[31mred");
        assert_eq!(escape("say \"hi\" \\"), "say \\\"hi\\\" \\\\");
        assert!(escape(&"a".repeat(2000)).len() <= 515);
        assert_eq!(escape("/café"), "/café");
    }
}
