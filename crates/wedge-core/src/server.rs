// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Listeners, the accept loop and per-connection protocol settings.
//!
//! Limits enforced here (threat model T2.5 to T2.8): a global connection cap,
//! a header read timeout, an idle timeout on the socket, header size and
//! count caps, a URI length cap, a per-request timeout, and HTTP/2 stream and
//! reset-flood limits.

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
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use wedge_config::{Config, Limits};

use crate::files::{self, Root};
use crate::idle::IdleTimeout;
use crate::response::{self, Body};
use crate::vhost::{Route, Router};

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
}

/// A server with its listeners bound, ready to run.
pub struct Server {
    listeners: Vec<TcpListener>,
    state: Arc<State>,
}

/// Shared, read-only state for all connections.
struct State {
    limits: Limits,
    roots: Vec<Root>,
    router: Router,
}

impl Server {
    /// Binds every configured listen address.
    pub async fn bind(config: &Config) -> Result<Self, ServerError> {
        if config.server.listen.is_empty() {
            return Err(ServerError::NoListeners);
        }
        let mut listeners = Vec::new();
        for &addr in &config.server.listen {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| ServerError::Bind { addr, source })?;
            listeners.push(listener);
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
        Ok(Self {
            listeners,
            state: Arc::new(State {
                limits: config.server.limits.clone(),
                roots,
                router: Router::new(config),
            }),
        })
    }

    /// The bound addresses (useful when a port of 0 was requested).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
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
        for listener in self.listeners {
            accept_tasks.push(tokio::spawn(accept_loop(
                listener,
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
        let state = Arc::clone(&state);
        let service = service_fn(move |req| {
            let state = Arc::clone(&state);
            async move { Ok::<_, Infallible>(handle(&state, req, peer).await) }
        });
        let conn = builder
            .serve_connection(TokioIo::new(IdleTimeout::new(stream, idle)), service)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%peer, error = %e, "connection ended with error");
            }
            drop(permit);
        });
    }
}

/// Applies request-level limits, then routes the request.
async fn handle(state: &State, req: Request<Incoming>, _peer: SocketAddr) -> Response<Body> {
    let limits = &state.limits;
    let uri_len = req.uri().path_and_query().map_or(0, |pq| pq.as_str().len());
    if uri_len > limits.max_uri_bytes {
        return response::status(StatusCode::URI_TOO_LONG);
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
        return close(response::status(StatusCode::BAD_REQUEST));
    }
    if has_body {
        return close(response::status(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let timeout = Duration::from_secs(limits.request_timeout_secs);
    match tokio::time::timeout(timeout, route(state, req)).await {
        Ok(response) => response,
        Err(_) => response::status(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Placeholder router: the static file handler arrives in task 2.2.
/// Dispatches a request to the vhost chosen by its Host.
async fn route(state: &State, req: Request<Incoming>) -> Response<Body> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            if state.roots.is_empty() {
                return response::status(StatusCode::NOT_FOUND);
            }
            match state.router.route(req.uri(), req.headers()) {
                Route::Vhost(index) => {
                    let root = &state.roots[index];
                    files::serve(root, req.method(), req.uri().path(), req.headers()).await
                }
                Route::Misdirected => response::status(StatusCode::MISDIRECTED_REQUEST),
                Route::BadHost => close(response::status(StatusCode::BAD_REQUEST)),
            }
        }
        Method::OPTIONS => {
            let mut response = Response::new(response::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            response
        }
        _ => {
            let mut response = response::status(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            response
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
