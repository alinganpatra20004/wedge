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
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use wedge_config::{AdminConfig, Config, DebugConfig, IpNet, Limits, Secret};

use crate::admin;
use crate::capture::{here, Capture, Handled, Recorded};
use crate::files::{self, Root};
use crate::headers::Policy;
use crate::idle::IdleTimeout;
use crate::metrics::Metrics;
use crate::proxy::Proxy;
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
    #[error("cannot open the debug capture log: {0}")]
    Capture(#[source] io::Error),
    #[error("admin token: {0}")]
    AdminToken(#[source] wedge_config::SecretError),
    #[error("invalid response header configuration: {0}")]
    Headers(String),
}

/// Why a reload was not applied. The server keeps its previous state.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("the server was not started from a configuration file")]
    NoConfigFile,
    #[error("another reload is in progress")]
    Busy,
    #[error("reloaded less than a second ago; try again")]
    TooSoon,
    #[error(transparent)]
    Config(#[from] wedge_config::ConfigError),
    #[error("{0} cannot change on reload; restart wedge to apply it")]
    RestartOnly(&'static str),
    #[error(transparent)]
    Server(#[from] ServerError),
}

/// A server with its listeners bound, ready to run.
pub struct Server {
    listeners: Vec<(TcpListener, Kind)>,
    shared: Arc<Shared>,
}

/// Triggers a configuration reload on a running server (`SIGHUP`, or the
/// admin endpoint). Cheap to clone.
#[derive(Clone)]
pub struct Reloader(Arc<Shared>);

impl Reloader {
    /// Re-reads the configuration file and swaps in the new state, or keeps
    /// the old one and returns why not (T5.4).
    pub async fn reload(&self) -> Result<(), ReloadError> {
        self.0.reload().await
    }
}

/// What a listener serves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    Tls,
    /// Metrics and reload, for allowed addresses only (T5.1).
    Admin,
}

/// Settings fixed for the life of the process, plus the swappable state.
struct Shared {
    current: RwLock<Arc<State>>,
    /// The settings that a reload may not change (T5.6).
    fixed: Fixed,
    config_path: Option<PathBuf>,
    /// Port of the first TLS listener as bound, for HTTPS redirects.
    https_port: Option<u16>,
    admin_allow: Vec<IpNet>,
    /// Bearer token for `POST /-/reload`, resolved once at startup.
    admin_token: Option<Secret>,
    /// Time of the last reload; the lock also serializes reloads (T5.5).
    last_reload: tokio::sync::Mutex<Option<Instant>>,
    /// The debug capture log, when `[server.debug] read_packet` is on.
    capture: Option<Arc<Capture>>,
}

#[derive(PartialEq)]
struct Fixed {
    listen: Vec<SocketAddr>,
    listen_tls: Vec<SocketAddr>,
    admin: Option<AdminConfig>,
    limits: Limits,
    debug: DebugConfig,
}

impl Fixed {
    fn of(config: &Config) -> Self {
        Self {
            listen: config.server.listen.clone(),
            listen_tls: config.server.listen_tls.clone(),
            admin: config.server.admin.clone(),
            limits: config.server.limits.clone(),
            debug: config.server.debug.clone(),
        }
    }

    /// The first restart-only setting that differs, if any.
    fn changed(&self, other: &Self) -> Option<&'static str> {
        if self.listen != other.listen {
            Some("server.listen")
        } else if self.listen_tls != other.listen_tls {
            Some("server.listen_tls")
        } else if self.admin != other.admin {
            Some("[server.admin]")
        } else if self.limits != other.limits {
            Some("[server.limits]")
        } else if self.debug != other.debug {
            // T5.6: a reload can never switch capture on.
            Some("[server.debug]")
        } else {
            None
        }
    }
}

/// Everything built from one configuration. Requests use the state that is
/// current when they arrive; a reload swaps in a new one (T5.4).
struct State {
    /// The same as `Fixed::limits`: limits are restart-only.
    limits: Limits,
    /// Indexed like the configured vhosts; `None` for proxy-only vhosts.
    roots: Vec<Option<Root>>,
    router: Router,
    tls: Option<Tls>,
    headers: Policy,
    proxy: Proxy,
    metrics: Metrics,
    /// Vhost names in config order, for the capture log.
    vhost_names: Vec<String>,
    /// Dropping or signalling this stops this state's health checks.
    health_stop: watch::Sender<bool>,
}

impl State {
    async fn build(config: &Config, https_port: Option<u16>) -> Result<Self, ServerError> {
        let tls = Tls::from_config(config)?;
        let mut roots = Vec::new();
        for vhost in &config.vhost {
            let Some(root) = &vhost.root else {
                roots.push(None);
                continue;
            };
            let dir = tokio::fs::canonicalize(root)
                .await
                .map_err(|source| ServerError::Root {
                    vhost: vhost.name.clone(),
                    source,
                })?;
            roots.push(Some(Root {
                dir,
                follow_symlinks: vhost.follow_symlinks,
            }));
        }
        let mut headers = Policy::new(config).map_err(ServerError::Headers)?;
        if let Some(port) = https_port {
            headers.set_https_port(port);
        }
        let proxy = Proxy::new(config);
        let (health_stop, stop_rx) = watch::channel(false);
        proxy.spawn_health_checks(&stop_rx);
        Ok(Self {
            limits: config.server.limits.clone(),
            roots,
            router: Router::new(config),
            tls,
            headers,
            proxy,
            metrics: Metrics::new(config),
            vhost_names: config.vhost.iter().map(|v| v.name.clone()).collect(),
            health_stop,
        })
    }
}

/// Facts about one client connection.
#[derive(Clone)]
struct ConnInfo {
    peer: SocketAddr,
    /// `Some` for TLS connections, holding the SNI name the client sent.
    tls_sni: Option<Option<Arc<str>>>,
    /// The capture log and this connection's id in it.
    capture: Option<(Arc<Capture>, u64)>,
}

/// Per-request view of the connection, resolved against the current state.
#[derive(Clone, Copy)]
struct Conn {
    peer: SocketAddr,
    /// For TLS connections, the vhost whose certificate the SNI selects in
    /// the current state.
    tls_vhost: Option<usize>,
}

impl Server {
    /// Loads certificates, then binds every configured listen address.
    pub async fn bind(config: &Config) -> Result<Self, ServerError> {
        Self::bind_reloadable(config, None).await
    }

    /// Like [`Server::bind`]; `config_path` is the master file that reloads
    /// read again.
    pub async fn bind_reloadable(
        config: &Config,
        config_path: Option<PathBuf>,
    ) -> Result<Self, ServerError> {
        if config.server.listen.is_empty() && config.server.listen_tls.is_empty() {
            return Err(ServerError::NoListeners);
        }
        // Certificates and roots are checked before any port is bound.
        drop(State::build(config, None).await?);
        let mut listeners = Vec::new();
        let plain = config.server.listen.iter().map(|a| (*a, Kind::Plain));
        let secure = config.server.listen_tls.iter().map(|a| (*a, Kind::Tls));
        let admin = config.server.admin.iter().map(|a| (a.listen, Kind::Admin));
        for (addr, kind) in plain.chain(secure).chain(admin) {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|source| ServerError::Bind { addr, source })?;
            if kind == Kind::Admin && !addr.ip().is_loopback() {
                tracing::warn!(%addr, "admin listener is not on a loopback address");
            }
            listeners.push((listener, kind));
        }
        let https_port = listeners
            .iter()
            .find(|(_, kind)| *kind == Kind::Tls)
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port());
        let admin_token = match config.server.admin.as_ref().and_then(|a| a.token.as_ref()) {
            Some(reference) => Some(reference.resolve().map_err(ServerError::AdminToken)?),
            None => None,
        };
        let state = State::build(config, https_port).await?;
        let capture = Capture::start(&config.server.debug).map_err(ServerError::Capture)?;
        if capture.is_some() {
            warn_capture_on(&config.server.debug);
        }
        if let (Some(c), true) = (&capture, config.server.debug.tcp_headers) {
            start_packet_capture(c, &listeners);
        }
        Ok(Self {
            listeners,
            shared: Arc::new(Shared {
                current: RwLock::new(Arc::new(state)),
                fixed: Fixed::of(config),
                config_path,
                https_port,
                admin_allow: config
                    .server
                    .admin
                    .as_ref()
                    .map(|a| a.allow.clone())
                    .unwrap_or_default(),
                admin_token,
                last_reload: tokio::sync::Mutex::new(None),
                capture,
            }),
        })
    }

    /// A handle that reloads this server's configuration while it runs.
    pub fn reloader(&self) -> Reloader {
        Reloader(Arc::clone(&self.shared))
    }

    /// The bound plain-HTTP addresses (useful when a port of 0 was requested).
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.addrs(Kind::Plain)
    }

    /// The bound TLS addresses.
    pub fn local_tls_addrs(&self) -> Vec<SocketAddr> {
        self.addrs(Kind::Tls)
    }

    /// The bound admin address, if the admin listener is configured.
    pub fn local_admin_addr(&self) -> Option<SocketAddr> {
        self.addrs(Kind::Admin).first().copied()
    }

    fn addrs(&self, kind: Kind) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter(|(_, k)| *k == kind)
            .filter_map(|(l, _)| l.local_addr().ok())
            .collect()
    }

    /// Serves until `shutdown` completes, then stops accepting and waits up
    /// to the configured grace period for open connections to finish.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let limits = &self.shared.fixed.limits;
        let permits = Arc::new(Semaphore::new(limits.max_connections));
        let graceful = Arc::new(GracefulShutdown::new());
        let builder = Arc::new(protocol_builder(limits));
        let (stop_tx, stop_rx) = watch::channel(false);
        if self.shared.capture.is_some() {
            tokio::spawn(remind_capture_on(Arc::clone(&self.shared), stop_rx.clone()));
        }

        let mut accept_tasks = Vec::new();
        for (listener, kind) in self.listeners {
            accept_tasks.push(tokio::spawn(accept_loop(
                listener,
                kind,
                Arc::clone(&self.shared),
                Arc::clone(&builder),
                Arc::clone(&permits),
                Arc::clone(&graceful),
                stop_rx.clone(),
            )));
        }

        shutdown.await;
        tracing::info!("shutdown requested; no longer accepting connections");
        let _ = stop_tx.send(true);
        let _ = self.shared.load().health_stop.send(true);
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

impl Shared {
    /// The current state. A poisoned lock still holds a complete state,
    /// because the swap is a single assignment.
    fn load(&self) -> Arc<State> {
        let guard = self.current.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    async fn reload(&self) -> Result<(), ReloadError> {
        let path = self.config_path.as_ref().ok_or(ReloadError::NoConfigFile)?;
        // T5.5: one reload at a time, at most one per second.
        let mut last = self.last_reload.try_lock().map_err(|_| ReloadError::Busy)?;
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return Err(ReloadError::TooSoon);
        }
        *last = Some(Instant::now());
        let config = wedge_config::load(path)?;
        if let Some(setting) = self.fixed.changed(&Fixed::of(&config)) {
            return Err(ReloadError::RestartOnly(setting));
        }
        // Built completely before the swap; any error leaves the old state.
        let state = Arc::new(State::build(&config, self.https_port).await?);
        let old = {
            let mut guard = self.current.write().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *guard, state)
        };
        let _ = old.health_stop.send(true);
        tracing::info!(config = %path.display(), "configuration reloaded");
        Ok(())
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
    kind: Kind,
    shared: Arc<Shared>,
    builder: Arc<Builder<TokioExecutor>>,
    permits: Arc<Semaphore>,
    graceful: Arc<GracefulShutdown>,
    mut stop: watch::Receiver<bool>,
) {
    let limits = &shared.fixed.limits;
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
        if kind == Kind::Admin && !shared.admin_allow.iter().any(|n| n.contains(peer.ip())) {
            // T5.1: refused before any HTTP is read.
            tracing::warn!(%peer, "admin connection from a disallowed address");
            continue;
        }
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().ok();
        let idle = Duration::from_secs(limits.idle_timeout_secs);
        let shared = Arc::clone(&shared);
        let builder = Arc::clone(&builder);
        let budget = Duration::from_secs(limits.header_timeout_secs);
        // Taken now, so shutdown also waits for connections still handshaking.
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // T2.5: a client must start its request (or TLS handshake, bounded
            // below) within the request-head budget. hyper's header timer
            // starts only with the first byte, so without this a silent
            // connection held a slot until the idle timeout, and enough of
            // them starved every other client. The idle timeout still applies
            // if it is shorter.
            if kind != Kind::Tls
                && tokio::time::timeout(budget.min(idle), stream.readable())
                    .await
                    .is_err()
            {
                tracing::debug!(%peer, "no request within the header timeout");
                drop(permit);
                return;
            }
            let stream = IdleTimeout::new(stream, idle);
            let state = shared.load();
            // The admin listener is never captured: it carries the reload token.
            let capture = shared
                .capture
                .clone()
                .filter(|_| kind != Kind::Admin)
                .map(|c| {
                    let id = c.connection_id();
                    let local = local.map_or_else(|| "-".to_owned(), |a| a.to_string());
                    let listener = if kind == Kind::Tls { "TLS" } else { "plain" };
                    let text = format!("accepted {peer} -> {local} on a {listener} listener");
                    c.event(id, "TCP", here!(), &text);
                    (c, id)
                });
            // On TLS listeners these bytes are ciphertext; no redaction needed.
            let stream = match &capture {
                Some((c, id)) => c.wrap(stream, *id, "TCP", kind != Kind::Tls),
                None => Recorded::plain(stream),
            };
            let plain = ConnInfo {
                peer,
                tls_sni: None,
                capture: capture.clone(),
            };
            match (&state.tls, kind) {
                (_, Kind::Admin) => serve(&builder, stream, &shared, plain, true, watcher).await,
                (Some(tls), Kind::Tls) => {
                    let _open = state.metrics.connection(true);
                    // T3.5: the handshake shares the request-head time budget.
                    match tokio::time::timeout(budget, tls.acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let session = stream.get_ref().1;
                            let sni = session.server_name().map(Arc::from);
                            let http2 = session.alpn_protocol() == Some(&b"h2"[..]);
                            if let Some((c, id)) = &capture {
                                let alpn = session
                                    .alpn_protocol()
                                    .map_or_else(|| "-".into(), String::from_utf8_lossy);
                                let version = session
                                    .protocol_version()
                                    .map_or_else(|| "-".to_owned(), |v| format!("{v:?}"));
                                let cipher = session
                                    .negotiated_cipher_suite()
                                    .map_or_else(|| "-".to_owned(), |s| format!("{:?}", s.suite()));
                                let text = format!(
                                    "handshake complete: sni={} alpn={alpn} version={version} \
                                     cipher={cipher}",
                                    sni.as_deref().unwrap_or("-"),
                                );
                                c.event(*id, "TLS", here!(), &text);
                            }
                            let mut stream = match &capture {
                                Some((c, id)) => c.wrap(stream, *id, "TLS", true),
                                None => Recorded::plain(stream),
                            };
                            if http2 {
                                stream.set_http2();
                            }
                            let conn = ConnInfo {
                                peer,
                                tls_sni: Some(sni),
                                capture,
                            };
                            serve(&builder, stream, &shared, conn, false, watcher).await;
                        }
                        Ok(Err(e)) => {
                            state.metrics.tls_handshake_failed();
                            tracing::debug!(%peer, error = %e, "TLS handshake failed");
                            if let Some((c, id)) = &capture {
                                c.event(*id, "TLS", here!(), &format!("handshake failed: {e}"));
                            }
                        }
                        Err(_) => {
                            state.metrics.tls_handshake_failed();
                            tracing::debug!(%peer, "TLS handshake timed out");
                            if let Some((c, id)) = &capture {
                                c.event(*id, "TLS", here!(), "handshake timed out");
                            }
                        }
                    }
                }
                _ => {
                    let _open = state.metrics.connection(false);
                    serve(&builder, stream, &shared, plain, false, watcher).await;
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
    shared: &Arc<Shared>,
    conn: ConnInfo,
    admin: bool,
    watcher: Watcher,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer = conn.peer;
    let shared = Arc::clone(shared);
    let service = service_fn(move |req| {
        let shared = Arc::clone(&shared);
        let conn = conn.clone();
        async move {
            let response = if admin {
                admin_request(&shared, req).await
            } else {
                handle(&shared.load(), req, &conn).await
            };
            Ok::<_, Infallible>(response)
        }
    });
    let connection = builder
        .serve_connection(TokioIo::new(io), service)
        .into_owned();
    if let Err(e) = watcher.watch(connection).await {
        tracing::debug!(%peer, error = %e, "connection ended with error");
    }
}

/// `POST /-/reload` with the admin token; everything else goes to the
/// metrics handler.
async fn admin_request(shared: &Shared, req: Request<Incoming>) -> Response<Body> {
    if req.uri().path() != "/-/reload" {
        let state = shared.load();
        return admin::respond(&state.metrics, &state.proxy, &req);
    }
    if let Some(response) = admin::reload_rejection(&req, shared.admin_token.as_ref()) {
        return response;
    }
    match shared.reload().await {
        Ok(()) => {
            let mut response = Response::new(response::full("reloaded\n"));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }
        Err(e) => {
            tracing::warn!(error = %e, "reload refused");
            let code = match e {
                ReloadError::Busy => StatusCode::CONFLICT,
                ReloadError::TooSoon => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            // Only an authenticated admin sees this; config errors never
            // contain secret values.
            let mut response = Response::new(response::full(format!("reload failed: {e}\n")));
            *response.status_mut() = code;
            response
        }
    }
}

/// Handles one request and writes its access log line.
async fn handle(state: &State, req: Request<Incoming>, info: &ConnInfo) -> Response<Body> {
    let started = std::time::Instant::now();
    let tls_vhost = info.tls_sni.as_ref().and_then(|sni| {
        let tls = state.tls.as_ref()?;
        tls.vhost_for(sni.as_deref())
    });
    let conn = Conn {
        peer: info.peer,
        tls_vhost,
    };
    let entry = AccessEntry::new(&req, conn);
    let method = req.method().clone();
    if let Some((c, id)) = &info.capture {
        let target = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
        let first = format!("request {method} {} {:?}", c.target(target), req.version());
        c.event(*id, "HTTP", here!(), &c.headers(&first, req.headers()));
    }
    let (mut response, vhost) = if info.tls_sni.is_some() && tls_vhost.is_none() {
        // After a reload removed the certificate this connection was made
        // with: the client must reconnect (T3.4).
        (response::status(StatusCode::MISDIRECTED_REQUEST), None)
    } else {
        respond(state, req, conn).await
    };
    state.headers.apply(&mut response, vhost, conn.tls_vhost);
    let elapsed = started.elapsed();
    state
        .metrics
        .request(vhost, &method, response.status().as_u16(), elapsed);
    if let Some((c, id)) = &info.capture {
        let name = vhost
            .and_then(|i| state.vhost_names.get(i))
            .map_or("-", String::as_str);
        match response.extensions().get::<Handled>() {
            Some(handled) => c.event(
                *id,
                "ROUTE",
                handled.at,
                &format!("vhost={name}: {}", handled.what),
            ),
            None => c.event(
                *id,
                "ROUTE",
                here!(),
                &format!("vhost={name}: answered by wedge"),
            ),
        }
        let first = format!(
            "response {} in {:.3} ms",
            response.status(),
            elapsed.as_secs_f64() * 1000.0
        );
        c.event(*id, "HTTP", here!(), &c.headers(&first, response.headers()));
    }
    entry.log(&response, elapsed);
    response
}

/// Starts IP/TCP header capture on the public listeners' ports (T5.11).
/// Failure is logged and the server runs on without packet headers.
fn start_packet_capture(capture: &Arc<Capture>, listeners: &[(TcpListener, Kind)]) {
    let public: Vec<SocketAddr> = listeners
        .iter()
        .filter(|(_, kind)| *kind != Kind::Admin)
        .filter_map(|(l, _)| l.local_addr().ok())
        .collect();
    #[cfg(feature = "packet-capture")]
    if let Err(e) = crate::pcap_capture::start(Arc::clone(capture), &public) {
        tracing::error!("{e}; continuing without packet headers");
    }
    #[cfg(not(feature = "packet-capture"))]
    {
        let _ = (capture, public);
        tracing::error!(
            "tcp_headers needs a wedge build with the packet-capture feature; \
             continuing without packet headers"
        );
    }
}

/// Logs a loud warning that capture is on (T5.9).
fn warn_capture_on(settings: &DebugConfig) {
    tracing::warn!(
        file = %settings.capture_file.display(),
        log_secrets = settings.log_secrets,
        "DEBUG CAPTURE IS ON: every request is written to the capture log; \
         turn it off and delete the file when done"
    );
    if settings.log_secrets {
        tracing::warn!("log_secrets is on: credentials are written UNREDACTED");
    }
}

/// Repeats the capture warning every hour while it stays on.
async fn remind_capture_on(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut hourly = tokio::time::interval(Duration::from_secs(3600));
    hourly.tick().await;
    loop {
        tokio::select! {
            _ = hourly.tick() => {}
            _ = stop.changed() => return,
        }
        warn_capture_on(&shared.fixed.debug);
        if let Some(c) = &shared.capture {
            tracing::warn!(dropped = c.dropped(), "capture events dropped so far");
        }
    }
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
    let timeout = Duration::from_secs(limits.request_timeout_secs);
    match tokio::time::timeout(timeout, route(state, req, conn)).await {
        Ok(routed) => routed,
        Err(_) => (response::status(StatusCode::SERVICE_UNAVAILABLE), None),
    }
}

/// Dispatches a request: Host picks the vhost, then a proxy route or the
/// static file handler answers.
async fn route(
    state: &State,
    req: Request<Incoming>,
    conn: Conn,
) -> (Response<Body>, Option<usize>) {
    let headers = req.headers();
    let has_body = headers.contains_key(hyper::header::TRANSFER_ENCODING)
        || headers
            .get(hyper::header::CONTENT_LENGTH)
            .is_some_and(|v| v.as_bytes() != b"0");
    // An unread body must not be parsed as the next request.
    let finish = |response| if has_body { close(response) } else { response };
    let misdirected = || {
        let response = finish(response::status(StatusCode::MISDIRECTED_REQUEST));
        (response, None)
    };
    // With no vhosts configured every request gets a static-route answer
    // (404, 405 or 413) without Host routing.
    let index = if state.roots.is_empty() {
        None
    } else {
        match state.router.route(req.uri(), req.headers()) {
            // T3.4: Host must name the vhost whose certificate was served.
            Route::Vhost(index) if conn.tls_vhost.is_some_and(|t| t != index) => {
                return misdirected();
            }
            Route::Vhost(index) => Some(index),
            Route::Misdirected => return misdirected(),
            Route::BadHost => return (close(response::status(StatusCode::BAD_REQUEST)), None),
        }
    };
    if let Some(index) = index {
        if conn.tls_vhost.is_none() {
            let host = request_host(req.uri(), req.headers());
            let redirect =
                state
                    .headers
                    .https_redirect(&state.router, index, host.as_deref(), req.uri());
            if let Some(redirect) = redirect {
                return (finish(redirect), Some(index));
            }
        }
        if let Some(proxy_route) = state.proxy.route(index, req.uri().path()) {
            // T4.1: no tunnels; TRACE would echo credentials back (XST).
            if matches!(*req.method(), Method::CONNECT | Method::TRACE) {
                let response = finish(response::status(StatusCode::METHOD_NOT_ALLOWED));
                return (response, Some(index));
            }
            let response = state
                .proxy
                .forward(
                    proxy_route,
                    req,
                    conn.peer,
                    conn.tls_vhost.is_some(),
                    &state.metrics,
                )
                .await;
            return (response, Some(index));
        }
    }
    // Static routes take no body (T2.7). Rejecting any Transfer-Encoding also
    // defeats CL.TE / TE.CL smuggling, because hyper drops Content-Length when
    // both are sent (T2.9).
    if headers.contains_key(hyper::header::TRANSFER_ENCODING) {
        return (close(response::status(StatusCode::BAD_REQUEST)), index);
    }
    if has_body {
        return (
            close(response::status(StatusCode::PAYLOAD_TOO_LARGE)),
            index,
        );
    }
    let root = index.and_then(|i| state.roots[i].as_ref());
    let response = match *req.method() {
        Method::GET | Method::HEAD => match root {
            Some(root) => files::serve(root, req.method(), req.uri().path(), req.headers()).await,
            None => response::status(StatusCode::NOT_FOUND),
        },
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
    };
    (response, index)
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
