// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Reverse proxy over real sockets with test upstreams (threat model T4.1 to
//! T4.13).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wedge_core::Server;

/// A test upstream. It answers with a one-line summary of what it received,
/// so tests can see exactly what wedge forwarded.
struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    /// Status returned for `/healthz`.
    health: Arc<AtomicU16>,
}

async fn upstream(name: &'static str) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let health = Arc::new(AtomicU16::new(200));
    let (h, s) = (Arc::clone(&hits), Arc::clone(&health));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (hits, health) = (Arc::clone(&h), Arc::clone(&s));
            let service = service_fn(move |req: Request<Incoming>| {
                let (hits, health) = (Arc::clone(&hits), Arc::clone(&health));
                async move { Ok::<_, Infallible>(answer(name, req, &hits, &health).await) }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Upstream { addr, hits, health }
}

async fn answer(
    name: &str,
    req: Request<Incoming>,
    hits: &AtomicUsize,
    health: &AtomicU16,
) -> Response<Full<Bytes>> {
    let path = req
        .uri()
        .path_and_query()
        .map_or("", |pq| pq.as_str())
        .to_owned();
    if path == "/healthz" {
        let mut res = Response::new(Full::new(Bytes::new()));
        *res.status_mut() = hyper::StatusCode::from_u16(health.load(Ordering::Relaxed)).unwrap();
        return res;
    }
    hits.fetch_add(1, Ordering::Relaxed);
    if path.starts_with("/api/slow") {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let method = req.method().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let mut names: Vec<String> = req.headers().keys().map(|k| k.to_string()).collect();
    names.sort();
    let len = req
        .into_body()
        .collect()
        .await
        .map_or(0, |b| b.to_bytes().len());
    let line = format!(
        "{name} {method} {path} host={host} len={len} headers={}",
        names.join(",")
    );
    let mut res = Response::new(Full::new(Bytes::from(line)));
    if path.starts_with("/api/hop") {
        let h = res.headers_mut();
        h.insert("connection", "x-up-secret".parse().unwrap());
        h.insert("x-up-secret", "1".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("x-up-kept", "1".parse().unwrap());
    }
    res
}

/// An address on which nothing listens.
async fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

struct Wedge {
    addr: SocketAddr,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// Starts wedge with `upstreams` (TOML) and a proxy-only vhost `a.test` whose
/// `/api` routes to upstream "app".
async fn wedge(upstreams: &str, route_extra: &str) -> Wedge {
    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"a\"\n\
         [server.limits]\nrequest_timeout_secs = 10\n{upstreams}\n\
         [[vhost]]\nname = \"a\"\nhosts = [\"a.test\"]\n\
         [[vhost.proxy]]\npath = \"/api\"\nupstream = \"app\"\n{route_extra}\n"
    );
    let config = wedge_config::from_str(&toml).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let addr = server.local_addrs()[0];
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Wedge { addr, _stop: tx }
}

fn pool(servers: &[SocketAddr], extra: &str) -> String {
    let list: Vec<String> = servers
        .iter()
        .map(|a| format!("{:?}", a.to_string()))
        .collect();
    format!(
        "[[upstream]]\nname = \"app\"\nservers = [{}]\n{extra}\n",
        list.join(", ")
    )
}

async fn send(wedge: &Wedge, request: &str) -> String {
    let mut stream = TcpStream::connect(wedge.addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

async fn get(wedge: &Wedge, target: &str) -> String {
    send(
        wedge,
        &format!("GET {target} HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"),
    )
    .await
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body(reply: &str) -> &str {
    reply.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn header<'a>(reply: &'a str, name: &str) -> Option<&'a str> {
    let head = reply.split("\r\n\r\n").next()?;
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test]
async fn forwards_and_balances_round_robin() {
    let (one, two) = (upstream("one").await, upstream("two").await);
    let w = wedge(&pool(&[one.addr, two.addr], ""), "").await;
    let mut seen = Vec::new();
    for _ in 0..4 {
        let reply = get(&w, "/api/items?q=1").await;
        assert_eq!(status(&reply), 200, "{reply}");
        let b = body(&reply);
        assert!(b.contains("GET /api/items?q=1 host=a.test"), "{b}");
        seen.push(b.split(' ').next().unwrap().to_owned());
    }
    assert_eq!(seen, ["one", "two", "one", "two"]);
    // The vhost has no root, so paths outside /api are 404 and never proxied.
    assert_eq!(status(&get(&w, "/other").await), 404);
    assert_eq!(status(&get(&w, "/apix").await), 404);
    assert_eq!(
        one.hits.load(Ordering::Relaxed) + two.hits.load(Ordering::Relaxed),
        4
    );
}

#[tokio::test]
async fn request_bodies_are_forwarded_within_the_limit() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], ""), "max_body_bytes = 10").await;
    let ok = send(
        &w,
        "POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert_eq!(status(&ok), 200, "{ok}");
    assert!(
        body(&ok).contains("POST /api/x") && body(&ok).contains("len=5"),
        "{ok}"
    );
    // Declared too large: refused before any upstream contact (T4.7).
    let declared = send(
        &w,
        "POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 11\r\n\r\nhello world",
    )
    .await;
    assert_eq!(status(&declared), 413, "{declared}");
    // Chunked and too large: cut off while streaming.
    let chunked = send(
        &w,
        "POST /api/x HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n\
         6\r\nhello \r\n6\r\nworld!\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(status(&chunked), 413, "{chunked}");
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped_both_ways() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], ""), "").await;
    let reply = send(
        &w,
        "GET /api/hop HTTP/1.1\r\nHost: a.test\r\nConnection: close, X-Drop-Me\r\n\
         X-Drop-Me: 1\r\nUpgrade: websocket\r\nTE: trailers\r\nKeep-Alive: 5\r\n\
         Proxy-Authorization: Basic eDp4\r\nX-Kept: 1\r\n\r\n",
    )
    .await;
    assert_eq!(status(&reply), 200, "{reply}");
    // Only Host and the ordinary header arrive upstream.
    let forwarded = body(&reply).rsplit_once("headers=").map_or("", |(_, h)| h);
    assert_eq!(forwarded, "host,x-kept", "{reply}");
    assert_eq!(header(&reply, "x-up-secret"), None, "{reply}");
    assert_eq!(header(&reply, "keep-alive"), None, "{reply}");
    assert_eq!(header(&reply, "x-up-kept"), Some("1"));
}

#[tokio::test]
async fn path_confusion_and_tunnels_are_refused() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], ""), "").await;
    for target in [
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/a%2fb",
        "/api/%00",
    ] {
        assert_eq!(status(&get(&w, target).await), 400, "{target}");
    }
    let trace = send(
        &w,
        "TRACE /api/x HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&trace), 405, "{trace}");
    let connect = send(&w, "CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").await;
    assert_ne!(status(&connect), 200, "{connect}");
    assert_eq!(
        up.hits.load(Ordering::Relaxed),
        0,
        "refused requests reached upstream"
    );
    // An absolute-form target only selects a vhost (here the default); the
    // request still goes to the configured upstream, never to the named
    // host (T4.1).
    let absolute = send(
        &w,
        "GET http://169.254.169.254/api/x HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&absolute), 200, "{absolute}");
    assert!(body(&absolute).starts_with("one GET /api/x"), "{absolute}");
}

#[tokio::test]
async fn dead_servers_fail_over_and_errors_are_generic() {
    let (live, dead) = (upstream("live").await, dead_addr().await);
    let w = wedge(&pool(&[dead, live.addr], "unhealthy_after = 1"), "").await;
    for _ in 0..3 {
        let reply = get(&w, "/api/x").await;
        assert_eq!(status(&reply), 200, "{reply}");
        assert!(body(&reply).starts_with("live "), "{reply}");
    }

    let only_dead = wedge(&pool(&[dead], "unhealthy_after = 1"), "").await;
    // A POST is never retried; the first failure is a 502 that does not
    // name the upstream (T4.9, T4.11).
    let post = send(
        &only_dead,
        "POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
    )
    .await;
    assert_eq!(status(&post), 502, "{post}");
    assert!(!post.contains(&dead.to_string()), "{post}");
    // The server is now marked down, so the next request gets 503.
    assert_eq!(status(&get(&only_dead, "/api/x").await), 503);
}

#[tokio::test]
async fn slow_upstream_times_out() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], "response_timeout_secs = 1"), "").await;
    let started = std::time::Instant::now();
    assert_eq!(status(&get(&w, "/api/slow").await), 504);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn health_checks_take_failing_servers_out() {
    let (good, bad) = (upstream("good").await, upstream("bad").await);
    bad.health.store(500, Ordering::Relaxed);
    let extra = "health_path = \"/healthz\"\nhealth_interval_secs = 1\nunhealthy_after = 1";
    let w = wedge(&pool(&[good.addr, bad.addr], extra), "").await;
    // The first check runs immediately; give it a moment.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..4 {
        let reply = get(&w, "/api/x").await;
        assert!(body(&reply).starts_with("good "), "{reply}");
    }
    assert_eq!(bad.hits.load(Ordering::Relaxed), 0);
    // Recovery: one passing check brings the server back.
    bad.health.store(200, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for _ in 0..4 {
        get(&w, "/api/x").await;
    }
    assert!(bad.hits.load(Ordering::Relaxed) > 0);
}
