// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Reverse proxy over real sockets with test upstreams (threat model T4.1 to
//! T4.13).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
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
    /// Every request target received, in order.
    paths: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
struct Seen {
    hits: Arc<AtomicUsize>,
    health: Arc<AtomicU16>,
    paths: Arc<Mutex<Vec<String>>>,
}

type TestBody = BoxBody<Bytes, Infallible>;

async fn upstream(name: &'static str) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Seen {
        hits: Arc::new(AtomicUsize::new(0)),
        health: Arc::new(AtomicU16::new(200)),
        paths: Arc::new(Mutex::new(Vec::new())),
    };
    let shared = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let seen = shared.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let seen = seen.clone();
                async move { Ok::<_, Infallible>(answer(name, req, &seen).await) }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Upstream {
        addr,
        hits: seen.hits,
        health: seen.health,
        paths: seen.paths,
    }
}

fn text(body: impl Into<Bytes>) -> TestBody {
    Full::new(body.into()).boxed()
}

async fn answer(name: &str, req: Request<Incoming>, seen: &Seen) -> Response<TestBody> {
    let path = req
        .uri()
        .path_and_query()
        .map_or("", |pq| pq.as_str())
        .to_owned();
    if path == "/healthz" {
        let mut res = Response::new(text(""));
        let code = seen.health.load(Ordering::Relaxed);
        *res.status_mut() = hyper::StatusCode::from_u16(code).unwrap();
        return res;
    }
    seen.hits.fetch_add(1, Ordering::Relaxed);
    seen.paths.lock().unwrap().push(path.clone());
    if path.starts_with("/api/slow") {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    if path.starts_with("/api/stall") {
        // Sends a first chunk, then nothing, forever.
        let chunks = futures_util::stream::iter([Ok(Frame::data(Bytes::from("partial")))])
            .chain(futures_util::stream::pending());
        return Response::new(BodyExt::boxed(StreamBody::new(chunks)));
    }
    let method = req.method().to_string();
    let get = |name: &str| {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("|")
    };
    let (host, xff, xfp, xfh) = (
        get("host"),
        get("x-forwarded-for"),
        get("x-forwarded-proto"),
        get("x-forwarded-host"),
    );
    let mut names: Vec<String> = req.headers().keys().map(|k| k.to_string()).collect();
    names.sort();
    let len = req
        .into_body()
        .collect()
        .await
        .map_or(0, |b| b.to_bytes().len());
    let line = format!(
        "{name} {method} {path} host={host} len={len} xff={xff} xfp={xfp} xfh={xfh} headers={}",
        names.join(",")
    );
    let mut res = Response::new(text(line));
    let h = res.headers_mut();
    if path.starts_with("/api/hop") {
        h.insert("connection", "x-up-secret".parse().unwrap());
        h.insert("x-up-secret", "1".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("x-up-kept", "1".parse().unwrap());
    }
    if path.starts_with("/api/own-headers") {
        h.insert("x-frame-options", "DENY".parse().unwrap());
        h.insert("content-security-policy", "from-app".parse().unwrap());
    }
    res
}

/// An upstream that answers every connection with fixed raw bytes, to test
/// how wedge handles malformed responses (T4.10).
async fn raw_upstream(reply: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
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
    wedge_with("", upstreams, route_extra).await
}

/// Like `wedge`, with extra `[server]` keys and `[vhost]`-level TOML in
/// `route_extra`.
async fn wedge_with(server_extra: &str, upstreams: &str, route_extra: &str) -> Wedge {
    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"a\"\n{server_extra}\n\
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
    assert_eq!(
        forwarded, "host,x-forwarded-for,x-forwarded-host,x-forwarded-proto,x-kept",
        "{reply}"
    );
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

/// The value of `key=` in the upstream's summary line.
fn field<'a>(reply: &'a str, key: &str) -> &'a str {
    let line = body(reply);
    let start = line
        .find(&format!(" {key}="))
        .map_or(line.len(), |i| i + key.len() + 2);
    line[start..].split(' ').next().unwrap_or("")
}

#[tokio::test]
async fn spoofed_forwarding_headers_are_replaced() {
    let up = upstream("one").await;
    let spoof = "GET /api/x HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\
                 X-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: https\r\n\
                 X-Forwarded-Host: admin.internal\r\nX-Real-IP: 6.6.6.6\r\n\
                 Forwarded: for=6.6.6.6\r\n\r\n";
    // Untrusted peer: everything it claimed is discarded (T4.6).
    let w = wedge(&pool(&[up.addr], ""), "").await;
    let reply = send(&w, spoof).await;
    assert_eq!(field(&reply, "xff"), "127.0.0.1", "{reply}");
    assert_eq!(field(&reply, "xfp"), "http", "{reply}");
    assert_eq!(field(&reply, "xfh"), "a.test", "{reply}");
    let headers = field(&reply, "headers");
    assert!(
        !headers.contains("x-real-ip") && !headers.contains("forwarded,"),
        "{reply}"
    );

    // Trusted peer (a load balancer): its chain is extended, not replaced.
    let w = wedge_with(
        "trusted_proxies = [\"127.0.0.0/8\"]",
        &pool(&[up.addr], ""),
        "",
    )
    .await;
    let reply = send(&w, spoof).await;
    assert_eq!(field(&reply, "xff"), "6.6.6.6,", "{reply}");
    assert!(body(&reply).contains("xff=6.6.6.6, 127.0.0.1 "), "{reply}");
    assert_eq!(field(&reply, "xfp"), "https", "{reply}");
    assert_eq!(field(&reply, "xfh"), "admin.internal", "{reply}");
}

#[tokio::test]
async fn application_security_headers_win_over_defaults() {
    let up = upstream("one").await;
    // The app sets its own X-Frame-Options and CSP on /api/own-headers.
    let w = wedge(&pool(&[up.addr], ""), "").await;
    let own = get(&w, "/api/own-headers").await;
    assert_eq!(header(&own, "x-frame-options"), Some("DENY"), "{own}");
    assert_eq!(header(&own, "content-security-policy"), Some("from-app"));
    // Where the app sets nothing, the defaults are added.
    let plain = get(&w, "/api/x").await;
    assert_eq!(
        header(&plain, "x-frame-options"),
        Some("SAMEORIGIN"),
        "{plain}"
    );
    assert_eq!(header(&plain, "x-content-type-options"), Some("nosniff"));
    // Headers the operator configured still override the app (T4.12).
    let w = wedge(
        &pool(&[up.addr], ""),
        "[vhost.headers]\n\"Content-Security-Policy\" = \"from-operator\"\n",
    )
    .await;
    let own = get(&w, "/api/own-headers").await;
    assert_eq!(
        header(&own, "content-security-policy"),
        Some("from-operator"),
        "{own}"
    );
    assert_eq!(header(&own, "x-frame-options"), Some("DENY"), "{own}");
}

#[tokio::test]
async fn stalled_response_bodies_are_cut_off() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], "response_timeout_secs = 1"), "").await;
    let started = std::time::Instant::now();
    let reply = get(&w, "/api/stall").await;
    // The head and the first chunk arrive; then the body is aborted.
    assert_eq!(status(&reply), 200, "{reply}");
    assert!(reply.contains("partial"), "{reply}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn smuggled_requests_never_reach_the_upstream() {
    let up = upstream("one").await;
    let w = wedge(&pool(&[up.addr], ""), "").await;
    // CL.TE: Content-Length covers only part of a chunked body that hides a
    // second request. hyper honours Transfer-Encoding and drops the
    // Content-Length, so the hidden request is just 30 bytes of body.
    let clte = "POST /api/a HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\
                Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
                1e\r\nGET /api/smuggled HTTP/1.1\r\n\r\n\r\n0\r\n\r\n";
    let reply = send(&w, clte).await;
    assert!(matches!(status(&reply), 200 | 400), "{reply}");
    if status(&reply) == 200 {
        assert!(body(&reply).contains("POST /api/a ") && body(&reply).contains("len=30"));
    }
    // A malformed chunked body is the client's error: 400, not 502.
    let bad_chunk = "POST /api/a HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n\
                     1c\r\nGET /api/smuggled HTTP/1.1\r\n\r\n\r\n0\r\n\r\n";
    let reply = send(&w, bad_chunk).await;
    assert_eq!(status(&reply), 400, "{reply}");
    // TE.TE with an obfuscated second Transfer-Encoding.
    let tete = "POST /api/b HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\
                Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\nGET /api/smuggled HTTP/1.1\r\n\
                Host: a.test\r\n\r\n";
    let reply = send(&w, tete).await;
    assert!(status(&reply) != 0, "{reply}");
    // Conflicting Content-Length values are rejected outright.
    let dup = "POST /api/c HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\n\
               Content-Length: 30\r\n\r\nxGET /api/smuggled HTTP/1.1\r\n\r\n";
    let reply = send(&w, dup).await;
    assert_eq!(status(&reply), 400, "{reply}");
    // Give any stray connection a moment, then check what the upstream saw.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let paths = up.paths.lock().unwrap().clone();
    assert!(
        paths.iter().all(|p| !p.contains("smuggled")),
        "upstream received a smuggled request: {paths:?}"
    );
}

#[tokio::test]
async fn malformed_upstream_responses_become_502() {
    let cases: [&'static [u8]; 4] = [
        // Header name with a space.
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 2\r\n\r\nok",
        // Obsolete line folding (could hide an injected header).
        b"HTTP/1.1 200 OK\r\nX-A: a\r\n Set-Cookie: evil=1\r\nContent-Length: 2\r\n\r\nok",
        // Two different Content-Length values.
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nok",
        // Not HTTP at all.
        b"SSH-2.0-OpenSSH_9.6\r\n",
    ];
    for reply_bytes in cases {
        let addr = raw_upstream(reply_bytes).await;
        let w = wedge(&pool(&[addr], ""), "").await;
        let reply = get(&w, "/api/x").await;
        assert_eq!(
            status(&reply),
            502,
            "{:?} => {reply}",
            String::from_utf8_lossy(reply_bytes)
        );
        assert!(
            !reply.to_ascii_lowercase().contains("set-cookie"),
            "{reply}"
        );
    }
}
