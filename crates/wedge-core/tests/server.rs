// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Server behaviour over real TCP sockets, including limit enforcement.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use wedge_config::Config;
use wedge_core::Server;

type Running = (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>);

/// Starts a server on an ephemeral port; `limits` is TOML placed in the
/// `[server.limits]` table. Returns its address, a shutdown trigger and the
/// server task.
async fn start(limits: &str) -> Running {
    let text = format!("[server]\nlisten = [\"127.0.0.1:0\"]\n[server.limits]\n{limits}\n");
    let config: Config = wedge_config::from_str(&text).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let addr = server.local_addrs()[0];
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    (addr, tx, task)
}

/// Sends raw bytes and returns everything the server writes before closing
/// (or before `wait` elapses).
async fn exchange(addr: SocketAddr, request: &[u8], wait: Duration) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(wait, stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

const WAIT: Duration = Duration::from_secs(5);
const CLOSE: &str = "Host: a\r\nConnection: close\r\n\r\n";

#[tokio::test]
async fn get_unknown_path_is_404_with_safe_headers() {
    let (addr, _stop, _task) = start("").await;
    let request = format!("GET /x HTTP/1.1\r\n{CLOSE}");
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
    let lower = reply.to_ascii_lowercase();
    assert!(lower.contains("x-content-type-options: nosniff"), "{reply}");
}

#[tokio::test]
async fn post_is_405_with_allow_header() {
    let (addr, _stop, _task) = start("").await;
    let request = format!("POST / HTTP/1.1\r\nContent-Length: 0\r\n{CLOSE}");
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 405"), "{reply}");
    let lower = reply.to_ascii_lowercase();
    assert!(lower.contains("allow: get, head, options"), "{reply}");
}

#[tokio::test]
async fn long_uri_is_414() {
    let (addr, _stop, _task) = start("max_uri_bytes = 256").await;
    let request = format!("GET /{} HTTP/1.1\r\n{CLOSE}", "a".repeat(300));
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 414"), "{reply}");
}

#[tokio::test]
async fn oversized_headers_are_rejected() {
    let (addr, _stop, _task) = start("max_header_bytes = 8192").await;
    let request = format!("GET / HTTP/1.1\r\nX-Big: {}\r\n{CLOSE}", "b".repeat(20_000));
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 431"), "{reply}");
}

#[tokio::test]
async fn too_many_headers_are_rejected() {
    let (addr, _stop, _task) = start("max_headers = 10").await;
    let mut request = String::from("GET / HTTP/1.1\r\n");
    for i in 0..20 {
        request.push_str(&format!("X-H{i}: v\r\n"));
    }
    request.push_str(CLOSE);
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 431"), "{reply}");
}

#[tokio::test]
async fn slowloris_connection_is_closed_after_header_timeout() {
    let (addr, _stop, _task) = start("header_timeout_secs = 1").await;
    let started = Instant::now();
    // Never finish the request head.
    let request = b"GET / HTTP/1.1\r\nHost: a\r\nX-Slow: ";
    let reply = exchange(addr, request, Duration::from_secs(10)).await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "held for {elapsed:?}");
    assert!(
        reply.is_empty() || reply.starts_with("HTTP/1.1 408"),
        "{reply}"
    );
}

#[tokio::test]
async fn silent_connection_is_closed_after_header_timeout() {
    let (addr, _stop, _task) = start("header_timeout_secs = 1\nidle_timeout_secs = 60").await;
    let started = Instant::now();
    let reply = exchange(addr, b"", Duration::from_secs(10)).await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "held for {elapsed:?}");
    assert!(reply.is_empty(), "{reply}");
}

#[tokio::test]
async fn silent_connections_do_not_lock_out_clients() {
    let (addr, _stop, _task) =
        start("header_timeout_secs = 1\nidle_timeout_secs = 60\nmax_connections = 1").await;
    // Holds the only slot without ever sending a byte.
    let _silent = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let reply = exchange(addr, format!("GET / HTTP/1.1\r\n{CLOSE}").as_bytes(), WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 "), "{reply}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "waited {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn ambiguous_framing_is_rejected() {
    // Content-Length together with Transfer-Encoding is a smuggling vector (T2.9).
    let (addr, _stop, _task) = start("").await;
    let request = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\
                    Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let reply = exchange(addr, request, WAIT).await;
    assert!(
        reply.starts_with("HTTP/1.1 400") || reply.is_empty(),
        "{reply}"
    );
}

#[tokio::test]
async fn graceful_shutdown_stops_accepting() {
    let (addr, stop, task) = start("shutdown_grace_secs = 2").await;
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(addr).await.is_err(), "still accepting");
}

#[tokio::test]
async fn connection_cap_queues_extra_clients() {
    let (addr, _stop, _task) = start("max_connections = 1\nidle_timeout_secs = 2").await;
    // The first client holds the only slot by sending nothing.
    let _hog = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let request = format!("GET / HTTP/1.1\r\n{CLOSE}");
    let reply = exchange(addr, request.as_bytes(), WAIT).await;
    // Served only after the hog times out (about 2 s), proving the cap applied.
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1500),
        "served after {elapsed:?}"
    );
}

#[test]
fn no_listeners_is_an_error() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(runtime.block_on(Server::bind(&Config::default())).is_err());
}

#[tokio::test]
async fn request_body_on_static_route_is_413_and_closes() {
    let (addr, _stop, _task) = start("").await;
    let request = b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
    let reply = exchange(addr, request, WAIT).await;
    assert!(reply.starts_with("HTTP/1.1 413"), "{reply}");
    assert!(
        reply.to_ascii_lowercase().contains("connection: close"),
        "{reply}"
    );
}

#[tokio::test]
async fn idle_client_that_sends_nothing_is_dropped() {
    let (addr, _stop, _task) = start("idle_timeout_secs = 1").await;
    let started = Instant::now();
    let reply = exchange(addr, b"", Duration::from_secs(10)).await;
    assert!(reply.is_empty(), "{reply}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "held for {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn http2_prior_knowledge_is_served() {
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let (addr, _stop, _task) = start("").await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let request = hyper::Request::get(format!("http://{addr}/missing"))
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.version(), hyper::Version::HTTP_2);
    assert_eq!(response.status(), 404);
}
