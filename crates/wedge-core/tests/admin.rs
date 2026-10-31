// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! The admin listener: metrics, access control and DNS-rebinding defence
//! (threat model T5.1 to T5.3).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wedge_core::Server;

struct Running {
    public: SocketAddr,
    admin: SocketAddr,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start(admin_extra: &str) -> Running {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "home").unwrap();
    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"site\"\n\
         [server.admin]\nlisten = \"127.0.0.1:0\"\n{admin_extra}\n\
         [[vhost]]\nname = \"site\"\nroot = {:?}\n",
        dir.path().display().to_string()
    );
    let config = wedge_config::from_str(&toml).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let public = server.local_addrs()[0];
    let admin = server.local_admin_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Running {
        public,
        admin,
        _dir: dir,
        _stop: tx,
    }
}

async fn send(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn get(path: &str, host: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[tokio::test]
async fn metrics_count_requests_and_connections() {
    let s = start("").await;
    for path in ["/", "/", "/missing"] {
        send(s.public, &get(path, "anything")).await;
    }
    send(
        s.public,
        "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let host = s.admin.to_string();
    let reply = send(s.admin, &get("/metrics", &host)).await;
    assert_eq!(status(&reply), 200, "{reply}");
    assert!(reply.contains("text/plain; version=0.0.4"), "{reply}");
    for line in [
        "wedge_http_requests_total{vhost=\"site\",method=\"GET\",status=\"2xx\"} 2",
        "wedge_http_requests_total{vhost=\"site\",method=\"GET\",status=\"4xx\"} 1",
        "wedge_http_requests_total{vhost=\"site\",method=\"POST\",status=\"4xx\"} 1",
        "wedge_http_request_duration_seconds_count{vhost=\"site\"} 4",
        "wedge_connections_total{tls=\"false\"} 4",
        "wedge_build_info{version=",
    ] {
        assert!(reply.contains(line), "missing {line}\n{reply}");
    }
    // The public listener does not serve metrics.
    assert_eq!(status(&send(s.public, &get("/metrics", "x")).await), 404);
}

#[tokio::test]
async fn admin_rejects_rebinding_hosts_and_other_routes() {
    let s = start("").await;
    for (host, expected) in [
        ("localhost", 200),
        ("127.0.0.1", 200),
        ("[::1]:9900", 200),
        ("evil.example", 421),
        ("127.0.0.1.nip.io", 421),
    ] {
        let reply = send(s.admin, &get("/metrics", host)).await;
        assert_eq!(status(&reply), expected, "{host}: {reply}");
    }
    let post = send(
        s.admin,
        "POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(status(&post), 405, "{post}");
    assert_eq!(status(&send(s.admin, &get("/", "localhost")).await), 404);
}

#[tokio::test]
async fn disallowed_clients_get_no_http_at_all() {
    // Loopback is not in the list, so the test client is refused.
    let s = start("allow = [\"10.0.0.0/8\"]").await;
    let reply = send(s.admin, &get("/metrics", "localhost")).await;
    assert!(reply.is_empty(), "{reply}");
}

#[tokio::test]
async fn admin_address_cannot_be_a_public_listener() {
    let toml = "[server]\nlisten = [\"127.0.0.1:9901\"]\n\
                [server.admin]\nlisten = \"127.0.0.1:9901\"\n";
    let err = wedge_config::from_str(toml).unwrap_err().to_string();
    assert!(err.contains("duplicate listen address"), "{err}");
}
