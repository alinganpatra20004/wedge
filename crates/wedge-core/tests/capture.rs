// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Debug capture log over real sockets (threat model T5.9 to T5.12).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wedge_core::Server;

const SECRET: &str = "s3cretT0ken";

struct Running {
    addr: SocketAddr,
    log: PathBuf,
    dir: tempfile::TempDir,
    reloader: wedge_core::Reloader,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Stops the server so every connection's final events are written.
    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn start(debug_extra: &str) -> Running {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("www")).unwrap();
    std::fs::write(dir.path().join("www/index.html"), "home page").unwrap();
    let text = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"site\"\n\
         [server.limits]\nshutdown_grace_secs = 1\n\
         [server.debug]\nread_packet = true\ncapture_file = \"capture.log\"\n{debug_extra}\n\
         [[vhost]]\nname = \"site\"\nroot = \"www\"\n"
    );
    let path = dir.path().join("wedge.toml");
    std::fs::write(&path, text).unwrap();
    let config = wedge_config::load(&path).unwrap();
    let server = Server::bind_reloadable(&config, Some(path)).await.unwrap();
    let addr = server.local_addrs()[0];
    let reloader = server.reloader();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Running {
        addr,
        log: dir.path().join("capture.log"),
        dir,
        reloader,
        stop: Some(tx),
        task: Some(task),
    }
}

async fn send(addr: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn secret_request() -> String {
    format!(
        "GET /index.html?api_key={SECRET} HTTP/1.1\r\nHost: site\r\n\
         Authorization: Bearer {SECRET}\r\nCookie: session={SECRET}\r\n\
         X-Trace: visible\r\nConnection: close\r\n\r\n"
    )
}

/// All bytes shown in the file's hex dumps, joined, so a secret split across
/// two 16-byte rows is still found.
fn dumped_bytes(log: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for line in log.lines() {
        let line = line.trim_start();
        let Some((offset, rest)) = line.split_once("  ") else {
            continue;
        };
        if offset.len() != 6 || !offset.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let hex = rest.split(" |").next().unwrap_or("");
        bytes.extend(
            hex.split_whitespace()
                .filter_map(|h| u8::from_str_radix(h, 16).ok()),
        );
    }
    bytes
}

fn read(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn capture_records_each_layer_and_redacts_credentials() {
    let mut s = start("").await;
    let reply = send(s.addr, &secret_request()).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    s.stop().await;
    let log = read(&s.log);

    assert!(log.starts_with("# "), "banner missing:\n{log}");
    assert!(log.contains("debug capture log"));
    // Layers, each tagged with the source file that produced the event.
    for (layer, source) in [
        ("TCP", "server.rs:"),
        ("HTTP", "server.rs:"),
        ("ROUTE", "files.rs:"),
        ("TCP", "capture.rs:"),
    ] {
        assert!(
            log.lines()
                .any(|l| l.contains(&format!(" {layer:<5} ")) && l.contains(source)),
            "no {layer} event from {source}:\n{log}"
        );
    }
    assert!(log.contains("accepted 127.0.0.1:"), "{log}");
    assert!(
        log.contains("request GET /index.html?[REDACTED] HTTP/1.1"),
        "{log}"
    );
    assert!(log.contains("authorization: [REDACTED]"), "{log}");
    assert!(log.contains("x-trace: visible"), "{log}");
    assert!(log.contains("static file"), "{log}");
    assert!(log.contains("response 200 OK"), "{log}");
    assert!(log.contains("closed: read"), "{log}");
    // The raw bytes were dumped (the response body is in them)...
    let dumped = dumped_bytes(&log);
    assert!(contains(&dumped, b"home page"), "no raw dump:\n{log}");
    assert!(contains(&dumped, b"Authorization: [REDACTED]"), "{log}");
    // ...but the secret appears nowhere: not in text, not in any dump.
    assert!(!log.contains(SECRET), "secret in capture log:\n{log}");
    assert!(
        !contains(&dumped, SECRET.as_bytes()),
        "secret in a hex dump"
    );
    // T5.12: no raw control characters reach the file.
    assert!(
        !log.bytes().any(|b| b < 0x20 && b != b'\n'),
        "control bytes in log"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&s.log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn log_secrets_writes_credentials_unredacted() {
    let mut s = start("log_secrets = true").await;
    send(s.addr, &secret_request()).await;
    s.stop().await;
    let log = read(&s.log);
    assert!(log.contains("CREDENTIALS ARE WRITTEN UNREDACTED"), "{log}");
    assert!(
        log.contains(&format!("authorization: Bearer {SECRET}")),
        "{log}"
    );
    assert!(contains(&dumped_bytes(&log), SECRET.as_bytes()));
}

#[tokio::test]
async fn http2_payloads_are_summarized_not_dumped() {
    let mut s = start("").await;
    // h2c with prior knowledge, carrying a credential in HPACK.
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tcp),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let req = hyper::Request::builder()
        .uri(format!("http://{}/index.html", s.addr))
        .header("authorization", format!("Bearer {SECRET}"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);
    drop(sender);
    s.stop().await;
    let log = read(&s.log);
    assert!(log.contains("HTTP/2 frames not dumped"), "{log}");
    assert!(log.contains("authorization: [REDACTED]"), "{log}");
    assert!(!log.contains(SECRET));
    assert!(!contains(&dumped_bytes(&log), SECRET.as_bytes()));
}

#[tokio::test]
async fn reload_cannot_change_capture_settings() {
    let mut s = start("").await;
    let path = s.dir.path().join("wedge.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace("read_packet = true", "read_packet = false"),
    )
    .unwrap();
    let err = s.reloader.reload().await.unwrap_err().to_string();
    assert!(err.contains("[server.debug] cannot change"), "{err}");
    s.stop().await;
}
