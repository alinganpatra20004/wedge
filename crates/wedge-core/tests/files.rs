// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Static file serving over real sockets, including traversal attempts that
//! must never leave the document root (threat model T2.1 to T2.4).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wedge_config::Config;
use wedge_core::Server;

struct Site {
    addr: SocketAddr,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// Layout: <tmp>/secret.txt outside the root, and <tmp>/www as the root.
async fn site(extra_vhost: &str) -> Site {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("www");
    let write = |rel: &str, body: &[u8]| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    };
    std::fs::write(dir.path().join("secret.txt"), "TOP SECRET").unwrap();
    write("index.html", b"<h1>home</h1>");
    write("hello.txt", b"0123456789");
    write("app.css", b"body{}");
    write("app.css.br", b"BROTLI");
    write("docs/index.html", b"docs");
    write("empty-dir/.keep", b"");
    write(".env", b"PASSWORD=x");
    write(".git/config", b"[core]");
    write(".well-known/security.txt", b"Contact: x");
    write("blob.bin", b"\x00\x01");

    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"t\"\n\
         [[vhost]]\nname = \"t\"\nroot = {:?}\n{extra_vhost}\n",
        root.display().to_string()
    );
    let config: Config = wedge_config::from_str(&toml).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let addr = server.local_addrs()[0];
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Site {
        addr,
        _dir: dir,
        _stop: tx,
    }
}

/// Sends a raw request (the target is written verbatim, unnormalized).
async fn get(site: &Site, target: &str, headers: &str) -> String {
    raw(
        site,
        &format!("GET {target} HTTP/1.1\r\nHost: t\r\n{headers}Connection: close\r\n\r\n"),
    )
    .await
}

async fn raw(site: &Site, request: &str) -> String {
    let mut stream = TcpStream::connect(site.addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn header<'a>(reply: &'a str, name: &str) -> Option<&'a str> {
    let head = reply.split("\r\n\r\n").next()?;
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn body(reply: &str) -> &str {
    reply.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

#[tokio::test]
async fn serves_index_and_files_with_headers() {
    let s = site("").await;
    let reply = get(&s, "/", "").await;
    assert_eq!(status(&reply), 200, "{reply}");
    assert_eq!(body(&reply), "<h1>home</h1>");
    assert_eq!(
        header(&reply, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(header(&reply, "x-content-type-options"), Some("nosniff"));
    assert!(header(&reply, "etag").is_some());
    assert!(header(&reply, "last-modified").is_some());

    let reply = get(&s, "/blob.bin", "").await;
    assert_eq!(
        header(&reply, "content-type"),
        Some("application/octet-stream")
    );
}

#[tokio::test]
async fn traversal_never_reaches_outside_root() {
    let s = site("").await;
    for target in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E%2Fsecret.txt",
        "/docs/../../secret.txt",
        "/..%5csecret.txt",
        "/..%2f..%2fsecret.txt",
        "/%252e%252e/secret.txt",
        "/.%2e/secret.txt",
        "//../secret.txt",
    ] {
        let reply = get(&s, target, "").await;
        assert!(!reply.contains("TOP SECRET"), "{target} leaked: {reply}");
        assert!([400, 404].contains(&status(&reply)), "{target}: {reply}");
    }
}

#[tokio::test]
async fn absolute_form_and_drive_paths_are_refused() {
    let s = site("").await;
    for target in [
        "/C:/Windows/win.ini",
        "/hello.txt::$DATA",
        "/hello.txt%00.html",
    ] {
        let reply = get(&s, target, "").await;
        assert_eq!(status(&reply), 400, "{target}: {reply}");
    }
}

#[tokio::test]
async fn hidden_files_are_404_but_well_known_is_served() {
    let s = site("").await;
    for target in ["/.env", "/.git/config", "/hello.txt.", "/CON"] {
        assert_eq!(status(&get(&s, target, "").await), 404, "{target}");
    }
    let reply = get(&s, "/.well-known/security.txt", "").await;
    assert_eq!(status(&reply), 200, "{reply}");
}

#[tokio::test]
async fn directories_redirect_and_never_list() {
    let s = site("").await;
    let reply = get(&s, "/docs", "").await;
    assert_eq!(status(&reply), 301, "{reply}");
    assert_eq!(header(&reply, "location"), Some("/docs/"));
    assert_eq!(body(&get(&s, "/docs/", "").await), "docs");
    assert_eq!(status(&get(&s, "/empty-dir/", "").await), 404);
}

#[tokio::test]
async fn ranges() {
    let s = site("").await;
    let reply = get(&s, "/hello.txt", "Range: bytes=2-4\r\n").await;
    assert_eq!(status(&reply), 206, "{reply}");
    assert_eq!(body(&reply), "234");
    assert_eq!(header(&reply, "content-range"), Some("bytes 2-4/10"));

    let reply = get(&s, "/hello.txt", "Range: bytes=50-\r\n").await;
    assert_eq!(status(&reply), 416, "{reply}");
    assert_eq!(header(&reply, "content-range"), Some("bytes */10"));

    let reply = get(&s, "/hello.txt", "Range: bytes=0-1,3-4\r\n").await;
    assert_eq!(status(&reply), 200, "multi-range must fall back: {reply}");

    let reply = get(
        &s,
        "/hello.txt",
        "Range: bytes=0-1\r\nIf-Range: \"stale\"\r\n",
    )
    .await;
    assert_eq!(status(&reply), 200, "stale If-Range must send full body");
}

#[tokio::test]
async fn conditional_requests() {
    let s = site("").await;
    let first = get(&s, "/hello.txt", "").await;
    let etag = header(&first, "etag").unwrap().to_owned();
    let reply = get(&s, "/hello.txt", &format!("If-None-Match: {etag}\r\n")).await;
    assert_eq!(status(&reply), 304, "{reply}");
    assert_eq!(body(&reply), "");
    let modified = header(&first, "last-modified").unwrap().to_owned();
    let reply = get(
        &s,
        "/hello.txt",
        &format!("If-Modified-Since: {modified}\r\n"),
    )
    .await;
    assert_eq!(status(&reply), 304, "{reply}");
}

#[tokio::test]
async fn head_has_headers_but_no_body() {
    let s = site("").await;
    let reply = raw(
        &s,
        "HEAD /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&reply), 200);
    assert_eq!(header(&reply, "content-length"), Some("10"));
    assert_eq!(body(&reply), "");
}

#[tokio::test]
async fn precompressed_variant_is_served_when_accepted() {
    let s = site("").await;
    let reply = get(&s, "/app.css", "Accept-Encoding: gzip, br\r\n").await;
    assert_eq!(body(&reply), "BROTLI");
    assert_eq!(header(&reply, "content-encoding"), Some("br"));
    assert_eq!(
        header(&reply, "content-type"),
        Some("text/css; charset=utf-8")
    );
    assert_eq!(header(&reply, "vary"), Some("accept-encoding"));
    let plain = get(&s, "/app.css", "").await;
    assert_eq!(body(&plain), "body{}");
    assert!(header(&plain, "content-encoding").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_are_refused_by_default_and_contained_when_allowed() {
    let s = site("").await;
    let root = s._dir.path().join("www");
    std::os::unix::fs::symlink(s._dir.path().join("secret.txt"), root.join("escape.txt")).unwrap();
    std::os::unix::fs::symlink(root.join("hello.txt"), root.join("inside.txt")).unwrap();
    assert_eq!(status(&get(&s, "/escape.txt", "").await), 404);
    assert_eq!(status(&get(&s, "/inside.txt", "").await), 404);

    let allowed = site("follow_symlinks = true").await;
    let root = allowed._dir.path().join("www");
    std::os::unix::fs::symlink(
        allowed._dir.path().join("secret.txt"),
        root.join("escape.txt"),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.join("hello.txt"), root.join("inside.txt")).unwrap();
    let escaped = get(&allowed, "/escape.txt", "").await;
    assert!(!escaped.contains("TOP SECRET"), "{escaped}");
    assert_eq!(status(&escaped), 404);
    assert_eq!(body(&get(&allowed, "/inside.txt", "").await), "0123456789");
}

#[tokio::test]
async fn missing_root_fails_at_startup() {
    let toml = "[server]\nlisten = [\"127.0.0.1:0\"]\n[[vhost]]\nname = \"x\"\nroot = \"/definitely/not/here\"\n";
    let config: Config = wedge_config::from_str(toml).unwrap();
    assert!(Server::bind(&config).await.is_err());
}

#[tokio::test]
async fn host_routing_over_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a", "b"] {
        std::fs::create_dir_all(dir.path().join(name)).unwrap();
        std::fs::write(dir.path().join(name).join("index.html"), name).unwrap();
    }
    let root = |n: &str| format!("{:?}", dir.path().join(n).display().to_string());
    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\n\
         [[vhost]]\nname = \"a\"\nroot = {}\nhosts = [\"a.test\"]\n\
         [[vhost]]\nname = \"b\"\nroot = {}\nhosts = [\"*.b.test\"]\n",
        root("a"),
        root("b")
    );
    let config: Config = wedge_config::from_str(&toml).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let addr = server.local_addrs()[0];
    let (_stop, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    let ask = |host: &'static str| async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\n{host}Connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    assert_eq!(body(&ask("Host: A.test:80\r\n").await), "a");
    assert_eq!(body(&ask("Host: www.b.test\r\n").await), "b");
    assert_eq!(status(&ask("Host: other.test\r\n").await), 421);
    assert_eq!(status(&ask("").await), 400);
    assert_eq!(
        status(&ask("Host: a.test\r\nHost: www.b.test\r\n").await),
        400
    );
}
