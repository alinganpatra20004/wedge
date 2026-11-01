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

/// A server started from a config file in a temp dir, with an admin token,
/// so it can be reloaded.
struct Reloadable {
    public: SocketAddr,
    admin: SocketAddr,
    dir: tempfile::TempDir,
    reloader: wedge_core::Reloader,
    _stop: tokio::sync::oneshot::Sender<()>,
}

fn write_config(dir: &std::path::Path, listen: &str, extra_vhost: &str) {
    let text = format!(
        "[server]\nlisten = [{listen:?}]\ndefault_vhost = \"site\"\n\
         [server.admin]\nlisten = \"127.0.0.1:0\"\ntoken = \"file:token.txt\"\n\
         [[vhost]]\nname = \"site\"\nroot = \"www\"\n{extra_vhost}"
    );
    std::fs::write(dir.join("wedge.toml"), text).unwrap();
}

async fn start_reloadable() -> Reloadable {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("www")).unwrap();
    std::fs::write(dir.path().join("www/index.html"), "home").unwrap();
    std::fs::write(dir.path().join("token.txt"), "s3cret-token\n").unwrap();
    write_config(dir.path(), "127.0.0.1:0", "");
    let path = dir.path().join("wedge.toml");
    let config = wedge_config::load(&path).unwrap();
    let server = Server::bind_reloadable(&config, Some(path)).await.unwrap();
    let public = server.local_addrs()[0];
    let admin = server.local_admin_addr().unwrap();
    let reloader = server.reloader();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Reloadable {
        public,
        admin,
        dir,
        reloader,
        _stop: tx,
    }
}

fn reload_request(token: Option<&str>) -> String {
    let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    format!(
        "POST /-/reload HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
}

fn header<'a>(reply: &'a str, name: &str) -> Option<&'a str> {
    let head = reply.split("\r\n\r\n").next()?;
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test]
async fn reload_needs_the_token() {
    let s = start_reloadable().await;
    for token in [
        None,
        Some("wrong"),
        Some("s3cret-token-but-longer"),
        Some("s3cret-toke"),
    ] {
        let reply = send(s.admin, &reload_request(token)).await;
        assert_eq!(status(&reply), 401, "{token:?}: {reply}");
        assert_eq!(header(&reply, "www-authenticate"), Some("Bearer"));
    }
    let get = send(
        s.admin,
        "GET /-/reload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&get), 405, "{get}");
    let rebind = reload_request(Some("s3cret-token")).replace("localhost", "evil.example");
    assert_eq!(status(&send(s.admin, &rebind).await), 421);
    // Without a configured token, the endpoint does not exist.
    let plain = start("").await;
    assert_eq!(
        status(&send(plain.admin, &reload_request(Some("x"))).await),
        404
    );
}

#[tokio::test]
async fn reload_applies_good_config_and_keeps_old_on_errors() {
    let s = start_reloadable().await;
    let home = get("/", "x");
    let page = || send(s.public, &home);
    assert_eq!(header(&page().await, "x-version"), None);

    // A good change is applied.
    write_config(
        s.dir.path(),
        "127.0.0.1:0",
        "[vhost.headers]\n\"X-Version\" = \"2\"\n",
    );
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 200, "{reply}");
    assert_eq!(header(&page().await, "x-version"), Some("2"));

    // A broken file is refused and the old state keeps serving (T5.4).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(s.dir.path().join("wedge.toml"), "[server\n").unwrap();
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 422, "{reply}");
    assert!(reply.contains("cannot parse"), "{reply}");
    let still = page().await;
    assert_eq!(status(&still), 200);
    assert_eq!(header(&still, "x-version"), Some("2"));

    // A missing document root is refused too.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    write_config(s.dir.path(), "127.0.0.1:0", "");
    std::fs::rename(s.dir.path().join("www"), s.dir.path().join("gone")).unwrap();
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 422, "{reply}");
    std::fs::rename(s.dir.path().join("gone"), s.dir.path().join("www")).unwrap();
    assert_eq!(header(&page().await, "x-version"), Some("2"));
}

/// A reloadable server with an admin account ("admin") and a token.
async fn start_with_users() -> Reloadable {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("www")).unwrap();
    std::fs::write(dir.path().join("www/index.html"), "home").unwrap();
    std::fs::write(dir.path().join("token.txt"), "s3cret-token\n").unwrap();
    let hash = wedge_core::auth::hash_password(PASSWORD).unwrap();
    std::fs::write(dir.path().join("users.txt"), format!("admin:{hash}\n")).unwrap();
    // The vhost name is markup, to check the status page escapes it.
    let text = "[server]\nlisten = [\"127.0.0.1:0\"]\ndefault_vhost = \"<b>site</b>\"\n\
         [server.admin]\nlisten = \"127.0.0.1:0\"\ntoken = \"file:token.txt\"\n\
         users = \"file:users.txt\"\n\
         [[vhost]]\nname = \"<b>site</b>\"\nroot = \"www\"\n";
    std::fs::write(dir.path().join("wedge.toml"), text).unwrap();
    let path = dir.path().join("wedge.toml");
    let config = wedge_config::load(&path).unwrap();
    let server = Server::bind_reloadable(&config, Some(path)).await.unwrap();
    let public = server.local_addrs()[0];
    let admin = server.local_admin_addr().unwrap();
    let reloader = server.reloader();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Reloadable {
        public,
        admin,
        dir,
        reloader,
        _stop: tx,
    }
}

const PASSWORD: &str = "correct horse battery";

fn basic(user: &str, password: &str) -> String {
    use base64ct::{Base64, Encoding};
    let encoded = Base64::encode_string(format!("{user}:{password}").as_bytes());
    format!("Authorization: Basic {encoded}\r\n")
}

fn admin_get(path: &str, auth: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/html\r\n{auth}Connection: close\r\n\r\n")
}

#[tokio::test]
async fn status_page_needs_a_login() {
    let s = start_with_users().await;
    // No credentials: the browser is asked for them.
    let reply = send(s.admin, &admin_get("/", "")).await;
    assert_eq!(status(&reply), 401, "{reply}");
    assert_eq!(
        header(&reply, "www-authenticate"),
        Some("Basic realm=\"wedge admin\", charset=\"UTF-8\"")
    );
    // Metrics are behind the login too.
    assert_eq!(
        status(&send(s.admin, &admin_get("/metrics", "")).await),
        401
    );
    let wrong = send(
        s.admin,
        &admin_get("/", &basic("admin", "not the password")),
    )
    .await;
    assert_eq!(status(&wrong), 401, "{wrong}");
    let unknown = send(s.admin, &admin_get("/", &basic("root", PASSWORD))).await;
    assert_eq!(status(&unknown), 401, "{unknown}");

    let page = send(s.admin, &admin_get("/", &basic("admin", PASSWORD))).await;
    assert_eq!(status(&page), 200, "{page}");
    assert!(page.contains("Signed in as admin"), "{page}");
    assert!(page.contains("wEdge admin"), "{page}");
    // Configuration text is escaped, never markup.
    assert!(page.contains("&lt;b&gt;site&lt;/b&gt;"), "{page}");
    assert!(!page.contains("<b>site</b>"), "{page}");
    let csp = header(&page, "content-security-policy").unwrap();
    assert!(
        csp.starts_with("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
        "{csp}"
    );
    assert_eq!(header(&page, "x-frame-options"), Some("DENY"));
    assert_eq!(header(&page, "cache-control"), Some("no-store"));
    let css = send(
        s.admin,
        &admin_get("/-/admin.css", &basic("admin", PASSWORD)),
    )
    .await;
    assert_eq!(status(&css), 200);
    assert_eq!(
        header(&css, "content-type"),
        Some("text/css; charset=utf-8")
    );
    let metrics = send(s.admin, &admin_get("/metrics", &basic("admin", PASSWORD))).await;
    assert_eq!(status(&metrics), 200, "{metrics}");
    // The public site is unaffected.
    assert_eq!(status(&send(s.public, &get("/", "x")).await), 200);
}

#[tokio::test]
async fn failed_logins_lock_the_address_out() {
    let s = start_with_users().await;
    for _ in 0..4 {
        let reply = send(s.admin, &admin_get("/", &basic("admin", "wrong password!"))).await;
        assert_eq!(status(&reply), 401, "{reply}");
    }
    let reply = send(s.admin, &admin_get("/", &basic("admin", "wrong password!"))).await;
    assert_eq!(status(&reply), 429, "{reply}");
    assert_eq!(header(&reply, "retry-after"), Some("300"));
    // While locked out, the right password does not help.
    let reply = send(s.admin, &admin_get("/", &basic("admin", PASSWORD))).await;
    assert_eq!(status(&reply), 429, "{reply}");
}

#[tokio::test]
async fn reload_button_works_and_refuses_cross_site_posts() {
    let s = start_with_users().await;
    let post = |extra: &str| {
        format!(
            "POST /-/reload HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/html\r\n{}{extra}\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
            basic("admin", PASSWORD)
        )
    };
    // T5.15: a form on another site cannot use the browser's login.
    for extra in [
        "Origin: http://evil.example\r\n",
        "Origin: null\r\n",
        "Sec-Fetch-Site: cross-site\r\n",
    ] {
        let reply = send(s.admin, &post(extra)).await;
        assert_eq!(status(&reply), 403, "{extra}: {reply}");
    }
    let host = s.admin.to_string();
    std::fs::write(
        s.dir.path().join("wedge.toml"),
        std::fs::read_to_string(s.dir.path().join("wedge.toml"))
            .unwrap()
            .replace(
                "root = \"www\"",
                "root = \"www\"\n[vhost.headers]\n\"X-Version\" = \"2\"",
            ),
    )
    .unwrap();
    let same = format!(
        "Origin: http://{}\r\nSec-Fetch-Site: same-origin\r\n",
        "127.0.0.1"
    );
    let reply = send(s.admin, &post(&same)).await;
    assert_eq!(status(&reply), 303, "{reply}");
    assert_eq!(header(&reply, "location"), Some("/"));
    let page = send(s.admin, &admin_get("/", &basic("admin", PASSWORD))).await;
    assert!(page.contains("Configuration reloaded."), "{page}");
    // The notice shows once.
    let page = send(s.admin, &admin_get("/", &basic("admin", PASSWORD))).await;
    assert!(!page.contains("Configuration reloaded."), "{page}");
    let site = send(s.public, &get("/", "x")).await;
    assert_eq!(header(&site, "x-version"), Some("2"), "{site}");
    // The bearer token still reloads (wedge reload), without a login.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 200, "{host}: {reply}");
    let reply = send(s.admin, &reload_request(Some("wrong"))).await;
    assert_eq!(status(&reply), 401, "{reply}");
}

#[tokio::test]
async fn bad_users_file_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("users.txt"), "admin:plain-text-password\n").unwrap();
    let toml = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\n[server.admin]\nlisten = \"127.0.0.1:0\"\n\
         users = \"file:{}\"\n",
        dir.path()
            .join("users.txt")
            .display()
            .to_string()
            .replace('\\', "/")
    );
    let config = wedge_config::from_str(&toml).unwrap();
    let err = Server::bind(&config).await.err().unwrap().to_string();
    assert!(
        err.contains("users file line 1: hash is not a PHC string"),
        "{err}"
    );
    assert!(!err.contains("plain-text-password"), "{err}");
}

#[tokio::test]
async fn restart_only_settings_and_rate_limit() {
    let s = start_reloadable().await;
    // T5.6: listeners cannot move on reload.
    write_config(s.dir.path(), "127.0.0.1:1", "");
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 422, "{reply}");
    assert!(reply.contains("server.listen cannot change"), "{reply}");
    // T5.5: a second attempt within a second is refused.
    write_config(s.dir.path(), "127.0.0.1:0", "");
    let reply = send(s.admin, &reload_request(Some("s3cret-token"))).await;
    assert_eq!(status(&reply), 429, "{reply}");
    // The SIGHUP path (Reloader) works once the second has passed.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    s.reloader.reload().await.unwrap();
    assert_eq!(status(&send(s.public, &get("/", "x")).await), 200);
}
