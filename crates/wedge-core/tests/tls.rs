// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! TLS termination over real sockets: SNI per vhost, the SNI/Host check,
//! version and ALPN policy, handshake limits and certificate loading
//! (threat model T3.1 to T3.10).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use wedge_core::Server;

struct Pki {
    dir: tempfile::TempDir,
    certs: Vec<CertificateDer<'static>>,
}

/// One self-signed certificate per name, written as `<name>.crt`/`<name>.key`,
/// plus a document root `<name>/index.html` containing the name.
fn pki(names: &[&str]) -> Pki {
    let dir = tempfile::tempdir().unwrap();
    let mut certs = Vec::new();
    for name in names {
        let generated = rcgen::generate_simple_self_signed(vec![(*name).to_owned()]).unwrap();
        std::fs::write(dir.path().join(format!("{name}.crt")), generated.cert.pem()).unwrap();
        std::fs::write(
            dir.path().join(format!("{name}.key")),
            generated.signing_key.serialize_pem(),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join(name)).unwrap();
        std::fs::write(dir.path().join(name).join("index.html"), *name).unwrap();
        certs.push(generated.cert.der().clone());
    }
    Pki { dir, certs }
}

fn vhost(dir: &Path, name: &str, with_tls: bool) -> String {
    let path = |file: String| dir.join(file).display().to_string();
    let mut text = format!(
        "[[vhost]]\nname = {name:?}\nroot = {:?}\nhosts = [{name:?}]\n",
        path(name.to_owned())
    );
    if with_tls {
        text += &format!(
            "[vhost.tls]\ncert = {:?}\nkey = {:?}\n",
            format!("file:{}", path(format!("{name}.crt"))),
            format!("file:{}", path(format!("{name}.key"))),
        );
    }
    text
}

struct Running {
    tls: SocketAddr,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start(server_section: &str, vhosts: &str) -> Running {
    let toml = format!(
        "[server]\nlisten_tls = [\"127.0.0.1:0\"]\n{server_section}\n\
         [server.limits]\nheader_timeout_secs = 1\n{vhosts}"
    );
    let config = wedge_config::from_str(&toml).unwrap();
    let server = Server::bind(&config).await.unwrap();
    let tls = server.local_tls_addrs()[0];
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.run(async {
        let _ = rx.await;
    }));
    Running { tls, _stop: tx }
}

fn client(
    pki: &Pki,
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for cert in &pki.certs {
        roots.add(cert.clone()).unwrap();
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

fn default_client(pki: &Pki) -> TlsConnector {
    client(pki, rustls::DEFAULT_VERSIONS, &[b"http/1.1"])
}

type Stream = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(connector: &TlsConnector, addr: SocketAddr, sni: &str) -> std::io::Result<Stream> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    connector.connect(name, tcp).await
}

/// Sends one HTTP/1.1 GET with the given Host and returns the raw reply.
async fn get(mut stream: Stream, host: &str) -> String {
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[tokio::test]
async fn sni_selects_each_vhost_certificate() {
    let pki = pki(&["a.test", "b.test"]);
    let vhosts = vhost(pki.dir.path(), "a.test", true) + &vhost(pki.dir.path(), "b.test", true);
    let server = start("", &vhosts).await;
    let connector = default_client(&pki);
    for (index, name) in ["a.test", "b.test"].into_iter().enumerate() {
        let stream = connect(&connector, server.tls, name).await.unwrap();
        let served = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
        assert_eq!(served, pki.certs[index], "{name}");
        let reply = get(stream, name).await;
        assert_eq!(status(&reply), 200, "{reply}");
        assert!(reply.ends_with(name), "{reply}");
    }
}

#[tokio::test]
async fn host_must_match_the_sni_vhost() {
    let pki = pki(&["a.test", "b.test"]);
    let vhosts = vhost(pki.dir.path(), "a.test", true) + &vhost(pki.dir.path(), "b.test", true);
    let server = start("", &vhosts).await;
    let stream = connect(&default_client(&pki), server.tls, "a.test")
        .await
        .unwrap();
    assert_eq!(status(&get(stream, "b.test").await), 421);
}

#[tokio::test]
async fn unknown_sni_uses_the_default_vhost_or_fails() {
    let pki = pki(&["a.test", "c.test"]);
    let vhosts = vhost(pki.dir.path(), "a.test", true) + &vhost(pki.dir.path(), "c.test", false);
    // c.test has no certificate, so SNI c.test cannot complete a handshake.
    let server = start("", &vhosts).await;
    assert!(connect(&default_client(&pki), server.tls, "c.test")
        .await
        .is_err());
    // With a.test as the default, an unknown name gets a.test's certificate,
    // which the client then rejects because the name does not match.
    let server = start("default_vhost = \"a.test\"", &vhosts).await;
    let err = connect(&default_client(&pki), server.tls, "other.test")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("certificate"), "{err}");
}

#[tokio::test]
async fn tls12_is_allowed_by_default_and_refused_when_min_is_13() {
    let pki = pki(&["a.test"]);
    let vhosts = vhost(pki.dir.path(), "a.test", true);
    let tls12 = client(&pki, &[&rustls::version::TLS12], &[]);
    let server = start("", &vhosts).await;
    let stream = connect(&tls12, server.tls, "a.test").await.unwrap();
    assert_eq!(status(&get(stream, "a.test").await), 200);
    let server = start("[server.tls]\nmin_version = \"1.3\"", &vhosts).await;
    assert!(connect(&tls12, server.tls, "a.test").await.is_err());
    let tls13 = client(&pki, &[&rustls::version::TLS13], &[]);
    assert!(connect(&tls13, server.tls, "a.test").await.is_ok());
}

#[tokio::test]
async fn alpn_negotiates_h2_and_refuses_other_protocols() {
    let pki = pki(&["a.test"]);
    let server = start("", &vhost(pki.dir.path(), "a.test", true)).await;
    let h2 = client(&pki, rustls::DEFAULT_VERSIONS, &[b"h2", b"http/1.1"]);
    let stream = connect(&h2, server.tls, "a.test").await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    // T3.7 (ALPACA): a client for another protocol must not get a session.
    let imap = client(&pki, rustls::DEFAULT_VERSIONS, &[b"imap"]);
    assert!(connect(&imap, server.tls, "a.test").await.is_err());
}

#[tokio::test]
async fn silent_and_plaintext_clients_are_dropped() {
    let pki = pki(&["a.test"]);
    let server = start("", &vhost(pki.dir.path(), "a.test", true)).await;
    // T3.5: a client that never sends a ClientHello is closed after the
    // handshake budget (1 s here).
    let mut silent = TcpStream::connect(server.tls).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
    // T3.10: plaintext HTTP on the TLS port gets no HTTP response.
    let mut plain = TcpStream::connect(server.tls).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut reply)).await;
    assert!(!reply.starts_with(b"HTTP/"), "{reply:?}");
}

#[tokio::test]
async fn bad_keys_fail_startup_without_leaking_key_material() {
    let pki = pki(&["a.test", "b.test"]);
    let dir = pki.dir.path();
    let base = vhost(dir, "a.test", true);
    let bind = |vhosts: String| async move {
        let toml = format!("[server]\nlisten_tls = [\"127.0.0.1:0\"]\n{vhosts}");
        let config = wedge_config::from_str(&toml).unwrap();
        Server::bind(&config).await.err().map(|e| e.to_string())
    };
    // A key that belongs to another certificate.
    let swapped = base.replace("a.test.key", "b.test.key");
    let err = bind(swapped).await.expect("mismatched key must fail");
    assert!(
        err.contains("a.test") && err.contains("KeyMismatch"),
        "{err}"
    );
    // Garbage in the key file: the error names the reference, not the bytes.
    std::fs::write(
        dir.join("a.test.key"),
        "-----BEGIN PRIVATE KEY-----\nSEKRIT\n",
    )
    .unwrap();
    let err = bind(base.clone()).await.expect("bad key must fail");
    assert!(
        err.contains("a.test.key") && !err.contains("SEKRIT"),
        "{err}"
    );
    // A missing certificate file.
    std::fs::remove_file(dir.join("a.test.crt")).unwrap();
    let err = bind(base).await.expect("missing cert must fail");
    assert!(err.contains("a.test.crt"), "{err}");
}
