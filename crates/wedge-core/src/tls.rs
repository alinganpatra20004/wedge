// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! TLS termination with rustls and the ring provider (threat model T3.1 to
//! T3.10).
//!
//! The certificate is chosen from SNI with the same exact/wildcard rules as
//! Host routing, falling back to the default vhost. The vhost picked here is
//! remembered per connection so that requests whose Host routes elsewhere get
//! 421 (T3.4). Early data and session tickets stay off (rustls defaults).

use std::sync::Arc;

use rustls::crypto::{ring, CryptoProvider};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::TlsAcceptor;
use wedge_config::{Config, SecretRef, TlsVersion, VirtualHost};

use crate::vhost::Router;

/// Errors raised while loading certificates. Messages name the vhost and the
/// secret reference, never key material.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("vhost {vhost:?}: {reason}")]
    Vhost { vhost: String, reason: String },
    #[error("TLS setup failed: {0}")]
    Setup(String),
}

/// TLS state shared by all TLS listeners.
pub(crate) struct Tls {
    pub(crate) acceptor: TlsAcceptor,
    resolver: Arc<SniResolver>,
}

impl Tls {
    /// Loads every vhost certificate. Returns `None` when no TLS listener is
    /// configured.
    pub(crate) fn from_config(config: &Config) -> Result<Option<Self>, TlsError> {
        if config.server.listen_tls.is_empty() {
            return Ok(None);
        }
        let provider = Arc::new(ring::default_provider());
        let mut keys = Vec::with_capacity(config.vhost.len());
        for vhost in &config.vhost {
            let key = match &vhost.tls {
                Some(tls) => Some(Arc::new(load_key(vhost, &tls.cert, &tls.key, &provider)?)),
                None => None,
            };
            keys.push(key);
        }
        let resolver = Arc::new(SniResolver {
            router: Router::new(config),
            keys,
        });
        let versions: &[&rustls::SupportedProtocolVersion] = match config.server.tls.min_version {
            TlsVersion::V1_2 => &[&rustls::version::TLS13, &rustls::version::TLS12],
            TlsVersion::V1_3 => &[&rustls::version::TLS13],
        };
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::Setup(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
        // T3.7: only HTTP; clients offering other protocols are refused.
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server.ignore_client_order = true;
        Ok(Some(Self {
            acceptor: TlsAcceptor::from(Arc::new(server)),
            resolver,
        }))
    }

    /// The vhost whose certificate was served for this SNI value.
    pub(crate) fn vhost_for(&self, sni: Option<&str>) -> Option<usize> {
        self.resolver.pick(sni)
    }
}

#[derive(Debug)]
struct SniResolver {
    router: Router,
    /// Indexed like the configured vhosts; `None` for vhosts without TLS.
    keys: Vec<Option<Arc<CertifiedKey>>>,
}

impl SniResolver {
    /// The vhost that SNI names, else the default vhost; only if it has a
    /// certificate. Without one the handshake fails (unrecognized_name).
    fn pick(&self, sni: Option<&str>) -> Option<usize> {
        let named = sni.and_then(|name| {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            self.router.lookup(&name)
        });
        let index = named.or(self.router.default_vhost())?;
        self.keys.get(index)?.as_ref().map(|_| index)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let index = self.pick(hello.server_name())?;
        self.keys[index].clone()
    }
}

/// Reads and checks one vhost's certificate chain and key (T3.2, T3.3).
fn load_key(
    vhost: &VirtualHost,
    cert: &SecretRef,
    key: &SecretRef,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, TlsError> {
    let fail = |reason: String| TlsError::Vhost {
        vhost: vhost.name.clone(),
        reason,
    };
    let cert_pem = cert.resolve().map_err(|e| fail(e.to_string()))?;
    let chain = CertificateDer::pem_slice_iter(cert_pem.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| fail(format!("{cert}: not a valid PEM certificate chain")))?;
    if chain.is_empty() {
        return Err(fail(format!("{cert}: no certificate found")));
    }
    warn_if_key_file_is_shared(vhost, key);
    let key_pem = key.resolve().map_err(|e| fail(e.to_string()))?;
    // The PEM parser's errors can quote input lines, so they are not shown.
    let der = PrivateKeyDer::from_pem_slice(key_pem.expose())
        .map_err(|_| fail(format!("{key}: not a valid PEM private key")))?;
    drop(key_pem);
    let certified =
        CertifiedKey::from_der(chain, der, provider).map_err(|e| fail(format!("{key}: {e}")))?;
    warn_on_uncovered_hosts(vhost, &certified);
    Ok(certified)
}

/// Startup warning for hosts the certificate does not cover. A wildcard
/// host is checked with a sample name under it.
fn warn_on_uncovered_hosts(vhost: &VirtualHost, certified: &CertifiedKey) {
    let Ok(leaf) = certified.end_entity_cert() else {
        return;
    };
    let Ok(leaf) = webpki::EndEntityCert::try_from(leaf) else {
        tracing::warn!(vhost = %vhost.name, "cannot parse the leaf certificate");
        return;
    };
    for host in &vhost.hosts {
        let sample = match host.strip_prefix("*.") {
            Some(parent) => format!("wedge-sample.{parent}"),
            None => host.clone(),
        };
        let covered = ServerName::try_from(sample.as_str())
            .is_ok_and(|name| leaf.verify_is_valid_for_subject_name(&name).is_ok());
        if !covered {
            tracing::warn!(vhost = %vhost.name, %host, "certificate does not cover this host");
        }
    }
}

#[cfg(unix)]
fn warn_if_key_file_is_shared(vhost: &VirtualHost, key: &SecretRef) {
    use std::os::unix::fs::PermissionsExt;
    if let SecretRef::File(path) = key {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    vhost = %vhost.name,
                    key = %key,
                    "private key file is readable by group or others; use chmod 600"
                );
            }
        }
    }
}

#[cfg(not(unix))]
fn warn_if_key_file_is_shared(_: &VirtualHost, _: &SecretRef) {}
