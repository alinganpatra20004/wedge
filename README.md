<p align="center"><img src="packaging/branding/wedge-logo.svg" alt="wEdge" width="420"></p>

<p align="center">A web and application server in Rust: static sites, TLS, reverse proxy and metrics in one memory-safe binary, with safe defaults.</p>

> Status: version 0.1.0, the first release. Security assessment of the
> released build is in progress; see [SECURITY.md](SECURITY.md).

## Features

- **HTTP/1.1 and HTTP/2**, with limits on headers, URIs, connections and
  every timeout.
- **Static files**: virtual hosts, ETag and Last-Modified, byte ranges,
  pre-compressed Brotli and gzip, path traversal protection, no directory
  listing.
- **TLS** with rustls: a certificate per vhost by SNI, TLS 1.2+ only, HSTS,
  HTTP to HTTPS redirects, security headers.
- **Reverse proxy**: round-robin upstreams with health checks, safe
  forwarding headers, body limits, timeouts.
- **Operations**: access and error logs (text or JSON), Prometheus metrics,
  hot configuration reload, systemd / OpenRC / Windows service.
- **Configuration**: one `wedge.toml` plus `conf.d/`, validated against a
  JSON Schema before use; secrets only by reference (`env:` / `file:`).
- **Debug capture**: an opt-in log of every request at each layer, tagged
  with the source file that handled it.

## Quick start

```sh
mkdir -p site && echo '<h1>Hello</h1>' > site/index.html
cat > wedge.toml <<'EOF'
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "site"

[[vhost]]
name = "site"
root = "site"
EOF
wedge run -c wedge.toml
```

## Documentation

- [Install guides](docs/install/README.md) for Debian, Ubuntu, Kali, Fedora,
  RHEL, Alpine, Windows and macOS.
- [User guide](docs/guide/README.md), including the
  [configuration reference](docs/guide/configuration-reference.md).
- [Security policy](SECURITY.md), [threat model](docs/security/threat-model.md)
  and [verification log](docs/security/verification.md).
- [Request flow](docs/architecture/request-flow.md) through the source.

## Building

Rust 1.80 or newer:

```sh
cargo build --release -p wedge
```

Release builds for every platform: `pwsh scripts/build-all.ps1` (see the
script header).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright (c) Alingan Patra
