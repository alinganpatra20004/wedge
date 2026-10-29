# webmaster

An open-source web and application server written in Rust.

> Status: early development (Phase 0, bootstrap). Not ready for production use.

## Planned features (v1)
- HTTP/1.1 and HTTP/2, TLS via rustls
- Static files, virtual hosts, reverse proxy
- One master config (`webmaster.toml`) plus `conf.d/`, schema-validated
- Access/error logs, Prometheus metrics, hot reload

## License
Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright (c) Alingan Patra
