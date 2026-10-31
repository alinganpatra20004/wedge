<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
<p align="center"><img src="../../packaging/branding/wedge-logo.svg" alt="wEdge" width="420"></p>

# wEdge user guide

wEdge (command and package name `wedge`) is a web and application server
written in Rust. One binary serves static sites, terminates TLS, proxies to
application servers, and exposes metrics, with safe defaults and a
configuration that is validated before it is used.

## Contents

1. [Getting started](getting-started.md): install, first run, first site.
2. [Configuration basics](configuration.md): files, merging, validation,
   secrets, reloading.
3. [Static sites and virtual hosts](static-sites.md): document roots, host
   names, caching, ranges, compression.
4. [TLS and HTTPS](tls.md): certificates, SNI, HSTS, redirects, security
   headers.
5. [Reverse proxy](reverse-proxy.md): upstreams, health checks, forwarded
   headers, timeouts.
6. [Operations](operations.md): logs, metrics, reload, limits.
7. [Running as a service](services.md): systemd, OpenRC, Windows service,
   containers.
8. [Debug capture](debug-capture.md): following a request through every
   layer.
9. [Troubleshooting](troubleshooting.md): common errors and what they mean.
10. [Security](security.md): hardening checklist and how to report a problem.
11. [Configuration reference](configuration-reference.md): every key, type and
    default (generated from the schema).

Installation steps for each operating system are in the
[install guides](../install/README.md). How a request flows through the source
code is in [request flow](../architecture/request-flow.md).

## Conventions

- Shell commands assume Linux; Windows equivalents are given where they
  differ.
- `wedge.toml` means your master configuration file. Packages install it at
  `/etc/wedge/wedge.toml`; the Windows guide uses
  `C:\ProgramData\wedge\wedge.toml`.
- Every configuration example in this guide is checked with
  `wedge check-config` before each release.
