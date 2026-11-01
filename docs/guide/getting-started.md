<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Getting started

## 1. Install

Follow the guide for your system in [docs/install](../install/README.md). Each
one downloads a release, checks its SHA-256 checksum, installs it and starts
the service. Afterwards:

```sh
wedge --version
```

## 2. Serve a folder

Create a folder with a page in it:

```sh
mkdir -p ~/site
echo '<h1>Hello from wEdge</h1>' > ~/site/index.html
```

Write a configuration file next to it, `~/site.toml`:

```toml
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "mysite"

[[vhost]]
name = "mysite"
root = "site"          # relative to this file
```

Check it, then run it in the foreground:

```sh
wedge check-config -c ~/site.toml
wedge run -c ~/site.toml
```

Open <http://127.0.0.1:8080/>. Each request is logged on the terminal; stop
with Ctrl+C. wedge finishes requests in flight before it exits.

## 3. What you get by default

Without any extra configuration, wedge already:

- refuses paths that leave the document root (`../`, encoded variants,
  backslashes, Windows device names) and never serves hidden files such as
  `.git` or `.env`;
- never lists directories;
- answers `If-None-Match` and `If-Modified-Since` with 304, and serves byte
  ranges;
- sends `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN` and
  `Referrer-Policy: strict-origin-when-cross-origin`;
- limits header size, header count, URI length, connection count and every
  timeout (see [Operations](operations.md#limits)).

## 4. Next steps

- Serve more than one site: [virtual hosts](static-sites.md#virtual-hosts).
- Add HTTPS: [TLS](tls.md).
- Put an application behind wedge: [reverse proxy](reverse-proxy.md).
- Run it permanently: [services](services.md).
