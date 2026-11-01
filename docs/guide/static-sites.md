<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Static sites and virtual hosts

## Document roots

A vhost's `root` is the folder it serves. `/` serves `index.html` from the
root; `/docs/` serves `docs/index.html`; `/docs` (no slash) redirects to
`/docs/`. A folder without `index.html` gives 404: wedge never lists
directories.

What is never served, whatever the URL encoding:

- anything outside the root (`..`, `%2e%2e`, `%2f`, backslashes, NUL, drive
  letters, Windows stream names);
- hidden files and folders (names starting with a dot), except
  `/.well-known/`;
- Windows device names (`CON`, `NUL`, `COM1`, ...) and names ending in a dot
  or space;
- files reached through a symbolic link, unless `follow_symlinks = true`
  (and even then only if the target is inside the root).

## Virtual hosts

One server can host many sites. wedge picks the vhost from the request's
`Host` header (HTTP/1.1) or `:authority` (HTTP/2):

```toml
[server]
listen = ["0.0.0.0:80"]
default_vhost = "main"         # answers hosts no vhost claims

[[vhost]]
name = "main"
root = "/srv/main"
hosts = ["example.com", "www.example.com"]

[[vhost]]
name = "blog"
root = "/srv/blog"
hosts = ["blog.example.com"]

[[vhost]]
name = "customers"
root = "/srv/customers"
hosts = ["*.customers.example.com"]   # any subdomain, one or more labels
```

Matching ignores case, the port and a trailing dot. Exact names win over
wildcards; the longest wildcard wins among wildcards.

Without `default_vhost`, a request for an unknown host gets
`421 Misdirected Request`. A missing, repeated or malformed `Host` gets
`400 Bad Request`. The host name only selects a vhost; it is never used to
build a file path.

## Caching and conditional requests

Every file response carries an `ETag` (from size and modification time) and
`Last-Modified`. Clients that send `If-None-Match` or `If-Modified-Since` get
`304 Not Modified` when nothing changed. wedge does not add `Cache-Control`;
set it per vhost if you want it:

```toml
[[vhost]]
name = "assets"
root = "/srv/assets"
hosts = ["static.example.com"]

[vhost.headers]
"Cache-Control" = "public, max-age=86400"
```

## Byte ranges

`Range: bytes=...` requests (for video seeking or resumed downloads) get
`206 Partial Content`. One range per request; multi-range requests get the
whole file, and impossible ranges get `416`.

## Compression

wedge does not compress on the fly (that costs CPU on every request and can
leak secrets through compression side channels). Instead it serves
pre-compressed files you create next to the originals:

```sh
brotli -k style.css      # creates style.css.br
gzip -k -9 style.css     # creates style.css.gz
```

A client that accepts `br` gets `style.css.br`, one that accepts `gzip` gets
`style.css.gz`, any other gets `style.css`. The response carries
`Content-Encoding` and `Vary: accept-encoding`.

## Content types

The type comes from the file extension (`.html`, `.css`, `.js`, `.json`,
`.svg`, images, fonts, `.wasm`, ...). Unknown extensions are sent as
`application/octet-stream`, and every response has
`X-Content-Type-Options: nosniff`, so browsers never guess.

## Methods

Static vhosts accept `GET`, `HEAD` and `OPTIONS`. Other methods get `405`
with an `Allow` header, and a request with a body gets `413`.
