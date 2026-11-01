<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Configuration basics

## Files

wedge reads one master file, `wedge.toml`, and then every `*.toml` file in
the `conf.d/` folder next to it, in alphabetical order:

```text
/etc/wedge/
├── wedge.toml          server settings
└── conf.d/
    ├── 10-blog.toml    one vhost per file is a good habit
    ├── 20-shop.toml
    └── 90-admin.toml
```

Merging rules:

- Tables merge key by key; a later file overrides a key set earlier.
- Lists of tables (`[[vhost]]`, `[[upstream]]`) and plain lists such as
  `listen` are appended, so each file can add its own vhosts.
- Hidden files and files not ending in `.toml` are ignored, so editor
  backups do not get loaded.

Relative paths (document roots, `file:` secrets, the capture log) are
relative to the master file, not to the directory wedge was started from.

## Validation

wedge refuses to start with a configuration it does not fully understand.
Three checks run in order:

1. The merged document is checked against the JSON Schema (shipped in
   `schema/wedge.schema.json`; print it with `wedge schema`). Every error is
   reported at once, with its location, for example
   `/vhost/0/root: ...`.
2. Values are decoded (addresses, ranges).
3. Cross-field rules: duplicate vhost names or host names, a
   `default_vhost` that does not exist, a TLS listener with no certificate,
   a proxy route to an unknown upstream.

Unknown keys are errors, so a misspelt security setting cannot be silently
ignored. Check a configuration without starting the server:

```sh
wedge check-config -c /etc/wedge/wedge.toml
```

Editors that support JSON Schema for TOML (for example with the Even Better
TOML extension) can validate as you type; add this first line:

```text
#:schema https://raw.githubusercontent.com/OpenEdge-Labs/wedge/main/schema/wedge.schema.json
```

## Secrets

Secrets (private keys, the admin token) are never written into the
configuration. They are references, resolved when they are needed:

- `env:NAME` reads the environment variable `NAME`;
- `file:/path` reads a file (at most 64 KiB; trailing newlines are removed).

```toml
[server]
listen_tls = ["0.0.0.0:443"]

[[vhost]]
name = "site"
root = "/srv/site"
hosts = ["example.com"]

[vhost.tls]
cert = "file:/etc/wedge/tls/example.com.crt"
key = "env:EXAMPLE_COM_KEY"
```

An inline value such as `key = "-----BEGIN PRIVATE KEY-----..."` is rejected,
and the error message never repeats it. Error messages name the reference,
never the secret.

## Reloading

Most settings can change while wedge runs (vhosts, certificates, upstreams,
headers, routes). After editing, check and reload:

```sh
wedge check-config -c /etc/wedge/wedge.toml
sudo systemctl reload wedge        # or: wedge reload -c /etc/wedge/wedge.toml
```

A reload builds the complete new configuration first and switches only if
everything succeeded; otherwise the old one keeps serving and the reason is
logged. Listen addresses, `[server.limits]`, `[server.admin]` and
`[server.debug]` need a restart. See [Operations](operations.md#reload).
