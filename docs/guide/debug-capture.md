<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
# Debug capture

When a request does not behave as expected, wedge can record everything it
sees for each connection, layer by layer, in a separate capture log:

| Layer | What is recorded |
|---|---|
| `IP` | IP/TCP packet headers: addresses, ports, flags, sequence and acknowledgement numbers, window, retransmissions (optional, see below) |
| `TCP` | connection accepted; every byte read and written (hex and ASCII); bytes on TLS listeners are ciphertext |
| `TLS` | handshake: SNI, ALPN, version, cipher suite; then every decrypted byte |
| `HTTP` | the parsed request (method, target, headers) and response (status, headers, time) |
| `ROUTE` | which vhost answered and how: the static file served, the upstream and server used, or a response from wedge itself |

Every event names the source file and line that produced it (for example
`crates\wedge-core\src\files.rs:84 vhost=main: static file /srv/main/index.html`).
The [request flow](../architecture/request-flow.md) diagram shows where each
of those files sits in a request's path.

**Use it for troubleshooting only, never in production.** The capture log
contains request data, including request bodies.

## Turning it on

```toml
[server.debug]
read_packet = true
capture_file = "capture.log"        # relative to wedge.toml
max_bytes_per_connection = 65536    # per direction; the rest is only counted
max_file_bytes = 104857600          # rotate at 100 MiB
keep_files = 5                      # capture.log.1 ... capture.log.5
redact_headers = ["X-Api-Key"]      # in addition to the built-in list
```

Restart wedge to apply it: a reload cannot switch capture on or off. While
it is on, wedge logs a warning at startup and every hour. The file is created
readable and writable by its owner only, and is rotated at `max_file_bytes`.
Turn capture off and delete the files when you are done.

## Example

```text
1793412060.710 conn=1 TCP   crates\wedge-core\src\server.rs:495 accepted 127.0.0.1:57369 -> 127.0.0.1:8080 on a plain listener
1793412060.734 conn=1 TCP   crates\wedge-core\src\capture.rs:265 <- 114 bytes at offset 24 (dump shows complete lines, redacted)
    000000  47 45 54 20 2f 69 6e 64 65 78 2e 68 74 6d 6c 3f  |GET /index.html?|
    000010  5b 52 45 44 41 43 54 45 44 5d 20 48 54 54 50 2f  |[REDACTED] HTTP/|
1793412060.742 conn=1 HTTP  crates\wedge-core\src\server.rs:654 request GET /index.html?[REDACTED] HTTP/1.1
    host: 127.0.0.1:8080
    authorization: [REDACTED]
1793412060.744 conn=1 ROUTE crates\wedge-core\src\files.rs:84 vhost=main: static file /srv/main/index.html
1793412060.744 conn=1 HTTP  crates\wedge-core\src\server.rs:691 response 200 OK in 1.077 ms
```

Lines start with a Unix timestamp in seconds. `conn=N` ties together the
events of one connection; `<-` is data received, `->` data sent.

## What is hidden by default

- `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization` and the
  headers in `redact_headers`, in the parsed view and in the raw byte dumps;
- query strings (they often carry tokens);
- HTTP/2 payloads: their headers are compressed (HPACK), which makes reliable
  redaction impossible, so only sizes are recorded;
- the admin listener: it carries the reload token and is never captured.

Request and response bodies are recorded as they are, up to
`max_bytes_per_connection`.

### Recording secrets

`log_secrets = true` turns redaction off: credentials, query strings and
HTTP/2 frames are recorded in full. While it is on, the capture log breaks the
rule that secrets never reach logs, and wedge says so loudly at startup and at
the top of the file. Use it only on a test system with test credentials.

## IP/TCP packet headers

`tcp_headers = true` adds the `IP` layer: one line per TCP segment on wedge's
listen ports, like `tcpdump`:

```text
conn=0 IP    crates/wedge-core/src/pcap_capture.rs:67 127.0.0.1:51276 > 127.0.0.1:8080 flags [S] seq 2692092534 ack 0 win 65495 len 0 ttl 64
conn=0 IP    crates/wedge-core/src/pcap_capture.rs:67 127.0.0.1:8080 > 127.0.0.1:51276 flags [S.] seq 1332025106 ack 2692092535 win 65483 len 0 ttl 64
```

Flags: `S` SYN, `F` FIN, `R` RST, `P` PSH, `.` ACK. Resent data is marked
`RETRANSMISSION`. Match these lines to a connection by the client port shown
in its `TCP ... accepted` event.

Requirements:

- a wedge build with the `packet-capture` feature
  (`cargo build --release --features packet-capture`); release binaries do
  not include it;
- libpcap (Linux, macOS) or [Npcap](https://npcap.com) (Windows);
- root, Administrator, or the `CAP_NET_RAW` capability. Grant it only for the
  debugging session.

Only packet headers are captured (payload bytes are already in the `TCP` and
`TLS` layers), the network interface is not put in promiscuous mode, and the
filter admits only TCP on wedge's own ports. If capture cannot start, wedge
logs why and continues without it.
