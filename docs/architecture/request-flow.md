# Request flow

How a request travels through wedge's source files, from the process entry
point to the bytes going back to the client. Use it with the debug capture
log (`[server.debug] read_packet = true`): every capture event names the
`file:line` that produced it, and those files are the boxes below.

Paths are relative to `crates/`. `wedge-core/src/server.rs` is the hub; the
other modules each own one step.

## Startup

```mermaid
flowchart TD
    main["wedge/src/main.rs<br/>main → run → serve"]
    load["wedge-config/src/lib.rs<br/>load: master file + conf.d/*.toml"]
    merge["wedge-config/src/merge.rs<br/>merge tables in lexical order"]
    schema["wedge-config/src/schema.rs<br/>validate against the JSON Schema"]
    model["wedge-config/src/model.rs<br/>typed Config + semantic_errors"]
    bind["wedge-core/src/server.rs<br/>Server::bind_reloadable"]
    build["server.rs State::build"]
    tls["tls.rs Tls::from_config<br/>load certs by reference, SNI resolver"]
    hdr["headers.rs Policy::new<br/>security headers, HSTS, redirects"]
    proxy["proxy.rs Proxy::new<br/>upstream pools, health checks"]
    metrics["metrics.rs Metrics::new"]
    cap["capture.rs Capture::start<br/>(only with read_packet)"]
    pcap["pcap_capture.rs start<br/>(only with tcp_headers + feature)"]
    runl["server.rs Server::run<br/>one accept_loop per listener"]
    svc["wedge/src/service.rs<br/>Windows service entry point"]

    main --> load --> merge --> schema --> model
    svc --> main
    main --> bind --> build
    build --> tls & hdr & proxy & metrics
    bind --> cap --> pcap
    bind --> runl
```

## One request

```mermaid
flowchart TD
    accept["server.rs accept_loop<br/>connection cap, admin allow-list"]
    idle["idle.rs IdleTimeout<br/>socket idle deadline"]
    rawcap["capture.rs Recorded (layer TCP)<br/>raw bytes, hex dump"]
    hs["tls.rs SniResolver + rustls<br/>handshake, certificate by SNI"]
    tlscap["capture.rs Recorded (layer TLS)<br/>decrypted bytes, redacted"]
    hyper["hyper / hyper-util auto::Builder<br/>HTTP/1.1 or HTTP/2 parsing, limits"]
    serve["server.rs serve → handle<br/>capture HTTP request event, access-log entry"]
    admin["server.rs admin_request<br/>admin.rs respond / reload_rejection"]
    respond["server.rs respond<br/>URI length, request timeout"]
    route["server.rs route"]
    vhost["vhost.rs Router::route + request_host<br/>Host → vhost (T2.16), SNI/Host check (T3.4)"]
    redirect["headers.rs Policy::https_redirect<br/>plain HTTP → 308 (T3.11, T3.12)"]
    proxyr["proxy.rs Proxy::route<br/>longest prefix match"]
    fwd["proxy.rs Proxy::forward<br/>path.rs proxy_path_ok (T4.13)<br/>strip_hop_by_hop, set_forwarding_headers<br/>Pool::pick, retries, IdleBody"]
    files["files.rs serve<br/>path.rs parse (T2.1–T2.4), locate,<br/>choose_encoding, validators, ranges"]
    apply["headers.rs Policy::apply<br/>default + vhost headers, HSTS"]
    meter["metrics.rs Metrics::request"]
    log["server.rs AccessEntry::log<br/>capture ROUTE + HTTP response events"]
    out["back through Recorded / TLS / idle.rs<br/>to the socket"]

    accept --> idle --> rawcap
    rawcap -->|TLS listener| hs --> tlscap --> hyper
    rawcap -->|plain listener| hyper
    rawcap -->|admin listener, never captured| admin
    hyper --> serve --> respond --> route --> vhost
    vhost --> redirect
    vhost --> proxyr
    proxyr -->|matched| fwd
    proxyr -->|no route| files
    redirect --> apply
    fwd --> apply
    files --> apply
    apply --> meter --> log --> out
```

## Reload

```mermaid
sequenceDiagram
    participant Op as Operator
    participant M as wedge/src/main.rs
    participant S as server.rs Shared::reload
    participant C as wedge-config load
    participant B as server.rs State::build
    Op->>M: SIGHUP, `wedge reload`, or POST /-/reload (admin.rs)
    M->>S: Reloader::reload
    S->>S: one at a time, at most once per second (T5.5)
    S->>C: read and validate wedge.toml + conf.d
    S->>S: refuse changes to listeners, admin, limits, debug (T5.6)
    S->>B: build the complete new state (certs, roots, upstreams)
    B-->>S: new State, or an error
    S->>S: swap atomically, or on error keep the old state (T5.4)
```

## Reading the capture log against this map

| Capture event (layer, source) | Box above | What it shows |
|---|---|---|
| `TCP server.rs` "accepted ..." | `accept_loop` | client and local address, listener kind |
| `TCP capture.rs` "<- / -> N bytes" | `Recorded (layer TCP)` | raw bytes; ciphertext on TLS listeners |
| `TLS server.rs` "handshake complete ..." | `SniResolver + rustls` | SNI, ALPN, TLS version, cipher suite |
| `TLS capture.rs` "<- / -> N bytes" | `Recorded (layer TLS)` | decrypted bytes, credentials redacted |
| `HTTP server.rs` "request ..." | `serve → handle` | parsed request line and headers |
| `ROUTE files.rs` "static file ..." | `files.rs serve` | the file that was served |
| `ROUTE proxy.rs` "proxy upstream=..." | `Proxy::forward` | upstream and server that answered |
| `ROUTE server.rs` "answered by wedge" | `route` / `respond` | an error, redirect or limit response |
| `HTTP server.rs` "response ..." | `AccessEntry::log` | status, headers, time to response head |
| `IP pcap_capture.rs` "a > b flags [...]" | below `accept_loop` | IP/TCP headers: seq, ack, flags, window, retransmissions |

Connection ids (`conn=N`) tie the events of one connection together. IP/TCP
header events have `conn=0`; match them to a connection by the client port in
the `TCP ... accepted` event.
