// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Prometheus metrics, rendered in the text exposition format.
//!
//! Every label value comes from configuration (vhost and upstream names,
//! server addresses) or a fixed set (method buckets, status classes), never
//! from request data, so an attacker cannot create new series (T5.2).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use hyper::Method;
use wedge_config::Config;

/// Methods with their own label value; anything else counts as `OTHER`.
const METHODS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "OTHER",
];
const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
/// Histogram bucket upper bounds, in seconds.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
/// Upstream request outcomes.
pub(crate) const OUTCOMES: [&str; 4] = ["ok", "connect_error", "error", "timeout"];

/// Counters for one vhost (or for requests that matched no vhost).
struct VhostSeries {
    requests: [[AtomicU64; CLASSES.len()]; METHODS.len()],
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl VhostSeries {
    fn new() -> Self {
        Self {
            requests: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }
}

/// What [`Metrics::totals`] returns.
pub(crate) struct Totals {
    pub(crate) requests: u64,
    /// Requests per vhost, in config order.
    pub(crate) per_vhost: Vec<u64>,
    pub(crate) open_connections: i64,
    pub(crate) connections: u64,
}

/// All metrics; shared by every connection.
pub(crate) struct Metrics {
    /// Vhost names in config order, then `"-"` for requests no vhost answered.
    vhost_names: Vec<String>,
    vhosts: Vec<VhostSeries>,
    upstream_names: Vec<String>,
    upstream_requests: Vec<[AtomicU64; OUTCOMES.len()]>,
    connections_open: AtomicI64,
    connections_total: [AtomicU64; 2],
    tls_handshake_failures: AtomicU64,
}

impl Metrics {
    pub(crate) fn new(config: &Config) -> Self {
        let mut vhost_names: Vec<String> = config.vhost.iter().map(|v| v.name.clone()).collect();
        vhost_names.push("-".to_owned());
        let upstream_names: Vec<String> = config.upstream.iter().map(|u| u.name.clone()).collect();
        Self {
            vhosts: vhost_names.iter().map(|_| VhostSeries::new()).collect(),
            vhost_names,
            upstream_requests: upstream_names
                .iter()
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            upstream_names,
            connections_open: AtomicI64::new(0),
            connections_total: [AtomicU64::new(0), AtomicU64::new(0)],
            tls_handshake_failures: AtomicU64::new(0),
        }
    }

    /// Records one finished request.
    pub(crate) fn request(
        &self,
        vhost: Option<usize>,
        method: &Method,
        status: u16,
        elapsed: Duration,
    ) {
        let index = vhost
            .filter(|&i| i + 1 < self.vhosts.len())
            .unwrap_or(self.vhosts.len() - 1);
        let series = &self.vhosts[index];
        let method = METHODS
            .iter()
            .position(|m| *m == method.as_str())
            .unwrap_or(METHODS.len() - 1);
        let class = usize::from(status / 100).clamp(1, 5) - 1;
        series.requests[method][class].fetch_add(1, Ordering::Relaxed);
        let seconds = elapsed.as_secs_f64();
        for (bound, bucket) in BUCKETS.iter().zip(&series.buckets) {
            if seconds <= *bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        series.count.fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        series.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// A connection opened; the returned guard records its close.
    pub(crate) fn connection(&self, tls: bool) -> ConnectionGuard<'_> {
        self.connections_total[usize::from(tls)].fetch_add(1, Ordering::Relaxed);
        self.connections_open.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard(self)
    }

    pub(crate) fn tls_handshake_failed(&self) {
        self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records the outcome (an index into `OUTCOMES`) of one upstream try.
    pub(crate) fn upstream(&self, upstream: usize, outcome: usize) {
        if let Some(counters) = self.upstream_requests.get(upstream) {
            counters[outcome.min(OUTCOMES.len() - 1)].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Summary counters for the admin status page.
    pub(crate) fn totals(&self) -> Totals {
        // The last series counts requests that no vhost answered.
        let per_vhost: Vec<u64> = self
            .vhosts
            .iter()
            .map(|s| s.count.load(Ordering::Relaxed))
            .collect();
        Totals {
            requests: per_vhost.iter().fold(0, |a, b| a.saturating_add(*b)),
            per_vhost,
            open_connections: self.connections_open.load(Ordering::Relaxed).max(0),
            connections: self
                .connections_total
                .iter()
                .fold(0, |a, c| a.saturating_add(c.load(Ordering::Relaxed))),
        }
    }

    /// Renders all metrics. `servers` lists (upstream name, server, up).
    pub(crate) fn render(&self, servers: &[(String, String, bool)]) -> String {
        let mut out = String::with_capacity(4096);
        let _ = writeln!(
            out,
            "# HELP wedge_build_info Build information.\n# TYPE wedge_build_info gauge\n\
             wedge_build_info{{version=\"{}\"}} 1",
            crate::VERSION
        );

        out.push_str("# HELP wedge_http_requests_total HTTP requests answered.\n");
        out.push_str("# TYPE wedge_http_requests_total counter\n");
        for (name, series) in self.vhost_names.iter().zip(&self.vhosts) {
            for (method, row) in METHODS.iter().zip(&series.requests) {
                for (class, counter) in CLASSES.iter().zip(row) {
                    let value = counter.load(Ordering::Relaxed);
                    if value > 0 {
                        let _ = writeln!(
                            out,
                            "wedge_http_requests_total{{vhost=\"{}\",method=\"{method}\",status=\"{class}\"}} {value}",
                            label(name)
                        );
                    }
                }
            }
        }

        out.push_str(
            "# HELP wedge_http_request_duration_seconds Time to produce a response head.\n",
        );
        out.push_str("# TYPE wedge_http_request_duration_seconds histogram\n");
        for (name, series) in self.vhost_names.iter().zip(&self.vhosts) {
            let name = label(name);
            for (bound, bucket) in BUCKETS.iter().zip(&series.buckets) {
                let _ = writeln!(
                    out,
                    "wedge_http_request_duration_seconds_bucket{{vhost=\"{name}\",le=\"{bound}\"}} {}",
                    bucket.load(Ordering::Relaxed)
                );
            }
            let count = series.count.load(Ordering::Relaxed);
            let sum = series.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
            let _ = writeln!(
                out,
                "wedge_http_request_duration_seconds_bucket{{vhost=\"{name}\",le=\"+Inf\"}} {count}\n\
                 wedge_http_request_duration_seconds_sum{{vhost=\"{name}\"}} {sum}\n\
                 wedge_http_request_duration_seconds_count{{vhost=\"{name}\"}} {count}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP wedge_connections_open Client connections currently open.\n\
             # TYPE wedge_connections_open gauge\nwedge_connections_open {}\n\
             # HELP wedge_connections_total Client connections accepted.\n\
             # TYPE wedge_connections_total counter\n\
             wedge_connections_total{{tls=\"false\"}} {}\nwedge_connections_total{{tls=\"true\"}} {}\n\
             # HELP wedge_tls_handshake_failures_total TLS handshakes that failed or timed out.\n\
             # TYPE wedge_tls_handshake_failures_total counter\nwedge_tls_handshake_failures_total {}",
            self.connections_open.load(Ordering::Relaxed),
            self.connections_total[0].load(Ordering::Relaxed),
            self.connections_total[1].load(Ordering::Relaxed),
            self.tls_handshake_failures.load(Ordering::Relaxed),
        );

        out.push_str("# HELP wedge_upstream_requests_total Upstream attempts by outcome.\n");
        out.push_str("# TYPE wedge_upstream_requests_total counter\n");
        for (name, counters) in self.upstream_names.iter().zip(&self.upstream_requests) {
            for (outcome, counter) in OUTCOMES.iter().zip(counters) {
                let _ = writeln!(
                    out,
                    "wedge_upstream_requests_total{{upstream=\"{}\",outcome=\"{outcome}\"}} {}",
                    label(name),
                    counter.load(Ordering::Relaxed)
                );
            }
        }
        out.push_str(
            "# HELP wedge_upstream_server_up Whether an upstream server is in rotation.\n",
        );
        out.push_str("# TYPE wedge_upstream_server_up gauge\n");
        for (upstream, server, up) in servers {
            let _ = writeln!(
                out,
                "wedge_upstream_server_up{{upstream=\"{}\",server=\"{}\"}} {}",
                label(upstream),
                label(server),
                u8::from(*up)
            );
        }
        out
    }
}

/// Decrements the open-connection gauge when dropped.
pub(crate) struct ConnectionGuard<'a>(&'a Metrics);

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.connections_open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Escapes a label value as the exposition format requires.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_bounded_and_escaped() {
        let config = wedge_config::from_str(
            "[[vhost]]\nname = \"a\\\"b\"\nroot = \"/x\"\n\
             [[upstream]]\nname = \"u\"\nservers = [\"127.0.0.1:9\"]\n",
        )
        .unwrap();
        let metrics = Metrics::new(&config);
        let any = Method::from_bytes(b"ATTACKER-CHOSEN").unwrap();
        metrics.request(Some(0), &Method::GET, 200, Duration::from_millis(3));
        metrics.request(Some(0), &any, 404, Duration::from_millis(30));
        metrics.request(None, &Method::POST, 999, Duration::from_secs(60));
        metrics.upstream(0, 1);
        let text = metrics.render(&[("u".into(), "127.0.0.1:9".into(), false)]);
        assert!(text.contains(
            "wedge_http_requests_total{vhost=\"a\\\"b\",method=\"GET\",status=\"2xx\"} 1"
        ));
        assert!(
            text.contains("method=\"OTHER\",status=\"4xx\"} 1"),
            "{text}"
        );
        assert!(!text.contains("ATTACKER"), "{text}");
        assert!(text
            .contains("wedge_http_requests_total{vhost=\"-\",method=\"POST\",status=\"5xx\"} 1"));
        assert!(text.contains("le=\"0.005\"} 1\n"), "{text}");
        assert!(text
            .contains("wedge_upstream_requests_total{upstream=\"u\",outcome=\"connect_error\"} 1"));
        assert!(text.contains("wedge_upstream_server_up{upstream=\"u\",server=\"127.0.0.1:9\"} 0"));
    }
}
