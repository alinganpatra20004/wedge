// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Requests on the admin listener (threat model T5.1 to T5.3). The client
//! address was already checked against `admin.allow` before any HTTP was
//! read.

use hyper::body::Incoming;
use hyper::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};

use crate::metrics::Metrics;
use crate::proxy::Proxy;
use crate::response::{self, Body};

/// Answers one admin request: `GET /metrics`; anything else is 404 or 405.
pub(crate) fn respond(metrics: &Metrics, proxy: &Proxy, req: &Request<Incoming>) -> Response<Body> {
    if !host_is_local(req) {
        // T5.3: a DNS-rebinding page reaches us with its own host name.
        return response::status(StatusCode::MISDIRECTED_REQUEST);
    }
    match (req.method(), req.uri().path()) {
        (&Method::GET | &Method::HEAD, "/metrics") => {
            let text = metrics.render(&proxy.health_snapshot());
            let mut response = Response::new(response::full(text));
            let headers = response.headers_mut();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        (_, "/metrics") => response::status(StatusCode::METHOD_NOT_ALLOWED),
        _ => response::status(StatusCode::NOT_FOUND),
    }
}

/// The request's host is an IP literal or `localhost`, never a DNS name that
/// an attacker could point at 127.0.0.1.
fn host_is_local(req: &Request<Incoming>) -> bool {
    let host = req.uri().host().map(str::to_owned).or_else(|| {
        let value = req.headers().get(hyper::header::HOST)?.to_str().ok()?;
        let authority: hyper::http::uri::Authority = value.parse().ok()?;
        Some(authority.host().to_owned())
    });
    host.is_some_and(|h| {
        let bare = h.trim_start_matches('[').trim_end_matches(']');
        h.eq_ignore_ascii_case("localhost") || bare.parse::<std::net::IpAddr>().is_ok()
    })
}
