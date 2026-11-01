// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Response helpers. Error bodies are generic and never include request data
//! or filesystem paths (threat model T2.13).

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::header::{HeaderValue, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use hyper::{Response, StatusCode};

/// Response body type used throughout the server.
pub type Body = BoxBody<Bytes, std::io::Error>;

/// An empty body.
pub fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed()
}

/// A body holding `bytes`.
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A plain-text response with the status's canonical reason as its body.
pub fn status(code: StatusCode) -> Response<Body> {
    let text = format!(
        "{} {}\n",
        code.as_u16(),
        code.canonical_reason().unwrap_or("")
    );
    let mut response = Response::new(full(text));
    *response.status_mut() = code;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}
