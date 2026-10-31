// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Static file serving: GET and HEAD, validators (ETag, Last-Modified),
//! conditional requests, a single byte range, and pre-compressed variants.
//!
//! Security properties (threat model): the request path is validated by
//! [`crate::path`], then the joined path is canonicalized and must stay inside
//! the canonical root (T2.1, T2.2); symlinks are refused unless enabled (T2.2);
//! there is no directory listing (T2.3); Content-Type comes from a fixed
//! extension map with `nosniff` (T2.12); multi-range requests get the full
//! body (T2.10); only pre-compressed files are served compressed (T2.15).

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use futures_util::TryStreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::capture::{here, Handled};
use crate::path::{self, Refusal};
use crate::response::{self, Body};

/// A document root, canonicalized at startup.
#[derive(Debug, Clone)]
pub(crate) struct Root {
    pub(crate) dir: PathBuf,
    pub(crate) follow_symlinks: bool,
}

/// Serves `raw_path` (still percent-encoded) from `root`.
pub(crate) async fn serve(
    root: &Root,
    method: &Method,
    raw_path: &str,
    headers: &HeaderMap,
) -> Response<Body> {
    let safe = match path::parse(raw_path) {
        Ok(safe) => safe,
        Err(refusal) => {
            tracing::debug!(?refusal, "request path refused");
            return response::status(match refusal {
                Refusal::BadEncoding | Refusal::Forbidden => StatusCode::BAD_REQUEST,
                Refusal::Hidden => StatusCode::NOT_FOUND,
            });
        }
    };
    let Some(mut file_path) = locate(root, &safe.segments).await else {
        return response::status(StatusCode::NOT_FOUND);
    };
    let Ok(mut meta) = tokio::fs::metadata(&file_path).await else {
        return response::status(StatusCode::NOT_FOUND);
    };
    if meta.is_dir() {
        if !safe.trailing_slash {
            return redirect_to_slash(raw_path);
        }
        let index = file_path.join("index.html");
        match tokio::fs::symlink_metadata(&index).await {
            Ok(m) if m.is_file() => {
                file_path = index;
                meta = m;
            }
            // No directory listings (T2.3).
            _ => return response::status(StatusCode::NOT_FOUND),
        }
    }
    if !meta.is_file() {
        return response::status(StatusCode::NOT_FOUND);
    }
    let content_type = mime_for(&file_path);
    let (file_path, meta, encoding) = choose_encoding(&file_path, meta, headers).await;
    let validators = Validators::new(meta.len(), meta.modified().ok(), encoding);

    let mut builder = Response::builder()
        .extension(Handled {
            what: format!("static file {}", file_path.display()),
            at: here!(),
        })
        .header(header::CONTENT_TYPE, content_type)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, &validators.etag)
        .header(header::VARY, "accept-encoding");
    if let Some(modified) = &validators.last_modified {
        builder = builder.header(header::LAST_MODIFIED, modified);
    }
    if let Some(encoding) = encoding {
        builder = builder.header(header::CONTENT_ENCODING, encoding);
    }
    if validators.not_modified(headers) {
        return finish(builder.status(StatusCode::NOT_MODIFIED), response::empty());
    }

    let len = meta.len();
    let range = match requested_range(headers, &validators, len) {
        RangeDecision::Full => None,
        RangeDecision::Partial(start, end) => Some((start, end)),
        RangeDecision::Unsatisfiable => {
            let builder = builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{len}"));
            return finish(builder, response::empty());
        }
    };
    let (status, start, count) = match range {
        Some((start, end)) => {
            builder = builder.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
            (StatusCode::PARTIAL_CONTENT, start, end - start + 1)
        }
        None => (StatusCode::OK, 0, len),
    };
    let builder = builder.status(status).header(header::CONTENT_LENGTH, count);
    if method == Method::HEAD {
        return finish(builder, response::empty());
    }
    match open_body(&file_path, start, count).await {
        Ok(body) => finish(builder, body),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read file");
            response::status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Joins the segments onto the root and confirms the canonical result is
/// still inside the root. Returns `None` (404) for anything else.
async fn locate(root: &Root, segments: &[String]) -> Option<PathBuf> {
    let mut candidate = root.dir.clone();
    for segment in segments {
        candidate.push(segment);
        if !root.follow_symlinks {
            let meta = tokio::fs::symlink_metadata(&candidate).await.ok()?;
            if meta.file_type().is_symlink() {
                tracing::debug!("symlink refused");
                return None;
            }
        }
    }
    let canonical = tokio::fs::canonicalize(&candidate).await.ok()?;
    if canonical.starts_with(&root.dir) {
        Some(canonical)
    } else {
        tracing::warn!("resolved path escapes document root");
        None
    }
}

fn redirect_to_slash(raw_path: &str) -> Response<Body> {
    // raw_path passed path::parse, so it has no CR/LF or other controls and
    // cannot inject headers; HeaderValue::from_str rejects them anyway.
    // Empty and `.` segments are dropped: `//host/dir` would otherwise become
    // a protocol-relative Location and redirect off-site (T2.11).
    let mut response = response::status(StatusCode::MOVED_PERMANENTLY);
    let path: Vec<&str> = raw_path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if let Ok(location) = HeaderValue::from_str(&format!("/{}/", path.join("/"))) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// Serves `file.br` or `file.gz` instead of `file` when the client accepts
/// that encoding and the variant exists as a regular file. Nothing is
/// compressed on the fly.
async fn choose_encoding(
    file_path: &Path,
    meta: std::fs::Metadata,
    headers: &HeaderMap,
) -> (PathBuf, std::fs::Metadata, Option<&'static str>) {
    let accepted = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for (encoding, suffix) in [("br", "br"), ("gzip", "gz")] {
        if !accepts(accepted, encoding) {
            continue;
        }
        let mut variant = file_path.as_os_str().to_owned();
        variant.push(".");
        variant.push(suffix);
        let variant = PathBuf::from(variant);
        if let Ok(m) = tokio::fs::symlink_metadata(&variant).await {
            if m.is_file() {
                return (variant, m, Some(encoding));
            }
        }
    }
    (file_path.to_path_buf(), meta, None)
}

/// True when `accept_encoding` lists `coding` with a non-zero quality.
fn accepts(accept_encoding: &str, coding: &str) -> bool {
    accept_encoding.split(',').any(|item| {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        let zero = parts.any(|p| {
            let p = p.trim();
            p.strip_prefix("q=")
                .is_some_and(|q| q.trim().parse::<f32>().is_ok_and(|q| q <= 0.0))
        });
        name.eq_ignore_ascii_case(coding) && !zero
    })
}

struct Validators {
    etag: String,
    last_modified: Option<String>,
    modified: Option<SystemTime>,
}

impl Validators {
    fn new(len: u64, modified: Option<SystemTime>, encoding: Option<&str>) -> Self {
        let nanos = modified
            .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        let suffix = encoding.map_or(String::new(), |e| format!("-{e}"));
        Self {
            etag: format!("\"{len:x}-{nanos:x}{suffix}\""),
            last_modified: modified.map(httpdate::fmt_http_date),
            modified,
        }
    }

    /// RFC 9110 section 13.2.2: If-None-Match wins over If-Modified-Since.
    fn not_modified(&self, headers: &HeaderMap) -> bool {
        if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
            let Ok(inm) = inm.to_str() else {
                return false;
            };
            return inm.split(',').any(|tag| {
                let tag = tag.trim();
                tag == "*" || tag.trim_start_matches("W/") == self.etag
            });
        }
        let since = headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok());
        match (since, self.modified) {
            // Compare at one-second precision, as HTTP dates have.
            (Some(since), Some(modified)) => httpdate::HttpDate::from(modified) <= since.into(),
            _ => false,
        }
    }
}

enum RangeDecision {
    Full,
    /// Inclusive start and end.
    Partial(u64, u64),
    Unsatisfiable,
}

/// Interprets a `Range` header. Only one range is honoured; multi-range or
/// malformed headers get the full body, as RFC 9110 permits (T2.10).
fn requested_range(headers: &HeaderMap, validators: &Validators, len: u64) -> RangeDecision {
    let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return RangeDecision::Full;
    };
    if let Some(if_range) = headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
        let matches =
            if_range == validators.etag || validators.last_modified.as_deref() == Some(if_range);
        if !matches {
            return RangeDecision::Full;
        }
    }
    let Some(spec) = range.trim().strip_prefix("bytes=") else {
        return RangeDecision::Full;
    };
    if spec.contains(',') {
        return RangeDecision::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return RangeDecision::Full;
    };
    let (first, last) = (first.trim(), last.trim());
    let parse = |s: &str| s.parse::<u64>().ok();
    let (start, end) = match (first.is_empty(), last.is_empty()) {
        // bytes=-N: the last N bytes.
        (true, false) => match parse(last) {
            Some(0) => return RangeDecision::Unsatisfiable,
            Some(n) => (len.saturating_sub(n), len.saturating_sub(1)),
            None => return RangeDecision::Full,
        },
        // bytes=N-: from N to the end.
        (false, true) => match parse(first) {
            Some(start) => (start, len.saturating_sub(1)),
            None => return RangeDecision::Full,
        },
        (false, false) => match (parse(first), parse(last)) {
            (Some(start), Some(end)) if start <= end => (start, end.min(len.saturating_sub(1))),
            _ => return RangeDecision::Full,
        },
        (true, true) => return RangeDecision::Full,
    };
    if len == 0 || start >= len {
        RangeDecision::Unsatisfiable
    } else {
        RangeDecision::Partial(start, end)
    }
}

async fn open_body(path: &Path, start: u64, count: u64) -> std::io::Result<Body> {
    let mut file = tokio::fs::File::open(path).await?;
    if start > 0 {
        file.seek(SeekFrom::Start(start)).await?;
    }
    let stream = ReaderStream::with_capacity(file.take(count), 64 * 1024).map_ok(Frame::data);
    Ok(StreamBody::new(stream).boxed())
}

fn finish(builder: hyper::http::response::Builder, body: Body) -> Response<Body> {
    builder
        .body(body)
        .unwrap_or_else(|_| response::status(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Content-Type by file extension. Unknown types are served as opaque bytes so
/// browsers never guess (T2.12).
fn mime_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators() -> Validators {
        Validators::new(10, Some(SystemTime::UNIX_EPOCH), None)
    }

    fn range(value: &str, len: u64) -> RangeDecision {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_str(value).unwrap());
        requested_range(&headers, &validators(), len)
    }

    #[test]
    fn single_ranges() {
        assert!(matches!(
            range("bytes=0-4", 10),
            RangeDecision::Partial(0, 4)
        ));
        assert!(matches!(
            range("bytes=5-", 10),
            RangeDecision::Partial(5, 9)
        ));
        assert!(matches!(
            range("bytes=-3", 10),
            RangeDecision::Partial(7, 9)
        ));
        assert!(matches!(
            range("bytes=-30", 10),
            RangeDecision::Partial(0, 9)
        ));
        assert!(matches!(
            range("bytes=2-99", 10),
            RangeDecision::Partial(2, 9)
        ));
    }

    #[test]
    fn unsatisfiable_and_ignored_ranges() {
        assert!(matches!(
            range("bytes=10-", 10),
            RangeDecision::Unsatisfiable
        ));
        assert!(matches!(
            range("bytes=-0", 10),
            RangeDecision::Unsatisfiable
        ));
        assert!(matches!(range("bytes=0-1,3-4", 10), RangeDecision::Full));
        assert!(matches!(range("bytes=5-2", 10), RangeDecision::Full));
        assert!(matches!(range("items=0-1", 10), RangeDecision::Full));
        assert!(matches!(range("bytes=x-y", 10), RangeDecision::Full));
    }

    #[test]
    fn accept_encoding_parsing() {
        assert!(accepts("gzip, br", "br"));
        assert!(accepts("BR;q=0.5", "br"));
        assert!(!accepts("br;q=0", "br"));
        assert!(!accepts("gzip", "br"));
        assert!(!accepts("", "gzip"));
    }

    #[test]
    fn unknown_extensions_are_opaque() {
        assert_eq!(mime_for(Path::new("a.exe")), "application/octet-stream");
        assert_eq!(mime_for(Path::new("noext")), "application/octet-stream");
        assert_eq!(mime_for(Path::new("A.HTML")), "text/html; charset=utf-8");
    }

    #[test]
    fn if_none_match_beats_if_modified_since() {
        let v = validators();
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"other\""));
        headers.insert(
            header::IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sun, 06 Nov 2094 08:49:37 GMT"),
        );
        assert!(!v.not_modified(&headers));
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&v.etag).unwrap(),
        );
        assert!(v.not_modified(&headers));
    }
}
