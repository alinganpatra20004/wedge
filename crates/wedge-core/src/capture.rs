// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Debug capture log (`[server.debug] read_packet`, threat model T5.9 to
//! T5.12).
//!
//! Records, per connection, what wedge sees at each layer: raw TCP bytes,
//! TLS handshake facts and decrypted bytes, parsed HTTP messages and routing
//! decisions. Every event names the source file and line that produced it,
//! so a request can be followed from the entry point.
//!
//! Safeguards: credentials and query strings are redacted unless
//! `log_secrets` is set; HTTP/2 payloads are summarized, not dumped, unless
//! `log_secrets` is set (HPACK makes header redaction unreliable); bytes are
//! written as hex plus escaped ASCII; recording is capped per connection;
//! events go through a bounded queue and are dropped (and counted) rather
//! than slowing the server; the file is owner-only and rotated.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use hyper::header::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wedge_config::DebugConfig;

/// `"path/to/file.rs:123"` for the call site.
macro_rules! here {
    () => {
        concat!(file!(), ":", line!())
    };
}
pub(crate) use here;

/// Header names always redacted unless `log_secrets` is on.
pub(crate) const SENSITIVE: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
];
/// Events waiting for the writer; beyond this they are dropped (T5.10).
const QUEUE: usize = 4096;
/// Longest partial line held back for redaction before it is written as is.
const MAX_PENDING_LINE: usize = 8192;

/// Attached to a response by the handler that produced it, so the capture
/// log can say which file did what (for example "static file /srv/a.html"
/// from `files.rs`).
#[derive(Clone)]
pub(crate) struct Handled {
    pub(crate) what: String,
    pub(crate) at: &'static str,
}

/// The capture log; shared by all connections.
pub(crate) struct Capture {
    tx: SyncSender<String>,
    dropped: Arc<AtomicU64>,
    next_conn: AtomicU64,
    log_secrets: bool,
    redact: Vec<String>,
    max_bytes: u64,
}

impl Capture {
    /// Opens the capture log and starts its writer thread, or returns `None`
    /// when `read_packet` is off.
    pub(crate) fn start(debug: &DebugConfig) -> io::Result<Option<Arc<Self>>> {
        if !debug.read_packet {
            return Ok(None);
        }
        let mut writer = Writer::open(
            debug.capture_file.clone(),
            debug.max_file_bytes,
            debug.keep_files,
            debug.log_secrets,
        )?;
        let (tx, rx) = sync_channel::<String>(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name("wedge-capture".into())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    if let Err(e) = writer.write(&line) {
                        tracing::error!(error = %e, "capture log write failed; capture stopped");
                        return;
                    }
                }
                let _ = writer.flush();
            })?;
        let mut redact: Vec<String> = SENSITIVE.iter().map(|s| (*s).to_owned()).collect();
        redact.extend(debug.redact_headers.iter().map(|h| h.to_ascii_lowercase()));
        Ok(Some(Arc::new(Self {
            tx,
            dropped,
            next_conn: AtomicU64::new(1),
            log_secrets: debug.log_secrets,
            redact,
            max_bytes: debug.max_bytes_per_connection,
        })))
    }

    /// Events dropped because the writer could not keep up.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A new connection id for the log.
    pub(crate) fn connection_id(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Records one event: `layer` such as `TCP`, `TLS`, `HTTP`, `ROUTE`;
    /// `at` from [`here!`]; `text` may span lines.
    pub(crate) fn event(&self, conn: u64, layer: &str, at: &str, text: &str) {
        let mut line = format!("{} conn={conn} {layer:<5} {at} ", timestamp());
        // T5.12: event text never carries raw control characters.
        for (i, part) in text.split('\n').enumerate() {
            if i > 0 {
                line.push_str("\n    ");
            }
            escape_into(&mut line, part.trim_end_matches('\r'));
        }
        line.push('\n');
        match self.tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Request or response headers as event text, redacted unless
    /// `log_secrets` is on.
    pub(crate) fn headers(&self, first: &str, headers: &HeaderMap) -> String {
        let mut text = first.to_owned();
        for (name, value) in headers {
            let shown = if !self.log_secrets && self.redact.iter().any(|r| r == name.as_str()) {
                "[REDACTED]".into()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            let _ = write!(text, "\n{name}: {shown}");
        }
        text
    }

    /// A request target with its query redacted unless `log_secrets` is on.
    pub(crate) fn target(&self, path_and_query: &str) -> String {
        match path_and_query.split_once('?') {
            Some((path, _)) if !self.log_secrets => format!("{path}?[REDACTED]"),
            _ => path_and_query.to_owned(),
        }
    }

    /// Wraps a byte stream so everything read and written is recorded under
    /// `layer`. `plaintext` streams get line redaction and the HTTP/2 rule;
    /// TLS ciphertext needs neither.
    pub(crate) fn wrap<S>(
        self: &Arc<Self>,
        inner: S,
        conn: u64,
        layer: &'static str,
        plaintext: bool,
    ) -> Recorded<S> {
        Recorded {
            inner,
            capture: Some(Arc::clone(self)),
            conn,
            layer,
            plaintext,
            directions: [Direction::new(), Direction::new()],
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let dropped = self.dropped();
        if dropped > 0 {
            tracing::warn!(dropped, "capture log events were dropped");
        }
    }
}

/// A stream whose bytes are copied into the capture log. With no capture it
/// is a plain pass-through.
pub(crate) struct Recorded<S> {
    inner: S,
    capture: Option<Arc<Capture>>,
    conn: u64,
    layer: &'static str,
    plaintext: bool,
    /// [read, written].
    directions: [Direction; 2],
}

impl<S> Recorded<S> {
    /// A pass-through wrapper (capture off).
    pub(crate) fn plain(inner: S) -> Self {
        Self {
            inner,
            capture: None,
            conn: 0,
            layer: "",
            plaintext: false,
            directions: [Direction::new(), Direction::new()],
        }
    }

    /// Marks the stream as HTTP/2 (after ALPN): payloads are summarized from
    /// now on unless `log_secrets` is set.
    pub(crate) fn set_http2(&mut self) {
        for d in &mut self.directions {
            d.http2 = true;
        }
    }

    fn record(&mut self, index: usize, bytes: &[u8]) {
        let Some(capture) = &self.capture else {
            return;
        };
        let arrow = if index == 0 { "<-" } else { "->" };
        let d = &mut self.directions[index];
        let offset = d.offset;
        d.offset += bytes.len() as u64;
        // h2c prior knowledge starts with the connection preface.
        if offset == 0 && bytes.starts_with(b"PRI * HTTP/2.0") {
            d.http2 = true;
        }
        let room = capture.max_bytes.saturating_sub(d.recorded);
        if room == 0 {
            d.skipped += bytes.len() as u64;
            return;
        }
        let take = usize::try_from(room).unwrap_or(usize::MAX).min(bytes.len());
        d.recorded += take as u64;
        d.skipped += (bytes.len() - take) as u64;
        let bytes = &bytes[..take];
        if self.plaintext && d.http2 && !capture.log_secrets {
            let text = format!(
                "{arrow} {} bytes at offset {offset} (HTTP/2 frames not dumped: header \
                 compression prevents redaction; set log_secrets to include them)",
                bytes.len()
            );
            capture.event(self.conn, self.layer, here!(), &text);
            return;
        }
        let shown = if capture.log_secrets || !self.plaintext {
            bytes.to_vec()
        } else {
            d.redactor.feed(bytes, &capture.redact)
        };
        let mut text = format!("{arrow} {} bytes at offset {offset}", bytes.len());
        if self.plaintext && !capture.log_secrets {
            text.push_str(if shown.is_empty() {
                " (held back until the line is complete, for redaction)"
            } else {
                " (dump shows complete lines, redacted)"
            });
        }
        hexdump(&mut text, &shown);
        capture.event(self.conn, self.layer, here!(), &text);
    }
}

impl<S> Drop for Recorded<S> {
    fn drop(&mut self) {
        let Some(capture) = &self.capture else {
            return;
        };
        let [read, written] = &mut self.directions;
        // Lines still held back for redaction are written as they are.
        for (arrow, d) in [("<-", &mut *read), ("->", &mut *written)] {
            let rest = d.redactor.finish(&capture.redact);
            if !rest.is_empty() && self.plaintext && !capture.log_secrets && !d.http2 {
                let mut text = format!("{arrow} {} bytes (end of stream)", rest.len());
                hexdump(&mut text, &rest);
                capture.event(self.conn, self.layer, here!(), &text);
            }
        }
        let text = format!(
            "closed: read {} bytes ({} not recorded), wrote {} bytes ({} not recorded)",
            read.offset, read.skipped, written.offset, written.skipped
        );
        capture.event(self.conn, self.layer, here!(), &text);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Recorded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let new = buf.filled()[before..].to_vec();
            if !new.is_empty() {
                self.record(0, &new);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recorded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            let n = *n;
            self.record(1, &buf[..n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Per-direction counters and redaction state.
struct Direction {
    offset: u64,
    recorded: u64,
    skipped: u64,
    http2: bool,
    redactor: LineRedactor,
}

impl Direction {
    fn new() -> Self {
        Self {
            offset: 0,
            recorded: 0,
            skipped: 0,
            http2: false,
            redactor: LineRedactor::default(),
        }
    }
}

/// Redacts credential header values and request-line query strings in a
/// byte stream that may split lines anywhere. Complete lines are released
/// redacted; a partial line is held back until it completes or grows past
/// `MAX_PENDING_LINE`. An over-long line is then judged by its start: if it
/// is sensitive, the redacted start is released and the rest of the line is
/// dropped up to its newline; otherwise it passes through.
#[derive(Default)]
pub(crate) struct LineRedactor {
    pending: Vec<u8>,
    /// Inside an over-long line: `Some(true)` drops the rest of it,
    /// `Some(false)` passes it through.
    long_line: Option<bool>,
}

impl LineRedactor {
    pub(crate) fn feed(&mut self, bytes: &[u8], names: &[String]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut bytes = bytes;
        if let Some(drop) = self.long_line {
            let Some(newline) = bytes.iter().position(|b| *b == b'\n') else {
                if !drop {
                    out.extend_from_slice(bytes);
                }
                return out;
            };
            let (line_rest, after) = bytes.split_at(newline + 1);
            if drop {
                let crlf = line_rest.len() > 1 && line_rest[line_rest.len() - 2] == b'\r';
                out.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
            } else {
                out.extend_from_slice(line_rest);
            }
            self.long_line = None;
            bytes = after;
        }
        self.pending.extend_from_slice(bytes);
        out.reserve(self.pending.len());
        let mut start = 0;
        while let Some(end) = self.pending[start..].iter().position(|b| *b == b'\n') {
            let line = &self.pending[start..=start + end];
            redact_line(line, names, &mut out);
            start += end + 1;
        }
        let rest = self.pending.split_off(start);
        if rest.len() > MAX_PENDING_LINE {
            self.long_line = Some(redact_partial(&rest, names, &mut out));
            self.pending.clear();
        } else {
            self.pending = rest;
        }
        out
    }

    /// Releases a line cut off by the end of the stream.
    pub(crate) fn finish(&mut self, names: &[String]) -> Vec<u8> {
        let rest = std::mem::take(&mut self.pending);
        let mut out = Vec::new();
        if !rest.is_empty() {
            redact_partial(&rest, names, &mut out);
        }
        out
    }
}

/// Writes the redacted form of the start of a line whose end has not been
/// seen, and returns whether the rest of the line must be dropped: a
/// credential header, or a request line (`METHOD SP target`) with a query.
fn redact_partial(start: &[u8], names: &[String], out: &mut Vec<u8>) -> bool {
    if let Some(colon) = start.iter().position(|b| *b == b':') {
        let name = String::from_utf8_lossy(&start[..colon])
            .trim()
            .to_ascii_lowercase();
        if names.contains(&name) {
            out.extend_from_slice(&start[..=colon]);
            out.extend_from_slice(b" [REDACTED]");
            return true;
        }
    }
    let method_len = start.iter().take_while(|b| b.is_ascii_uppercase()).count();
    let request_line = method_len > 0 && start.get(method_len) == Some(&b' ');
    if let (true, Some(q)) = (request_line, start.iter().position(|b| *b == b'?')) {
        out.extend_from_slice(&start[..=q]);
        out.extend_from_slice(b"[REDACTED]");
        return true;
    }
    out.extend_from_slice(start);
    false
}

fn redact_line(line: &[u8], names: &[String], out: &mut Vec<u8>) {
    let ending = if line.ends_with(b"\r\n") {
        &b"\r\n"[..]
    } else if line.ends_with(b"\n") {
        &b"\n"[..]
    } else {
        &b""[..]
    };
    let body = &line[..line.len() - ending.len()];
    if let Some(colon) = body.iter().position(|b| *b == b':') {
        let name = String::from_utf8_lossy(&body[..colon])
            .trim()
            .to_ascii_lowercase();
        if names.contains(&name) {
            out.extend_from_slice(&body[..=colon]);
            out.extend_from_slice(b" [REDACTED]");
            out.extend_from_slice(ending);
            return;
        }
    }
    // A request line: METHOD SP target SP HTTP/x; hide the query.
    let is_request_line =
        body.windows(6).any(|w| w == b" HTTP/") && body.first().is_some_and(u8::is_ascii_uppercase);
    if let (true, Some(q)) = (is_request_line, body.iter().position(|b| *b == b'?')) {
        let end = body[q..]
            .iter()
            .position(|b| *b == b' ')
            .map_or(body.len(), |i| q + i);
        out.extend_from_slice(&body[..=q]);
        out.extend_from_slice(b"[REDACTED]");
        out.extend_from_slice(&body[end..]);
        out.extend_from_slice(ending);
        return;
    }
    out.extend_from_slice(line);
}

/// `offset  hex bytes  |ascii|`, 16 bytes per line (T5.12).
fn hexdump(text: &mut String, bytes: &[u8]) {
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(text, "\n{:06x}  ", row * 16);
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(text, "{b:02x} ");
                }
                None => text.push_str("   "),
            }
        }
        text.push(' ');
        text.push('|');
        for b in chunk {
            text.push(if b.is_ascii_graphic() || *b == b' ' {
                char::from(*b)
            } else {
                '.'
            });
        }
        text.push('|');
    }
}

fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
}

/// Seconds since the Unix epoch with milliseconds, in UTC.
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

/// Appends lines to the capture file, rotating it at `max_bytes`.
struct Writer {
    path: PathBuf,
    file: BufWriter<File>,
    written: u64,
    max_bytes: u64,
    keep: u32,
    log_secrets: bool,
}

impl Writer {
    fn open(path: PathBuf, max_bytes: u64, keep: u32, log_secrets: bool) -> io::Result<Self> {
        let file = open_private(&path)?;
        let written = file.metadata().map_or(0, |m| m.len());
        let mut writer = Self {
            path,
            file: BufWriter::new(file),
            written,
            max_bytes,
            keep,
            log_secrets,
        };
        writer.banner()?;
        Ok(writer)
    }

    fn banner(&mut self) -> io::Result<()> {
        let secrets = if self.log_secrets {
            "log_secrets = true: CREDENTIALS ARE WRITTEN UNREDACTED"
        } else {
            "credentials and query strings are redacted; request bodies are not"
        };
        let line = format!(
            "# {} wedge {} debug capture log. Contains request data ({secrets}). \
             Delete it when you are done.\n",
            timestamp(),
            crate::VERSION
        );
        self.write_raw(&line)
    }

    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.written + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.write_raw(line)?;
        // Flush per event: the log is for debugging crashes too.
        self.file.flush()
    }

    fn write_raw(&mut self, line: &str) -> io::Result<()> {
        self.file.write_all(line.as_bytes())?;
        self.written += line.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    /// capture.log -> capture.log.1 -> ... -> capture.log.<keep>, deleted
    /// beyond that.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let numbered = |n: u32| {
            let mut name = self.path.clone().into_os_string();
            name.push(format!(".{n}"));
            PathBuf::from(name)
        };
        let _ = std::fs::remove_file(numbered(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(numbered(n), numbered(n + 1));
        }
        std::fs::rename(&self.path, numbered(1))?;
        self.file = BufWriter::new(open_private(&self.path)?);
        self.written = 0;
        self.banner()
    }
}

/// Opens `path` for appending, readable and writable by its owner only
/// (T5.9).
fn open_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        let file = options.open(path)?;
        // Remove inherited access; leave only the file's owner (OWNER RIGHTS).
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", "*S-1-3-4:F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::other(
                "icacls could not restrict the capture log",
            ));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        options.open(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        SENSITIVE.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn redactor_handles_split_lines() {
        let mut r = LineRedactor::default();
        let mut out = r.feed(b"GET /a?token=abc HTTP/1.1\r\nAuthor", &names());
        out.extend(r.feed(
            b"ization: Bearer s3cret\r\nX-Ok: 1\r\nCookie: sid=",
            &names(),
        ));
        out.extend(r.feed(b"zzz\r\n\r\nbody", &names()));
        out.extend(r.finish(&names()));
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "GET /a?[REDACTED] HTTP/1.1\r\nAuthorization: [REDACTED]\r\nX-Ok: 1\r\n\
             Cookie: [REDACTED]\r\n\r\nbody"
        );
        assert!(!text.contains("s3cret") && !text.contains("abc") && !text.contains("sid="));
    }

    #[test]
    fn redactor_hides_long_lines_split_across_reads() {
        // Lines longer than MAX_PENDING_LINE arrive in TCP-sized pieces; the
        // secret must not be released when the held-back part overflows.
        let secret = "S".repeat(9000);
        let query = "q".repeat(9000);
        let stream = format!(
            "GET /a?{query} HTTP/1.1\r\nAuthorization: Bearer {secret}\r\nX-Ok: {}\r\n\r\n",
            "o".repeat(9000)
        );
        let mut r = LineRedactor::default();
        let mut out = Vec::new();
        for chunk in stream.as_bytes().chunks(1400) {
            out.extend(r.feed(chunk, &names()));
        }
        out.extend(r.finish(&names()));
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SSSS"), "secret leaked");
        assert!(!text.contains("qqqq"), "query leaked");
        assert!(text.contains("GET /a?[REDACTED]"), "{}", &text[..80]);
        assert!(text.contains("\r\nAuthorization: [REDACTED]\r\nX-Ok: ooo"));
        assert!(text.ends_with(&format!("{}\r\n\r\n", "o".repeat(100))));
    }

    #[test]
    fn hexdump_escapes_everything() {
        let mut text = String::new();
        hexdump(&mut text, b"GET /\r\n\x1b[31m");
        assert!(
            text.contains("47 45 54 20 2f 0d 0a 1b 5b 33 31 6d"),
            "{text}"
        );
        assert!(text.contains("|GET /...[31m|"), "{text}");
        assert!(!text.contains('\x1b'));
        let mut line = String::new();
        escape_into(&mut line, "a\x1b[2Jb\x07");
        assert_eq!(line, "a\\x1b[2Jb\\x07");
    }

    #[test]
    fn writer_rotates_and_keeps_n_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cap.log");
        let mut w = Writer::open(path.clone(), 65_536, 2, false).unwrap();
        let line = "x".repeat(1000) + "\n";
        for _ in 0..300 {
            w.write(&line).unwrap();
        }
        assert!(path.exists());
        assert!(dir.path().join("cap.log.1").exists());
        assert!(dir.path().join("cap.log.2").exists());
        assert!(!dir.path().join("cap.log.3").exists());
        assert!(std::fs::metadata(&path).unwrap().len() <= 65_536 + 1000);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
