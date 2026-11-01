// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Maps a request path to a location inside a document root.
//!
//! This is the first line of defence against path traversal (threat model
//! T2.1 to T2.4). It works on the request path alone; the file handler then
//! canonicalizes the result and checks it is still inside the root.

/// Why a request path was refused. Every variant maps to a generic response;
/// the reason is only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Malformed percent-encoding or invalid UTF-8: 400.
    BadEncoding,
    /// Traversal or a character that could change path meaning: 400.
    Forbidden,
    /// Hidden or platform-special name: 404, so its existence is not revealed.
    Hidden,
}

/// A validated request path: decoded segments, none empty, `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafePath {
    pub(crate) segments: Vec<String>,
    /// The request path ended with `/` (a directory was asked for).
    pub(crate) trailing_slash: bool,
}

/// Validates a raw (still percent-encoded) URI path.
pub(crate) fn parse(raw: &str) -> Result<SafePath, Refusal> {
    if !raw.starts_with('/') {
        return Err(Refusal::Forbidden);
    }
    let decoded = percent_decode(raw.as_bytes()).ok_or(Refusal::BadEncoding)?;
    let decoded = String::from_utf8(decoded).map_err(|_| Refusal::BadEncoding)?;
    // Decode exactly once, then reject anything that a filesystem API could
    // interpret as a separator, drive, stream or terminator.
    if decoded
        .chars()
        .any(|c| c == '\\' || c == ':' || c == '\0' || c.is_control())
    {
        return Err(Refusal::Forbidden);
    }
    let mut segments = Vec::new();
    for (index, segment) in decoded.split('/').enumerate() {
        match segment {
            "" | "." => continue,
            ".." => return Err(Refusal::Forbidden),
            _ => {}
        }
        // Dot-files (.git, .env, .htpasswd) are never served, except the
        // RFC 8615 /.well-known/ prefix.
        if segment.starts_with('.') && !(index == 1 && segment == ".well-known") {
            return Err(Refusal::Hidden);
        }
        if is_platform_special(segment) {
            return Err(Refusal::Hidden);
        }
        segments.push(segment.to_owned());
    }
    Ok(SafePath {
        segments,
        trailing_slash: decoded.ends_with('/'),
    })
}

/// Names that Windows treats specially: trailing dots or spaces are stripped
/// (so `secret.txt.` opens `secret.txt`), and device names like `CON` or
/// `nul.txt` open devices. Refused on every platform for consistent behaviour.
fn is_platform_special(segment: &str) -> bool {
    if segment.ends_with('.') || segment.ends_with(' ') {
        return true;
    }
    let stem = segment.split('.').next().unwrap_or(segment);
    let stem = stem.trim_end().to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit())
}

/// Whether a raw request path may be forwarded to an upstream (T4.13). Each
/// segment is decoded once; a `.` or `..` segment, an encoded `/` or `\`, a
/// NUL or a bad escape would let the upstream resolve a path outside the
/// route that wedge matched, so the request is refused. The raw path is
/// forwarded unchanged when this passes.
pub(crate) fn proxy_path_ok(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|segment| {
        percent_decode(segment.as_bytes()).is_some_and(|decoded| {
            decoded != b"."
                && decoded != b".."
                && !decoded.iter().any(|b| matches!(b, b'/' | b'\\' | 0))
        })
    })
}

/// Decodes `%XX` escapes. Returns `None` for a truncated or non-hex escape.
pub(crate) fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let hi = hex(*input.get(i + 1)?)?;
            let lo = hex(*input.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Some(out)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_paths() {
        for ok in [
            "/",
            "/api/x",
            "/api//x",
            "/a%20b",
            "/.well-known/x",
            "/a.b/..c",
            "/%e2%82%ac",
        ] {
            assert!(proxy_path_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "api",
            "/api/../admin",
            "/api/./x",
            "/api/%2e%2e/admin",
            "/api/%2E%2e/admin",
            "/api/.%2e/admin",
            "/api/..",
            "/api/a%2fb",
            "/api/a%5cb",
            "/api/a\\b",
            "/api/%00",
            "/api/%zz",
            "/api/%2",
        ] {
            assert!(!proxy_path_ok(bad), "{bad}");
        }
    }

    fn ok(raw: &str) -> Vec<String> {
        parse(raw).unwrap().segments
    }

    #[test]
    fn accepts_normal_paths() {
        assert_eq!(ok("/"), Vec::<String>::new());
        assert_eq!(ok("/a/b.html"), ["a", "b.html"]);
        assert_eq!(ok("//a/./b/"), ["a", "b"]);
        assert_eq!(ok("/caf%C3%A9.txt"), ["café.txt"]);
        assert_eq!(ok("/.well-known/acme"), [".well-known", "acme"]);
        assert!(parse("/dir/").unwrap().trailing_slash);
    }

    #[test]
    fn rejects_traversal_in_every_encoding() {
        for raw in [
            "/../etc/passwd",
            "/a/../../etc/passwd",
            "/%2e%2e/etc/passwd",
            "/%2E%2E%2Fetc%2Fpasswd",
            "/a/%2e%2e",
            "/..",
        ] {
            assert_eq!(parse(raw), Err(Refusal::Forbidden), "{raw}");
        }
    }

    #[test]
    fn rejects_separators_drives_and_nul() {
        for raw in [
            "/..%5c..%5cwindows",
            "/a\\b",
            "/C:/windows/win.ini",
            "/file.txt::$DATA",
            "/a%00.html",
            "/a%0d%0aSet-Cookie:x",
            "relative/path",
        ] {
            assert_eq!(parse(raw), Err(Refusal::Forbidden), "{raw}");
        }
    }

    #[test]
    fn hides_dot_files_and_windows_specials() {
        for raw in [
            "/.git/config",
            "/.env",
            "/a/.htpasswd",
            "/a/.well-known/x",
            "/secret.txt.",
            "/secret.txt%20",
            "/CON",
            "/nul.txt",
            "/com1.log",
            "/LPT9",
        ] {
            assert_eq!(parse(raw), Err(Refusal::Hidden), "{raw}");
        }
        assert!(parse("/console.log").is_ok());
        assert!(parse("/com10").is_ok());
    }

    #[test]
    fn rejects_bad_encoding() {
        for raw in ["/%", "/%2", "/%zz", "/%ff%fe"] {
            assert_eq!(parse(raw), Err(Refusal::BadEncoding), "{raw}");
        }
    }

    #[test]
    fn double_encoding_is_decoded_only_once() {
        // %252e%252e decodes to the literal name "%2e%2e", not "..".
        assert_eq!(ok("/%252e%252e/x"), ["%2e%2e", "x"]);
    }
}
