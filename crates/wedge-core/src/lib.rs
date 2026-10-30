// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Core server for wedge: listeners, connection handling and request routing.

mod files;
mod headers;
mod idle;
mod path;
mod response;
mod server;
mod tls;
mod vhost;

pub use response::Body;
pub use server::{Server, ServerError};
pub use tls::TlsError;

/// Entry points for the fuzz targets in `fuzz/`. Not a stable API.
#[doc(hidden)]
pub mod fuzzing {
    /// Parses a raw request path and panics if an accepted path could escape
    /// a document root or reach a hidden file.
    pub fn check_request_path(raw: &str) {
        let Ok(safe) = crate::path::parse(raw) else {
            return;
        };
        for (index, segment) in safe.segments.iter().enumerate() {
            assert!(!segment.is_empty() && segment != "." && segment != "..");
            assert!(!segment.contains(['/', '\\', ':', '\0']), "{segment:?}");
            assert!(!segment.chars().any(char::is_control), "{segment:?}");
            assert!(
                !segment.starts_with('.') || (index == 0 && segment == ".well-known"),
                "{segment:?}"
            );
        }
    }
}

/// Crate version, taken from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
