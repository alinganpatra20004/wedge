// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Core server types for wedge.

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
