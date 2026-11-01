// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Feeds arbitrary request paths to the path validator; it panics if an
//! accepted path could escape the document root (threat model T2.1 to T2.4).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|raw: &str| {
    wedge_core::fuzzing::check_request_path(raw);
});
