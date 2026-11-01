// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Feeds arbitrary request header lines to Host routing, Range parsing and
//! the capture log redactor (threat model T2.16, T2.10, T5.9).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    wedge_core::fuzzing::check_request_headers(input);
});
