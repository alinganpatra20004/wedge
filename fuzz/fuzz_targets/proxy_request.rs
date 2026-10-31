// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Feeds arbitrary request paths and header sets to the reverse proxy's path
//! check and header sanitiser (threat model T4.5, T4.6, T4.13).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    wedge_core::fuzzing::check_proxy_request(input);
});
