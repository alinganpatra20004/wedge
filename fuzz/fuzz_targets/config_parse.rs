// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Parses and validates arbitrary text as a configuration document.
//! Must never panic, whatever the input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = wedge_config::from_str(text);
    }
});
