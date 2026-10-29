// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Parses arbitrary strings as secret references. Error messages must not
//! depend on the input, because the input may be a pasted secret.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wedge_config::SecretRef;

fn message(text: &str) -> String {
    SecretRef::try_from(text.to_owned()).err().unwrap_or_default()
}

fuzz_target!(|text: String| {
    if let Err(got) = SecretRef::try_from(text) {
        // Every rejection must be one of the fixed messages.
        assert!(
            got == message("x") || got == message("env:-"),
            "input-dependent error message: {got}"
        );
    }
});
