// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! End-to-end tests for the `wedge` binary.

use std::path::Path;
use std::process::Command;

fn wedge() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wedge"))
}

fn example() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/wedge.toml")
}

#[test]
fn check_config_accepts_example() {
    let out = wedge()
        .args(["check-config", "-c"])
        .arg(example())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("1 listener(s), 2 vhost(s)"), "{stdout}");
}

#[test]
fn check_config_rejects_bad_file() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("wedge.toml");
    std::fs::write(&bad, "[server]\nlisten = 5\n").unwrap();
    let out = wedge()
        .args(["check-config", "-c"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("/server/listen"));
}

#[test]
fn schema_prints_json() {
    let out = wedge().arg("schema").output().unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value.get("$defs").is_some());
}
