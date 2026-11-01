// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

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
    assert!(
        stdout.contains("1 listener(s), 0 TLS listener(s), 2 vhost(s)"),
        "{stdout}"
    );
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

/// A free TCP port on loopback (released before use, so another process
/// could grab it in between; acceptable for a test).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Kills the child process when dropped, even if the test panics.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reload_command_reaches_a_running_server() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("www")).unwrap();
    std::fs::write(dir.path().join("token"), "t0ken").unwrap();
    let (public, admin) = (free_port(), free_port());
    let config = dir.path().join("wedge.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten = [\"127.0.0.1:{public}\"]\n\
             [server.admin]\nlisten = \"127.0.0.1:{admin}\"\ntoken = \"file:token\"\n\
             [[vhost]]\nname = \"v\"\nroot = \"www\"\n"
        ),
    )
    .unwrap();
    let _server = Running(
        wedge()
            .args(["run", "-c"])
            .arg(&config)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let started = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", admin)).is_err() {
        assert!(started.elapsed().as_secs() < 20, "server did not start");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let out = wedge()
        .args(["reload", "-c"])
        .arg(&config)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("reloaded"), "{stdout}");

    // A wrong token is reported as a failure.
    std::fs::write(dir.path().join("token"), "wrong").unwrap();
    let out = wedge()
        .args(["reload", "-c"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("401"));
}
