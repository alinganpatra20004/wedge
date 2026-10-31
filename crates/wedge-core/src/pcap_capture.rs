// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Live IP/TCP header capture for `[server.debug] tcp_headers` (threat
//! model T5.11). Built only with the `packet-capture` feature.
//!
//! The BPF filter admits only TCP on wedge's own listen ports, the snapshot
//! length keeps headers only (payload bytes are already in the capture log's
//! TCP/TLS layers), and the interface is not put in promiscuous mode.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::capture::{here, Capture};
use crate::packet::{decode, Flows, Link};

/// Bytes kept per packet: enough for link, IPv6 and TCP headers with options.
const SNAPLEN: i32 = 128;

/// Opens the capture and starts the reader thread. On error, wedge carries
/// on without packet headers.
pub(crate) fn start(capture: Arc<Capture>, listening: &[SocketAddr]) -> Result<(), String> {
    let mut ports: Vec<u16> = listening.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Ok(());
    }
    let device = pick_device(listening)?;
    let name = device.name.clone();
    let mut live = pcap::Capture::from_device(device)
        .and_then(|c| {
            c.promisc(false)
                .snaplen(SNAPLEN)
                .immediate_mode(true)
                .timeout(1000)
                .open()
        })
        .map_err(|e| {
            format!("cannot open packet capture on {name} (needs root/admin or CAP_NET_RAW, and libpcap or Npcap): {e}")
        })?;
    let ports_expr: Vec<String> = ports.iter().map(|p| format!("port {p}")).collect();
    let filter = format!("tcp and ({})", ports_expr.join(" or "));
    live.filter(&filter, true)
        .map_err(|e| format!("cannot set capture filter {filter:?}: {e}"))?;
    let link = Link::from_dlt(live.get_datalink().0)
        .ok_or_else(|| format!("unsupported link type {:?} on {name}", live.get_datalink()))?;
    capture.event(
        0,
        "IP",
        here!(),
        &format!("packet capture started on {name} ({link:?}), filter {filter:?}"),
    );
    std::thread::Builder::new()
        .name("wedge-pcap".into())
        .spawn(move || {
            let mut flows = Flows::default();
            loop {
                match live.next_packet() {
                    Ok(packet) => {
                        if let Some(segment) = decode(link, packet.data) {
                            let note = if flows.is_retransmit(&segment) {
                                " RETRANSMISSION"
                            } else {
                                ""
                            };
                            capture.event(0, "IP", here!(), &format!("{segment}{note}"));
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "packet capture stopped");
                        return;
                    }
                }
            }
        })
        .map_err(|e| format!("cannot start the packet capture thread: {e}"))?;
    Ok(())
}

/// Linux: the "any" pseudo-device. Elsewhere: the loopback device when all
/// listeners are on loopback, else the device that owns a listen address,
/// else the system default.
fn pick_device(listening: &[SocketAddr]) -> Result<pcap::Device, String> {
    if cfg!(target_os = "linux") {
        return Ok(pcap::Device::from("any"));
    }
    let devices = pcap::Device::list().map_err(|e| format!("cannot list capture devices: {e}"))?;
    let all_loopback = listening.iter().all(|a| a.ip().is_loopback());
    let chosen = devices.iter().find(|d| {
        if all_loopback {
            d.flags.is_loopback()
        } else {
            d.addresses
                .iter()
                .any(|a| listening.iter().any(|l| l.ip() == a.addr))
        }
    });
    match chosen {
        Some(device) => Ok(device.clone()),
        None => pcap::Device::lookup()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no capture device found".to_owned()),
    }
}
