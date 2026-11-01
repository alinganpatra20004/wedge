// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Decodes captured frames into IP and TCP header fields for the debug
//! capture log (`[server.debug] tcp_headers`). Pure parsing, so it is tested
//! on every platform; the live capture that feeds it needs the
//! `packet-capture` feature.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Link-layer framing, as pcap's DLT values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Link {
    /// DLT_EN10MB (1): Ethernet II.
    Ethernet,
    /// DLT_NULL (0) / DLT_LOOP (108): 4-byte address family (BSD, Npcap loopback).
    Null,
    /// DLT_RAW (12, 101): the frame is the IP packet.
    Raw,
    /// DLT_LINUX_SLL (113): Linux "any" device, 16-byte header.
    LinuxSll,
    /// DLT_LINUX_SLL2 (276): Linux "any" device, 20-byte header.
    LinuxSll2,
}

impl Link {
    pub(crate) fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            1 => Some(Self::Ethernet),
            0 | 108 => Some(Self::Null),
            12 | 101 => Some(Self::Raw),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            _ => None,
        }
    }
}

/// The fields of one TCP segment that the capture log shows.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    pub(crate) payload: usize,
    /// IPv4 TTL or IPv6 hop limit.
    pub(crate) ttl: u8,
}

impl Segment {
    /// tcpdump-style flags: `S` SYN, `F` FIN, `R` RST, `P` PSH, `.` ACK, `U` URG.
    fn flag_text(&self) -> String {
        let mut text = String::new();
        for (bit, c) in [
            (0x02, 'S'),
            (0x01, 'F'),
            (0x04, 'R'),
            (0x08, 'P'),
            (0x20, 'U'),
        ] {
            if self.flags & bit != 0 {
                text.push(c);
            }
        }
        if self.flags & 0x10 != 0 {
            text.push('.');
        }
        if text.is_empty() {
            text.push_str("none");
        }
        text
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} > {} flags [{}] seq {} ack {} win {} len {} ttl {}",
            self.src,
            self.dst,
            self.flag_text(),
            self.seq,
            self.ack,
            self.window,
            self.payload,
            self.ttl
        )
    }
}

/// Decodes one captured frame. Returns `None` for anything that is not a
/// complete IPv4/IPv6 TCP header (truncated or other protocols).
pub(crate) fn decode(link: Link, frame: &[u8]) -> Option<Segment> {
    let (ethertype, ip) = match link {
        Link::Ethernet => {
            let mut offset = 12;
            let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
            // One 802.1Q VLAN tag.
            if ethertype == 0x8100 {
                offset += 4;
                ethertype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
            }
            (ethertype, frame.get(offset + 2..)?)
        }
        Link::Null => {
            // Host byte order; 2 = IPv4, 24/28/30 = IPv6 on BSDs and Windows.
            let family = u32::from_le_bytes(frame.get(..4)?.try_into().ok()?);
            let family = if family > 0xffff {
                family.swap_bytes()
            } else {
                family
            };
            let ethertype = match family {
                2 => 0x0800,
                24 | 28 | 30 => 0x86dd,
                _ => return None,
            };
            (ethertype, frame.get(4..)?)
        }
        Link::Raw => {
            let version = frame.first()? >> 4;
            (if version == 6 { 0x86dd } else { 0x0800 }, frame)
        }
        Link::LinuxSll => (
            u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]),
            frame.get(16..)?,
        ),
        Link::LinuxSll2 => (
            u16::from_be_bytes([*frame.first()?, *frame.get(1)?]),
            frame.get(20..)?,
        ),
    };
    match ethertype {
        0x0800 => decode_v4(ip),
        0x86dd => decode_v6(ip),
        _ => None,
    }
}

fn decode_v4(ip: &[u8]) -> Option<Segment> {
    if ip.first()? >> 4 != 4 {
        return None;
    }
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    if header < 20 || *ip.get(9)? != 6 {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(ip.get(12..16)?).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(ip.get(16..20)?).ok()?);
    let ttl = ip[8];
    // `total` bounds the segment (ignoring Ethernet padding) and gives the
    // true payload length even when the capture was cut short (snaplen).
    let end = total.min(ip.len());
    let declared = total.checked_sub(header)?;
    decode_tcp(ip.get(header..end)?, declared, src.into(), dst.into(), ttl)
}

fn decode_v6(ip: &[u8]) -> Option<Segment> {
    if ip.first()? >> 4 != 6 || *ip.get(6)? != 6 {
        // Next header must be TCP directly; extension headers are skipped.
        return None;
    }
    let payload = usize::from(u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]));
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(ip.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(ip.get(24..40)?).ok()?);
    let end = (40 + payload).min(ip.len());
    decode_tcp(ip.get(40..end)?, payload, src.into(), dst.into(), ip[7])
}

/// `declared` is the TCP segment length from the IP header, which may exceed
/// the bytes captured.
fn decode_tcp(tcp: &[u8], declared: usize, src: IpAddr, dst: IpAddr, ttl: u8) -> Option<Segment> {
    let word =
        |i: usize| -> Option<u32> { Some(u32::from_be_bytes(tcp.get(i..i + 4)?.try_into().ok()?)) };
    let port =
        |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*tcp.get(i)?, *tcp.get(i + 1)?])) };
    let offset = usize::from(tcp.get(12)? >> 4) * 4;
    if offset < 20 || tcp.len() < offset {
        return None;
    }
    Some(Segment {
        src: SocketAddr::new(src, port(0)?),
        dst: SocketAddr::new(dst, port(2)?),
        seq: word(4)?,
        ack: word(8)?,
        flags: tcp[13],
        window: port(14)?,
        payload: declared.saturating_sub(offset),
        ttl,
    })
}

/// Spots retransmissions: a segment carrying data that starts before the
/// highest sequence number already seen in the same direction.
#[derive(Default)]
pub(crate) struct Flows {
    next: HashMap<(SocketAddr, SocketAddr), u32>,
}

impl Flows {
    /// Flows remembered at most; the table is cleared when it fills.
    const MAX: usize = 4096;

    pub(crate) fn is_retransmit(&mut self, s: &Segment) -> bool {
        if self.next.len() >= Self::MAX {
            self.next.clear();
        }
        let syn_or_fin = u32::from(s.flags & 0x03 != 0);
        let len = u32::try_from(s.payload)
            .unwrap_or(u32::MAX)
            .wrapping_add(syn_or_fin);
        let end = s.seq.wrapping_add(len);
        let key = (s.src, s.dst);
        let retransmit = match self.next.get(&key) {
            // Wrapping comparison: `seq` is behind `expected`.
            Some(&expected) if len > 0 => (expected.wrapping_sub(s.seq) as i32) > 0,
            _ => false,
        };
        let advanced = self
            .next
            .get(&key)
            .is_none_or(|&expected| (end.wrapping_sub(expected) as i32) > 0);
        if advanced {
            self.next.insert(key, end);
        }
        retransmit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 + TCP packet from 10.0.0.1:40000 to 10.0.0.2:443.
    fn ipv4_tcp(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&7u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp.extend_from_slice(payload);
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let total = u16::try_from(ip.len() + tcp.len()).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend(tcp);
        ip
    }

    #[test]
    fn decodes_each_link_type() {
        assert_eq!(Link::from_dlt(1), Some(Link::Ethernet));
        assert_eq!(Link::from_dlt(276), Some(Link::LinuxSll2));
        assert_eq!(Link::from_dlt(9999), None);
        let ip = ipv4_tcp(1000, 0x18, b"hello");
        // Only the headers captured (snaplen): the length still comes out right.
        let cut = decode(Link::Raw, &ip[..40]).unwrap();
        assert_eq!(cut.payload, 5);
        let mut ether = vec![0u8; 12];
        ether.extend([0x08, 0x00]);
        ether.extend(&ip);
        let mut null = 2u32.to_le_bytes().to_vec();
        null.extend(&ip);
        let mut sll = vec![0u8; 14];
        sll.extend([0x08, 0x00]);
        sll.extend(&ip);
        let mut sll2 = vec![0x08, 0x00];
        sll2.extend([0u8; 18]);
        sll2.extend(&ip);
        for (link, frame) in [
            (Link::Ethernet, ether),
            (Link::Null, null),
            (Link::Raw, ip.clone()),
            (Link::LinuxSll, sll),
            (Link::LinuxSll2, sll2),
        ] {
            let s = decode(link, &frame).unwrap_or_else(|| panic!("{link:?}"));
            assert_eq!(
                s.to_string(),
                "10.0.0.1:40000 > 10.0.0.2:443 flags [P.] seq 1000 ack 7 win 64240 len 5 ttl 64",
                "{link:?}"
            );
        }
    }

    #[test]
    fn decodes_ipv6_and_rejects_junk() {
        let mut tcp = ipv4_tcp(5, 0x02, b"")[20..].to_vec();
        tcp[13] = 0x02;
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend(u16::try_from(tcp.len()).unwrap().to_be_bytes());
        ip.extend([6, 57]);
        ip.extend(Ipv6Addr::LOCALHOST.octets());
        ip.extend(Ipv6Addr::LOCALHOST.octets());
        ip.extend(tcp);
        let s = decode(Link::Raw, &ip).unwrap();
        assert_eq!(
            s.to_string(),
            "[::1]:40000 > [::1]:443 flags [S] seq 5 ack 7 win 64240 len 0 ttl 57"
        );
        // Truncated frames, UDP and garbage decode to nothing, never panic.
        let full = ipv4_tcp(1, 0x10, b"x");
        for cut in 0..full.len() - 1 {
            let _ = decode(Link::Raw, &full[..cut]);
        }
        let mut udp = full.clone();
        udp[9] = 17;
        assert!(decode(Link::Raw, &udp).is_none());
        assert!(decode(Link::Ethernet, &[0xff; 64]).is_none());
    }

    #[test]
    fn spots_retransmissions() {
        let mut flows = Flows::default();
        let seg = |seq, payload: &[u8]| decode(Link::Raw, &ipv4_tcp(seq, 0x18, payload)).unwrap();
        assert!(!flows.is_retransmit(&seg(100, b"aaaa")));
        assert!(!flows.is_retransmit(&seg(104, b"bbbb")));
        assert!(
            flows.is_retransmit(&seg(100, b"aaaa")),
            "resent first segment"
        );
        assert!(
            !flows.is_retransmit(&seg(108, b"")),
            "pure ACK is not a retransmit"
        );
        // Sequence numbers wrap around (a fresh flow starting just below 2^32).
        let mut flows = Flows::default();
        assert!(!flows.is_retransmit(&seg(u32::MAX - 1, b"zz")));
        assert!(
            !flows.is_retransmit(&seg(0, b"next")),
            "continues past the wrap"
        );
        assert!(
            flows.is_retransmit(&seg(u32::MAX - 1, b"zz")),
            "resent across the wrap"
        );
    }
}
