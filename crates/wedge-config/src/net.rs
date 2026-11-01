// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! IP address ranges in CIDR notation, used for `server.trusted_proxies`.

use std::fmt;
use std::net::IpAddr;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;

/// An address range such as `"10.0.0.0/8"` or `"::1/128"`. A bare address
/// means a single host.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Whether `ip` lies in this range. IPv4-mapped IPv6 addresses
    /// (`::ffff:a.b.c.d`) are compared as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let rest = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[full] & mask == b[full] & mask
}

impl TryFrom<String> for IpNet {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text.as_str(), None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address or CIDR range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("{text:?}: prefix length must be 0 to {max}"))?,
        };
        Ok(Self { addr, prefix })
    }
}

impl JsonSchema for IpNet {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "IpNet".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "IP address or CIDR range, such as \"10.0.0.0/8\" or \"::1\"."
        })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl fmt::Debug for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpNet({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::try_from(text.to_owned()).unwrap()
    }

    #[test]
    fn ranges() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(net("10.0.0.0/8").contains(ip("10.255.1.2")));
        assert!(!net("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(net("192.168.1.0/25").contains(ip("192.168.1.127")));
        assert!(!net("192.168.1.0/25").contains(ip("192.168.1.128")));
        assert!(net("127.0.0.1").contains(ip("127.0.0.1")));
        assert!(!net("127.0.0.1").contains(ip("127.0.0.2")));
        assert!(net("127.0.0.1").contains(ip("::ffff:127.0.0.1")));
        assert!(net("fd00::/8").contains(ip("fd12::1")));
        assert!(!net("fd00::/8").contains(ip("10.0.0.1")));
        assert!(net("0.0.0.0/0").contains(ip("8.8.8.8")));
        for bad in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0/8",
            "host",
            "10.0.0.0/x",
        ] {
            assert!(IpNet::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}
