//! IPv4/IPv6 头部读写辅助函数。
//!
//! 所有函数带长度边界检查，畸形包返回保守默认值，绝不 panic。
//! 写入函数只在长度足够时修改，否则静默跳过。

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 头部最小长度
pub const IPV4_MIN_HDR: usize = 20;
/// IPv6 固定头部长度
pub const IPV6_HDR: usize = 40;
/// TCP 头部最小长度
pub const TCP_MIN_HDR: usize = 20;
/// UDP 头部长度
pub const UDP_HDR: usize = 8;

/// IP 版本（4 或 6），无法判定为 0
pub fn ip_version(p: &[u8]) -> u8 {
    p.first().map(|b| b >> 4).unwrap_or(0)
}

/// IPv4 IHL（头部长度，单位字节）；非 IPv4 或畸形返回 0
pub fn ipv4_ihl(p: &[u8]) -> usize {
    if ip_version(p) != 4 || p.len() < IPV4_MIN_HDR {
        return 0;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < IPV4_MIN_HDR || p.len() < ihl {
        0
    } else {
        ihl
    }
}

/// IPv4 TTL
pub fn ipv4_ttl(p: &[u8]) -> u8 {
    if p.len() < 9 {
        0
    } else {
        p[8]
    }
}

/// 设置 IPv4 TTL
pub fn set_ipv4_ttl(p: &mut [u8], ttl: u8) {
    if p.len() >= 9 {
        p[8] = ttl;
    }
}

/// IPv4 协议号（TCP=6 UDP=17 ICMP=1）
pub fn ipv4_proto(p: &[u8]) -> u8 {
    if p.len() < 10 {
        0
    } else {
        p[9]
    }
}

/// IPv4 源地址
pub fn ipv4_src(p: &[u8]) -> Option<Ipv4Addr> {
    if p.len() < 16 {
        return None;
    }
    Some(Ipv4Addr::new(p[12], p[13], p[14], p[15]))
}

/// IPv4 目的地址
pub fn ipv4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    if p.len() < 20 {
        return None;
    }
    Some(Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

/// 设置 IPv4 源地址
pub fn set_ipv4_src(p: &mut [u8], addr: Ipv4Addr) {
    if p.len() >= 16 {
        p[12..16].copy_from_slice(&addr.octets());
    }
}

/// 设置 IPv4 目的地址
pub fn set_ipv4_dst(p: &mut [u8], addr: Ipv4Addr) {
    if p.len() >= 20 {
        p[16..20].copy_from_slice(&addr.octets());
    }
}

/// IPv4 DF（Don't Fragment）位是否置位
pub fn ipv4_df_set(p: &[u8]) -> bool {
    if p.len() < 7 {
        return false;
    }
    (p[6] & 0x40) != 0
}

/// IPv6 Hop Limit
pub fn ipv6_hop_limit(p: &[u8]) -> u8 {
    if p.len() < 8 {
        0
    } else {
        p[7]
    }
}

/// 设置 IPv6 Hop Limit
pub fn set_ipv6_hop_limit(p: &mut [u8], hl: u8) {
    if p.len() >= 8 {
        p[7] = hl;
    }
}

/// IPv6 Next Header（第一个扩展头或传输层协议）
pub fn ipv6_next_header(p: &[u8]) -> u8 {
    if p.len() < 7 {
        0
    } else {
        p[6]
    }
}

/// IPv6 源地址
pub fn ipv6_src(p: &[u8]) -> Option<Ipv6Addr> {
    if p.len() < 24 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&p[8..24]);
    Some(Ipv6Addr::from(octets))
}

/// IPv6 目的地址
pub fn ipv6_dst(p: &[u8]) -> Option<Ipv6Addr> {
    if p.len() < 40 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&p[24..40]);
    Some(Ipv6Addr::from(octets))
}

/// 设置 IPv6 源地址
pub fn set_ipv6_src(p: &mut [u8], addr: Ipv6Addr) {
    if p.len() >= 24 {
        p[8..24].copy_from_slice(&addr.octets());
    }
}

/// 设置 IPv6 目的地址
pub fn set_ipv6_dst(p: &mut [u8], addr: Ipv6Addr) {
    if p.len() >= 40 {
        p[24..40].copy_from_slice(&addr.octets());
    }
}

/// 定位传输层头部偏移（跳过 IPv6 扩展头链）
/// 返回 (proto, offset)；无法定位返回 (0, 0)
pub fn l4_offset(p: &[u8]) -> (u8, usize) {
    match ip_version(p) {
        4 => {
            let ihl = ipv4_ihl(p);
            if ihl == 0 {
                (0, 0)
            } else {
                (ipv4_proto(p), ihl)
            }
        }
        6 => {
            if p.len() < IPV6_HDR {
                return (0, 0);
            }
            let mut next = ipv6_next_header(p);
            let mut off = IPV6_HDR;
            for _ in 0..8 {
                match next {
                    6 | 17 | 58 | 1 => break, // TCP/UDP/ICMPv6/ICMP
                    0 | 43 | 60 => {
                        // Hop-by-Hop / Routing / Destination Options
                        if off + 2 > p.len() {
                            return (0, 0);
                        }
                        let hlen = ((p[off + 1] as usize) + 1) * 8;
                        next = p[off];
                        off = off.saturating_add(hlen);
                        if off > p.len() {
                            return (0, 0);
                        }
                    }
                    44 => {
                        // Fragment
                        if off + 8 > p.len() {
                            return (0, 0);
                        }
                        next = p[off];
                        off += 8;
                    }
                    51 => {
                        // AH
                        if off + 2 > p.len() {
                            return (0, 0);
                        }
                        let hlen = ((p[off + 1] as usize) + 2) * 4;
                        next = p[off];
                        off = off.saturating_add(hlen);
                        if off > p.len() {
                            return (0, 0);
                        }
                    }
                    _ => break,
                }
            }
            (next, off)
        }
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_basic_fields() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(ip_version(&p), 4);
        assert_eq!(ipv4_ihl(&p), 20);
        assert_eq!(ipv4_ttl(&p), 64);
        assert_eq!(ipv4_proto(&p), 6);
        assert_eq!(ipv4_src(&p), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ipv4_dst(&p), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn ipv4_df_bit() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[6] = 0x40; // DF set
        assert!(ipv4_df_set(&p));
        p[6] = 0x00;
        assert!(!ipv4_df_set(&p));
    }

    #[test]
    fn ipv6_basic_fields() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 6; // TCP
        p[7] = 64;
        p[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        assert_eq!(ip_version(&p), 6);
        assert_eq!(ipv6_hop_limit(&p), 64);
        assert_eq!(ipv6_next_header(&p), 6);
        assert_eq!(ipv6_src(&p), Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn malformed_packets_safe() {
        assert_eq!(ip_version(&[]), 0);
        assert_eq!(ipv4_ihl(&[0x45]), 0);
        assert_eq!(l4_offset(&[0x45]), (0, 0));
        assert_eq!(ipv6_src(&[0x60]), None);
    }
}
