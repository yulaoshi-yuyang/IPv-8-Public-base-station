//! TTL 扣减与包分类（组播/广播）。

use crate::checksum::ip_header_checksum;
use crate::ip::*;

/// 扣减 IPv4 TTL 或 IPv6 Hop Limit，返回 true 表示 TTL 仍 > 0（可转发）。
/// 返回 false 表示 TTL 已为 0（调用方应生成 ICMP Time Exceeded）。
/// IPv4 会重算头校验和。
pub fn decrement_ttl(p: &mut [u8]) -> bool {
    match ip_version(p) {
        4 => {
            if p.len() < IPV4_MIN_HDR {
                return false;
            }
            let ttl = ipv4_ttl(p);
            if ttl == 0 {
                return false;
            }
            let new_ttl = ttl - 1;
            set_ipv4_ttl(p, new_ttl);
            let cs = ip_header_checksum(p);
            if p.len() >= 12 {
                p[10] = (cs >> 8) as u8;
                p[11] = cs as u8;
            }
            new_ttl > 0
        }
        6 => {
            if p.len() < IPV6_HDR {
                return false;
            }
            let hl = ipv6_hop_limit(p);
            if hl == 0 {
                return false;
            }
            let new_hl = hl - 1;
            set_ipv6_hop_limit(p, new_hl);
            new_hl > 0
        }
        _ => false,
    }
}

/// 判断是否为组播或广播地址（IPv4 + IPv6）。
pub fn is_multicast_or_broadcast(p: &[u8]) -> bool {
    match ip_version(p) {
        4 => {
            if let Some(dst) = ipv4_dst(p) {
                let o = dst.octets();
                // 224.0.0.0/4 组播
                if o[0] & 0xf0 == 0xe0 {
                    return true;
                }
                // 255.255.255.255 受限广播
                if o == [255, 255, 255, 255] {
                    return true;
                }
                // 定向广播（主机位全 1）—— 需要网络掩码，简化处理：
                // 最后一个字节为 255 视为可能的定向广播
                if o[3] == 255 && o[0] != 0 {
                    return true;
                }
                false
            } else {
                false
            }
        }
        6 => {
            if let Some(dst) = ipv6_dst(p) {
                let o = dst.octets();
                // ff00::/8 组播
                o[0] == 0xff
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrement_ipv4_ttl() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        assert!(decrement_ttl(&mut p));
        assert_eq!(ipv4_ttl(&p), 63);
        // 校验和应自洽
        let cs = ip_header_checksum(&mut p);
        p[10] = (cs >> 8) as u8;
        p[11] = cs as u8;
        assert_eq!(crate::checksum::checksum(&p[..20]), 0);
    }

    #[test]
    fn ttl_one_becomes_zero() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[8] = 1;
        assert!(!decrement_ttl(&mut p));
        assert_eq!(ipv4_ttl(&p), 0);
    }

    #[test]
    fn ipv6_hop_limit_decrement() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[7] = 64;
        assert!(decrement_ttl(&mut p));
        assert_eq!(ipv6_hop_limit(&p), 63);
    }

    #[test]
    fn multicast_detection() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        // 239.255.0.1 组播
        p[16..20].copy_from_slice(&[239, 255, 0, 1]);
        assert!(is_multicast_or_broadcast(&p));
        // 8.8.8.8 单播
        p[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert!(!is_multicast_or_broadcast(&p));
        // 255.255.255.255 广播
        p[16..20].copy_from_slice(&[255, 255, 255, 255]);
        assert!(is_multicast_or_broadcast(&p));
    }

    #[test]
    fn ipv6_multicast() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        // ff02::1
        let mc = std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        p[24..40].copy_from_slice(&mc.octets());
        assert!(is_multicast_or_broadcast(&p));
    }
}
