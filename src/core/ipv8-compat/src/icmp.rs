//! ICMP / ICMPv6 差错报文生成。
//!
//! 生成两类差错报文：
//! - **Time Exceeded**（TTL/HopLimit 归零）：ICMPv4 Type=11 Code=0；ICMPv6 Type=3 Code=0
//! - **Fragmentation Needed**（DF 置位且包过大）：ICMPv4 Type=3 Code=4；ICMPv6 Type=2（Packet Too Big）
//!
//! 载荷包含原 IP 头 + 原载荷前 8 字节（RFC 792 / RFC 4443）。

use crate::checksum::{icmp_checksum, icmpv6_checksum, ip_header_checksum};
use crate::ip::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// ICMPv4 类型
const ICMP4_TYPE_TIME_EXCEEDED: u8 = 11;
const ICMP4_TYPE_DEST_UNREACH: u8 = 3;
const ICMP4_CODE_TTL_EXPIRED: u8 = 0;
const ICMP4_CODE_FRAG_NEEDED: u8 = 4;

/// ICMPv6 类型
const ICMP6_TYPE_TIME_EXCEEDED: u8 = 3;
const ICMP6_TYPE_PACKET_TOO_BIG: u8 = 2;
const ICMP6_CODE_TTL_EXPIRED: u8 = 0;

/// 生成 ICMPv4 Time Exceeded 报文（TTL 归零）。
///
/// - `original`：触发超时的原始 IPv4 包。
/// - `our_addr`：本机 TUN 地址（作为差错报文源地址，模拟路由器）。
/// - 返回完整的 IPv4+ICMP 包，可直接写回 TUN。
pub fn generate_time_exceeded_v4(original: &[u8], our_addr: Ipv4Addr) -> Option<Vec<u8>> {
    if ip_version(original) != 4 || original.len() < IPV4_MIN_HDR {
        return None;
    }
    let src = ipv4_src(original)?;
    // 载荷 = 原 IP 头 + 原载荷前 8 字节（上限 8，若不足取全部）
    let orig_ihl = ipv4_ihl(original);
    let payload_end = (orig_ihl + 8).min(original.len());
    let payload = &original[..payload_end];

    // ICMP 头：type(1) + code(1) + checksum(2) + unused(4) = 8B
    let icmp_len = 8 + payload.len();
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = ICMP4_TYPE_TIME_EXCEEDED;
    icmp[1] = ICMP4_CODE_TTL_EXPIRED;
    icmp[8..].copy_from_slice(payload);
    let cs = icmp_checksum(&mut icmp);
    icmp[2] = (cs >> 8) as u8;
    icmp[3] = cs as u8;

    // 外层 IPv4 头
    let total_len = IPV4_MIN_HDR + icmp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    set_ipv4_src(&mut pkt, our_addr);
    set_ipv4_dst(&mut pkt, src);
    let ip_cs = ip_header_checksum(&mut pkt);
    pkt[10] = (ip_cs >> 8) as u8;
    pkt[11] = ip_cs as u8;
    pkt[IPV4_MIN_HDR..].copy_from_slice(&icmp);
    Some(pkt)
}

/// 生成 ICMPv4 Fragmentation Needed 报文（DF 置位且包过大）。
///
/// - `original`：触发的原始 IPv4 包。
/// - `our_addr`：本机 TUN 地址。
/// - `mtu`：下一跳 MTU（写入 ICMP 报文字段）。
pub fn generate_frag_needed_v4(
    original: &[u8],
    our_addr: Ipv4Addr,
    mtu: u16,
) -> Option<Vec<u8>> {
    if ip_version(original) != 4 || original.len() < IPV4_MIN_HDR {
        return None;
    }
    let src = ipv4_src(original)?;
    let orig_ihl = ipv4_ihl(original);
    let payload_end = (orig_ihl + 8).min(original.len());
    let payload = &original[..payload_end];

    let icmp_len = 8 + payload.len();
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = ICMP4_TYPE_DEST_UNREACH;
    icmp[1] = ICMP4_CODE_FRAG_NEEDED;
    // ICMP 头 offset 6-7: 下一跳 MTU（RFC 1191）
    icmp[6..8].copy_from_slice(&mtu.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let cs = icmp_checksum(&mut icmp);
    icmp[2] = (cs >> 8) as u8;
    icmp[3] = cs as u8;

    let total_len = IPV4_MIN_HDR + icmp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    set_ipv4_src(&mut pkt, our_addr);
    set_ipv4_dst(&mut pkt, src);
    let ip_cs = ip_header_checksum(&mut pkt);
    pkt[10] = (ip_cs >> 8) as u8;
    pkt[11] = ip_cs as u8;
    pkt[IPV4_MIN_HDR..].copy_from_slice(&icmp);
    Some(pkt)
}

/// 生成 ICMPv6 Time Exceeded 报文（Hop Limit 归零）。
pub fn generate_time_exceeded_v6(original: &[u8], our_addr: Ipv6Addr) -> Option<Vec<u8>> {
    if ip_version(original) != 6 || original.len() < IPV6_HDR {
        return None;
    }
    let src = ipv6_src(original)?;
    // 载荷 = 原 IPv6 头 + 前 8 字节
    let payload_end = (IPV6_HDR + 8).min(original.len());
    let payload = &original[..payload_end];

    // ICMPv6 头 8B
    let icmp_len = 8 + payload.len();
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = ICMP6_TYPE_TIME_EXCEEDED;
    icmp[1] = ICMP6_CODE_TTL_EXPIRED;
    icmp[8..].copy_from_slice(payload);

    let total_len = IPV6_HDR + icmp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = 58; // ICMPv6
    pkt[7] = 64;
    set_ipv6_src(&mut pkt, our_addr);
    set_ipv6_dst(&mut pkt, src);
    pkt[IPV6_HDR..].copy_from_slice(&icmp);
    // ICMPv6 校验和必须在外层 src/dst 就位后、按伪首部计算（RFC 4443）
    let cs = icmpv6_checksum(&mut pkt);
    pkt[42] = (cs >> 8) as u8;
    pkt[43] = cs as u8;
    Some(pkt)
}

/// 生成 ICMPv6 Packet Too Big 报文。
pub fn generate_packet_too_big_v6(
    original: &[u8],
    our_addr: Ipv6Addr,
    mtu: u32,
) -> Option<Vec<u8>> {
    if ip_version(original) != 6 || original.len() < IPV6_HDR {
        return None;
    }
    let src = ipv6_src(original)?;
    let payload_end = (IPV6_HDR + 8).min(original.len());
    let payload = &original[..payload_end];

    let icmp_len = 8 + payload.len();
    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = ICMP6_TYPE_PACKET_TOO_BIG;
    icmp[1] = 0;
    // ICMPv6 PTB offset 4-7: MTU（32 位）
    icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
    icmp[8..].copy_from_slice(payload);

    let total_len = IPV6_HDR + icmp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = 58;
    pkt[7] = 64;
    set_ipv6_src(&mut pkt, our_addr);
    set_ipv6_dst(&mut pkt, src);
    pkt[IPV6_HDR..].copy_from_slice(&icmp);
    // 同 Time Exceeded：按 IPv6 伪首部计算校验和
    let cs = icmpv6_checksum(&mut pkt);
    pkt[42] = (cs >> 8) as u8;
    pkt[43] = cs as u8;
    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_echo(ttl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 28]; // 20 IP + 8 ICMP
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = ttl;
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20] = 8; // Echo Request
        p[21] = 0;
        p
    }

    #[test]
    fn time_exceeded_v4_structure() {
        let orig = make_ipv4_echo(1);
        let pkt = generate_time_exceeded_v4(&orig, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        // 外层 IP
        assert_eq!(pkt[0] >> 4, 4);
        assert_eq!(pkt[9], 1); // ICMP
        // ICMP type/code
        assert_eq!(pkt[20], ICMP4_TYPE_TIME_EXCEEDED);
        assert_eq!(pkt[21], ICMP4_CODE_TTL_EXPIRED);
        // 载荷应包含原 IP 头
        assert_eq!(&pkt[28..48], &orig[..20]);
        // 校验和自洽：写入后 ones_complement_sum 应为 0xffff
        let icmp_data = &pkt[20..];
        assert_eq!(crate::checksum::ones_complement_sum(icmp_data), 0xffff);
    }

    #[test]
    fn frag_needed_v4_mtu_field() {
        let orig = make_ipv4_echo(64);
        let pkt = generate_frag_needed_v4(&orig, Ipv4Addr::new(10, 0, 0, 1), 1392).unwrap();
        assert_eq!(pkt[20], ICMP4_TYPE_DEST_UNREACH);
        assert_eq!(pkt[21], ICMP4_CODE_FRAG_NEEDED);
        let mtu = u16::from_be_bytes([pkt[26], pkt[27]]);
        assert_eq!(mtu, 1392);
    }

    #[test]
    fn time_exceeded_v6_structure() {
        let mut orig = vec![0u8; 48];
        orig[0] = 0x60;
        orig[4..6].copy_from_slice(&8u16.to_be_bytes());
        orig[6] = 58;
        orig[7] = 1;
        orig[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        orig[24..40].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        let pkt = generate_time_exceeded_v6(&orig, Ipv6Addr::LOCALHOST).unwrap();
        assert_eq!(pkt[0] >> 4, 6);
        assert_eq!(pkt[6], 58); // ICMPv6
        assert_eq!(pkt[40], ICMP6_TYPE_TIME_EXCEEDED);
        assert_eq!(pkt[41], ICMP6_CODE_TTL_EXPIRED);
        // 载荷包含原 IPv6 头
        assert_eq!(&pkt[48..88], &orig[..40]);
        // F-1 回归：ICMPv6 校验和必须在伪首部+ICMP 折叠后为 0xffff
        let mut sum = {
            // 重构伪首部
            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(&pkt[8..24]);
            pseudo[16..32].copy_from_slice(&pkt[24..40]);
            pseudo[32..36].copy_from_slice(&((pkt.len() - 40) as u32).to_be_bytes());
            pseudo[39] = 58;
            crate::checksum::ones_complement_sum(&pseudo) as u32
                + crate::checksum::ones_complement_sum(&pkt[40..]) as u32
        };
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff, "ICMPv6 校验和必须覆盖伪首部");
    }

    #[test]
    fn packet_too_big_v6_mtu_and_checksum() {
        let mut orig = vec![0u8; 60];
        orig[0] = 0x60;
        orig[4..6].copy_from_slice(&20u16.to_be_bytes());
        orig[6] = 6;
        orig[7] = 64;
        orig[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        orig[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        let our = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe);
        let pkt = generate_packet_too_big_v6(&orig, our, 1392).unwrap();
        assert_eq!(pkt[40], ICMP6_TYPE_PACKET_TOO_BIG);
        assert_eq!(u32::from_be_bytes(pkt[44..48].try_into().unwrap()), 1392);
        // 伪首部校验
        let mut sum = {
            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(&pkt[8..24]);
            pseudo[16..32].copy_from_slice(&pkt[24..40]);
            pseudo[32..36].copy_from_slice(&((pkt.len() - 40) as u32).to_be_bytes());
            pseudo[39] = 58;
            crate::checksum::ones_complement_sum(&pseudo) as u32
                + crate::checksum::ones_complement_sum(&pkt[40..]) as u32
        };
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
        // 源地址必须是 our（不能是 ::）
        assert_eq!(&pkt[8..24], &our.octets());
    }

    #[test]
    fn malformed_returns_none() {
        assert!(generate_time_exceeded_v4(&[], Ipv4Addr::UNSPECIFIED).is_none());
        assert!(generate_frag_needed_v4(&[0x45], Ipv4Addr::UNSPECIFIED, 1000).is_none());
        assert!(generate_time_exceeded_v6(&[0x60], Ipv6Addr::UNSPECIFIED).is_none());
    }
}
