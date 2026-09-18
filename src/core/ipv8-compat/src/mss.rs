//! TCP MSS（Maximum Segment Size）选项钳制。
//!
//! 仅处理 TCP SYN / SYN-ACK 包的 MSS option，将其钳制到隧道有效 MTU 以内，
//! 避免 TCP 段超过隧道 MTU 导致分片。钳制后重算 IPv4 头校验和与 TCP 校验和。

use crate::checksum::{ip_header_checksum, tcp_checksum_v4, tcp_checksum_v6};
use crate::ip::*;

/// TCP 标志位
const TCP_FLAG_SYN: u8 = 0x02;

/// TCP option kind
const OPT_KIND_MSS: u8 = 2;
const OPT_KIND_NOP: u8 = 1;
const OPT_KIND_EOL: u8 = 0;

/// 钳制 TCP MSS 选项。
///
/// - 仅处理 IPv4/IPv6 + TCP，且 SYN 置位（SYN 或 SYN-ACK）的包。
/// - 遍历 TCP options 找到 MSS（kind=2, len=4），若值 > `target_mss` 则改写。
/// - `target_mss` 为**最终 MSS 值**（调用方负责按协议换算，如 v4=mtu-40、v6=mtu-60，
///   或直接采用用户 `--mss-clamp` 指定值；本函数不再二次扣减）。
/// - 改写后重算 IP 头校验和（v4）与 TCP 校验和。
/// - 无 MSS option 或非 SYN 包返回 false（不修改）。
/// - MSS 已 <= target 返回 true（已合规，未修改）。
///
/// 返回值：true = 处理过（可能修改也可能未修改但合规）；false = 不适用。
pub fn clamp_mss(packet: &mut [u8], target_mss: u16) -> bool {
    let (proto, l4_off) = l4_offset(packet);
    if proto != 6 {
        // 非 TCP
        return false;
    }
    if packet.len() < l4_off + TCP_MIN_HDR {
        return false;
    }
    // TCP 头：flags 在 offset 13（TCP 头内偏移）
    let flags = packet[l4_off + 13];
    if flags & TCP_FLAG_SYN == 0 {
        // 非 SYN 包
        return false;
    }
    // Data Offset（TCP 头长度，单位 4 字节）在 TCP 头 offset 12 高 4 位
    let data_off = ((packet[l4_off + 12] >> 4) & 0x0f) as usize * 4;
    if data_off < TCP_MIN_HDR || packet.len() < l4_off + data_off {
        return false;
    }

    let target = target_mss;

    // 遍历 TCP options 找 MSS
    let opts_start = l4_off + TCP_MIN_HDR;
    let opts_end = l4_off + data_off;
    let mut pos = opts_start;
    while pos < opts_end {
        let kind = packet[pos];
        if kind == OPT_KIND_EOL {
            break;
        }
        if kind == OPT_KIND_NOP {
            pos += 1;
            continue;
        }
        if pos + 1 >= opts_end {
            break;
        }
        let opt_len = packet[pos + 1] as usize;
        if opt_len == 0 || pos + opt_len > opts_end {
            break;
        }
        if kind == OPT_KIND_MSS && opt_len == 4 {
            let cur_mss = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
            if cur_mss > target {
                packet[pos + 2] = (target >> 8) as u8;
                packet[pos + 3] = target as u8;
                recompute_checksums(packet, l4_off);
            }
            return true;
        }
        pos += opt_len;
    }
    // 无 MSS option
    false
}

/// 重算 IP 头校验和（v4）与 TCP 校验和
fn recompute_checksums(packet: &mut [u8], l4_off: usize) {
    match ip_version(packet) {
        4 => {
            // IP 头校验和
            let cs = ip_header_checksum(&mut packet[..l4_off]);
            packet[10] = (cs >> 8) as u8;
            packet[11] = cs as u8;
            // TCP 校验和
            let tcp_cs = tcp_checksum_v4(packet, l4_off);
            packet[l4_off + 16] = (tcp_cs >> 8) as u8;
            packet[l4_off + 17] = tcp_cs as u8;
        }
        6 => {
            // IPv6 无 IP 头校验和
            let tcp_cs = tcp_checksum_v6(packet, l4_off);
            packet[l4_off + 16] = (tcp_cs >> 8) as u8;
            packet[l4_off + 17] = tcp_cs as u8;
        }
        _ => {}
    }
}

/// 读取 TCP 包的 MSS option 值（调试/测试用）
pub fn read_mss(packet: &[u8]) -> Option<u16> {
    let (proto, l4_off) = l4_offset(packet);
    if proto != 6 || packet.len() < l4_off + TCP_MIN_HDR {
        return None;
    }
    let data_off = ((packet[l4_off + 12] >> 4) & 0x0f) as usize * 4;
    if data_off < TCP_MIN_HDR || packet.len() < l4_off + data_off {
        return None;
    }
    let opts_start = l4_off + TCP_MIN_HDR;
    let opts_end = l4_off + data_off;
    let mut pos = opts_start;
    while pos < opts_end {
        let kind = packet[pos];
        if kind == OPT_KIND_EOL {
            break;
        }
        if kind == OPT_KIND_NOP {
            pos += 1;
            continue;
        }
        if pos + 1 >= opts_end {
            break;
        }
        let opt_len = packet[pos + 1] as usize;
        if opt_len == 0 || pos + opt_len > opts_end {
            break;
        }
        if kind == OPT_KIND_MSS && opt_len == 4 {
            return Some(u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]));
        }
        pos += opt_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_syn(mss: u16) -> Vec<u8> {
        // 20B IPv4 + 24B TCP（20B 头 + 4B MSS option）
        let mut p = vec![0u8; 44];
        // IPv4
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p[24..28].copy_from_slice(&1u32.to_be_bytes());
        p[28..32].copy_from_slice(&0u32.to_be_bytes());
        p[32] = 6 << 4; // data offset = 6 (24B)
        p[33] = TCP_FLAG_SYN; // SYN
        p[34..36].copy_from_slice(&65535u16.to_be_bytes());
        // MSS option at offset 40 (within TCP): kind=2, len=4, value
        p[40] = OPT_KIND_MSS;
        p[41] = 4;
        p[42..44].copy_from_slice(&mss.to_be_bytes());
        p
    }

    #[test]
    fn clamp_ipv4_syn_mss() {
        let mut p = make_ipv4_syn(1460);
        assert!(clamp_mss(&mut p, 1352));
        assert_eq!(read_mss(&p), Some(1352));
        // IP 头校验和自洽
        assert_eq!(crate::checksum::ones_complement_sum(&p[..20]), 0xffff);
        // TCP 校验和自洽
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&p[12..16]);
        pseudo[4..8].copy_from_slice(&p[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&24u16.to_be_bytes());
        let sum = crate::checksum::ones_complement_sum(&pseudo) as u32
            + crate::checksum::ones_complement_sum(&p[20..]) as u32;
        let folded = ((sum & 0xffff) + (sum >> 16)) as u16;
        assert_eq!(folded, 0xffff);
    }

    #[test]
    fn no_clamp_when_already_smaller() {
        let mut p = make_ipv4_syn(1000);
        assert!(clamp_mss(&mut p, 1352));
        assert_eq!(read_mss(&p), Some(1000));
    }

    #[test]
    fn non_syn_not_clamped() {
        let mut p = make_ipv4_syn(1460);
        p[33] = 0x10; // 改为 ACK
        assert!(!clamp_mss(&mut p, 1352));
        assert_eq!(read_mss(&p), Some(1460));
    }

    #[test]
    fn syn_ack_clamped() {
        let mut p = make_ipv4_syn(1460);
        p[33] = TCP_FLAG_SYN | 0x10; // SYN-ACK
        assert!(clamp_mss(&mut p, 1352));
        assert_eq!(read_mss(&p), Some(1352));
    }

    #[test]
    fn ipv6_syn_clamped() {
        // 40B IPv6 + 24B TCP
        let mut p = vec![0u8; 64];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&24u16.to_be_bytes()); // payload len
        p[6] = 6; // next header = TCP
        p[7] = 64;
        // src/dst
        p[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
        // TCP
        p[40..42].copy_from_slice(&1234u16.to_be_bytes());
        p[42..44].copy_from_slice(&80u16.to_be_bytes());
        p[44..48].copy_from_slice(&1u32.to_be_bytes());
        p[48..52].copy_from_slice(&0u32.to_be_bytes());
        p[52] = 6 << 4; // data offset 6
        p[53] = TCP_FLAG_SYN;
        p[54..56].copy_from_slice(&65535u16.to_be_bytes());
        // MSS option
        p[60] = OPT_KIND_MSS;
        p[61] = 4;
        p[62..64].copy_from_slice(&1440u16.to_be_bytes());
        assert!(clamp_mss(&mut p, 1332));
        assert_eq!(read_mss(&p), Some(1332));
        // TCP 校验和自洽（IPv6 伪首部 + TCP 段）
        let mut pseudo = [0u8; 40];
        pseudo[0..16].copy_from_slice(&p[8..24]);
        pseudo[16..32].copy_from_slice(&p[24..40]);
        pseudo[32..36].copy_from_slice(&24u32.to_be_bytes());
        pseudo[39] = 6;
        let sum = crate::checksum::ones_complement_sum(&pseudo) as u32
            + crate::checksum::ones_complement_sum(&p[40..]) as u32;
        let folded = ((sum & 0xffff) + (sum >> 16)) as u16;
        assert_eq!(folded, 0xffff);
    }

    #[test]
    fn no_mss_option_returns_false() {
        // 20B IPv4 + 20B TCP（无 options）
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p[32] = 5 << 4; // data offset 5
        p[33] = TCP_FLAG_SYN;
        assert!(!clamp_mss(&mut p, 1352));
    }
}
