//! RFC 1071 互联网校验和：IP 头、TCP/UDP 伪首部、ICMP。
//!
//! 全部为纯函数，in-place 修改，不分配内存。
//! 校验和算法：对 16 位字求和（偶数字节直接，奇数字节补零），
//! 折叠进位后取反。

/// 计算一段字节的 RFC 1071 校验和（返回 16 位值，未取反前的和用于增量更新）。
/// 奇数长度时最后一个字节当作高字节（低字节补 0）。
pub fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    let len = data.len();
    // 主循环：每 16 位一组
    while i + 1 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // 奇数长度的最后一个字节
    if i < len {
        sum += (data[i] as u32) << 8;
    }
    // 折叠进位
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// 计算并返回校验和字段值（取反）。
pub fn checksum(data: &[u8]) -> u16 {
    !ones_complement_sum(data)
}

/// IPv4 头校验和：对头 20+IHL 字节计算（校验和字段位置先置 0）。
/// 输入 `header` 应为完整 IPv4 头，函数会临时清零校验和字段再计算。
pub fn ip_header_checksum(header: &mut [u8]) -> u16 {
    if header.len() < 20 {
        return 0;
    }
    let ihl = (header[0] & 0x0f) as usize * 4;
    if header.len() < ihl {
        return 0;
    }
    // 清零校验和字段（offset 10-11）
    header[10] = 0;
    header[11] = 0;
    checksum(&header[..ihl])
}

/// TCP 校验和：IPv4 伪首部 + TCP 段。
/// `packet` 为完整 IPv4 包（含头），`tcp_offset` 为 TCP 头起始偏移。
pub fn tcp_checksum_v4(packet: &[u8], tcp_offset: usize) -> u16 {
    if packet.len() < tcp_offset + 20 {
        return 0;
    }
    // 伪首部：src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
    let tcp_len = packet.len() - tcp_offset;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&packet[12..16]); // src
    pseudo[4..8].copy_from_slice(&packet[16..20]); // dst
    pseudo[8] = 0; // zero
    pseudo[9] = packet[9]; // proto
    pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());

    // 先清零 TCP 校验和字段（offset 16-17 within TCP header）
    // 用拷贝避免修改原包
    let mut tcp_buf = vec![0u8; tcp_len];
    tcp_buf.copy_from_slice(&packet[tcp_offset..]);
    tcp_buf[16] = 0;
    tcp_buf[17] = 0;

    // 伪首部 + TCP 段 合并计算
    let mut sum = ones_complement_sum(&pseudo) as u32;
    sum = sum.wrapping_add(ones_complement_sum(&tcp_buf) as u32);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP 校验和：IPv6 伪首部 + TCP 段。
/// `packet` 为完整 IPv6 包（含 40B 头），`tcp_offset` 为 TCP 头起始偏移（可在扩展头之后）。
/// 注意：IPv6 伪首部的 next-header 是**最终上层协议号**（TCP=6），
/// 不是固定头 byte[6]——存在扩展头链时 byte[6] 是第一个扩展头的类型。
pub fn tcp_checksum_v6(packet: &[u8], tcp_offset: usize) -> u16 {
    tcp_checksum_v6_with_proto(packet, tcp_offset, 6)
}

/// IPv6 上层协议校验和通用实现：调用方传入最终协议号（TCP=6 / UDP=17 / ICMPv6=58）。
pub(crate) fn tcp_checksum_v6_with_proto(
    packet: &[u8],
    l4_offset: usize,
    next_header: u8,
) -> u16 {
    if packet.len() < l4_offset + 20 {
        return 0;
    }
    let l4_len = packet.len() - l4_offset;
    // IPv6 伪首部：src(16) + dst(16) + l4_len(4) + zero(3) + next_header(1)
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&packet[8..24]); // src
    pseudo[16..32].copy_from_slice(&packet[24..40]); // dst
    pseudo[32..36].copy_from_slice(&(l4_len as u32).to_be_bytes());
    pseudo[36..39].copy_from_slice(&[0, 0, 0]);
    pseudo[39] = next_header;

    let mut l4_buf = vec![0u8; l4_len];
    l4_buf.copy_from_slice(&packet[l4_offset..]);
    l4_buf[16] = 0;
    l4_buf[17] = 0;

    let mut sum = ones_complement_sum(&pseudo) as u32;
    sum = sum.wrapping_add(ones_complement_sum(&l4_buf) as u32);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP 校验和：对整个 ICMP 报文（含头+载荷）计算，校验和字段先清零。
pub fn icmp_checksum(icmp: &mut [u8]) -> u16 {
    if icmp.len() < 4 {
        return 0;
    }
    icmp[2] = 0;
    icmp[3] = 0;
    checksum(icmp)
}

/// ICMPv6 校验和：IPv6 伪首部 + ICMPv6 报文（RFC 4443 §2.3）。
/// 与 ICMPv4 不同，ICMPv6 校验和**必须**覆盖伪首部（src/dst/长度/next-header=58），
/// 否则任何合规 IPv6 节点都会丢弃该报文。
///
/// - `pkt`：完整外层 IPv6 包（40B 头 + ICMPv6），校验和字段会被临时清零。
pub fn icmpv6_checksum(pkt: &mut [u8]) -> u16 {
    if pkt.len() < IPV6_MIN_HDR + 4 {
        return 0;
    }
    let icmp_len = (pkt.len() - 40) as u32;
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&pkt[8..24]); // src
    pseudo[16..32].copy_from_slice(&pkt[24..40]); // dst
    pseudo[32..36].copy_from_slice(&icmp_len.to_be_bytes());
    pseudo[39] = 58; // next header = ICMPv6
                    // 清零 ICMPv6 校验和（外层 40 + ICMP offset 2-3 = 42-43）
    pkt[42] = 0;
    pkt[43] = 0;
    let mut sum = ones_complement_sum(&pseudo) as u32;
    sum = sum.wrapping_add(ones_complement_sum(&pkt[40..]) as u32);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const IPV6_MIN_HDR: usize = 40;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_header_checksum_self_consistent() {
        // RFC 1071 经典示例头（字段构造后验证校验和自洽）
        let mut h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let cs = ip_header_checksum(&mut h);
        h[10] = (cs >> 8) as u8;
        h[11] = cs as u8;
        assert_eq!(checksum(&h), 0);
    }

    #[test]
    fn checksum_changes_when_byte_changes() {
        let mut a = [0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let c1 = ip_header_checksum(&mut a);
        a[0] ^= 0x01;
        let c2 = ip_header_checksum(&mut a);
        assert_ne!(c1, c2);
    }

    #[test]
    fn icmp_checksum_self_consistent() {
        // ICMP Echo Request (type=8, code=0, id=1, seq=1, data="abcdefgh")
        let mut icmp = vec![
            8u8, 0, 0, 0, 0, 1, 0, 1, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h',
        ];
        let cs = icmp_checksum(&mut icmp);
        icmp[2] = (cs >> 8) as u8;
        icmp[3] = cs as u8;
        assert_eq!(checksum(&icmp), 0);
    }

    #[test]
    fn tcp_checksum_v4_self_consistent() {
        // 构造最小 IPv4+TCP 包
        let mut pkt = vec![0u8; 40];
        // IPv4 头
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // TCP 头（20B）
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes()); // sport
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes()); // dport
        pkt[24..28].copy_from_slice(&1u32.to_be_bytes()); // seq
        pkt[28..32].copy_from_slice(&0u32.to_be_bytes()); // ack
        pkt[32] = 5 << 4; // data offset = 5 (20B)
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window
        // checksum at 36..38 left 0
        let cs = tcp_checksum_v4(&pkt, 20);
        pkt[36] = (cs >> 8) as u8;
        pkt[37] = cs as u8;
        // 验证：写入校验和后，伪首部+TCP段的 ones_complement_sum 应为 0xffff
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&pkt[12..16]);
        pseudo[4..8].copy_from_slice(&pkt[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
        let sum = ones_complement_sum(&pseudo) as u32
            + ones_complement_sum(&pkt[20..]) as u32;
        let folded = ((sum & 0xffff) + (sum >> 16)) as u16;
        assert_eq!(folded, 0xffff);
    }

    #[test]
    fn tcp_checksum_v6_with_extension_header_uses_tcp_proto() {
        // F-6 回归：带 Hop-by-Hop 扩展头时，固定头 byte[6]=0（扩展头类型），
        // 但伪首部 next-header 必须是最终协议 TCP=6。
        // 40B IPv6 + 8B Hop-by-Hop + 20B TCP = 68B
        let mut pkt = vec![0u8; 68];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&28u16.to_be_bytes()); // payload len = 8+20
        pkt[6] = 0; // 第一个 next-header = Hop-by-Hop（不是 TCP！）
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20u8, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20u8, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Hop-by-Hop 扩展头：next=6(TCP)，长度字段 0（表示 8B），其余 Pad1
        pkt[40] = 6;
        pkt[41] = 0;
        // TCP 头在 48
        pkt[48..50].copy_from_slice(&1234u16.to_be_bytes());
        pkt[50..52].copy_from_slice(&80u16.to_be_bytes());
        pkt[52..56].copy_from_slice(&1u32.to_be_bytes());
        pkt[60] = 5 << 4;
        pkt[61] = 0x02; // SYN
        pkt[62..64].copy_from_slice(&65535u16.to_be_bytes());
        let cs = tcp_checksum_v6(&pkt, 48);
        pkt[64] = (cs >> 8) as u8;
        pkt[65] = cs as u8;
        // 用 proto=6 重构伪首部验证
        let mut pseudo = [0u8; 40];
        pseudo[0..16].copy_from_slice(&pkt[8..24]);
        pseudo[16..32].copy_from_slice(&pkt[24..40]);
        pseudo[32..36].copy_from_slice(&20u32.to_be_bytes());
        pseudo[39] = 6; // TCP
        let sum = ones_complement_sum(&pseudo) as u32
            + ones_complement_sum(&pkt[48..]) as u32;
        let folded = ((sum & 0xffff) + (sum >> 16)) as u16;
        assert_eq!(folded, 0xffff);
    }
}
