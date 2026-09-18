//! 内层 IP 包检查：从裸 IPv4/IPv6 包提取协议号、地址、端口。
//!
//! 只做只读解析，全部带长度边界检查，畸形包返回保守默认值（proto=0），
//! 绝不 panic——这是数据面包容性要求。

/// 从一个内层数据包提取的元数据
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketInfo {
    pub ipver: u8,
    /// IANA IP 协议号（TCP=6 UDP=17 ICMP=1 ICMPv6=58）；无法判定为 0
    pub proto_num: u8,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

/// 解析内层包。任何异常都返回 proto_num=0 的保守结果，事件仍会上抛，
/// 由外部判决者决定去留。
pub fn inspect(p: &[u8]) -> PacketInfo {
    let Some(&ver_byte) = p.first() else {
        return PacketInfo::default();
    };
    match ver_byte >> 4 {
        4 => inspect_v4(p),
        6 => inspect_v6(p),
        _ => PacketInfo::default(),
    }
}

fn inspect_v4(p: &[u8]) -> PacketInfo {
    if p.len() < 20 {
        return PacketInfo::default();
    }
    let ihl = (p[0] & 0x0f) as usize;
    if ihl < 5 {
        return PacketInfo::default();
    }
    let l4 = ihl * 4;
    if l4 > p.len() {
        return PacketInfo::default();
    }
    let proto_num = p[9];
    let src = std::net::Ipv4Addr::new(p[12], p[13], p[14], p[15]).to_string();
    let dst = std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]).to_string();
    let (sport, dport) = parse_ports(p, l4, proto_num);
    PacketInfo {
        ipver: 4,
        proto_num,
        src,
        dst,
        sport,
        dport,
    }
}

fn inspect_v6(p: &[u8]) -> PacketInfo {
    // 固定头 40 字节
    if p.len() < 40 {
        return PacketInfo::default();
    }
    let mut next = p[6];
    let mut off = 40usize;

    // 跟随扩展头链（上限 8 跳，防环/防巨长链）
    for _ in 0..8 {
        match next {
            // TCP / UDP / ICMPv6：到达传输层
            6 | 17 | 58 => break,
            // Hop-by-Hop(0) / Routing(43) / Destination(60)：长度以 8 字节为单位
            0 | 43 | 60 => {
                if off + 2 > p.len() {
                    return PacketInfo::default();
                }
                let hlen = ((p[off + 1] as usize) + 1) * 8;
                next = p[off];
                off = off.saturating_add(hlen);
                if off > p.len() {
                    return PacketInfo::default();
                }
            }
            // Fragment(44)：固定 8 字节；非首片没有传输头，端口不可得
            44 => {
                if off + 8 > p.len() {
                    return PacketInfo::default();
                }
                let frag_info = u16::from_be_bytes([p[off + 2], p[off + 3]]);
                next = p[off];
                off += 8;
                if frag_info & 0x0001 == 0 && (frag_info >> 3) != 0 {
                    // 非首片：返回地址信息，端口留 0
                    break;
                }
            }
            // AH(51)：长度单位 4 字节，含固定 2 单位
            51 => {
                if off + 2 > p.len() {
                    return PacketInfo::default();
                }
                let hlen = ((p[off + 1] as usize) + 2) * 4;
                next = p[off];
                off = off.saturating_add(hlen);
                if off > p.len() {
                    return PacketInfo::default();
                }
            }
            // 其他/无扩展头：到此为止
            _ => break,
        }
    }

    let src = std::net::Ipv6Addr::new(
        u16::from_be_bytes([p[8], p[9]]),
        u16::from_be_bytes([p[10], p[11]]),
        u16::from_be_bytes([p[12], p[13]]),
        u16::from_be_bytes([p[14], p[15]]),
        u16::from_be_bytes([p[16], p[17]]),
        u16::from_be_bytes([p[18], p[19]]),
        u16::from_be_bytes([p[20], p[21]]),
        u16::from_be_bytes([p[22], p[23]]),
    )
    .to_string();
    let dst = std::net::Ipv6Addr::new(
        u16::from_be_bytes([p[24], p[25]]),
        u16::from_be_bytes([p[26], p[27]]),
        u16::from_be_bytes([p[28], p[29]]),
        u16::from_be_bytes([p[30], p[31]]),
        u16::from_be_bytes([p[32], p[33]]),
        u16::from_be_bytes([p[34], p[35]]),
        u16::from_be_bytes([p[36], p[37]]),
        u16::from_be_bytes([p[38], p[39]]),
    )
    .to_string();
    let (sport, dport) = parse_ports(p, off, next);
    PacketInfo {
        ipver: 6,
        proto_num: next,
        src,
        dst,
        sport,
        dport,
    }
}

/// 从传输层头取端口（仅 TCP/UDP）
fn parse_ports(p: &[u8], off: usize, proto: u8) -> (u16, u16) {
    if !matches!(proto, 6 | 17) {
        return (0, 0);
    }
    if off + 4 > p.len() {
        return (0, 0);
    }
    (
        u16::from_be_bytes([p[off], p[off + 1]]),
        u16::from_be_bytes([p[off + 2], p[off + 3]]),
    )
}

/// IANA 协议号 → 事件用短名
pub fn proto_name(num: u8) -> &'static str {
    match num {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

/// 方向无关的规范 5 元组流标识：两端点排序后拼接，保证双向同 key。
pub fn flow_key(info: &PacketInfo) -> String {
    let a = format!("{}:{}", info.src, info.sport);
    let b = format!("{}:{}", info.dst, info.dport);
    if a <= b {
        format!("{}:{}<->{}", proto_name(info.proto_num), a, b)
    } else {
        format!("{}:{}<->{}", proto_name(info.proto_num), b, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage_are_safe() {
        assert_eq!(inspect(&[]).proto_num, 0);
        assert_eq!(inspect(&[4u8 << 4]).proto_num, 0); // 声称 v4 但太短
        assert_eq!(inspect(&[0xff, 0xff]).proto_num, 0);
    }

    #[test]
    fn parses_ipv4_tcp() {
        // 20B IPv4 头 + TCP 端口 1234→443
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = 6;
        p[12..16].copy_from_slice(&[100, 64, 0, 1]);
        p[16..20].copy_from_slice(&[100, 64, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        let i = inspect(&p);
        assert_eq!(i.ipver, 4);
        assert_eq!(i.proto_num, 6);
        assert_eq!(i.src, "100.64.0.1");
        assert_eq!(i.dst, "100.64.0.2");
        assert_eq!(i.sport, 1234);
        assert_eq!(i.dport, 443);
    }

    #[test]
    fn parses_ipv6_udp() {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = 17;
        // ::1 → ::2（src 末两字节在 22..24，dst 末两字节在 38..40）
        p[22..24].copy_from_slice(&[0, 1]);
        p[38..40].copy_from_slice(&[0, 2]);
        p[40..42].copy_from_slice(&5353u16.to_be_bytes());
        p[42..44].copy_from_slice(&53u16.to_be_bytes());
        let i = inspect(&p);
        assert_eq!(i.ipver, 6);
        assert_eq!(i.proto_num, 17);
        assert_eq!(i.sport, 5353);
        assert_eq!(i.dport, 53);
        assert_eq!(i.src, "::1");
        assert_eq!(i.dst, "::2");
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let mut p1 = vec![0u8; 40];
        p1[0] = 0x45;
        p1[9] = 6;
        p1[12..16].copy_from_slice(&[100, 64, 0, 1]);
        p1[16..20].copy_from_slice(&[100, 64, 0, 2]);
        p1[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p1[22..24].copy_from_slice(&443u16.to_be_bytes());
        let i1 = inspect(&p1);

        let mut p2 = vec![0u8; 40];
        p2[0] = 0x45;
        p2[9] = 6;
        p2[12..16].copy_from_slice(&[100, 64, 0, 2]);
        p2[16..20].copy_from_slice(&[100, 64, 0, 1]);
        p2[20..22].copy_from_slice(&443u16.to_be_bytes());
        p2[22..24].copy_from_slice(&1234u16.to_be_bytes());
        let i2 = inspect(&p2);

        assert_eq!(flow_key(&i1), flow_key(&i2));
    }
}
