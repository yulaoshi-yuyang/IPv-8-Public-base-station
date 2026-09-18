//! # ipv8-compat
//!
//! IPv8+ 隧道兼容性处理：让数据面行为接近真正的 IP 路由器。
//!
//! - [`checksum`]：RFC 1071 校验和（IP/TCP/ICMP）
//! - [`ip`]：IPv4/IPv6 头部读写辅助
//! - [`ttl`]：TTL/HopLimit 扣减 + 组播/广播分类
//! - [`mss`]：TCP MSS 选项钳制
//! - [`icmp`]：ICMP/ICMPv6 差错报文生成
//!
//! 高层入口：[`Outcome`] + [`process_outbound`]，数据面在出站方向调用。
//!
//! 所有函数为纯函数、零依赖、带边界检查，绝不 panic。

pub mod checksum;
pub mod icmp;
pub mod ip;
pub mod mss;
pub mod ttl;

pub use ip::{ipv4_df_set, l4_offset};
pub use ttl::{decrement_ttl, is_multicast_or_broadcast};

use std::net::{Ipv4Addr, Ipv6Addr};

/// 出站兼容处理的结果
pub enum Outcome {
    /// 包可正常进入隧道（可能已被原地修改：TTL 扣减、MSS 钳制）
    Forward,
    /// 包被丢弃，需向本地 TUN 回注此 ICMP 差错报文
    InjectIcmp(Vec<u8>),
    /// 包被丢弃且无需回注（理论上不出现）
    Drop,
}

/// 出站方向兼容处理流水线。
///
/// 按顺序执行：
/// 0. 组播/广播：**逐字节透传**，不扣 TTL、不回注 ICMP（RFC 1812/4443 禁止对组播
///    发差错报文，且链路本地发现类流量常以 TTL=1 发送，扣减会造成黑洞）。
/// 1. TTL 扣减；若归零 → 生成 Time Exceeded 回注。
/// 2. 若 DF 置位且包长 > effective_mtu → 生成 Fragmentation Needed 回注。
/// 3. TCP SYN 包 MSS 钳制。
///
/// 参数：
/// - `packet` 会被原地修改（TTL、MSS、校验和）。
/// - `effective_mtu`：隧道有效 MTU，**只用于** DF/PTB 判定和自动 MSS 换算。
/// - `mss_target`：用户显式 MSS 值；`None` 时自动按 v4=mtu-40、v6=mtu-60 计算。
///   显式值不会再被扣减，也不影响 DF/PTB 阈值。
/// - `our_addr_v4`：本机 TUN IPv4 地址（ICMPv4 源地址）。
/// - `our_addr_v6`：本机 TUN IPv6 地址；`None`（TUN 未配置 v6）时 v6 差错无法合法
///   生成，v6 包 TTL 归零/超大返回 [`Outcome::Drop`]，绝不从 `::` 发非法报文。
pub fn process_outbound(
    packet: &mut [u8],
    effective_mtu: usize,
    mss_target: Option<u16>,
    our_addr_v4: Ipv4Addr,
    our_addr_v6: Option<Ipv6Addr>,
) -> Outcome {
    let ver = ip::ip_version(packet);
    if ver != 4 && ver != 6 {
        // 非 IP 包，直接转发
        return Outcome::Forward;
    }

    // 0. 组播/广播逐字节透传：不扣 TTL、不钳制、不回注
    if is_multicast_or_broadcast(packet) {
        return Outcome::Forward;
    }

    // 1. TTL 扣减
    if !decrement_ttl(packet) {
        // TTL 归零
        let icmp = match ver {
            4 => icmp::generate_time_exceeded_v4(packet, our_addr_v4),
            6 => our_addr_v6.and_then(|a6| icmp::generate_time_exceeded_v6(packet, a6)),
            _ => None,
        };
        return match icmp {
            Some(p) => Outcome::InjectIcmp(p),
            None => Outcome::Drop,
        };
    }

    // 2. DF + 超大包 → Fragmentation Needed。
    //    长度以实际缓冲为准（不信任头中 length 字段，防伪造小长度绕过）。
    let pkt_len = packet.len();
    if ver == 4 && ipv4_df_set(packet) && pkt_len > effective_mtu {
        if let Some(icmp) =
            icmp::generate_frag_needed_v4(packet, our_addr_v4, effective_mtu as u16)
        {
            return Outcome::InjectIcmp(icmp);
        }
        return Outcome::Drop;
    }
    if ver == 6 && pkt_len > effective_mtu {
        // IPv6 没有 DF 位，所有包都隐含不可分片；超大即 Packet Too Big
        if let Some(a6) = our_addr_v6 {
            if let Some(icmp) =
                icmp::generate_packet_too_big_v6(packet, a6, effective_mtu as u32)
            {
                return Outcome::InjectIcmp(icmp);
            }
        }
        return Outcome::Drop;
    }

    // 3. TCP MSS 钳制（仅 SYN/SYN-ACK，原地修改）
    //    用户显式值优先；否则按协议自动换算（v4=mtu-40，v6=mtu-60）。
    let target = mss_target.unwrap_or_else(|| {
        if ver == 6 {
            effective_mtu.saturating_sub(60) as u16
        } else {
            effective_mtu.saturating_sub(40) as u16
        }
    });
    let _ = mss::clamp_mss(packet, target);

    Outcome::Forward
}

/// 入站方向兼容处理：仅 MSS 钳制（SYN-ACK）。
///
/// 入站不做 TTL 扣减（对端已扣减）、不生成 ICMP。
/// `mss_target` 语义同[`process_outbound`]：显式值优先，`None` 时按 mtu 自动换算。
pub fn process_inbound(packet: &mut [u8], effective_mtu: usize, mss_target: Option<u16>) {
    let ver = ip::ip_version(packet);
    let target = mss_target.unwrap_or_else(|| {
        if ver == 6 {
            effective_mtu.saturating_sub(60) as u16
        } else {
            effective_mtu.saturating_sub(40) as u16
        }
    });
    let _ = mss::clamp_mss(packet, target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_ttl_zero_generates_icmp() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 1; // TTL=1
        p[9] = 1;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20] = 8; // Echo
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        match outcome {
            Outcome::InjectIcmp(icmp) => {
                assert_eq!(icmp[20], 11); // Time Exceeded
            }
            _ => panic!("应返回 InjectIcmp"),
        }
    }

    #[test]
    fn outbound_df_oversize_generates_frag_needed() {
        let mut p = vec![0u8; 1500];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1500u16.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        match outcome {
            Outcome::InjectIcmp(icmp) => {
                assert_eq!(icmp[20], 3); // Dest Unreachable
                assert_eq!(icmp[21], 4); // Frag Needed
                // MTU 字段必须是 effective_mtu=1392，而不是用户 mss 值
                assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1392);
            }
            _ => panic!("应返回 InjectIcmp"),
        }
    }

    #[test]
    fn outbound_normal_packet_forwards() {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Forward));
        assert_eq!(ip::ipv4_ttl(&p), 63); // TTL 已扣减
    }

    #[test]
    fn multicast_forwards_unchanged() {
        // F-3：组播逐字节透传，TTL 不被扣减
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[239, 255, 0, 1]);
        let before = p.clone();
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Forward));
        assert_eq!(p, before, "组播包内容必须逐字节不变");
        assert_eq!(p[8], 64, "组播 TTL 不应扣减");
    }

    #[test]
    fn multicast_ttl1_is_not_blackholed() {
        // F-3 关键场景：TTL=1 的组播包（链路本地 mDNS/SSDP 常见）必须透传，
        // 绝不能回注 Time Exceeded（RFC 1812 禁止）。
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 1; // TTL=1
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[224, 0, 0, 251]); // mDNS
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Forward));
        assert_eq!(p[8], 1);
    }

    #[test]
    fn broadcast_forwards_unchanged() {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 1; // TTL=1 广播同样不能黑洞
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[255, 255, 255, 255]);
        let before = p.clone();
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Forward));
        assert_eq!(p, before);
    }

    #[test]
    fn v6_ttl_zero_without_addr6_drops() {
        // F-2：TUN 无 v6 地址时，v6 TTL 归零只能 Drop，不能从 :: 发非法 ICMPv6
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = 58;
        p[7] = 1; // HopLimit=1
        p[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Drop));
    }

    #[test]
    fn v6_ttl_zero_with_addr6_injects() {
        // F-2：配置了 v6 TUN 地址时正常回注 Time Exceeded
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = 58;
        p[7] = 1;
        p[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        let our = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe);
        let outcome = process_outbound(
            &mut p,
            1392,
            None,
            Ipv4Addr::new(10, 0, 0, 1),
            Some(our),
        );
        match outcome {
            Outcome::InjectIcmp(icmp) => {
                assert_eq!(icmp[40], 3); // ICMPv6 Time Exceeded
                assert_eq!(&icmp[8..24], &our.octets(), "源地址必须是配置的 v6 地址");
            }
            _ => panic!("应返回 InjectIcmp"),
        }
    }

    /// 构造 20B IPv4 + 24B TCP SYN（MSS option 在内）
    fn make_v4_syn_packet(mss: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p[32] = 6 << 4;
        p[33] = 0x02; // SYN
        p[34..36].copy_from_slice(&65535u16.to_be_bytes());
        p[40] = 2; // MSS option
        p[41] = 4;
        p[42..44].copy_from_slice(&mss.to_be_bytes());
        p
    }

    #[test]
    fn explicit_mss_target_is_not_double_subtracted() {
        // F-4：用户指定 --mss-clamp 1200，出站 SYN 的 MSS 必须恰好是 1200，
        // 不能被再次减 40（旧 bug 会得到 1160）。
        let mut p = make_v4_syn_packet(1460);
        let outcome = process_outbound(
            &mut p,
            1392,
            Some(1200),
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::Forward));
        assert_eq!(mss::read_mss(&p), Some(1200));
    }

    #[test]
    fn explicit_mss_does_not_change_pmtu_threshold() {
        // F-4：显式 mss=1352 时，1400B 的 DF 包仍应以 1392 阈值判超大回注
        let mut p = vec![0u8; 1400];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1400u16.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let outcome = process_outbound(
            &mut p,
            1392,
            Some(1200),
            Ipv4Addr::new(10, 0, 0, 1),
            None,
        );
        assert!(matches!(outcome, Outcome::InjectIcmp(_)));
    }

    #[test]
    fn inbound_explicit_mss_target() {
        // F-4 入站：显式值直达
        let mut p = make_v4_syn_packet(1460);
        p[33] = 0x12; // SYN-ACK
        process_inbound(&mut p, 1392, Some(1234));
        assert_eq!(mss::read_mss(&p), Some(1234));
    }

    #[test]
    fn inbound_auto_mss() {
        let mut p = make_v4_syn_packet(1460);
        p[33] = 0x12;
        process_inbound(&mut p, 1392, None);
        assert_eq!(mss::read_mss(&p), Some(1352));
    }

    #[test]
    fn bench_perf_hot_path() {
        use std::time::Instant;
        // 普通 UDP 包：走完整流水线（TTL 扣减 + DF 检查 + MSS 跳过）
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);

        const N: u32 = 1_000_000;
        // 预热
        for _ in 0..10_000 {
            p[8] = 64;
            let _ = process_outbound(
                &mut p,
                1392,
                None,
                Ipv4Addr::new(10, 0, 0, 1),
                None,
            );
        }
        let start = Instant::now();
        for _ in 0..N {
            // TTL 会扣到 0，每次重置
            p[8] = 64;
            let _ = process_outbound(
                &mut p,
                1392,
                None,
                Ipv4Addr::new(10, 0, 0, 1),
                None,
            );
        }
        let elapsed = start.elapsed();
        let ns_per_pkt = elapsed.as_nanos() as f64 / N as f64;
        println!("process_outbound: {ns_per_pkt:.1} ns/包（{N} 包，{elapsed:?}）");
        // 200ns 阈值只在 release 优化构建强制；debug 未优化约 200ns+，仅打印不失败
        if !cfg!(debug_assertions) {
            assert!(ns_per_pkt < 200.0, "热路径单包开销应 <200ns，实际 {ns_per_pkt:.1}ns");
        }
    }
}
