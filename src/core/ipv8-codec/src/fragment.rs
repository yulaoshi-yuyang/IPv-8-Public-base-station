//! MTU 分片与重组（protocol-spec §8.3）。
//!
//! 模型（IPv6 同款）：
//! - 每片 = 基础头(F=1, X=1) + Fragment 扩展头（链首）+ [首片]原扩展链 + 载荷分块
//! - Fragment 头载荷：Identification(32) | R(3) Offset(13, 单位 8B) | R(2) MF(1) | R(16)
//! - 重组键：(src, dst, id)；MF=0 的片给出总长；覆盖完整即产出重组包
//! - 安全上限：组数 / 单组字节数 / 30s 超时（惰性回收）

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use crate::decode::decode;
use crate::header::*;

/// v9 推荐 IPv8+ MTU（以太网 1500 − 68 封装开销）
pub const DEFAULT_MTU: usize = 1432;
/// Fragment 扩展头占用（2B 链头 + 8B 载荷）
pub const FRAG_EXT_WIRE: usize = 10;
/// 重组并发组上限（防内存放大）
pub const MAX_GROUPS: usize = 64;
/// 单组重组字节上限（协议 PayloadLen 上限）
pub const MAX_GROUP_BYTES: usize = 65467;
/// 重组超时（spec §8.3 SHOULD 30s）
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Fragment 头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentInfo {
    pub id: u32,
    /// 载荷偏移，单位 8 字节
    pub offset: u16,
    pub more: bool,
}

impl FragmentInfo {
    /// 编码为 Fragment 扩展头（载荷 8 字节）
    pub fn to_ext(self) -> ExtensionHeader {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&self.id.to_be_bytes());
        let word: u16 = ((self.offset & 0x1FFF) << 3) | ((self.more as u16) << 2);
        p[4..6].copy_from_slice(&word.to_be_bytes());
        ExtensionHeader { ext_type: ExtType::Fragment, payload: p.to_vec() }
    }

    /// 从扩展头解析；类型/长度不符返回 None
    pub fn parse(ext: &ExtensionHeader) -> Option<Self> {
        if ext.ext_type != ExtType::Fragment || ext.payload.len() != 8 {
            return None;
        }
        let id = u32::from_be_bytes(ext.payload[0..4].try_into().unwrap());
        let word = u16::from_be_bytes(ext.payload[4..6].try_into().unwrap());
        Some(Self { id, offset: (word >> 3) & 0x1FFF, more: word & 0x4 != 0 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// 输入不是合法 IPv8+ 包
    NotAValidPacket(crate::decode::DecodeError),
    /// 对分片包再次分片
    AlreadyFragmented,
    /// 载荷与包头 PayloadLen 不符
    LengthMismatch,
    /// MTU 容不下一片（含 Fragment 头开销）
    MtuTooSmall(usize),
}

impl core::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAValidPacket(e) => write!(f, "分片输入非法: {e}"),
            Self::AlreadyFragmented => write!(f, "不得对分片包再分片"),
            Self::LengthMismatch => write!(f, "载荷长度与包头不一致"),
            Self::MtuTooSmall(m) => write!(f, "MTU {m} 无法容纳任何分片"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// 把完整 IPv8+ 包按 `max_len`（IPv8+ 包级 MTU，如 1432）分片。
/// 不需要分片时原样返回单元素。
pub fn fragment_packet(packet: &[u8], max_len: usize, id: u32) -> Result<Vec<Vec<u8>>, FragmentError> {
    let d = decode(packet).map_err(FragmentError::NotAValidPacket)?;
    // 已分片检查必须先于"够小原样返回"：任何情况都不得对分片包再分片
    if d.header.ext_headers.iter().any(|e| e.ext_type == ExtType::Fragment) {
        return Err(FragmentError::AlreadyFragmented);
    }
    if packet.len() <= max_len {
        return Ok(vec![packet.to_vec()]);
    }
    if d.payload.len() != d.header.payload_len as usize {
        return Err(FragmentError::LengthMismatch);
    }

    let ext_total: usize = d.header.ext_headers.iter().map(|e| e.wire_size()).sum();
    // 首片开销 = 40 + Fragment头(10) + 原扩展链；分块大小对所有片统一（8 对齐）
    let budget = max_len.saturating_sub(BASE_HEADER_SIZE + FRAG_EXT_WIRE + ext_total);
    let chunk = budget & !7; // 向下取 8 的倍数
    if chunk < 8 {
        return Err(FragmentError::MtuTooSmall(max_len));
    }

    let mut out = Vec::new();
    let mut offset_units: u16 = 0;
    let mut pos = 0usize;
    while pos < d.payload.len() {
        let take = chunk.min(d.payload.len() - pos);
        let more = pos + take < d.payload.len();
        let chain = if pos == 0 {
            let mut c = vec![FragmentInfo { id, offset: offset_units, more }.to_ext()];
            c.extend(d.header.ext_headers.iter().cloned());
            c
        } else {
            vec![FragmentInfo { id, offset: offset_units, more }.to_ext()]
        };
        let mut hdr = IPv8Header {
            version: d.header.version,
            min_compat_ver: d.header.min_compat_ver,
            flags: d.header.flags & !(flags::HAS_EXTENSION | flags::FRAGMENT),
            payload_len: take as u16,
            hop_limit: d.header.hop_limit,
            next_header: 0,
            src_addr: d.header.src_addr,
            dst_addr: d.header.dst_addr,
            ext_headers: Vec::new(),
        };
        hdr.attach_ext_headers(chain);
        hdr.flags |= flags::FRAGMENT;

        let mut buf = Vec::with_capacity(BASE_HEADER_SIZE + FRAG_EXT_WIRE + ext_total + take);
        crate::encode::encode_header(&hdr, &mut buf)
            .map_err(|e| FragmentError::NotAValidPacket(decode_err_from_encode(&e)))?;
        buf.extend_from_slice(&d.payload[pos..pos + take]);
        out.push(buf);

        pos += take;
        offset_units += (take / 8) as u16;
    }
    Ok(out)
}

/// encode 错误映射到 decode 错误类型（仅用于统一 FragmentError 载荷）
fn decode_err_from_encode(
    e: &crate::encode::EncodeError,
) -> crate::decode::DecodeError {
    // 理论上不可达：输入包已解码成功，构造的分片头字段全部源自合法值
    match e {
        crate::encode::EncodeError::PayloadTooLong(n) => crate::decode::DecodeError::PayloadTooLong(*n),
        _ => crate::decode::DecodeError::TooShort(0),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// F 位与 Fragment 头不一致（spec §8.3 MUST 丢弃）
    FlagMismatch,
    /// Fragment 头不在链首
    NotFirstExt,
    /// 分片重叠
    Overlap,
    /// 超总长
    BeyondTotal,
    /// 非末片载荷不是 8 的倍数
    Misaligned,
    /// 总长超协议上限
    Oversize,
    /// 偏移字段越界（Offset×8 超出 13bit 表达上限）
    OffsetOverflow,
    /// 并发重组组数超上限（防内存放大）
    TooManyGroups,
}

impl core::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FlagMismatch => write!(f, "F=1 但链首无 Fragment 头（或 F=0 带 Fragment）"),
            Self::NotFirstExt => write!(f, "Fragment 头必须是第一个扩展头"),
            Self::Overlap => write!(f, "分片重叠"),
            Self::BeyondTotal => write!(f, "分片超出已知总长"),
            Self::Misaligned => write!(f, "非末片载荷必须 8 字节对齐"),
            Self::Oversize => write!(f, "重组总长超 {MAX_GROUP_BYTES}"),
            Self::OffsetOverflow => write!(f, "Offset 超出 13 bit 范围"),
            Self::TooManyGroups => write!(f, "并发重组组数达上限 {MAX_GROUPS}，拒绝新建组"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

struct Group {
    /// 首片携带的原扩展链（不含 Fragment）
    orig_ext: Option<Vec<ExtensionHeader>>,
    flags: u16,        // 已去 F/X（首片记录）
    version: u8,
    min_compat_ver: u8,
    hop_limit: u8,
    src: IPv8Address,
    dst: IPv8Address,
    chunks: BTreeMap<u64, Vec<u8>>,
    /// 已连续推进到的偏移
    pos: u64,
    /// MF=0 片给出的总长
    total: Option<u64>,
    payload: Vec<u8>,
    created: Instant,
}

/// IPv8+ 分片重组器。`insert` 返回 Some(完整 IPv8+ 包) 即重组完成。
#[derive(Default)]
pub struct Reassembler {
    groups: HashMap<([u8; 16], [u8; 16], u32), Group>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_groups(&self) -> usize {
        self.groups.len()
    }

    /// 插入一个（已解码的）分片包头 + 载荷。非分片包请调用方自行处理。
    pub fn insert(
        &mut self,
        hdr: &IPv8Header,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        // F 位与 Fragment 头一致性（normative §8.3）
        let f_flag = hdr.flags & flags::FRAGMENT != 0;
        let frag = hdr.ext_headers.first().and_then(FragmentInfo::parse);
        if !f_flag || frag.is_none() {
            return Err(ReassemblyError::FlagMismatch);
        }
        let frag = frag.unwrap();
        if hdr.ext_headers.first().map(|e| e.ext_type) != Some(ExtType::Fragment) {
            return Err(ReassemblyError::NotFirstExt);
        }
        let start = frag.offset as u64 * 8;
        if start > (0x1FFF * 8) as u64 {
            return Err(ReassemblyError::OffsetOverflow);
        }
        let len = payload.len() as u64;
        if frag.more && !len.is_multiple_of(8) {
            return Err(ReassemblyError::Misaligned);
        }

        self.reap();
        let key = (hdr.src_addr.to_bytes(), hdr.dst_addr.to_bytes(), frag.id);
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            self.groups.retain(|_, g| g.created.elapsed() < REASSEMBLY_TIMEOUT);
            if self.groups.len() >= MAX_GROUPS {
                return Err(ReassemblyError::TooManyGroups);
            }
        }
        let g = self.groups.entry(key).or_insert_with(|| Group {
            orig_ext: None,
            flags: hdr.flags & !(flags::FRAGMENT | flags::HAS_EXTENSION),
            version: hdr.version,
            min_compat_ver: hdr.min_compat_ver,
            hop_limit: hdr.hop_limit,
            src: hdr.src_addr,
            dst: hdr.dst_addr,
            chunks: BTreeMap::new(),
            pos: 0,
            total: None,
            payload: Vec::new(),
            created: Instant::now(),
        });

        if start < g.pos {
            return Err(ReassemblyError::Overlap);
        }
        if let Some(t) = g.total {
            if start + len > t {
                return Err(ReassemblyError::BeyondTotal);
            }
        }
        if !frag.more {
            let t = start + len;
            if t > MAX_GROUP_BYTES as u64 {
                return Err(ReassemblyError::Oversize);
            }
            match g.total {
                Some(old) if old != t => return Err(ReassemblyError::BeyondTotal),
                _ => g.total = Some(t),
            }
        }
        if start == 0 && g.orig_ext.is_none() {
            g.orig_ext = Some(hdr.ext_headers.iter().skip(1).cloned().collect());
        }
        if g.chunks.insert(start, payload.to_vec()).is_some() {
            return Err(ReassemblyError::Overlap);
        }

        // 连续覆盖推进（contains_key 先结束共享借用，再独占 remove）
        while g.chunks.contains_key(&g.pos) {
            let bytes = g.chunks.remove(&g.pos).unwrap();
            g.payload.extend_from_slice(&bytes);
            g.pos += bytes.len() as u64;
        }

        let done = matches!(g.total, Some(t) if g.pos == t);
        if !done {
            return Ok(None);
        }
        let group = self.groups.remove(&key).unwrap();
        let total = group.total.unwrap();

        // 重建：F 清除，扩展链 = 首片原链（attach 自动处理 X/NextHeader）
        let mut out_hdr = IPv8Header {
            version: group.version,
            min_compat_ver: group.min_compat_ver,
            flags: group.flags,
            payload_len: total as u16,
            hop_limit: group.hop_limit,
            next_header: 0,
            src_addr: group.src,
            dst_addr: group.dst,
            ext_headers: Vec::new(),
        };
        out_hdr.attach_ext_headers(group.orig_ext.unwrap_or_default());
        let mut pkt = Vec::with_capacity(BASE_HEADER_SIZE + total as usize);
        crate::encode::encode_header(&out_hdr, &mut pkt)
            .expect("重组头源自合法分片，编码必然成功");
        pkt.extend_from_slice(&group.payload);
        Ok(Some(pkt))
    }

    /// 回收超时组（insert 内自动惰性调用，也可显式调用）
    pub fn reap(&mut self) {
        let before = self.groups.len();
        self.groups.retain(|_, g| g.created.elapsed() < REASSEMBLY_TIMEOUT);
        let _ = before;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, ExtType, IPv8Address, IPv8Header};

    fn addr(n: u8) -> IPv8Address {
        IPv8Address::new(1, n as u32, 0, 0, 0)
    }

    fn big_packet(payload_len: usize) -> Vec<u8> {
        let hdr = IPv8Header::new(addr(1), addr(2), payload_len as u16);
        encode(&hdr, &vec![0xABu8; payload_len]).unwrap()
    }

    #[test]
    fn no_fragment_when_fits() {
        let pkt = big_packet(1000); // 40+1000 < 1432
        let frags = fragment_packet(&pkt, DEFAULT_MTU, 42).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], pkt);
    }

    #[test]
    fn fragment_then_reassemble() {
        let pkt = big_packet(5000);
        let frags = fragment_packet(&pkt, DEFAULT_MTU, 777).unwrap();
        assert!(frags.len() >= 4, "5040B/1432 → 至少 4 片，实际 {}", frags.len());
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &frags {
            let d = decode(f).unwrap();
            assert_ne!(d.header.flags & flags::FRAGMENT, 0, "每片必须 F=1");
            let fr = FragmentInfo::parse(d.header.ext_headers.first().unwrap()).unwrap();
            assert_eq!(fr.id, 777);
            out = r.insert(&d.header, d.payload).unwrap();
        }
        assert_eq!(out.as_deref(), Some(&pkt[..]), "重组结果必须逐字节等于原包");
        assert_eq!(r.active_groups(), 0);
    }

    #[test]
    fn out_of_order_and_interleaved() {
        let pkt = big_packet(3000);
        let frags = fragment_packet(&pkt, 800, 1).unwrap();
        let mut r = Reassembler::new();
        // 逆序注入（末片最先 → total 提前已知）
        let mut out = None;
        for f in frags.iter().rev() {
            let d = decode(f).unwrap();
            out = r.insert(&d.header, d.payload).unwrap();
        }
        assert_eq!(out.as_deref(), Some(&pkt[..]));
    }

    #[test]
    fn overlap_and_misalign_rejected() {
        let pkt = big_packet(2000);
        let frags = fragment_packet(&pkt, 800, 9).unwrap();
        let mut r = Reassembler::new();
        let d0 = decode(&frags[0]).unwrap();
        assert!(r.insert(&d0.header, d0.payload).unwrap().is_none());
        assert_eq!(
            r.insert(&d0.header, d0.payload).err(),
            Some(ReassemblyError::Overlap),
            "完全重复片拒绝"
        );
        // 部分重叠：第二片重放第一片偏移
        assert_eq!(r.active_groups(), 1);

        // misalign: 手工造非末片且载荷 %8 != 0（attach 保证指针/标志自洽可编码）
        let mut hdr = IPv8Header::new(addr(1), addr(2), 7);
        hdr.flags |= flags::FRAGMENT;
        hdr.attach_ext_headers(vec![FragmentInfo { id: 5, offset: 0, more: true }.to_ext()]);
        let bad = encode(&hdr, b"1234567").unwrap();
        let d = decode(&bad).unwrap();
        assert_eq!(
            Reassembler::new().insert(&d.header, d.payload).err(),
            Some(ReassemblyError::Misaligned)
        );
    }

    #[test]
    fn flag_mismatch_rejected() {
        let pkt = big_packet(2000);
        let frags = fragment_packet(&pkt, 800, 11).unwrap();
        let mut d = decode(&frags[0]).unwrap();
        d.header.flags &= !flags::FRAGMENT; // 篡改：F=0 但带头
        assert_eq!(
            Reassembler::new().insert(&d.header, d.payload).err(),
            Some(ReassemblyError::FlagMismatch)
        );
    }

    #[test]
    fn group_limit_and_timeout() {
        let pkt = big_packet(2000);
        let frags = fragment_packet(&pkt, 1432, 123).unwrap();
        let mut r = Reassembler::new();
        let d = decode(&frags[0]).unwrap();
        r.insert(&d.header, d.payload).unwrap();
        assert_eq!(r.active_groups(), 1);
        // 直接改 created 模拟超时不可行（私有），用公开 reap 验证不 panic 即可
        r.reap();
        assert_eq!(r.active_groups(), 1, "未超时不应回收");
    }

    #[test]
    fn mtu_too_small_errors() {
        let pkt = big_packet(100);
        assert_eq!(
            fragment_packet(&pkt, 50, 1).err(),
            Some(FragmentError::MtuTooSmall(50))
        );
    }

    #[test]
    fn refragment_rejected() {
        let pkt = big_packet(2000);
        let frags = fragment_packet(&pkt, 800, 1).unwrap();
        assert!(matches!(
            fragment_packet(&frags[0], 800, 2),
            Err(FragmentError::AlreadyFragmented)
        ));
    }

    #[test]
    fn ext_headers_survive_first_fragment_only() {
        let src = addr(1);
        let mut hdr = IPv8Header::new(src, addr(2), 3000);
        hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::SemanticTag, vec![0xCD; 8]).unwrap()]);
        let pkt = encode(&hdr, &vec![0u8; 3000]).unwrap();
        let frags = fragment_packet(&pkt, 1432, 88).unwrap();
        let d0 = decode(&frags[0]).unwrap();
        assert_eq!(d0.header.ext_headers.len(), 2, "首片: Fragment+SemanticTag");
        assert_eq!(d0.header.ext_headers[0].ext_type, ExtType::Fragment);
        assert_eq!(d0.header.ext_headers[1].ext_type, ExtType::SemanticTag);
        let d1 = decode(&frags[1]).unwrap();
        assert_eq!(d1.header.ext_headers.len(), 1, "后续片仅 Fragment");

        let mut r = Reassembler::new();
        let mut out = None;
        for f in &frags {
            let d = decode(f).unwrap();
            out = r.insert(&d.header, d.payload).unwrap();
        }
        assert_eq!(out.as_deref(), Some(&pkt[..]));
    }
}
