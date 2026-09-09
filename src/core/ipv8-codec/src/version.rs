//! 版本协商与 MinCompatVer 降级（protocol-spec §7.2）。
//!
//! 规则：
//! - Version 不匹配（≠0x8）的包直接丢弃（decode 层已做）。
//! - 收到 MinCompatVer > 本地版本 → 无法降级兼容，拒绝通信。
//! - 收到 MinCompatVer ≤ 本地版本 → 本端可用旧语义处理，允许降级通信。

use crate::header::{IPv8Header, VERSION};

/// 本实现协议版本
pub const LOCAL_VERSION: u8 = VERSION;

/// 协商结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// 双方版本完全兼容
    Full,
    /// 对端要求最低兼容版本低于本端，本端以降级模式处理
    Degrade { their_min_compat: u8 },
    /// 无法兼容：对端要求的最低版本高于本端版本
    Incompatible { their_min_compat: u8, local: u8 },
}

/// 基于包头做版本协商判定。
pub fn negotiate(hdr: &IPv8Header, local_version: u8) -> Negotiation {
    if hdr.min_compat_ver > local_version {
        Negotiation::Incompatible { their_min_compat: hdr.min_compat_ver, local: local_version }
    } else if hdr.min_compat_ver < local_version {
        Negotiation::Degrade { their_min_compat: hdr.min_compat_ver }
    } else {
        Negotiation::Full
    }
}

/// 快速路径：与本实现（LOCAL_VERSION）协商
pub fn negotiate_local(hdr: &IPv8Header) -> Negotiation {
    negotiate(hdr, LOCAL_VERSION)
}
