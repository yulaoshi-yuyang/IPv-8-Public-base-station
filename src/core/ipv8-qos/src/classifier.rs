//! 流量分类（v9 `ipv8-qos/classifier.rs`）。
//!
//! 唯一输入 = IPv8+ 基头字节（spec §5 Flags 位 0-3 = QoS Level 0-15）。
//! 分类是纯函数：引擎在拆壳后的明文基头上直接调用，无需完整解码路径
//! （转发节点只看 40 字节头，载荷是密文）。

use ipv8_codec::{flags, BASE_HEADER_SIZE};

/// 调度类数（v9 四级：0 最低/尽力而为，3 最高）
pub const NUM_CLASSES: usize = 4;

/// QoS Level(0-15) → 调度类(0-3)。线性映射：`class = level / 4`。
/// 防御：越界输入钳到最高类（协议上 level 仅 4 bit，不会发生）。
pub const fn class_of_level(level: u8) -> usize {
    let c = (level >> 2) as usize;
    if c >= NUM_CLASSES {
        NUM_CLASSES - 1
    } else {
        c
    }
}

/// 从编码后的基头提取 QoS Level（字节 1-2 的低 4 bit，大端）。
///
/// 长度不足 40 字节返回 None（调用方按尽力而为处理，MUST NOT 恐慌）。
pub fn qos_level_of_base_header(base40: &[u8]) -> Option<u8> {
    if base40.len() < BASE_HEADER_SIZE {
        return None;
    }
    let f = u16::from_be_bytes([base40[1], base40[2]]);
    Some((f & flags::QOS_LEVEL_MASK) as u8)
}

/// 分类一站式：基头 → 调度类。取不到 QoS 位（畸形输入）时归最低类。
pub fn classify_base_header(base40: &[u8]) -> usize {
    qos_level_of_base_header(base40).map_or(0, class_of_level)
}
