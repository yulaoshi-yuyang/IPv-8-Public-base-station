//! ipv8-ffi：C ABI 导出，仅用于 Phase 0 编解码验证（ADR-008）。
//! Phase 1 起全部走 gRPC，此模块冻结。

use std::ffi::c_char;
use std::os::raw::c_uint;

use ipv8_codec::{encode, ExtType, IPv8Address, IPv8Header, BASE_HEADER_SIZE};

/// 编码结果缓冲区（供 C 侧读取）
#[repr(C)]
pub struct Ipv8Buf {
    pub data: *mut u8,
    pub len: c_uint,
}

/// 解码输出：Phase 0 只需验证字段往返一致
#[repr(C)]
#[derive(Debug)]
pub struct Ipv8Decoded {
    pub src_asn: u32,
    pub src_host: u32,
    pub src_dev: u16,
    pub src_cap: u16,
    pub src_sec: u8,
    pub dst_asn: u32,
    pub dst_host: u32,
    pub dst_dev: u16,
    pub dst_cap: u16,
    pub dst_sec: u8,
    pub flags: u16,
    pub payload_len: u16,
    pub hop_limit: u8,
    pub next_header: u8,
}

/// 编码 40 字节基础包头 + 复制载荷，返回堆缓冲区（Rust 分配，须用 ipv8_free_buf 释放）。
/// 失败返回 { null, 0 }。
///
/// # Safety
/// `payload` 必须为 null，或指向 `payload_len` 个有效可读字节的对齐指针。
#[no_mangle]
pub unsafe extern "C" fn ipv8_encode(
    src_asn: u32,
    src_host: u32,
    src_dev: u16,
    src_cap: u16,
    src_sec: u8,
    dst_asn: u32,
    dst_host: u32,
    dst_dev: u16,
    dst_cap: u16,
    dst_sec: u8,
    flags: u16,
    hop_limit: u8,
    payload: *const u8,
    payload_len: c_uint,
) -> Ipv8Buf {
    if payload.is_null() && payload_len != 0 {
        return Ipv8Buf { data: std::ptr::null_mut(), len: 0 };
    }
    let payload_slice = unsafe { std::slice::from_raw_parts(payload, payload_len as usize) };
    let Ok(payload_len_u16): Result<u16, _> = payload_len.try_into() else {
        return Ipv8Buf { data: std::ptr::null_mut(), len: 0 };
    };
    let src = IPv8Address::new(src_asn, src_host, src_dev, src_cap, src_sec);
    let dst = IPv8Address::new(dst_asn, dst_host, dst_dev, dst_cap, dst_sec);
    let mut hdr = IPv8Header::new(src, dst, payload_len_u16);
    hdr.flags = flags;
    hdr.hop_limit = hop_limit;
    match encode(&hdr, payload_slice) {
        Ok(bytes) => {
            let len = bytes.len() as c_uint;
            let mut boxed = bytes.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            Ipv8Buf { data: ptr, len }
        }
        Err(_) => Ipv8Buf { data: std::ptr::null_mut(), len: 0 },
    }
}

/// 解码 IPv8+ 包，抽取基础字段用于一致性断言。0=成功，非 0=错误码。
///
/// # Safety
/// `buf` 必须为 null 或指向 `len` 个有效可读字节的对齐指针；
/// `out` 必须为 null 或指向可写 `Ipv8Decoded` 的对齐指针。
#[no_mangle]
pub unsafe extern "C" fn ipv8_decode(buf: *const u8, len: c_uint, out: *mut Ipv8Decoded) -> i32 {
    if buf.is_null() || out.is_null() {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    match ipv8_codec::decode(bytes) {
        Ok(d) => {
            unsafe {
                *out = Ipv8Decoded {
                    src_asn: d.header.src_addr.asn,
                    src_host: d.header.src_addr.host_id,
                    src_dev: d.header.src_addr.device_id,
                    src_cap: d.header.src_addr.cap_tag,
                    src_sec: d.header.src_addr.sec_level,
                    dst_asn: d.header.dst_addr.asn,
                    dst_host: d.header.dst_addr.host_id,
                    dst_dev: d.header.dst_addr.device_id,
                    dst_cap: d.header.dst_addr.cap_tag,
                    dst_sec: d.header.dst_addr.sec_level,
                    flags: d.header.flags,
                    payload_len: d.header.payload_len,
                    hop_limit: d.header.hop_limit,
                    next_header: d.header.next_header,
                };
            }
            0
        }
        Err(_) => -2,
    }
}

/// 基础包头固定长度常量（供 C 侧校验）
#[no_mangle]
pub extern "C" fn ipv8_base_header_size() -> c_uint {
    BASE_HEADER_SIZE as c_uint
}

/// 释放 ipv8_encode 返回的缓冲区
///
/// # Safety
/// `buf`/`len` 必须来自同一次 `ipv8_encode` 成功返回，且未被重复释放。
#[no_mangle]
pub unsafe extern "C" fn ipv8_free_buf(buf: *mut u8, len: c_uint) {
    if !buf.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(buf, len as usize, len as usize));
        }
    }
}

/// C 头文件生成占位（真实头文件在 include/ipv8.h 手工维护，保持 ABI 同步）
#[allow(dead_code)]
fn _abi_note() -> *const c_char {
    std::ptr::null()
}

// 保证 ExtType 在 ffi 层可用（Phase 0 只测无扩展头路径，接口预留）
#[allow(dead_code)]
fn _type_anchor(_: ExtType) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_roundtrip() {
        let payload = b"hello ipv8+";
        let buf = unsafe {
            ipv8_encode(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x10, 64, payload.as_ptr(), payload.len() as c_uint)
        };
        assert!(!buf.data.is_null());
        assert_eq!(buf.len as usize, 40 + payload.len());

        let mut out = std::mem::MaybeUninit::<Ipv8Decoded>::zeroed();
        let rc = unsafe { ipv8_decode(buf.data, buf.len, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let d = unsafe { out.assume_init() };
        assert_eq!((d.src_asn, d.src_host, d.src_dev, d.src_cap, d.src_sec), (1, 2, 3, 4, 5));
        assert_eq!((d.dst_asn, d.dst_host, d.dst_dev, d.dst_cap, d.dst_sec), (6, 7, 8, 9, 10));
        assert_eq!(d.flags, 0x10);
        assert_eq!(d.payload_len as usize, payload.len());
        assert_eq!(d.hop_limit, 64);
        unsafe { ipv8_free_buf(buf.data, buf.len) };
    }

    #[test]
    fn ffi_rejects_bad_input() {
        let mut out = std::mem::MaybeUninit::<Ipv8Decoded>::zeroed();
        assert_ne!(unsafe { ipv8_decode(std::ptr::null(), 0, std::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { ipv8_decode(std::ptr::null(), 40, out.as_mut_ptr()) }, -1);
    }
}
