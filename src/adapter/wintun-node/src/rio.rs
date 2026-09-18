//! Phase 2 降维打击：RIO（Registered I/O）极速用户态 UDP 数据面。
//!
//! 叙事：WireGuard 的速度 + NFQUEUE 的自由。普通用户态 UDP 的天生成本是
//! **每包一次 syscall + 一次线程唤醒 + 每包缓冲区锁页**；RIO 把这三者全部
//! 改成批量模型：
//! - [`RIORegisterBuffer`]：启动时一次性锁页，之后收包零额外锁页、零拷贝
//!   （帧直接落在注册缓冲内借用，AEAD 产出新 Vec 的既有模型不变）；
//! - [`RIOReceiveEx`] / [`RIOSendEx`]：预投递请求，数据到了直接写缓冲入队；
//! - [`RIODequeueCompletion`]：一次调用收割至多 [`DEQUEUE_BATCH`] 个完成，
//!   每批一次 syscall、一次唤醒，而非每包一次。
//!
//! 本模块把全部 `unsafe` FFI 封闭在 [`RioRuntime`] 内部，对外只暴露
//! [`UdpIo`]（Std/Rio 同构接口）与纯数据结构。Win7+ 可用；任何初始化失败
//! 都由调用方按 `--rio` 策略回退到标准 [`std::net::UdpSocket`] 双线程路径。
//!
//! 铁约束（Microsoft 文档）：request queue 创建后，该 socket 禁止普通
//! recv/send（返回 WSAEOPNOTSUPP）——主 socket 的全部发送站点必须走
//! [`UdpIo::send_to`]；打洞专用临时 socket 不经本模块。
//!
//! [`RIORegisterBuffer`]: https://learn.microsoft.com/windows/win32/api/mswsock/nc-mswsock-lpfn_rioregisterbuffer
//! [`RIOReceiveEx`]: https://learn.microsoft.com/windows/win32/api/mswsock/nc-mswsock-lpfn_rioreceiveex
//! [`RIOSendEx`]: https://learn.microsoft.com/windows/win32/api/mswsock/nc-mswsock-lpfn_riosendex
//! [`RIODequeueCompletion`]: https://learn.microsoft.com/windows/win32/api/mswsock/nc-mswsock-lpfn_riodequeuecompletion

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io;
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, Sleep, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::Networking::WinSock::{
    bind as wsa_bind, closesocket, getsockname, WSAEnumProtocolsW, WSAGetLastError, WSAIoctl,
    WSAStartup, WSASocketW, WSADATA, WSAPROTOCOL_INFOW, AF_INET, AF_INET6, INVALID_SOCKET,
    RIO_BUF, RIO_CQ, RIO_EVENT_COMPLETION, RIO_EXTENSION_FUNCTION_TABLE,
    RIO_NOTIFICATION_COMPLETION, RIO_RQ, RIORESULT, RIO_BUFFERID,
    SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SOCK_DGRAM, WSA_FLAG_OVERLAPPED,
    WSA_FLAG_REGISTERED_IO, IPPROTO_UDP,
};
use windows_sys::core::{GUID, PCSTR};

/// --rio 策略：On=强制（失败即退出）、Auto=能力探测（失败回退 std）、Off=永远 std。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RioMode {
    On,
    Auto,
    Off,
    /// Phase 8: 直接 L2 帧收发（ipv8proto.sys 0xFB14 裸帧）
    L2,
}

/// 单个 UDP 数据报槽位容量：UDP 载荷理论上限（65535 - 20 IP - 8 UDP）。
/// 收发都用全尺寸：隧道帧（≤ MTU）与 --tun-mtu 调大后的整包/分片都装得下，
/// 发送路径永不因长度回退；锁页成本以「槽位数减半重试」兜底。
const SLOT_CAP: usize = 65_507;
/// 每槽对端地址区：sockaddr_in6 仅 28B，32B 对齐留余量。
const ADDR_CAP: usize = 32;
/// 单批收割上限（与 TUN 出站 TUN_BATCH_CAP 对齐，事件循环每轮两侧各 ≤64）。
const DEQUEUE_BATCH: usize = 64;

/// 首选槽位规模：recv 256 + send 128（约 25MB 锁页）。
const FULL_RECV_SLOTS: usize = 256;
const FULL_SEND_SLOTS: usize = 128;
/// 锁页配额受限时的减半档（约 6MB），再失败即放弃 RIO 回退 std。
const SMALL_RECV_SLOTS: usize = 64;
const SMALL_SEND_SLOTS: usize = 32;

/// 完成上下文（RIORESULT.RequestContext 原样返回）高位标记：发送完成。
/// 低 63 位是槽号；接收完成不带标记。
const CTX_SEND_BIT: u64 = 1 << 63;

/// WSAID_MULTIPLE_RIO（mswsock.h 定义，windows-sys 未导出该 GUID 常量，按 SDK 本地声明）。
/// 权威来源：Windows SDK mswsock.h——
/// `{0x8509e081,0x96dd,0x4005,{0xb1,0x65,0x9e,0x2e,0xe8,0xc7,0x9e,0x3f}}`
/// 注意：网上流传的 ...b89c-1a8f36608103 是错误值，用它发
/// SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 会在任何机器上得到 WSAEOPNOTSUPP(10045)。
const WSAID_MULTIPLE_RIO: GUID = GUID {
    data1: 0x8509_e081,
    data2: 0x96dd,
    data3: 0x4005,
    data4: [0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f],
};

static WSA_START: Once = Once::new();

/// RIOSendEx 的**实机正确 ABI**（10 参，Flags 是第 4 参，末尾 pfnCompletion）。
///
/// windows-sys 0.52 把 LPFN_RIOSENDEX 错绑成 Win8 预览头的 9 参布局
/// （Flags 错放在第 8 参），照它调用在 Win11 26200 上稳定 WSAEINVAL(10022)。
/// 已用 C# 最小探针在本机实测：10 参/9 参 Flags 在第 4 位均 rc=1，
/// Flags 在第 8 位的旧布局 rc=0。RIOReceiveEx 同理。
/// 故对函数表里这两个指针做 transmute 后再调。
type RioSendExFn = unsafe extern "system" fn(
    RIO_RQ,
    *const RIO_BUF,
    u32,
    u32, // Flags（第 4 参）
    *const c_void, // pLocalAddress
    *const RIO_BUF, // pRemoteAddress
    *const c_void, // pControlContext
    *const c_void, // pInternalContext
    *const c_void, // RequestContext
    *const c_void, // pfnCompletionFunction
) -> i32;

/// RIOReceiveEx 的实机正确 ABI（与 RIOSendEx 同构，10 参 Flags 第 4）。
type RioRecvExFn = unsafe extern "system" fn(
    RIO_RQ,
    *const RIO_BUF,
    u32,
    u32,
    *const RIO_BUF, // pLocalAddress
    *const RIO_BUF, // pRemoteAddress
    *const c_void, // pControlContext
    *const c_void, // pInternalContext
    *const c_void, // RequestContext
    *const c_void, // pfnCompletionFunction
) -> i32;

/// 主 socket 的统一 I/O 接口。Std 变体保持历史行为逐字节不变；
/// Rio 变体走注册缓冲批量数据面；L2 变体经 ipv8proto.sys 收发 0xFB14 裸帧。
/// 三个变体内部都是 Arc，clone 即廉价共享。
#[derive(Clone)]
pub(crate) enum UdpIo {
    Std(Arc<UdpSocket>),
    Rio(Arc<RioRuntime>),
    L2(Arc<L2Io>),
}

impl UdpIo {
    /// 按模式绑定。`On` 失败返回错误（用户强制）；`Auto` 失败打印原因并回退 std；
    /// `Off` 只走 std。
    pub(crate) fn bind(addr: SocketAddr, mode: RioMode) -> io::Result<Self> {
        match mode {
            RioMode::Off => Ok(UdpIo::Std(Self::bind_std(addr)?)),
            RioMode::On => Ok(UdpIo::Rio(Arc::new(RioRuntime::create_with_fallback(
                addr,
            )?))),
            RioMode::Auto => match RioRuntime::create_with_fallback(addr) {
                Ok(rt) => {
                    println!("[rio] RIO 数据面已启用: {} 收 / {} 发槽位", rt.n_recv, rt.n_send);
                    Ok(UdpIo::Rio(Arc::new(rt)))
                }
                Err(e) => {
                    eprintln!("[rio] RIO 不可用，回退标准 UDP 数据面: {e}");
                    Ok(UdpIo::Std(Self::bind_std(addr)?))
                }
            },
            RioMode::L2 => {
                let l2 = L2Io::bind()?;
                println!(
                    "[l2] 已打开 ipv8proto.sys 0xFB14 数据面: if_index={}, local_mac={:02x?}",
                    l2.if_index(),
                    l2.local_mac()
                );
                Ok(UdpIo::L2(Arc::new(l2)))
            }
        }
    }

    fn bind_std(addr: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        Ok(Arc::new(UdpSocket::bind(addr)?))
    }

    /// 统一发送：隧道帧、握手帧、明文降级帧全部经此。
    /// 与旧代码 `let _ = sock.send_to(...)` 语义对齐：错误由调用方决定丢弃/计数。
    pub(crate) fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<()> {
        match self {
            UdpIo::Std(s) => {
                let n = s.send_to(buf, dest)?;
                if n == buf.len() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP 短写（数据报未完整发出）",
                    ))
                }
            }
            UdpIo::Rio(rt) => rt.send_to(buf, dest),
            UdpIo::L2(l2) => {
                // L2 模式忽略 dest SocketAddr，用已配置的 peer_mac 或广播
                let peer = l2.peer_mac.lock().unwrap();
                let dst = peer.unwrap_or([0xFFu8; 6]);
                l2.send_to_mac(buf, dst)
            }
        }
    }

    /// std 数据面专用：接收线程只在非 RIO/L2 模式启动，拿 Arc 克隆进线程。
    pub(crate) fn as_std(&self) -> Option<&Arc<UdpSocket>> {
        match self {
            UdpIo::Std(s) => Some(s),
            UdpIo::Rio(_) | UdpIo::L2(_) => None,
        }
    }

    /// RIO 运行时引用：Some 时调用方应启动 RIO 事件循环替代 std 收发线程。
    pub(crate) fn as_rio(&self) -> Option<&Arc<RioRuntime>> {
        match self {
            UdpIo::Rio(rt) => Some(rt),
            UdpIo::Std(_) | UdpIo::L2(_) => None,
        }
    }

    /// L2 运行时引用：Some 时调用方应启动 L2 recv 线程。
    pub(crate) fn as_l2(&self) -> Option<&Arc<L2Io>> {
        match self {
            UdpIo::L2(l2) => Some(l2),
            UdpIo::Std(_) | UdpIo::Rio(_) => None,
        }
    }

    /// 本地绑定地址（打洞 observed 诊断复用 std 的 local_addr 语义）。
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            UdpIo::Std(s) => s.local_addr(),
            UdpIo::Rio(rt) => rt.local_addr(),
            UdpIo::L2(_) => Ok(SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }
}

// ── P8.4: L2 传输层（ipv8proto.sys 0xFB14 裸帧收发）───────────────────
// 与 UdpIo 并列；main() 按 --l2 选择 L2Io 替代 UdpIo。
// 接口设计：send_to_mac(buf, [u8; 6]) / recv() -> (payload, [u8; 6])
// 入站/出站的 IPv8+ 帧已在 AEAD 层封装好，L2Io 只负责：
//   send: 加 14B 以太网头 (dst, 0, 0xFB14, payload) → IOCTL SEND_FRAME
//   recv: IOCTL RECV_FRAME → 去掉 14B 以太网头 → 返回 payload + src_mac

// 驱动 IOCTL 常量（与 ipv8proto 内核驱动 driver.h 对齐）
const IPV8_DRIVER_PATH: &str = r"\\.\IPv8Proto";
const IPV8_IOCTL_RECV_FRAME: u32 = 0x0022_200c;
const IPV8_IOCTL_SEND_FRAME: u32 = 0x0022_2010;
const IPV8_IOCTL_GET_BINDINGS: u32 = 0x0022_2008;
const IPV8_ETH_HEADER_LEN: usize = 14;
const IPV8_RECV_IN_LEN: usize = 16; // magic(4) + ifindex(4) + reserved(8)
const IPV8_FRAME_HDR_LEN: usize = 16;
const IPV8_FRAME_MAX: usize = 1514;
const IPV8_BINDING_SIZE: usize = 180; // driver.h 里 IPV8_BINDING 结构大小
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const ERROR_IO_PENDING: i32 = 997;
const WAIT_TIMEOUT: u32 = 258;

// L2 FFI（CreateFileW / DeviceIoControl / GetOverlappedResult 需自行声明；
// CloseHandle/CreateEventW/WaitForSingleObject 已从 windows_sys 导入）
extern "system" {
    fn CreateFileW(
        lpfilename: *const u16,
        dwdesiredaccess: u32,
        dwsharemode: u32,
        lpsecurityattributes: *const c_void,
        dwcreationdisposition: u32,
        dwflagsandattributes: u32,
        htemplatefile: usize,
    ) -> isize;
    fn DeviceIoControl(
        hdevice: isize,
        dwiocontrolcode: u32,
        lpinbuffer: *const c_void,
        ninbuffersize: u32,
        lpoutbuffer: *mut c_void,
        noutbuffersize: u32,
        lpbytesreturned: *mut u32,
        lpoverlapped: *mut c_void,
    ) -> i32;
    fn GetOverlappedResult(
        hfile: isize,
        lpoverlapped: *mut c_void,
        lpnumberofbytestransferred: *mut u32,
        bwait: i32,
    ) -> i32;
}

/// L2 传输层：经 ipv8proto.sys IOCTL 收发 0xFB14 以太网帧
pub(crate) struct L2Io {
    handle: isize,
    event: HANDLE,
    if_index: u32,
    local_mac: [u8; 6],
    /// 对端 MAC（None=广播，或运行时 set）
    peer_mac: std::sync::Mutex<Option<[u8; 6]>>,
}

impl L2Io {
    /// 打开驱动 + 绑定第一张 bound 网卡
    pub(crate) fn bind() -> io::Result<Self> {
        // CreateFileW: GENERIC_READ|GENERIC_WRITE (0xC0000000), FILE_SHARE_READ|WRITE (3), OPEN_EXISTING (3)
        let wide: Vec<u16> = IPV8_DRIVER_PATH.encode_utf16().chain([0]).collect();
        let handle = unsafe {
            CreateFileW(wide.as_ptr(), 0xC000_0000, 3, ptr::null(), 3, FILE_FLAG_OVERLAPPED, 0)
        };
        if handle == -1 {
            return Err(io::Error::last_os_error());
        }
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event == 0 {
            unsafe { CloseHandle(handle) };
            return Err(io::Error::last_os_error());
        }
        // 查 bindings 拿第一张 bound 网卡的 if_index 和 MAC
        let bindings = unsafe { l2_query_bindings(handle)? };
        let binding = bindings.into_iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "ipv8proto.sys 已安装但无网卡 bound")
        })?;
        Ok(Self {
            handle,
            event,
            if_index: binding.if_index,
            local_mac: binding.mac,
            peer_mac: std::sync::Mutex::new(None),
        })
    }

    pub(crate) fn set_peer_mac(&self, mac: [u8; 6]) {
        *self.peer_mac.lock().unwrap() = Some(mac);
    }

    pub(crate) fn peer_mac(&self) -> Option<[u8; 6]> {
        *self.peer_mac.lock().unwrap()
    }

    pub(crate) fn if_index(&self) -> u32 { self.if_index }

    /// 发送 IPv8+ 帧：封装 14B 以太网头 → SEND_FRAME IOCTL
    pub(crate) fn send_to_mac(&self, buf: &[u8], dst_mac: [u8; 6]) -> io::Result<()> {
        if buf.len() > IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("L2 payload 过长: {} > {}", buf.len(), IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN),
            ));
        }
        // 16B frame header + 14B eth header + payload
        let mut frame = Vec::with_capacity(16 + IPV8_ETH_HEADER_LEN + buf.len());
        frame.extend_from_slice(&0xFB14u32.to_le_bytes()); // magic
        frame.extend_from_slice(&self.if_index.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes()); // reserved
        frame.extend_from_slice(&dst_mac);              // dst MAC
        frame.extend_from_slice(&[0u8; 6]);             // src MAC (驱动覆写)
        frame.push(0xFB); frame.push(0x14);              // EtherType
        frame.extend_from_slice(buf);

        let ov = unsafe { l2_overlapped(self.event) };
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IPV8_IOCTL_SEND_FRAME,
                frame.as_ptr().cast(),
                frame.len() as u32,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ov,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error().raw_os_error();
        if err != Some(ERROR_IO_PENDING) {
            return Err(io::Error::other("SEND_FRAME IOCTL 失败"));
        }
        // 等待
        match unsafe { WaitForSingleObject(self.event, 2000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::Error::new(io::ErrorKind::TimedOut, "SEND_FRAME 超时")),
            _ => Err(io::Error::other("WaitForSingleObject 失败")),
        }
    }

    /// 接收 IPv8+ 帧：RECV_FRAME IOCTL → 去掉 14B 以太网头 → 返回 (payload, src_mac)
    pub(crate) fn recv(&self) -> io::Result<(Vec<u8>, [u8; 6])> {
        let mut buf = [0u8; IPV8_FRAME_MAX];
        buf[0..4].copy_from_slice(&0xFB14u32.to_le_bytes());
        buf[4..8].copy_from_slice(&self.if_index.to_le_bytes());

        let ov = unsafe { l2_overlapped(self.event) };
        let mut out_len: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IPV8_IOCTL_RECV_FRAME,
                buf.as_ptr().cast(),
                IPV8_RECV_IN_LEN as u32,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut out_len,
                ov,
            )
        };
        let total = if ok != 0 {
            out_len as usize
        } else {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err != Some(ERROR_IO_PENDING) {
                return Err(io::Error::other("RECV_FRAME IOCTL 失败"));
            }
            match unsafe { WaitForSingleObject(self.event, 1000) } {
                WAIT_OBJECT_0 => {
                    let mut n: u32 = 0;
                    unsafe { GetOverlappedResult(self.handle, ov, &mut n, 0) };
                    n as usize
                }
                WAIT_TIMEOUT => return Err(io::Error::new(io::ErrorKind::TimedOut, "RECV_FRAME 超时")),
                _ => return Err(io::Error::other("WaitForSingleObject 失败")),
            }
        };

        if total < IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "收到帧太短"));
        }
        let eth_frame = &buf[IPV8_FRAME_HDR_LEN..total];
        // EtherType 校验
        if eth_frame[12] != 0xFB || eth_frame[13] != 0x14 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "EtherType 不是 0xFB14"));
        }
        let src_mac: [u8; 6] = [
            eth_frame[6], eth_frame[7], eth_frame[8],
            eth_frame[9], eth_frame[10], eth_frame[11],
        ];
        let payload = eth_frame[IPV8_ETH_HEADER_LEN..].to_vec();
        Ok((payload, src_mac))
    }

    pub(crate) fn local_mac(&self) -> [u8; 6] { self.local_mac }
}

// ── L2Io 私有辅助 ──

/// 构造 OVERLAPPED 结构（零初始化 + hEvent）
unsafe fn l2_overlapped(event: HANDLE) -> *mut c_void {
    let ov: [u8; 64] = zeroed();
    let p = Box::into_raw(Box::new(ov)) as *mut c_void;
    // OVERLAPPED 偏移 40 处是 hEvent（win64）
    let bytes = std::slice::from_raw_parts_mut(p as *mut u8, 64);
    bytes[..40].fill(0);
    let ev = event as u64;
    bytes[40..48].copy_from_slice(&ev.to_le_bytes());
    p
}

/// 查 driver bindings（返回每张 bound 网卡的 if_index + MAC）
unsafe fn l2_query_bindings(handle: isize) -> io::Result<Vec<L2Binding>> {
    let mut buf = vec![0u8; 4096];
    let mut out_len: u32 = 0;
    let ok = DeviceIoControl(
        handle,
        IPV8_IOCTL_GET_BINDINGS,
        ptr::null(),
        0,
        buf.as_mut_ptr().cast(),
        buf.len() as u32,
        &mut out_len,
        ptr::null_mut(),
    );
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let count = (out_len as usize) / IPV8_BINDING_SIZE;
    let mut bindings = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * IPV8_BINDING_SIZE;
        let bound = buf[off + 12] != 0; // offset 12 是 bound 标志（u32 bool）
        if !bound { continue; }
        let if_index = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let mac: [u8; 6] = buf[off + 16..off + 22].try_into().unwrap();
        bindings.push(L2Binding { if_index, mac });
    }
    Ok(bindings)
}

struct L2Binding {
    if_index: u32,
    mac: [u8; 6],
}

/// 一个收割到的入站完成：槽号 + 字节数 + 对端地址。载荷借用见
/// [`RioRuntime::packet_data`]；处理完必须 [`RioRuntime::repost_recv`]。
#[derive(Clone, Copy, Debug)]
pub(crate) struct RioPacket {
    pub(crate) slot: usize,
    pub(crate) len: usize,
    pub(crate) from: SocketAddr,
}

/// RIO 运行时：拥有 socket、函数表、CQ/RQ、注册缓冲与全部描述符。
/// 创建后以 `Arc` 跨线程共享：RIO 函数表本身线程安全（文档承诺），
/// 发送可从任意线程发起；CQ 收割只允许事件循环线程唯一消费。
pub(crate) struct RioRuntime {
    socket: usize, // SOCKET（windows-sys 中即 usize）
    t: RIO_EXTENSION_FUNCTION_TABLE,
    /// 实机正确 ABI 的 RIOSendEx（10 参，Flags 第 4）—— windows-sys 0.52 绑错为 9 参
    send_ex: RioSendExFn,
    /// 实机正确 ABI 的 RIOReceiveEx（10 参，Flags 第 4）
    recv_ex: RioRecvExFn,
    cq: RIO_CQ,
    rq: RIO_RQ,
    event: HANDLE,
    /// 接收注册缓冲：布局 = [n_recv 个数据槽 | n_recv 个地址槽]，一次锁页。
    recv_buf: Vec<u8>,
    recv_buf_id: RIO_BUFFERID,
    /// 发送注册缓冲：布局 = [n_send 个数据槽 | n_send 个地址槽]。
    /// `UnsafeCell`：发送可从任意线程发起，不同线程经 [`SlotTable`] 抢占到
    /// 互不相交的槽位区间后，在 &self 下直接写各自区间（无数据竞争）；
    /// Send/Sync 已在下方手动声明显式背书。
    send_buf: UnsafeCell<Vec<u8>>,
    send_buf_id: RIO_BUFFERID,
    /// 每槽稳定的 RIO_BUF 描述符（RIO 请求期间地址必须有效，故随结构体存放）。
    recv_data_desc: Vec<RIO_BUF>,
    recv_addr_desc: Vec<RIO_BUF>,
    send_data_desc: Vec<RIO_BUF>,
    send_addr_desc: Vec<RIO_BUF>,
    /// 发送槽位占用表：跨线程 CAS 抢占，完成回收时清位。
    send_slots: SlotTable,
    n_recv: usize,
    n_send: usize,
    is_v6: bool,
    /// 发送完成计数（自检与诊断用）。
    send_completed: std::sync::atomic::AtomicU64,
}

// RIO_RQ/CQ 与完成队列的跨线程使用由 Winsock 文档明确允许（发送可多线程，
// dequeue 单消费者）。socket 句柄与注册缓冲的共享均遵循该模型。
unsafe impl Send for RioRuntime {}
unsafe impl Sync for RioRuntime {}

impl RioRuntime {
    /// 首选规模创建，锁页失败则减半档重试；两档都失败返回错误（交由 Auto 回退）。
    fn create_with_fallback(addr: SocketAddr) -> io::Result<Self> {
        match Self::create(addr, FULL_RECV_SLOTS, FULL_SEND_SLOTS) {
            Ok(rt) => Ok(rt),
            Err(full) => match Self::create(addr, SMALL_RECV_SLOTS, SMALL_SEND_SLOTS) {
                Ok(rt) => {
                    eprintln!(
                        "[rio] 全量锁页失败（{full}），已用减半槽位 {SMALL_RECV_SLOTS}/{SMALL_SEND_SLOTS}"
                    );
                    Ok(rt)
                }
                Err(_small) => Err(full),
            },
        }
    }

    fn create(addr: SocketAddr, n_recv: usize, n_send: usize) -> io::Result<Self> {
        // ① WSA 初始化（进程内一次；std::net 在其他路径也会做，引用计数安全）。
        WSA_START.call_once(|| unsafe {
            let mut data: WSADATA = std::mem::zeroed();
            let rc = WSAStartup(0x0202, &mut data);
            if rc != 0 {
                // 进程级初始化失败时后续 Winsock 全部不可用，直接 abort 合理：
                // 这是环境性致命错误，任何降级路径（含 std UDP）同样起不来。
                panic!("[rio] WSAStartup 失败: {rc}");
            }
        });

        // ② 建 RIO socket 并 bind（族跟随配置地址，与 std 路径一致）。
        let is_v6 = addr.is_ipv6();
        // 显式指定基础 provider（MSAFD），绕开 RSVP/第三方 LSP——
        // 否则 RIO 扩展 IOCTL 直接 WSAEOPNOTSUPP。
        let proto_info = unsafe { find_base_protocol_info(is_v6)? };
        let family = if is_v6 { AF_INET6 } else { AF_INET };
        let socket = unsafe {
            WSASocketW(
                family as i32,
                SOCK_DGRAM,
                IPPROTO_UDP,
                &proto_info,
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO,
            )
        };
        if socket == INVALID_SOCKET {
            return Err(wsa_err("WSASocketW(WSA_FLAG_REGISTERED_IO)"));
        }

        // ③ 取 RIO 扩展函数表。
        // 顺序铁律（mswsock 文档/官方 RIOServer 示例）：必须在 bind 之前对
        // 裸 RIO socket 发此 IOCTL——bind 后再取会得到 WSAEOPNOTSUPP(10045)。
        let table = match unsafe { load_rio_table(socket) } {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    closesocket(socket);
                }
                return Err(e);
            }
        };

        // ④ 完成队列（事件通知）+ 自动复位事件（CQ 非空时 signaled）。
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        // windows-sys 0.52 中 HANDLE = isize，NULL 即 0。
        if event == 0 {
            let e = io::Error::last_os_error();
            unsafe {
                closesocket(socket);
            }
            return Err(io::Error::new(e.kind(), format!("CreateEventW: {e}")));
        }
        // CQ 容量必须 ≥ 在途收发请求总和（每个预投请求占一个完成槽）。
        let cq_entries = (n_recv + n_send) as u32;
        let mut notify = RIO_NOTIFICATION_COMPLETION {
            Type: RIO_EVENT_COMPLETION,
            Anonymous: windows_sys::Win32::Networking::WinSock::RIO_NOTIFICATION_COMPLETION_0 {
                Event: windows_sys::Win32::Networking::WinSock::RIO_NOTIFICATION_COMPLETION_0_0 {
                    EventHandle: event,
                    NotifyReset: 1, // TRUE：事件随 CQ 排空自动复位
                },
            },
        };
        let cq = unsafe { (table.RIOCreateCompletionQueue.unwrap())(cq_entries, &mut notify) };
        // RIO_CQ 是 isize 句柄类型，无效值为 0（不是指针，没有 is_null）。
        if cq == 0 {
            let e = wsa_err("RIOCreateCompletionQueue");
            unsafe {
                CloseHandle(event);
                closesocket(socket);
            }
            return Err(e);
        }

        // ⑤ 注册缓冲（一次性锁页；失败按槽位减半重试）。
        let recv_total = checked_region(n_recv, "recv 注册缓冲")?;
        let send_total = checked_region(n_send, "send 注册缓冲")?;
        let mut recv_buf = vec![0u8; recv_total];
        let mut send_buf = vec![0u8; send_total];
        let recv_buf_id = unsafe {
            (table.RIORegisterBuffer.unwrap())(recv_buf.as_mut_ptr() as PCSTR, recv_total as u32)
        };
        if recv_buf_id == 0 {
            let e = wsa_err("RIORegisterBuffer(recv)");
            unsafe {
                (table.RIOCloseCompletionQueue.unwrap())(cq);
                CloseHandle(event);
                closesocket(socket);
            }
            return Err(e);
        }
        let send_buf_id = unsafe { register_send_buf(&table, send_buf.as_mut_ptr(), send_total as u32) };
        let send_buf_id = match send_buf_id {
            Ok(id) => id,
            Err(e) => {
                unsafe {
                    (table.RIODeregisterBuffer.unwrap())(recv_buf_id);
                    (table.RIOCloseCompletionQueue.unwrap())(cq);
                    CloseHandle(event);
                    closesocket(socket);
                }
                return Err(e);
            }
        };

        // ⑥ 描述符表（偏移 = 数据区在前、地址区在后）。
        let recv_data_desc: Vec<RIO_BUF> = (0..n_recv)
            .map(|i| RIO_BUF {
                BufferId: recv_buf_id,
                Offset: (i * SLOT_CAP) as u32,
                Length: SLOT_CAP as u32,
            })
            .collect();
        let recv_addr_desc: Vec<RIO_BUF> = (0..n_recv)
            .map(|i| RIO_BUF {
                BufferId: recv_buf_id,
                Offset: (n_recv * SLOT_CAP + i * ADDR_CAP) as u32,
                Length: ADDR_CAP as u32,
            })
            .collect();
        let send_data_desc: Vec<RIO_BUF> = (0..n_send)
            .map(|i| RIO_BUF {
                BufferId: send_buf_id,
                Offset: (i * SLOT_CAP) as u32,
                Length: 0, // 每次发送按实际帧长填写
            })
            .collect();
        let send_addr_desc: Vec<RIO_BUF> = (0..n_send)
            .map(|i| RIO_BUF {
                BufferId: send_buf_id,
                Offset: (n_send * SLOT_CAP + i * ADDR_CAP) as u32,
                Length: 0,
            })
            .collect();

        // ⑦ Request queue（CQ 收发共用；SocketContext 不用，传 null）。
        let rq = unsafe {
            (table.RIOCreateRequestQueue.unwrap())(
                socket,
                n_recv as u32,
                1,
                n_send as u32,
                1,
                cq,
                cq,
                ptr::null(),
            )
        };
        if rq == 0 {
            let e = wsa_err("RIOCreateRequestQueue");
            unsafe {
                (table.RIODeregisterBuffer.unwrap())(send_buf_id);
                (table.RIODeregisterBuffer.unwrap())(recv_buf_id);
                (table.RIOCloseCompletionQueue.unwrap())(cq);
                CloseHandle(event);
                closesocket(socket);
            }
            return Err(e);
        }

        // ⑧ bind：函数表/RQ 就绪后再绑定（见上方顺序铁律）。
        // 失败需释放全套 RIO 资源再关 socket（回退 std 还要释放端口）。
        if let Err(e) = unsafe { bind_socket(socket, addr) } {
            unsafe {
                (table.RIODeregisterBuffer.unwrap())(send_buf_id);
                (table.RIODeregisterBuffer.unwrap())(recv_buf_id);
                (table.RIOCloseCompletionQueue.unwrap())(cq);
                CloseHandle(event);
                closesocket(socket);
            }
            return Err(e);
        }

        // 从函数表取出 SendEx/RecvEx 并 transmute 到实机正确的 10 参 ABI
        let send_ex: RioSendExFn = unsafe { std::mem::transmute(table.RIOSendEx.unwrap()) };
        let recv_ex: RioRecvExFn = unsafe { std::mem::transmute(table.RIOReceiveEx.unwrap()) };

        let rt = RioRuntime {
            socket,
            t: table,
            send_ex,
            recv_ex,
            cq,
            rq,
            event,
            recv_buf,
            recv_buf_id,
            send_buf: UnsafeCell::new(send_buf),
            send_buf_id,
            recv_data_desc,
            recv_addr_desc,
            send_data_desc,
            send_addr_desc,
            send_slots: SlotTable::new(n_send),
            n_recv,
            n_send,
            is_v6,
            send_completed: std::sync::atomic::AtomicU64::new(0),
        };

        // ⑨ 预投递全部接收槽（bind 完成后，自环探针与业务包才有处落）。
        for slot in 0..n_recv {
            rt.post_recv(slot).map_err(|e| {
                // 回收由 Drop 统一完成；这里只需返回失败触发上层回退。
                io::Error::new(e.kind(), format!("RIOReceiveEx 预投槽 {slot}: {e}"))
            })?;
        }

        // ⑩ 自环自检：向自身端口发一个探测包并收割，验证全链路真的能通
        // （防止「初始化全成功但收发语义错位」的静默降级）。
        rt.self_check()?;
        Ok(rt)
    }

    /// 阻塞等待 CQ 或 wintun ring 事件任一就绪（事件循环空闲态）。
    /// `tun_event=None`（--no-tun）时只等 CQ。返回仅用于区分系统错误。
    pub(crate) fn wait_io(&self, tun_event: Option<HANDLE>) -> io::Result<()> {
        let rc = unsafe {
            if let Some(h) = tun_event {
                let handles = [h, self.event];
                WaitForMultipleObjects(
                    handles.len() as u32,
                    handles.as_ptr(),
                    0,
                    INFINITE,
                )
            } else {
                let handles = [self.event];
                WaitForMultipleObjects(
                    1,
                    handles.as_ptr(),
                    0,
                    INFINITE,
                )
            }
        };
        if rc == WAIT_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// 事件通知上膛：每次阻塞等待前调用。CQ 已有完成时事件会立即置位，
    /// 因而「排空 → arm → 等待」之间不存在丢唤醒窗口。
    pub(crate) fn arm_notify(&self) -> io::Result<()> {
        let ok = unsafe { (self.t.RIONotify.unwrap())(self.cq) };
        if ok == 0 {
            Err(wsa_err("RIONotify"))
        } else {
            Ok(())
        }
    }

    /// 收割一批完成。发送完成回收发送槽；接收成功产出 [`RioPacket`]，
    /// 接收异常立即重投（槽位不泄漏）。返回入站包数量。
    pub(crate) fn dequeue(&self, out: &mut Vec<RioPacket>) -> io::Result<usize> {
        let mut results: [RIORESULT; DEQUEUE_BATCH] = unsafe { std::mem::zeroed() };
        let n = unsafe {
            (self.t.RIODequeueCompletion.unwrap())(self.cq, results.as_mut_ptr(), DEQUEUE_BATCH as u32)
        };
        if n == u32::MAX {
            return Err(wsa_err("RIODequeueCompletion(RIO_CORRUPT_CQ)"));
        }
        let start = out.len();
        for r in results.iter().take(n as usize) {
            let ctx = r.RequestContext;
            if ctx & CTX_SEND_BIT != 0 {
                let slot = (ctx & !CTX_SEND_BIT) as usize;
                self.send_slots.free(slot);
                self.send_completed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let slot = ctx as usize;
            if r.Status != 0 || r.BytesTransferred == 0 {
                // 异常/空收：立即重投，避免接收槽静默流失。
                self.post_recv(slot)?;
                continue;
            }
            let len = r.BytesTransferred as usize;
            match self.read_remote_addr(slot) {
                Some(from) if len <= SLOT_CAP => out.push(RioPacket { slot, len, from }),
                _ => self.post_recv(slot)?,
            }
        }
        Ok(out.len() - start)
    }

    /// 借读一个接收槽内的数据（帧在注册缓冲内，零拷贝）。
    /// 调用方处理完且不再引用后必须 [`Self::repost_recv`]。
    pub(crate) fn packet_data(&self, pkt: &RioPacket) -> &[u8] {
        let start = pkt.slot * SLOT_CAP;
        // pkt 由本模块产生：slot< n_recv、len≤SLOT_CAP 已在 dequeue 校验。
        &self.recv_buf[start..start + pkt.len]
    }

    /// 重新投递一个已消费的接收槽。
    pub(crate) fn repost_recv(&self, slot: usize) -> io::Result<()> {
        self.post_recv(slot)
    }

    /// 取一个发送槽、拷帧入注册缓冲、写目的地址，发起 RIOSendEx。
    /// 无空槽返回 WouldBlock（调用方按既有「尽力发送，丢弃计数」语义处理）；
    /// 槽位在发送完成收割时回收。
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<()> {
        if buf.len() > SLOT_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("RIO 发送帧超长: {} > {SLOT_CAP}", buf.len()),
            ));
        }
        let slot = self
            .send_slots
            .alloc()
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "RIO 发送槽全忙"))?;

        // 拷贝进注册缓冲（RIO 只接受注册内存；帧本身是调用方的临时 Vec）。
        // 安全性：slot 已被本次调用独占（SlotTable），数据区与地址区和任何
        // 其他在途槽位互不相交；Vec 注册后长度固定、永不 realloc，裸写合法。
        let data_off = slot * SLOT_CAP;
        let addr_off = self.n_send * SLOT_CAP + slot * ADDR_CAP;
        let addr_len = unsafe {
            let base = (*self.send_buf.get()).as_mut_ptr();
            ptr::copy_nonoverlapping(buf.as_ptr(), base.add(data_off), buf.len());
            let region = std::slice::from_raw_parts_mut(base.add(addr_off), ADDR_CAP);
            encode_sockaddr(dest, region)
        };

        // 描述符随结构体可变（&self 下用裸指针写 Length；这些字段只被本次
        // RIOSendEx 读取，单槽单请求，无竞争）。
        unsafe {
            let data_desc = self.send_data_desc.as_ptr().add(slot) as *mut RIO_BUF;
            (*data_desc).Length = buf.len() as u32;
            let addr_desc = self.send_addr_desc.as_ptr().add(slot) as *mut RIO_BUF;
            (*addr_desc).Length = addr_len;

            let ok = (self.send_ex)(
                self.rq,
                self.send_data_desc.as_ptr().add(slot),
                1,
                0,           // Flags（必须是第 4 参）
                ptr::null(), // pLocalAddress
                self.send_addr_desc.as_ptr().add(slot),
                ptr::null(), // pControlContext
                ptr::null(), // pInternalContext
                (CTX_SEND_BIT | slot as u64) as *const c_void, // RequestContext
                ptr::null(), // pfnNotifyCompletion（轮询模式不用）
            );
            if ok == 0 {
                // 发起失败：同步回收槽位（不会有完成事件）。
                self.send_slots.free(slot);
                return Err(wsa_err("RIOSendEx"));
            }
        }
        Ok(())
    }

    /// 预投/重投一个接收槽（ABI 顺序以 Windows SDK mswsock.h 为准：
    /// rq, pData, count, Flags, pLocal, pRemote, pControl, pInternal,
    /// RequestContext, pfnNotifyCompletion）。
    fn post_recv(&self, slot: usize) -> io::Result<()> {
        let ok = unsafe {
            (self.recv_ex)(
                self.rq,
                self.recv_data_desc.as_ptr().add(slot),
                1,
                0, // Flags（必须是第 4 参）
                ptr::null(),
                self.recv_addr_desc.as_ptr().add(slot),
                ptr::null(),
                ptr::null(),
                slot as *const c_void,
                ptr::null(),
            )
        };
        if ok == 0 {
            Err(wsa_err("RIOReceiveEx"))
        } else {
            Ok(())
        }
    }

    /// 读接收槽里 RIO 填回的对端地址（地址区开头；family 由地址字节判定）。
    fn read_remote_addr(&self, slot: usize) -> Option<SocketAddr> {
        let addr_off = self.n_recv * SLOT_CAP + slot * ADDR_CAP;
        let region = &self.recv_buf[addr_off..addr_off + ADDR_CAP];
        decode_sockaddr(region)
    }

    /// 启动自检：向自身绑定端口环回发探测包，2s 内必须同时看到发送完成与
    /// 逐字节一致的接收完成。此刻尚未有任何业务线程收发，收到的只可能是探针。
    fn self_check(&self) -> io::Result<()> {
        let probe = b"IPV8-RIO-SELFCHECK";
        // 发到自身绑定端口的环回地址（族跟随绑定族）。
        let bound = self.local_addr()?;
        let loopback = if self.is_v6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let target = SocketAddr::new(loopback, bound.port());
        self.send_to(probe, target)?;

        let mut packets = Vec::new();
        for _ in 0..2000 {
            packets.clear();
            self.dequeue(&mut packets)?;
            for pkt in packets.drain(..) {
                let data = self.packet_data(&pkt);
                let matched = data == probe;
                self.repost_recv(pkt.slot)?;
                if matched && self.send_completed.load(Ordering::Relaxed) >= 1 {
                    return Ok(());
                }
            }
            unsafe { Sleep(1) };
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RIO 自环自检超时（2s 内未收到自身探测包）",
        ))
    }

    /// 自身绑定地址：getsockname 从内核取回（族/端口以内核实际绑定为准）。
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut buf = [0u8; 128]; // SOCKADDR_STORAGE 尺寸，v4/v6 都装得下
        let mut len = buf.len() as i32;
        let rc = unsafe { getsockname(self.socket, buf.as_mut_ptr() as *mut _, &mut len) };
        if rc != 0 {
            return Err(wsa_err("getsockname"));
        }
        let n = (len as usize).min(buf.len());
        decode_sockaddr(&buf[..n])
            .ok_or_else(|| io::Error::other("getsockname 返回未知地址族"))
    }
}

impl Drop for RioRuntime {
    fn drop(&mut self) {
        unsafe {
            // 顺序：RQ 随 socket 关闭而销毁 → 注销缓冲 → 关 CQ → 关事件 → 关 socket。
            (self.t.RIODeregisterBuffer.unwrap())(self.send_buf_id);
            (self.t.RIODeregisterBuffer.unwrap())(self.recv_buf_id);
            (self.t.RIOCloseCompletionQueue.unwrap())(self.cq);
            CloseHandle(self.event);
            closesocket(self.socket);
        }
    }
}

/// 发送缓冲注册的薄封装（独立函数让 create() 内的 ? 错误处理保持线性）。
unsafe fn register_send_buf(
    table: &RIO_EXTENSION_FUNCTION_TABLE,
    base: *mut u8,
    len: u32,
) -> io::Result<RIO_BUFFERID> {
    let id = (table.RIORegisterBuffer.unwrap())(base as PCSTR, len);
    if id == 0 {
        Err(wsa_err("RIORegisterBuffer(send)"))
    } else {
        Ok(id)
    }
}

/// 无溢出计算 n 个槽位的注册缓冲总长。
fn checked_region(n: usize, what: &str) -> io::Result<usize> {
    n.checked_mul(SLOT_CAP)
        .and_then(|d| d.checked_add(n.checked_mul(ADDR_CAP)?))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{what} 尺寸溢出")))
}

/// bind 的 FFI 包装（地址按目标族手工编 sockaddr 字节，绕开 IN_ADDR 联合体）。
unsafe fn bind_socket(socket: usize, addr: SocketAddr) -> io::Result<()> {
    let mut sa = [0u8; ADDR_CAP];
    let len = encode_sockaddr(addr, &mut sa);
    let rc = wsa_bind(socket, sa.as_ptr() as *const _, len as i32);
    if rc == 0 {
        Ok(())
    } else {
        Err(wsa_err("bind"))
    }
}

/// 枚举 Winsock 协议目录，找出 UDP/IPv4 或 UDP/IPv6 的**基础 provider**
/// （ProtocolChain.ChainLen == 1，即微软 MSAFD，而非 RSVP 等 LSP 分层项）。
///
/// 必须显式选基础 provider 的原因：裸 WSASocketW 传 NULL 协议信息时按目录顺序
/// 选第一个匹配项；若机器装了 LSP（含系统自带的 RSVP QoS 分层），拿到的是
/// 分层 socket，对它发 SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 会返回
/// WSAEOPNOTSUPP(10045)——RIO 扩展只在基础 provider 上实现。
unsafe fn find_base_protocol_info(is_v6: bool) -> io::Result<WSAPROTOCOL_INFOW> {
    let want_family = if is_v6 { AF_INET6 } else { AF_INET };
    // 第一次：NULL 缓冲，WSAEnumProtocolsW 把所需字节数写回 size。
    let mut size = 0u32;
    let _ = WSAEnumProtocolsW(ptr::null(), ptr::null_mut(), &mut size);
    if size == 0 {
        return Err(wsa_err("WSAEnumProtocolsW(探测长度)"));
    }
    let mut buf: Vec<WSAPROTOCOL_INFOW> =
        Vec::with_capacity(size as usize / size_of::<WSAPROTOCOL_INFOW>());
    let n = WSAEnumProtocolsW(ptr::null(), buf.as_mut_ptr(), &mut size);
    if n < 0 {
        return Err(wsa_err("WSAEnumProtocolsW"));
    }
    buf.set_len(n as usize);
    buf.into_iter()
        .find(|p| {
            p.iAddressFamily == want_family as i32
                && p.iSocketType == SOCK_DGRAM
                && p.iProtocol == IPPROTO_UDP
                && p.ProtocolChain.ChainLen == 1
        })
        .ok_or_else(|| {
            io::Error::other(format!(
                "Winsock 目录中找不到 {} UDP 基础 provider（被 LSP 完全接管？）",
                if is_v6 { "IPv6" } else { "IPv4" }
            ))
        })
}

/// WSAIoctl 取 RIO 扩展函数表。
unsafe fn load_rio_table(socket: usize) -> io::Result<RIO_EXTENSION_FUNCTION_TABLE> {
    let mut table: RIO_EXTENSION_FUNCTION_TABLE = std::mem::zeroed();
    table.cbSize = std::mem::size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32;
    let mut bytes = 0u32;
    let rc = WSAIoctl(
        socket,
        SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
        &WSAID_MULTIPLE_RIO as *const GUID as *const c_void,
        std::mem::size_of::<GUID>() as u32,
        &mut table as *mut _ as *mut c_void,
        std::mem::size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32,
        &mut bytes,
        ptr::null_mut::<c_void>() as *mut _,
        None,
    );
    if rc != 0 {
        return Err(wsa_err("WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER)"));
    }
    // 关键函数指针缺失等于平台不支持（正常 Windows 7+ 不会发生）。
    if table.RIOReceiveEx.is_none()
        || table.RIOSendEx.is_none()
        || table.RIODequeueCompletion.is_none()
        || table.RIORegisterBuffer.is_none()
        || table.RIOCreateCompletionQueue.is_none()
        || table.RIOCreateRequestQueue.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RIO 函数表不完整（系统过旧？）",
        ));
    }
    Ok(table)
}

/// 把最近一次 WSA 错误包装成 io::Error（带错误码，供 --rio off 诊断）。
fn wsa_err(ctx: &'static str) -> io::Error {
    let code = unsafe { WSAGetLastError() };
    io::Error::other(format!("{ctx} (WSA {code})"))

}

// =======================================================================
// 纯逻辑：不触 FFI，全部单测覆盖（槽位状态机 / sockaddr 编解码）
// =======================================================================

/// 无锁发送槽位表：每槽一个 AtomicBool，抢占 swap、完成清位。
struct SlotTable {
    used: Vec<AtomicBool>,
}

impl SlotTable {
    fn new(n: usize) -> Self {
        Self {
            used: (0..n).map(|_| AtomicBool::new(false)).collect(),
        }
    }

    /// 找一个空闲槽标记占用，返回槽号；全忙返回 None。
    /// 线性扫描 + swap：槽位仅几十到几百，且竞争只在突发双发时出现，足够。
    fn alloc(&self) -> Option<usize> {
        for (i, b) in self.used.iter().enumerate() {
            // swap 比 CAS 少一次读：false→true 即抢占成功
            if !b.swap(true, Ordering::AcqRel) {
                return Some(i);
            }
        }
        None
    }

    fn free(&self, slot: usize) {
        // 仅允许释放「占用中」的槽；debug 下抓双重回收。
        debug_assert!(self.used[slot].swap(false, Ordering::AcqRel));
    }
}

/// 把 SocketAddr 编码为原生 sockaddr（v4=16B sockaddr_in / v6=28B sockaddr_in6）
/// 写入 `out`（至少 28B），返回写入长度。
fn encode_sockaddr(addr: SocketAddr, out: &mut [u8]) -> u32 {
    match addr {
        SocketAddr::V4(v4) => {
            let oct = v4.ip().octets();
            out[..16].fill(0);
            out[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&oct);
            16
        }
        SocketAddr::V6(v6) => {
            let oct = v6.ip().octets();
            out[..28].fill(0);
            out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            // flowinfo(4..8)=0；地址 8..24；scope_id 24..28=0
            out[8..24].copy_from_slice(&oct);
            28
        }
    }
}

/// 从原生 sockaddr 字节解出 SocketAddr；family 未知/缓冲过短返回 None。
fn decode_sockaddr(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    if family == AF_INET && buf.len() >= 8 {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&buf[4..8]);
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
    } else if family == AF_INET6 && buf.len() >= 24 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&buf[8..24]);
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_table_alloc_covers_all_then_free_reuses() {
        let t = SlotTable::new(4);
        let mut slots = Vec::new();
        for _ in 0..4 {
            slots.push(t.alloc().expect("前 4 次必须有槽"));
        }
        assert!(t.alloc().is_none(), "全占用后 alloc 必须返回 None");
        // 释放的槽必须能被再次分配（且不串槽）
        t.free(slots[2]);
        assert_eq!(t.alloc().expect("回收后立即可用"), 2);
        assert!(t.alloc().is_none());
    }

    #[test]
    fn slot_table_slots_do_not_duplicate_under_contention_shape() {
        // 分配序列不重不漏（模拟多轮 alloc/free 交错）
        let t = SlotTable::new(8);
        let a = t.alloc().unwrap();
        let b = t.alloc().unwrap();
        t.free(a);
        let c = t.alloc().unwrap();
        assert_eq!(c, a, "线性扫描优先复用最低位空槽");
        assert_ne!(b, c);
        t.free(b);
        t.free(c);
        assert_eq!(t.alloc(), Some(0));
        assert_eq!(t.alloc(), Some(1));
    }

    #[test]
    fn sockaddr_v4_roundtrip() {
        let addr: SocketAddr = "203.0.113.7:45700".parse().unwrap();
        let mut buf = [0u8; ADDR_CAP];
        let len = encode_sockaddr(addr, &mut buf);
        assert_eq!(len, 16);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), AF_INET);
        assert_eq!(decode_sockaddr(&buf[..len as usize]), Some(addr));
    }

    #[test]
    fn sockaddr_v6_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut buf = [0u8; ADDR_CAP];
        let len = encode_sockaddr(addr, &mut buf);
        assert_eq!(len, 28);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), AF_INET6);
        assert_eq!(decode_sockaddr(&buf[..len as usize]), Some(addr));
    }

    #[test]
    fn sockaddr_port_is_network_order() {
        let addr: SocketAddr = "10.0.0.1:45700".parse().unwrap();
        let mut buf = [0u8; ADDR_CAP];
        encode_sockaddr(addr, &mut buf);
        // 45700 = 0xB284 → 大端 B2 84
        assert_eq!(&buf[2..4], &[0xB2, 0x84]);
    }

    #[test]
    fn sockaddr_decode_rejects_garbage() {
        assert!(decode_sockaddr(&[]).is_none());
        assert!(decode_sockaddr(&[0, 0, 0, 80]).is_none()); // family 0
        let mut weird = [0u8; ADDR_CAP];
        weird[0] = 99;
        weird[1] = 0;
        assert!(decode_sockaddr(&weird).is_none()); // family 99
    }

    #[test]
    fn would_block_does_not_lose_slot_state() {
        // 全忙返回 None 不改变占用状态；free 后立即恢复可用
        let t = SlotTable::new(1);
        assert_eq!(t.alloc(), Some(0));
        assert!(t.alloc().is_none());
        assert!(t.alloc().is_none());
        t.free(0);
        assert_eq!(t.alloc(), Some(0));
    }
}
