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
use std::time::{Duration, Instant};

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
    /// `Off` 只走 std。L2 模式按 `l2_peer_v4` 选同子网 bound 网卡（多网卡机），
    /// 传 None 或匹配不到时回退第一张并打印警告。
    pub(crate) fn bind(
        addr: SocketAddr,
        mode: RioMode,
        l2_peer_v4: Option<Ipv4Addr>,
    ) -> io::Result<Self> {
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
                let l2 = L2Io::bind(l2_peer_v4)?;
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
const IPV8_BINDINGS_HDR_LEN: usize = 16; // Magic/Total/Count/Reserved
const IPV8_DRIVER_MAGIC: u32 = 0x0000_FB14;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const ERROR_IO_PENDING: i32 = 997;
const ERROR_OPERATION_ABORTED: i32 = 995;
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
    fn CancelIoEx(hfile: isize, lpoverlapped: *mut c_void) -> i32;
}

/// L2 传输层：经 ipv8proto.sys IOCTL 收发 0xFB14 以太网帧
pub(crate) struct L2Io {
    handle: isize,
    // send/recv 在不同线程并发，event 必须分开；共用一个会导致一方完成
    // 唤醒另一方等待（P8 真机 2026-10-14 抓到：recv 孤儿 IRP 完成事件打醒发送）。
    send_event: HANDLE,
    recv_event: HANDLE,
    if_index: u32,
    local_mac: [u8; 6],
    /// 对端 MAC（None=广播，或运行时 set）
    peer_mac: std::sync::Mutex<Option<[u8; 6]>>,
}

impl L2Io {
    /// 打开驱动 + 选卡绑定。多网卡机按对端 IPv4 同子网选卡（peer 的 underlay
    /// IP 已知）；无提示或匹配不到时回退驱动枚举的第一张 bound 网卡并警告。
    pub(crate) fn bind(peer_v4: Option<Ipv4Addr>) -> io::Result<Self> {
        // CreateFileW: GENERIC_READ|GENERIC_WRITE (0xC0000000), FILE_SHARE_READ|WRITE (3), OPEN_EXISTING (3)
        let wide: Vec<u16> = IPV8_DRIVER_PATH.encode_utf16().chain([0]).collect();
        let handle = unsafe {
            CreateFileW(wide.as_ptr(), 0xC000_0000, 3, ptr::null(), 3, FILE_FLAG_OVERLAPPED, 0)
        };
        if handle == -1 {
            return Err(io::Error::last_os_error());
        }
        let send_event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if send_event == 0 {
            unsafe { CloseHandle(handle) };
            return Err(io::Error::last_os_error());
        }
        let recv_event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if recv_event == 0 {
            unsafe {
                CloseHandle(send_event);
                CloseHandle(handle);
            }
            return Err(io::Error::last_os_error());
        }
        // 查 bindings，按对端 IPv4 同子网选卡，回退第一张
        let bindings = unsafe { l2_query_bindings(handle) };
        if bindings.is_err() {
            unsafe {
                CloseHandle(recv_event);
                CloseHandle(send_event);
                CloseHandle(handle);
            }
            return Err(bindings.err().unwrap());
        }
        let bindings = bindings.unwrap();
        if bindings.is_empty() {
            unsafe {
                CloseHandle(recv_event);
                CloseHandle(send_event);
                CloseHandle(handle);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "ipv8proto.sys 已安装但无网卡 bound",
            ));
        }
        let binding = match peer_v4.and_then(|peer| l2_pick_by_subnet(&bindings, peer)) {
            Some(b) => {
                println!("[l2] 按对端 {peer_v4:?} 同子网选中 if#{}", b.if_index);
                b
            }
            None => {
                let fallback = bindings[0].clone();
                eprintln!(
                    "[l2] 未能按对端子网定位网卡（peer_v4={peer_v4:?}，{} 张 bound 卡），\
                     回退第一张 if#{} local_mac={:02x?}——多网卡环境若该卡不在对端网段将无法互通",
                    bindings.len(),
                    fallback.if_index,
                    fallback.mac
                );
                fallback
            }
        };
        Ok(Self {
            handle,
            send_event,
            recv_event,
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
        // 16B IPV8_FRAME_HDR（Magic/IfIndex/FrameLen/Reserved）+ 14B 以太头 + payload。
        // FrameLen 是驱动硬校验字段（driver-ctl.c IPv8IoctlSend：<14 或 >1514 直接
        // STATUS_INVALID_PARAMETER），权威范本：ipv8-client 注入路径 buf[8..12]=frame.len()。
        let frame = l2_build_send_frame(self.if_index, dst_mac, buf);

        let ov = unsafe { l2_overlapped(self.send_event) };
        let _guard = OvGuard(ov); // 任何出口都必须回收 OVERLAPPED
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
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING) {
            return Err(io::Error::other("SEND_FRAME IOCTL 失败"));
        }
        // PENDING：等到 SendComplete；超时必须 CancelIoEx 让 IRP 落地，
        // 否则 IRP 孤儿化（占 TX inflight 节点）且完成事件会打醒后续等待。
        unsafe { l2_await(self.handle, self.send_event, ov, 2000) }
            .map(|_| ())
            .map_err(|e| {
                if e.kind() == io::ErrorKind::TimedOut {
                    io::Error::new(io::ErrorKind::TimedOut, "SEND_FRAME 超时")
                } else {
                    e
                }
            })
    }

    /// 接收 IPv8+ 帧：RECV_FRAME IOCTL → 去掉 14B 以太网头 → 返回 (payload, src_mac)
    pub(crate) fn recv(&self) -> io::Result<(Vec<u8>, [u8; 6])> {
        let mut buf = [0u8; IPV8_FRAME_MAX];
        buf[0..4].copy_from_slice(&0xFB14u32.to_le_bytes());
        buf[4..8].copy_from_slice(&self.if_index.to_le_bytes());

        let ov = unsafe { l2_overlapped(self.recv_event) };
        let _guard = OvGuard(ov);
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
            if io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING) {
                return Err(io::Error::other("RECV_FRAME IOCTL 失败"));
            }
            // PENDING：无帧时驱动把 IRP 挂 CSQ；超时按驱动契约 CancelIoEx
            // （driver-ctl.c：内核不实现超时，取消经 CSQ CompleteCanceledIrp 回完）。
            // 不取消会让 IRP 永久排队，后续帧 FIFO 完成给无人等待的旧 IRP——
            // 表现为 Rx 计数增长但 recv 全超时（P8 真机 2026-10-14 抓到）。
            match unsafe { l2_await(self.handle, self.recv_event, ov, 1000) } {
                Ok(n) => n as usize,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "RECV_FRAME 超时"));
                }
                Err(e) => return Err(e),
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

impl Drop for L2Io {
    fn drop(&mut self) {
        // 关句柄触发驱动 CLEANUP，回完本句柄全部挂起 IRP（CSQ ByFileObject 匹配）。
        // 前提：调用方已停收发线程；进程退出场景由 OS 兜底。
        unsafe {
            CloseHandle(self.recv_event);
            CloseHandle(self.send_event);
            CloseHandle(self.handle);
        }
    }
}

// ── L2Io 私有辅助 ──

/// 纯函数：构造 SEND_FRAME 输入缓冲 = 16B IPV8_FRAME_HDR + 14B 以太头 + payload。
/// 布局锁死（driver.h IPV8_FRAME_HDR，#pragma pack(1)）：
/// magic@0 ifindex@4 **framelen@8** reserved@12；以太头 dst@16 src@22 ethertype@28。
/// src MAC 留零由驱动覆写。曾因漏掉 FrameLen 字段（12B 头 + 以太头整体错位 4B）
/// 导致驱动 STATUS_INVALID_PARAMETER——P8 真机验收 2026-10-14 抓到。
fn l2_build_send_frame(if_index: u32, dst_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let frame_len = (IPV8_ETH_HEADER_LEN + payload.len()) as u32;
    let mut frame = Vec::with_capacity(IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN + payload.len());
    frame.extend_from_slice(&0xFB14u32.to_le_bytes()); // Magic
    frame.extend_from_slice(&if_index.to_le_bytes());
    frame.extend_from_slice(&frame_len.to_le_bytes()); // FrameLen（驱动硬校验 14..=1514）
    frame.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&[0u8; 6]); // src MAC（驱动覆写）
    frame.push(0xFB);
    frame.push(0x14); // EtherType 0xFB14
    frame.extend_from_slice(payload);
    frame
}

/// 构造 OVERLAPPED 结构（零初始化 + hEvent）
unsafe fn l2_overlapped(event: HANDLE) -> *mut c_void {
    let ov: [u8; 64] = zeroed();
    let p = Box::into_raw(Box::new(ov)) as *mut c_void;
    // win64 OVERLAPPED：Internal@0(8) InternalHigh@8(8) Offset/Pointer@16(8) hEvent@24(8)，共 32B。
    // 曾误写偏移 40，event 永不置位：每个 PENDING IRP 走满超时+取消等待，
    // 取消不消耗驱动队列帧导致积压暴发与重放窗丢弃——P8 真机 2026-10-14 第八轮抓到。
    let bytes = std::slice::from_raw_parts_mut(p as *mut u8, 64);
    let ev = event as u64;
    bytes[24..32].copy_from_slice(&ev.to_le_bytes());
    p
}

/// 回收 l2_overlapped 分配的 64B OVERLAPPED（IRP 已落地后才可 drop）。
unsafe fn l2_free_overlapped(ov: *mut c_void) {
    drop(Box::from_raw(ov as *mut [u8; 64]));
}

/// RAII：任何返回路径（含校验失败）都回收 OVERLAPPED。
struct OvGuard(*mut c_void);
impl Drop for OvGuard {
    fn drop(&mut self) {
        unsafe { l2_free_overlapped(self.0) };
    }
}

/// 等待已确认 ERROR_IO_PENDING 的 overlapped 请求。
/// 超时 → CancelIoEx → 等取消落地 → GetOverlappedResult 终裁：
/// 取消与完成竞态时，帧抢先完成算成功；ERROR_OPERATION_ABORTED 算超时。
/// 驱动契约（driver-ctl.c 行 407-409）：内核无超时，挂起 IRP 只能由
/// CancelIoEx / CLEANUP / 卸载回完，不允许用户态撒手不管。
unsafe fn l2_await(
    handle: isize,
    event: HANDLE,
    ov: *mut c_void,
    timeout_ms: u32,
) -> io::Result<u32> {
    let wait = WaitForSingleObject(event, timeout_ms);
    if wait == WAIT_OBJECT_0 {
        let mut n: u32 = 0;
        return if GetOverlappedResult(handle, ov, &mut n, 0) != 0 {
            Ok(n)
        } else {
            Err(io::Error::last_os_error())
        };
    }
    // WAIT_FAILED 也走取消兜底，避免 IRP 孤儿化
    if wait != WAIT_TIMEOUT {
        CancelIoEx(handle, ov);
        WaitForSingleObject(event, 2000);
        return Err(io::Error::other("WaitForSingleObject 失败"));
    }
    CancelIoEx(handle, ov);
    // 等 CSQ CompleteCanceledIrp / 抢先完成把 event 置位
    WaitForSingleObject(event, 2000);
    let mut n: u32 = 0;
    if GetOverlappedResult(handle, ov, &mut n, 0) != 0 {
        return Ok(n); // 竞态：帧在取消生效前完成
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(ERROR_OPERATION_ABORTED) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "overlapped 超时已取消"))
        }
        code => Err(io::Error::other(format!(
            "overlapped 取消后异常 (os error {code:?})"
        ))),
    }
}

#[derive(Clone)]
struct L2Binding {
    /// 驱动自编号（非 Windows InterfaceIndex；SEND/RECV 帧头用它选适配器）
    if_index: u32,
    mac: [u8; 6],
}

/// GET_BINDINGS 输出头：Magic(4) Total(4) Count(4) Reserved(4) = 16B。
/// entry 布局（v0.10，pack(1) 180B，与 driver-ctl.c / ipv8-client 对齐）：
/// rx@0 tx@8 rxdrop@16 txdrop@24 bound@32 ifindex@36 mac@40 pad@46
/// namechars@48 name@52。5A 时代是无头部 144B 旧 ABI，曾导致 node 恒报
/// "无网卡 bound"——P8 真机验收 2026-10-14 抓到。
unsafe fn l2_query_bindings(handle: isize) -> io::Result<Vec<L2Binding>> {
    let mut buf = vec![0u8; 64 * 1024];
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
    if (out_len as usize) < IPV8_BINDINGS_HDR_LEN
        || u32::from_le_bytes(buf[0..4].try_into().unwrap()) != IPV8_DRIVER_MAGIC
    {
        return Err(io::Error::other(
            "绑定响应格式无效（驱动版本过旧？需要 ipv8proto.sys v0.10+）",
        ));
    }
    let count = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
    let mut bindings = Vec::with_capacity(count);
    for i in 0..count {
        let base = IPV8_BINDINGS_HDR_LEN + i * IPV8_BINDING_SIZE;
        if base + IPV8_BINDING_SIZE > out_len as usize {
            break;
        }
        if u32::from_le_bytes(buf[base + 32..base + 36].try_into().unwrap()) == 0 {
            continue; // 解绑中
        }
        let if_index = u32::from_le_bytes(buf[base + 36..base + 40].try_into().unwrap());
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[base + 40..base + 46]);
        bindings.push(L2Binding { if_index, mac });
    }
    Ok(bindings)
}

/// 枚举本机 Up 适配器的（MAC, IPv4, 前缀长度）。只做 L2 选卡，任何失败返回空表，
/// 调用方按"选不到就回退第一张"处理——FFI 异常不得阻断隧道启动。
unsafe fn l2_enum_adapters_v4() -> Vec<([u8; 6], Ipv4Addr, u8)> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    // IF_OPER_STATUS_UP：windows-sys 0.52 未导出该枚举名，SDK 字面值为 1（类型 i32）
    const IF_OPER_STATUS_UP: i32 = 1;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut len: u32 = 16 * 1024;
    let mut raw = vec![0u8; len as usize];
    let mut ret = GetAdaptersAddresses(
        AF_INET as u32,
        flags,
        ptr::null(),
        raw.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
        &mut len,
    );
    if ret == ERROR_BUFFER_OVERFLOW {
        raw = vec![0u8; len as usize];
        ret = GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            ptr::null(),
            raw.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
            &mut len,
        );
    }
    if ret != ERROR_SUCCESS {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut adapter = raw.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        let mac_len = (*adapter).PhysicalAddressLength as usize;
        if (*adapter).OperStatus == IF_OPER_STATUS_UP && mac_len == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&(&(*adapter).PhysicalAddress)[..6]);
            let mut ua = (*adapter).FirstUnicastAddress;
            while !ua.is_null() {
                let sa = (*ua).Address.lpSockaddr as *const SOCKADDR_IN;
                if !sa.is_null() && (*sa).sin_family == AF_INET {
                    // S_addr 网络字节序（大端），转 host 后与 u32::from(Ipv4Addr) 同序
                    let ip = Ipv4Addr::from(u32::from_be((*sa).sin_addr.S_un.S_addr));
                    out.push((mac, ip, (*ua).OnLinkPrefixLength));
                }
                ua = (*ua).Next;
            }
        }
        adapter = (*adapter).Next;
    }
    out
}

/// 在驱动 bound 卡里选一张本机 IPv4 与 peer 同子网的。同 MAC 多地址任一匹配即可。
fn l2_pick_by_subnet(bindings: &[L2Binding], peer: Ipv4Addr) -> Option<L2Binding> {
    let adapters = unsafe { l2_enum_adapters_v4() };
    bindings
        .iter()
        .find(|b| {
            adapters.iter().any(|(mac, ip, prefix)| {
                *mac == b.mac && l2_same_subnet(*ip, peer, *prefix)
            })
        })
        .cloned()
}

/// 同子网判定（纯函数）。prefix 异常按 /32 收紧，绝不放宽。
fn l2_same_subnet(ip: Ipv4Addr, peer: Ipv4Addr, prefix: u8) -> bool {
    if prefix >= 32 {
        return ip == peer;
    }
    let mask = u32::MAX << (32 - prefix);
    u32::from(ip) & mask == u32::from(peer) & mask
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
    /// 首选规模创建：自检超时直接失败；锁页类失败则减半档重试；
    /// 都失败返回错误（交由 Auto 回退）。
    fn create_with_fallback(addr: SocketAddr) -> io::Result<Self> {
        match Self::create(addr, FULL_RECV_SLOTS, FULL_SEND_SLOTS) {
            Ok(rt) => Ok(rt),
            // 自检超时 = RIO 收发语义在此环境不通，减半槽位不可能改变收发
            // 结果，重试只是再等一个超时——直接返回触发 std 回退。
            Err(full) if full.kind() == io::ErrorKind::TimedOut => Err(full),
            // 其余错误（典型：全量锁页内存不足）才值得用减半槽位兜底。
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

        // 超时以墙上时钟为唯一依据，禁止用「轮数 × Sleep(1)」折算时间：
        // 默认系统时钟粒度约 15.6ms（Hyper-V 虚拟机里 Sleep(1) 常常实睡
        // ~15ms），固定 2000 轮会膨胀到 ~30s；full/small 两次 create 叠加
        // ~60s，启动即被卡一分钟，握手与数据面全部推迟。环回探针通常在
        // send_to 返回后首次 dequeue 立即可见，只有失败路径才走等待。
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut packets = Vec::new();
        loop {
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
            if Instant::now() >= deadline {
                break;
            }
            // 让出时间片即可；deadline 兜底，Sleep 的实际粒度不影响超时语义。
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
        // 总是释放；debug 下额外抓双重回收（swap 返回之前的值=是否曾占用）。
        let was_used = self.used[slot].swap(false, Ordering::AcqRel);
        debug_assert!(was_used, "双重回收槽位 {slot}");
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
    fn l2_same_subnet_masks_by_prefix() {
        let ip = Ipv4Addr::new(192, 168, 200, 2);
        // /24：主路径对端同段
        assert!(l2_same_subnet(ip, Ipv4Addr::new(192, 168, 200, 1), 24));
        // uplink 段对 peer 必须判异（B 机选错卡的根因场景）
        assert!(!l2_same_subnet(
            Ipv4Addr::new(172, 23, 19, 188),
            Ipv4Addr::new(192, 168, 200, 1),
            24
        ));
        // /16 跨段判异
        assert!(!l2_same_subnet(
            Ipv4Addr::new(192, 168, 201, 2),
            Ipv4Addr::new(192, 168, 200, 1),
            24
        ));
        // /32 与异常前缀（>32）收紧为严格相等
        assert!(!l2_same_subnet(ip, Ipv4Addr::new(192, 168, 200, 1), 32));
        assert!(l2_same_subnet(ip, ip, 32));
        assert!(!l2_same_subnet(ip, Ipv4Addr::new(192, 168, 200, 1), 33));
    }

    #[test]
    fn l2_build_send_frame_abi_layout() {
        // 锁死 SEND_FRAME ABI（driver.h IPV8_FRAME_HDR）：少写 FrameLen 会让
        // 驱动 STATUS_INVALID_PARAMETER，真机表现为首发即"SEND_FRAME IOCTL 失败"。
        let payload = vec![0xAAu8; 100];
        let dst = [0x00, 0x15, 0x5D, 0x83, 0xB5, 0x11];
        let f = l2_build_send_frame(2, dst, &payload);

        assert_eq!(f.len(), IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN + 100);
        assert_eq!(&f[0..4], 0xFB14u32.to_le_bytes()); // Magic
        assert_eq!(&f[4..8], 2u32.to_le_bytes()); // IfIndex
        assert_eq!(&f[8..12], (IPV8_ETH_HEADER_LEN as u32 + 100).to_le_bytes()); // FrameLen
        assert_eq!(&f[12..16], 0u32.to_le_bytes()); // Reserved
        assert_eq!(&f[16..22], &dst); // 以太头 dst
        assert_eq!(&f[22..28], &[0u8; 6]); // src 留零，驱动覆写
        assert_eq!(&f[28..30], &[0xFB, 0x14]); // EtherType
        assert_eq!(&f[30..130], &payload[..]);
        // 最小 payload：FrameLen=14 恰好过驱动下界
        let fmin = l2_build_send_frame(1, [0xFF; 6], &[]);
        assert_eq!(&fmin[8..12], 14u32.to_le_bytes());
        assert_eq!(fmin.len(), IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN);
    }

    #[test]
    fn l2_overlapped_hevent_offset_24() {
        // 锁死 win64 OVERLAPPED ABI：hEvent 在偏移 24（Internal/InternalHigh/Pointer 各 8B）。
        // 误写偏移 40 时 event 永不置位，PENDING IRP 全部走满超时+取消路径。
        let fake_event = 0x1234_5678_9ABC_DEF0u64 as isize;
        let ov = unsafe { l2_overlapped(fake_event) };
        let bytes = unsafe { std::slice::from_raw_parts(ov as *const u8, 64) };
        assert_eq!(&bytes[24..32], fake_event.to_le_bytes());
        // 偏移 40（历史错误值）必须保持为 0，其余字段全零
        assert_eq!(&bytes[40..48], &[0u8; 8]);
        assert_eq!(&bytes[0..24], &[0u8; 24]);
        assert_eq!(&bytes[32..64], &[0u8; 32]);
        unsafe { l2_free_overlapped(ov) };
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
