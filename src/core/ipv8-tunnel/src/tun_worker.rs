//! TUN 工作线程模型（v9 §8 铁律的 Phase 1 实现）。
//!
//! 核心规则（与 wintun crate 的同步阻塞 API 对齐）：
//! - 读循环运行在**独立 std::thread**，不进异步运行时；
//! - 每收到一包立即**拷贝为 Vec<u8>**（等价 packet.bytes().to_vec()），
//!   底层缓冲区句柄随即释放归环；
//! - 通过 `std::sync::mpsc` 投递给处理侧（生产形态下由 C# 宿主经
//!   gRPC 流转发，本 crate 保持 runtime 无关）；
//! - 读错误 `Transient` 不退出循环（瞬态错误继续等下一包）；
//! - 关停：调用方 `join_on` 一个唤醒包 —— 读线程处理后检测到
//!   关停标志即退出（阻塞式 read_blocking 的唤醒由真实设备用
//!   wintun session 关闭触发，MockTun 用 channel 关闭触发）。
//!
//! 本模块对 TUN 设备零依赖：设备以 [`TunIo`] trait 注入，
//! 测试用内存队列实现（CI 不碰真实 wintun）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// TUN 设备抽象：同步语义（与 wintun receive_blocking / 写 API 一致）。
/// `read_blocking` 返回 Ok(bytes) 即一包的完整拷贝。
pub trait TunIo: Send {
    /// 阻塞读取一包；`Closed` 表示设备关闭或通道结束，读线程应退出
    fn read_blocking(&mut self) -> Result<Vec<u8>, TunError>;
    /// 写入一包（返回给 OS）
    fn write(&mut self, packet: &[u8]) -> Result<(), TunError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunError {
    /// 设备已关闭，读线程应退出
    Closed,
    /// 瞬态错误，可忽略继续
    Transient,
}

/// 读线程句柄。drop 时自动请求关停并 join。
pub struct TunWorker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TunWorker {
    /// 启动独立读线程：每包先经 `processor`（可转换/丢弃，返回 None 即丢），
    /// 非 None 的结果投递到返回的 Receiver。
    pub fn spawn<F>(mut device: impl TunIo + 'static, processor: F) -> (Self, Receiver<Vec<u8>>)
    where
        F: FnMut(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    {
        let (tx, rx) = channel::<Vec<u8>>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = thread::spawn(move || {
            let mut processor = processor;
            loop {
                if stop_thread.load(Ordering::Relaxed) {
                    break;
                }
                match device.read_blocking() {
                    Ok(raw) => {
                        // ★ 铁律：raw 已是独立拷贝（TunIo 契约），可安全跨线程
                        if let Some(processed) = processor(raw) {
                            if tx.send(processed).is_err() {
                                break; // 接收端关闭 → 退出
                            }
                        }
                    }
                    Err(TunError::Closed) => break,
                    Err(TunError::Transient) => continue, // 不退出，等下一包
                }
            }
        });
        (Self { stop, handle: Some(handle) }, rx)
    }

    /// 请求关停并等待读线程退出（幂等）。
    ///
    /// **设备契约**：若读线程可能正阻塞在 `read_blocking`，调用方必须先
    /// 让设备进入关闭态（wintun：drop session；MockTun：`close()` 哨兵），
    /// 否则本方法会无限 join。正确顺序：`ctl.close()` → `worker.shutdown()`。
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TunWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 内存队列版 TUN（CI 测试用，对应方案 §13 MockTunAdapter 思路）。
/// OS→栈方向用 channel；外部持有 [`MockTunHandle`] 喂包/看写出，
/// 设备本体 move 进读线程。
pub struct MockTun {
    inbound: Receiver<Vec<u8>>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// MockTun 的外部控制句柄（Clone，可多持有者）
#[derive(Clone)]
pub struct MockTunHandle {
    inbound_tx: Sender<Vec<u8>>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockTunHandle {
    /// 模拟 OS 写入 TUN（OS → 协议栈方向）
    pub fn feed_inbound(&self, packet: Vec<u8>) {
        let _ = self.inbound_tx.send(packet);
    }

    /// 模拟 OS 关闭 TUN 设备：投递空哨兵包唤醒阻塞的 read_blocking，
    /// 读线程下一轮 `Ok(空)` → `Err(Closed)` → 退出。
    pub fn close(&self) {
        let _ = self.inbound_tx.send(Vec::new());
    }

    /// 弹出协议栈写回 OS 的包（FIFO）
    pub fn pop_outbound(&self) -> Option<Vec<u8>> {
        let mut q = self.outbound.lock().unwrap();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.lock().unwrap().len()
    }
}

/// 测试专用：读入空包（唤醒哨兵）后转为 Closed
pub struct ClosableMockTun {
    inner: MockTun,
}

impl TunIo for ClosableMockTun {
    fn read_blocking(&mut self) -> Result<Vec<u8>, TunError> {
        self.inner.read_blocking()
    }
    fn write(&mut self, packet: &[u8]) -> Result<(), TunError> {
        self.inner.write(packet)
    }
}

pub fn mock_tun() -> (ClosableMockTun, MockTunHandle) {
    let (tx, rx) = channel();
    let outbound = Arc::new(Mutex::new(Vec::new()));
    (
        ClosableMockTun { inner: MockTun { inbound: rx, outbound: outbound.clone() } },
        MockTunHandle { inbound_tx: tx, outbound },
    )
}

impl TunIo for MockTun {
    fn read_blocking(&mut self) -> Result<Vec<u8>, TunError> {
        match self.inbound.recv() {
            Ok(bytes) if bytes.is_empty() => Err(TunError::Closed), // 空包 = 唤醒哨兵
            Ok(bytes) => Ok(bytes),
            Err(_) => Err(TunError::Closed),
        }
    }

    fn write(&mut self, packet: &[u8]) -> Result<(), TunError> {
        self.outbound.lock().unwrap().push(packet.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn worker_delivers_packets_in_order() {
        let (device, ctl) = mock_tun();
        ctl.feed_inbound(vec![1, 2, 3]);
        ctl.feed_inbound(vec![4, 5]);
        let (worker, rx) = TunWorker::spawn(device, Some);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![1, 2, 3]);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![4, 5]);
        ctl.close();
        worker.shutdown();
    }

    #[test]
    fn transient_errors_do_not_exit() {
        struct Flaky {
            reads: usize,
        }
        impl TunIo for Flaky {
            fn read_blocking(&mut self) -> Result<Vec<u8>, TunError> {
                self.reads += 1;
                match self.reads {
                    1..=3 => Err(TunError::Transient),
                    4 => Ok(vec![0xAA]),
                    _ => Err(TunError::Closed),
                }
            }
            fn write(&mut self, _: &[u8]) -> Result<(), TunError> {
                Ok(())
            }
        }
        let (_w, rx) = TunWorker::spawn(Flaky { reads: 0 }, Some);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![0xAA]);
    }

    #[test]
    fn pipeline_can_drop_packets() {
        struct TwoThenClosed {
            fed: usize,
        }
        impl TunIo for TwoThenClosed {
            fn read_blocking(&mut self) -> Result<Vec<u8>, TunError> {
                self.fed += 1;
                match self.fed {
                    1 => Ok(vec![9]),
                    2 => Ok(vec![8]),
                    _ => Err(TunError::Closed),
                }
            }
            fn write(&mut self, _: &[u8]) -> Result<(), TunError> {
                Ok(())
            }
        }
        let (_w, rx) = TunWorker::spawn(TwoThenClosed { fed: 0 }, |p| {
            if p[0] == 9 {
                None
            } else {
                Some(p)
            }
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), vec![8]);
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "被丢弃的包不应投递");
    }

    #[test]
    fn closed_device_terminates_thread() {
        struct Immediately;
        impl TunIo for Immediately {
            fn read_blocking(&mut self) -> Result<Vec<u8>, TunError> {
                Err(TunError::Closed)
            }
            fn write(&mut self, _: &[u8]) -> Result<(), TunError> {
                Ok(())
            }
        }
        let (w, rx) = TunWorker::spawn(Immediately, Some);
        // 线程退出后 sender 被释放，recv 返回 Err
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_err());
        w.shutdown(); // join 成功 = 线程确实退出
    }

    #[test]
    fn mock_write_collects_outbound() {
        let (mut device, ctl) = mock_tun();
        device.write(&[0xDE, 0xAD]).unwrap();
        assert_eq!(ctl.outbound_len(), 1);
        assert_eq!(ctl.pop_outbound().unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(ctl.pop_outbound(), None);
    }
}
