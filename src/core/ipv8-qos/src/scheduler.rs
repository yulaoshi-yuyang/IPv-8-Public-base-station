//! 优先级调度（v9 `ipv8-qos/scheduler.rs`）。
//!
//! 4 级严格优先队列（class 3 最高）：`take_next` 永远先出非空最高类的
//! FIFO 头。本轮**只做排序**，不做带宽保证/整形（v9 验收 = "QoS 标记"
//! 的调度语义，速率承诺留给 QoSReservation 的消费端后置）。
//!
//! 类内严格 FIFO 保证同标记包不互相插队；跨类抢占仅在入队时刻生效
//! （已在途的帧不受影响——帧级粒度，与 v9 隧道数据面一致）。

use std::collections::VecDeque;

use crate::classifier::NUM_CLASSES;

/// 有界 4 级优先队列（界 = 每类 cap 个包；满则按最低可容忍类丢弃）
pub struct PriorityScheduler<T> {
    queues: [VecDeque<T>; NUM_CLASSES],
    counts: [usize; NUM_CLASSES],
    cap: usize,
    dropped: u64,
}

impl<T> PriorityScheduler<T> {
    /// `cap` = 单类最大排队包数（部署值：转发 4096 帧/类量级）
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            queues: Default::default(),
            counts: [0; NUM_CLASSES],
            cap,
            dropped: 0,
        }
    }

    /// 入队到调度类 `class`（0..NUM_CLASSES）。该类满则返回 Some(item)
    /// 交还调用方（丢弃语义：RED 简化版，低类先满）。
    pub fn push(&mut self, class: usize, item: T) -> Option<T> {
        let class = class.min(NUM_CLASSES - 1);
        if self.counts[class] >= self.cap {
            self.dropped += 1;
            return Some(item);
        }
        self.queues[class].push_back(item);
        self.counts[class] += 1;
        None
    }

    /// 出队：非空最高优先类的队首。
    pub fn take_next(&mut self) -> Option<T> {
        for class in (0..NUM_CLASSES).rev() {
            if let Some(item) = self.queues[class].pop_front() {
                self.counts[class] -= 1;
                return Some(item);
            }
        }
        None
    }

    /// 当前所有类的排队总数
    pub fn len(&self) -> usize {
        self.counts.iter().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 指定类的排队数（观测/测试用）
    pub fn class_len(&self, class: usize) -> usize {
        self.counts.get(class).copied().unwrap_or(0)
    }

    /// 容量丢弃计数（单调不减）
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl<T> Default for PriorityScheduler<T> {
    fn default() -> Self {
        Self::new(4096)
    }
}
