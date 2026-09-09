namespace IPv8Plus.Abstractions;

/// <summary>
/// QoS 调度抽象（v9 Phase 3 · 铁律 1：接口先行）。
/// 与 Rust 引擎 ipv8-qos 的 4 级语义对齐：QoS Level 0-15 → 类 = level/4，
/// 严格优先 + 类内 FIFO，仅排序、不做带宽保证。
/// Host 侧实现负责在隧道出队路径上消费；Rust 引擎侧独立自测。
/// </summary>
public interface IQoSScheduler
{
    /// <summary>调度类数（4）。</summary>
    static int NumClasses => 4;

    /// <summary>基头 QoS Level（0-15）→ 调度类（0-3）。</summary>
    static int ClassOfLevel(int qosLevel) =>
        Math.Clamp(qosLevel >> 2, 0, NumClasses - 1);

    /// <summary>入队；类满返回 false（调用方执行丢弃语义）。</summary>
    bool TryEnqueue(int cls, byte[] frame);

    /// <summary>出队：非空最高优先类的队首；全空返回 null。</summary>
    byte[]? DequeueNext();

    /// <summary>因容量丢弃的帧计数（诊断用，单调不减）。</summary>
    long DroppedCount { get; }
}
