using IPv8Plus.Abstractions;
using Microsoft.Extensions.Options;

namespace IPv8Plus.Host;

/// <summary>
/// QoS 调度宿主服务（v9 Phase 3 · QoSManagerService）。
///
/// 职责边界（铁律 2：事件驱动）：
/// - 本类是 <see cref="IQoSScheduler"/> 的宿主实现，维护 4 级出队队列，
///   隧道引擎（Rust 经 gRPC）推送来的帧按 <see cref="IQoSScheduler.ClassOfLevel"/>
///   分类入队，宿主消费端按优先级出队写 TUN；
/// - 不做带宽保证/整形（本轮仅排序语义，与 Rust ipv8-qos 一致）。
///
/// 包 = (QoS 类, 帧字节)。实现为无锁通道之上的简单优先聚合。
/// </summary>
public sealed class QoSManagerService : IQoSScheduler
{
    private readonly object _gate = new();
    private readonly Queue<byte[]>[] _classes;
    private long _dropped;
    private readonly int _classCap;

    public QoSManagerService(IOptions<ClientOptions> options)
    {
        _classCap = Math.Max(1, options.Value.QoSClassCapacity);
        _classes = new Queue<byte[]>[IQoSScheduler.NumClasses];
        for (int i = 0; i < IQoSScheduler.NumClasses; i++)
        {
            _classes[i] = new Queue<byte[]>();
        }
    }

    /// <inheritdoc />
    public bool TryEnqueue(int cls, byte[] frame)
    {
        if (cls < 0 || cls >= IQoSScheduler.NumClasses)
        {
            throw new ArgumentOutOfRangeException(nameof(cls), $"调度类必须在 0..{IQoSScheduler.NumClasses - 1}");
        }

        lock (_gate)
        {
            if (_classes[cls].Count >= _classCap)
            {
                _dropped++;
                return false;
            }

            _classes[cls].Enqueue(frame);
            return true;
        }
    }

    /// <inheritdoc />
    public byte[]? DequeueNext()
    {
        lock (_gate)
        {
            for (int cls = IQoSScheduler.NumClasses - 1; cls >= 0; cls--)
            {
                if (_classes[cls].Count > 0)
                {
                    return _classes[cls].Dequeue();
                }
            }
        }

        return null;
    }

    /// <inheritdoc />
    public long DroppedCount
    {
        get
        {
            lock (_gate)
            {
                return _dropped;
            }
        }
    }

    /// <summary>当前全部排队帧数（观测/测试用）。</summary>
    public int Backlog
    {
        get
        {
            lock (_gate)
            {
                int n = 0;
                foreach (var q in _classes)
                {
                    n += q.Count;
                }

                return n;
            }
        }
    }
}
