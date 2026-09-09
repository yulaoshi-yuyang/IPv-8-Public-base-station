using System.Threading.Channels;
using IPv8Plus.Abstractions;

namespace IPv8Plus.Services.Tests;

/// <summary>内存队列模拟 TUN 设备（方案 §13 MockTunAdapter：CI 不碰真实 TUN）。</summary>
public sealed class MockTunAdapter : ITunAdapter
{
    private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>();
    private readonly Channel<byte[]> _outbound = Channel.CreateUnbounded<byte[]>();
    private bool _disposed;

    public string Name => "MockTUN";

    /// <summary>测试侧：模拟 OS 写入 TUN</summary>
    public void FeedInbound(byte[] packet) => _inbound.Writer.TryWrite(packet);

    /// <summary>测试侧：弹出协议栈写回 OS 的包</summary>
    public Task<byte[]> ReadOutboundAsync(CancellationToken ct = default)
        => _outbound.Reader.ReadAsync(ct).AsTask();

    public Task<byte[]> ReadAsync(CancellationToken ct = default)
        => _inbound.Reader.ReadAsync(ct).AsTask();

    public Task WriteAsync(byte[] packet, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _outbound.Writer.WriteAsync((byte[])packet.Clone(), ct).AsTask(); // 拷贝语义契约
    }

    public Task StartAsync(CancellationToken ct = default) => Task.CompletedTask;

    public Task StopAsync(CancellationToken ct = default)
    {
        _inbound.Writer.TryComplete();
        _outbound.Writer.TryComplete();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopAsync().Wait(TimeSpan.FromSeconds(1));
    }
}
