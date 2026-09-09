namespace IPv8Plus.Abstractions;

/// <summary>
/// TUN 适配器抽象（方案 §13）。CI 用 MockTunAdapter，生产用 WintunAdapter。
/// 实现方保证 ReadAsync 返回的是独立拷贝，可安全跨层传递。
/// </summary>
public interface ITunAdapter : IDisposable
{
    string Name { get; }
    Task<byte[]> ReadAsync(CancellationToken ct = default);
    Task WriteAsync(byte[] packet, CancellationToken ct = default);
    Task StartAsync(CancellationToken ct = default);
    Task StopAsync(CancellationToken ct = default);
}
