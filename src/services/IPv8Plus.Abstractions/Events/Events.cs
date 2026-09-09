namespace IPv8Plus.Abstractions.Events;

/// <summary>事件基类：同层模块间只经事件总线通信（铁律 2）。</summary>
public abstract record ModuleEvent
{
    /// <summary>事件发生时间（UTC）。</summary>
    public DateTimeOffset OccurredAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>TUN 收到一个待封装的 IP 包。</summary>
public sealed record PacketReceivedEvent(byte[] RawPacket) : ModuleEvent;

/// <summary>与某对端的隧道已建立（握手完成）。</summary>
public sealed record TunnelEstablishedEvent(string PeerAddrText, ulong InitialEpoch) : ModuleEvent;

/// <summary>DNS 代理拦截到一个 .ipv8.net 查询。</summary>
public sealed record DnsInterceptedEvent(string QueryName) : ModuleEvent;

/// <summary>隧道路径失败，已切换到降级路径（Level: 1 备用入口 / 2 明文 TCP / 3 明文 UDP）。</summary>
public sealed record FallbackTriggeredEvent(string PeerAddrText, int Level, string Reason) : ModuleEvent;
