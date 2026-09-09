using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace IPv8Plus.Adapter.Wintun;

/// <summary>
/// wintun.dll 的 P/Invoke 声明（v9 决策：官方 crate 已封装好，零额外 C 代码；
/// C# 侧只负责【设备生命周期】——创建/删除适配器、开/关 Session。
/// 数据面的收发在 Rust 引擎（wintun crate）内完成，C# 不搬包字节。）
///
/// API 契约来源：wintun.h（https://www.wintun.net）——以下签名与其逐字段一致。
/// </summary>
[SupportedOSPlatform("windows")]
internal static class NativeWintun
{
    private const string Dll = "wintun";

    // 注：WINTUN_CREATE_ADAPTER_OPTIONS（当前版本仅含保留字段）传 NULL，
    // 由安装程序决定驱动类型，故此处不声明该结构体。

    [DllImport(Dll, EntryPoint = "WintunCreateAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunCreateAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
        [MarshalAs(UnmanagedType.LPWStr)] string? requestedGuid);

    [DllImport(Dll, EntryPoint = "WintunDeleteAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WintunDeleteAdapter(IntPtr adapter, [MarshalAs(UnmanagedType.Bool)] bool forceDeletion, out int rebootRequired);

    [DllImport(Dll, EntryPoint = "WintunOpenSession", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunOpenSession(IntPtr adapter, [MarshalAs(UnmanagedType.LPWStr)] string sessionName);

    [DllImport(Dll, EntryPoint = "WintunStartSession", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WintunStartSession(IntPtr session, uint capacity);

    [DllImport(Dll, EntryPoint = "WintunEndSession", CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunEndSession(IntPtr session);

    [DllImport(Dll, EntryPoint = "WintunCloseSession", CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunCloseSession(IntPtr session);

    [DllImport(Dll, EntryPoint = "WintunCloseAdapter", CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(Dll, EntryPoint = "WintunGetAdapterLuid", CallingConvention = CallingConvention.StdCall)]
    public static extern long WintunGetAdapterLuid(IntPtr adapter);
}

/// <summary>
/// wintun 设备句柄（IDisposable）。仅管理生命周期：
/// Create → (Rust 侧 open/start session 收发包) → EndSession/Close → Delete。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WintunDevice : IDisposable
{
    public const uint DefaultRingCapacity = 0x400000; // 4 MiB，方案推荐值

    private IntPtr _adapter;
    private bool _disposed;

    public string Name { get; }

    /// <exception cref="WintunException">非管理员或 wintun.dll 缺失时抛出。</exception>
    public WintunDevice(string name = "IPv8Plus", string tunnelType = "IPv8Plus Tunnel")
    {
        Name = name;
        _adapter = NativeWintun.WintunCreateAdapter(name, tunnelType, null);
        if (_adapter == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            throw new WintunException($"WintunCreateAdapter 失败 (Win32 {err})。" +
                "请确认以管理员运行且 wintun.dll 可加载。", err);
        }
    }

    /// <summary>打开一个命名 Session（返回裸句柄，交给 Rust 引擎持有使用）。</summary>
    public IntPtr OpenSession(string sessionName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var session = NativeWintun.WintunOpenSession(_adapter, sessionName);
        if (session == IntPtr.Zero)
        {
            throw new WintunException($"WintunOpenSession('{sessionName}') 失败", Marshal.GetLastWin32Error());
        }
        return session;
    }

    public static void StartSession(IntPtr session, uint ringCapacity = DefaultRingCapacity)
    {
        if (!NativeWintun.WintunStartSession(session, ringCapacity))
        {
            throw new WintunException("WintunStartSession 失败", Marshal.GetLastWin32Error());
        }
    }

    public static void EndSession(IntPtr session) => NativeWintun.WintunEndSession(session);
    public static void CloseSession(IntPtr session) => NativeWintun.WintunCloseSession(session);

    /// <summary>删除虚拟网卡（forceDeletion=true 即使有进程引用）。</summary>
    public void DeleteAdapter(bool forceDeletion = true)
    {
        if (_disposed) return;
        if (!NativeWintun.WintunDeleteAdapter(_adapter, forceDeletion, out var reboot))
        {
            throw new WintunException($"WintunDeleteAdapter 失败 (rebootRequired={reboot})", Marshal.GetLastWin32Error());
        }
        Dispose();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_adapter != IntPtr.Zero)
        {
            NativeWintun.WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }
    }
}

public sealed class WintunException : Exception
{
    public int Win32Error { get; }
    public WintunException(string message, int win32Error) : base(message) => Win32Error = win32Error;
}
