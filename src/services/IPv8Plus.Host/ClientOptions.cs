namespace IPv8Plus.Host;

/// <summary>appsettings.json 的 "Client" 节（铁律 3：配置外部化，零硬编码）。</summary>
public sealed class ClientOptions
{
    public const string Section = "Client";

    /// <summary>wintun 虚拟网卡名</summary>
    public string TunAdapterName { get; set; } = "IPv8Plus";

    /// <summary>本地 gRPC Rust 引擎端口；0 = 随机端口（ADR-011）</summary>
    public int LocalGrpcRustEnginePort { get; set; } = 0;

    /// <summary>DNS 命名空间根（部署参数，禁止硬编码公共实例，spec §10.4）</summary>
    public string NamespaceRoot { get; set; } = ".ipv8.net";

    /// <summary>建议 MTU（v9: 1500 - 68 overhead）</summary>
    public int Mtu { get; set; } = 1432;

    /// <summary>QoS 单类排队上限（帧数）；超出按最低可容忍类丢弃</summary>
    public int QoSClassCapacity { get; set; } = 4096;

    /// <summary>NRPT 清理脚本路径（相对程序基目录）</summary>
    public string NrptCleanupScriptPath { get; set; } = Path.Combine("deploy", "client", "cleanup-nrpt.ps1");
}
