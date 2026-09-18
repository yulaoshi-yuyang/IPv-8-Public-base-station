/* ============================================================
   IPv8+ 文档数据（结构化，改文档不改代码）
   四块：快速开始 / 命令参考 / 概念科普 / 常见问题
   ============================================================ */
window.IPV8_DOCS = {
  quickstart: {
    title: "快速开始",
    lead: "三步接入 IPv8+ 网络：自动配置 → 启动服务 → 跨机互连。全程无需手动编辑配置文件。",
    sections: [
      {
        id: "qs-install",
        title: "第一步：下载客户端",
        body: [
          { type: "p", text: "从本门户下载 ping8.exe，它是一个单文件工具，包含所有功能（签证、驱动、隧道、防火墙、诊断）。" },
          { type: "p", text: "建议以管理员身份运行，以便自动安装到系统 PATH 和配置防火墙。" }
        ],
        terms: [
          { prompt: "ping8", comment: "查看完整命令列表" }
        ]
      },
      {
        id: "qs-auto",
        title: "第二步：一键自动配置",
        body: [
          { type: "p", text: "运行 <code>ping8 auto</code>，自动完成以下操作：" },
          { type: "ul", items: [
            "生成 CA 密钥对（用于签发签证）",
            "根据机器指纹生成 IPv8 地址",
            "签发 30 天有效签证（到期自动续签）",
            "安装 NDIS 协议驱动（需关闭 Secure Boot）",
            "配置防火墙放行标准端口"
          ]},
          { type: "p", text: "配置完成后会显示你的 IPv8 地址，格式如 <code>fb14:0000:0000:0001:0001:0000:0100:0000</code>。" }
        ],
        terms: [
          { prompt: "ping8 auto", comment: "一键配置，推荐新用户" }
        ]
      },
      {
        id: "qs-serve",
        title: "第三步：启动客户端服务",
        body: [
          { type: "p", text: "运行 <code>ping8 serve</code> 启动本地管理服务，监听 127.0.0.1:9100。" },
          { type: "p", text: "服务启动后，本门户的「本机客户端信息」会优先读取本机数据，否则回落显示服务器端数据。" },
          { type: "p", text: "如需后台运行，可使用 Windows 任务计划程序或服务包装器。" }
        ],
        terms: [
          { prompt: "ping8 serve", comment: "启动本地管理服务（默认端口 9100）" },
          { prompt: "ping8 serve --port 9200", comment: "自定义端口" }
        ]
      },
      {
        id: "qs-cross",
        title: "第四步：跨机互连",
        body: [
          { type: "p", text: "两台机器都完成上述配置后，即可建立信任连接：" },
          { type: "ol", items: [
            "对端机器运行 <code>ping8 trust listen</code> 监听信任请求",
            "本机在门户「控制台 → 跨机互连」填入对端 IP，点击「发送信任请求」",
            "对端 CMD 弹出确认，输入 Y 同意即建立连接",
            "使用 <code>ping8 ping</code> 互相测试连通性"
          ]}
        ],
        terms: [
          { prompt: "ping8 trust listen", comment: "对端：监听信任请求" },
          { prompt: "ping8 ping fb14:0000:...:0000", comment: "测试与对端的连通性" }
        ]
      }
    ]
  },

  cli: {
    title: "命令参考",
    lead: "ping8 全部子命令一览。所有命令均支持 <code>-h</code> / <code>--help</code> 查看详细参数。",
    sections: [
      {
        id: "cli-core",
        title: "核心命令",
        body: [
          { type: "table", headers: ["命令", "说明"], rows: [
            ["ping8 install", "安装到系统 PATH（管理员，仅一次）"],
            ["ping8 auto", "一键自动配置（CA + 签证 + 防火墙 + 驱动检查）"],
            ["ping8 diagnose", "一键诊断（签证/驱动/隧道/DNS/防火墙 共 9 项）"],
            ["ping8 addr", "查看本机 IPv8 地址详情"],
            ["ping8 status", "查看驱动/隧道/签证整体状态"],
            ["ping8 serve", "启动本地管理服务（HTTP API）"]
          ]}
        ]
      },
      {
        id: "cli-visa",
        title: "签证管理",
        body: [
          { type: "table", headers: ["命令", "说明"], rows: [
            ["ping8 visa ca-init", "生成 CA 密钥对（管理员，仅一次）"],
            ["ping8 visa issue --addr <hex> --ca-seed <hex>", "签发签证"],
            ["ping8 visa show", "查看当前签证"],
            ["ping8 visa verify --ca-pub <hex>", "验证签证签名"],
            ["ping8 visa renew", "手动续签（到期前刷新）"],
            ["ping8 visa revoke", "吊销签证（删除本地文件）"],
            ["ping8 visa fingerprint", "显示本机机器指纹"]
          ]}
        ],
        terms: [
          { prompt: "ping8 visa show", comment: "查看签证有效期与地址" }
        ]
      },
      {
        id: "cli-trust",
        title: "跨机互连",
        body: [
          { type: "table", headers: ["命令", "说明"], rows: [
            ["ping8 trust listen", "监听信任请求（被动模式）"],
            ["ping8 trust request --ip <ip> --port <port>", "发送信任请求（主动模式）"],
            ["ping8 ping <ipv8-addr>", "ping 远端 IPv8 地址（测连通+延迟）"]
          ]}
        ],
        terms: [
          { prompt: "ping8 trust listen", comment: "等待对端发起信任请求" }
        ]
      },
      {
        id: "cli-firewall",
        title: "防火墙",
        body: [
          { type: "table", headers: ["命令", "说明"], rows: [
            ["ping8 firewall open", "放行 IPv8+ 标准端口（45801, 9001）"],
            ["ping8 firewall close", "清除 IPv8+ 端口规则"],
            ["ping8 firewall status", "查看当前防火墙规则状态"]
          ]}
        ]
      },
      {
        id: "cli-hook",
        title: "数据面钩子（高级）",
        body: [
          { type: "table", headers: ["命令", "说明"], rows: [
            ["ping8 hook watch", "实时观察数据包事件流"],
            ["ping8 hook watch --decision", "接管数据包判决（allow/drop/modify）"],
            ["ping8 hook stats", "查询钩子总线统计"]
          ]},
          { type: "p", text: "钩子系统允许外部程序对经过 ipv8-node 的数据包进行实时判决，类似 Linux 的 NFQUEUE。支持观察模式和判决模式。" }
        ]
      }
    ]
  },

  concepts: {
    title: "概念科普",
    lead: "理解 IPv8+ 的核心概念：地址结构、签证机制、DNS 解析。",
    sections: [
      {
        id: "what-is-ipv8",
        title: "什么是 IPv8+",
        body: [
          { type: "p", text: "IPv8+ 是一个实验性的 128 位扩展地址空间协议，运行在 IPv6 之上。它通过自定义 NDIS 协议驱动实现，为每台设备分配一个以 <code>fb14</code> 开头的 8 段冒号分隔地址。" },
          { type: "p", text: "与公网 IPv6 不同，IPv8+ 地址是虚拟的，由 CA 签发的签证绑定到特定机器，不可伪造。流量通过 wintun 虚拟网卡和 Cloudflare 隧道传输。" }
        ]
      },
      {
        id: "addr-structure",
        title: "fb14 地址 8 段结构",
        body: [
          { type: "p", text: "一个完整的 IPv8+ 地址如下：" },
          { type: "code", text: "fb14:0000:0000:0001:0001:0000:0100:0000" },
          { type: "p", text: "各段含义：" },
          { type: "table", headers: ["段", "含义"], rows: [
            ["fb14", "协议魔数前缀，标识 IPv8+"],
            ["0000:0000", "区域 ID（Region）"],
            ["0001", "子网 1（Subnet 1）"],
            ["0001", "子网 2（Subnet 2）"],
            ["0000", "节点身份哈希（Node Hash）"],
            ["0100", "临时会话 ID（Session ID）"],
            ["0000", "服务/接口位（Service/Interface）"]
          ]},
          { type: "p", text: "地址由机器指纹（Windows MachineGuid 的 SHA-256）派生，保证唯一性。" }
        ]
      },
      {
        id: "visa-ca",
        title: "签证与 CA 机制",
        body: [
          { type: "p", text: "IPv8+ 使用基于 Ed25519 的签证系统证明地址归属：" },
          { type: "ul", items: [
            "CA 持有 Ed25519 私钥，对 {machine_id, ipv8_addr, ed_pubkey, issued_at, expires_at} 签名",
            "客户端只有 CA 公钥，验签通过才能证明签证来自 CA",
            "签证绑定机器指纹，换机器即失效",
            "签证默认 30 天过期，到期前 7 天自动续签（需本地有 CA 种子）"
          ]},
          { type: "p", text: "这种设计确保了 IPv8+ 地址不可伪造，且与物理机器绑定。" }
        ]
      },
      {
        id: "local-dns",
        title: "*.ipv8.net 本地 DNS 解析",
        body: [
          { type: "p", text: "IPv8+ 门户运行一个本地 DNS 解析器（127.0.0.1:5353），负责解析 <code>*.ipv8.net</code> 域名。" },
          { type: "p", text: "当你访问 <code>portal.ipv8.net</code> 或客户端子域名时，DNS 查询被本地解析器拦截并返回对应的 IPv8 地址，不经过外部 DNS 服务器。" },
          { type: "p", text: "这保证了 IPv8+ 域名的解析完全在本地可控，不依赖外部服务。" }
        ]
      }
    ]
  },

  faq: {
    title: "常见问题",
    lead: "遇到问题？先看这里。找不到答案？试试页面顶部的「诊断」向导。",
    sections: [
      {
        id: "faq-driver",
        title: "NDIS 驱动安装失败怎么办？",
        body: [
          { type: "p", text: "确保已在 BIOS 中关闭 Secure Boot。Windows 测试签名模式需要 Secure Boot 关闭才能加载未签名的驱动。" },
          { type: "p", text: "关闭后重新运行 <code>ping8 auto</code>，驱动会自动安装。" }
        ]
      },
      {
        id: "faq-visa",
        title: "签证过期了怎么办？",
        body: [
          { type: "p", text: "签证默认 30 天有效。如果本地有 CA 种子，会在到期前 7 天自动续签。" },
          { type: "p", text: "手动续签：运行 <code>ping8 auto</code> 或 <code>ping8 visa renew</code>。" }
        ]
      },
      {
        id: "faq-connect",
        title: "两台机器无法互连？",
        body: [
          { type: "p", text: "按顺序排查：" },
          { type: "ol", items: [
            "两端都运行了 <code>ping8 auto</code> 并获得签证",
            "对端运行了 <code>ping8 trust listen</code>",
            "防火墙已放行端口 45801 和 9001（<code>ping8 firewall open</code>）",
            "使用本门户「诊断」向导检查各项状态"
          ]}
        ]
      },
      {
        id: "faq-dns",
        title: "ipv8.net 域名无法解析？",
        body: [
          { type: "p", text: "确保门户服务正在运行，本地 DNS 解析器监听 127.0.0.1:5353。" },
          { type: "p", text: "运行 <code>ping8 diagnose</code> 检查 DNS 解析项。" }
        ]
      },
      {
        id: "faq-path",
        title: "CMD 里输入 ping8 提示找不到命令？",
        body: [
          { type: "p", text: "需要以管理员身份运行 <code>ping8 install</code>，将 ping8.exe 复制到 C:\\Windows\\System32\\。" },
          { type: "p", text: "安装后重新打开 CMD 即可直接使用 ping8 命令。" }
        ]
      }
    ]
  }
};
