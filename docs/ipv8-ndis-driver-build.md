# IPv8 NDIS 协议驱动 — 构建与安装指南

## 这是什么

一个 NDIS 6.x 协议驱动，装完之后在网络适配器属性里会多出一个
**"Internet 协议版本 8 (TCP/IPv8)"** 的勾选项，和 IPv4/IPv6 并列。

目前是最小化实现（能装上、能显示、能绑定），数据面还是走现有的
wintun 方案。这个驱动的核心作用是 **UI 存在感 + 协议栈注册占位**。

---

## 构建步骤

### 前置条件

| 工具 | 版本 | 下载 |
|------|------|------|
| Visual Studio 2022 | 17.0+ | https://visualstudio.microsoft.com/ |
| Windows SDK | 10.0.26100.0 | VS 安装器里勾 "Windows 11 SDK" |
| Windows Driver Kit (WDK) | 10.0.26100.0 | https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk |

> 注意：WDK 版本必须和 SDK 版本完全一致（都是 10.0.26100.0）。
> 装 WDK 时它会自动集成到 VS 里。

### 编译

**方法一：Visual Studio 打开**

1. VS 2022 打开 `src/driver/ipv8-ndis-protocol/ipv8proto.vcxproj`
2. 配置选 `Release` / `x64`
3. 菜单 → 生成 → 生成解决方案
4. 输出在 `bin/x64/Release/ipv8proto.sys` + `ipv8proto.inf`

**方法二：命令行**

```powershell
# 打开 "x64 Native Tools Command Prompt for VS 2022"
cd src\driver\ipv8-ndis-protocol
msbuild ipv8proto.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## 安装步骤

### 1. 开启测试模式（必须做）

未签名的驱动默认装不上，要开测试模式：

```powershell
# 管理员 PowerShell
bcdedit /set testsigning on
```

然后**重启电脑**。重启后右下角会有"测试模式"水印，正常现象。

### 2. 编译驱动

按上面的构建步骤编出 `ipv8proto.sys` 和 `ipv8proto.inf`。

### 3. 运行安装脚本

```powershell
# 管理员 PowerShell
cd deploy\driver
.\install-ipv8-protocol.ps1 -DriverPath "..\..\src\driver\ipv8-ndis-protocol\bin\x64\Release"
```

### 4. 验证

1. `Win + R` → 输入 `ncpa.cpl` → 回车
2. 右键随便一个网卡 → **属性**
3. 看列表里有没有 **"Internet 协议版本 8 (TCP/IPv8)"**
4. 有 = 成功

---

## 卸载

```powershell
# 管理员 PowerShell
cd deploy\driver
.\uninstall-ipv8-protocol.ps1
```

然后重启一下最干净。

---

## 关于你截图里的两个位置

### 图二（协议列表打勾）

这个位置我们的驱动装完就会显示。它显示的是绑定到这张网卡上的协议，
IPv8 协议驱动注册后就会出现在这里，前面有个复选框可以勾/取消。

### 图一（WiFi 属性页）

这个页面显示的是物理 WiFi 连接的属性（SSID、频段、速率、IPv4/IPv6 地址等）。
IPv8 作为一个 overlay 协议，它的地址不会显示在物理网卡的属性页里——
它属于 IPv8 虚拟网卡（wintun 那层）。

要在那个位置也显示 IPv8 信息，有两个方案：

- **方案 A（推荐）**：在 wintun 虚拟网卡的状态页里显示 IPv8 地址。
  这个改动小，符合网络栈的分层逻辑。

- **方案 B**：写一个属性页扩展 DLL，往物理网卡的属性页里插一个
  "IPv8" 标签页。技术上可行，但工作量大，而且不符合网络分层规范。

---

## 文件清单

```
src/driver/ipv8-ndis-protocol/
├── ipv8proto.inf        ← 安装信息文件（控制显示名称、图标、绑定方式）
├── ipv8proto.vcxproj    ← VS 项目文件
├── driver.h             ← 驱动头文件
└── driver.c             ← 驱动主代码（入口、注册、绑定、收发 stub）

deploy/driver/
├── install-ipv8-protocol.ps1    ← 一键安装脚本
└── uninstall-ipv8-protocol.ps1  ← 一键卸载脚本
```

---

## 常见问题

**Q: 装完蓝屏了怎么办？**
A: 进安全模式，运行卸载脚本，或者 `netcfg -u ms_ag1`。
   测试模式下开发驱动蓝屏很正常，说明哪里写得有问题。

**Q: 能不能不开启测试模式？**
A: 正式发布需要 EV 代码签名证书 + Microsoft 合作伙伴中心 + WHQL 认证。
   你说你是官方，后面可以走这条路。

**Q: 这个驱动和现有的 wintun 方案是什么关系？**
A: 目前各干各的。NDIS 协议驱动负责 UI 展示和协议栈注册；
   wintun 负责实际的数据面。后续可以整合：让协议驱动截获
   IPv8 包后转发给用户态的 Rust 引擎处理。
