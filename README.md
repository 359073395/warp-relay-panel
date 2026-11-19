# WarpRelayPanel · 极简防失联住宅链式面板

基于 Python + Mihomo (Clash.Meta) 内核的 Windows 极简桌面客户端：
通过 **「防失联第一跳前置 + 第二跳住宅/家宽落地（`dialer-proxy`）」** 的链式架构，解决单靠公益节点易失联、直连住宅 IP 易被阻断的问题。

## 核心特性

- **极简 3 标签页中文界面**（内置 `pywebview` 独立窗口，关闭自动断开并恢复系统代理）：
  1. **🏡 免费家宽 (VPN Gate)**：一键拉取并通过 ASN/Hosting 识别区分「家宽 / 机房」节点，支持 **并发测速并选最快**，底层使用 Mihomo 原生 `openvpn` 链式穿透；连接时自动对备选家宽兜底。
  2. **🚀 防失联直出 (WARP)**：支持纯 Python 免翻墙直接注册 Cloudflare WARP（启用 AmneziaWG 防干扰混淆），并可联合公益备胎池做第一跳自动优选。
  3. **⚙️ 自定义前置 / 我的住宅 IP**：支持导入自己的前置节点（`vless`/`vmess`/`trojan`/`ss`/`hy2`/`socks5`/`http`）与前置订阅（Clash YAML / Base64），以及个人私有落地住宅 IP（仅保存在本机 `data/` 目录，绝不上传）。
- **接管与分流模式**：
  - 支持 **系统代理模式**（无需管理员权限）与 **TUN 全局网卡模式**（面板右上角一键 UAC 管理员提权重启）。
  - 支持 **大陆分流（国内直连）** 与 **全局代理**。

## 直接使用（Windows 免安装版）

1. 前往本仓库右侧 [Releases](../../releases) 下载最新的 `WarpRelayPanel-win64.zip`。
2. 解压到任意目录后，双击 `WarpRelayPanel.exe` 即可打开中文桌面窗口。
3. 普通权限默认开启系统代理；如需启用 **TUN 全局网卡模式**，点击面板右上角「管理员重启(开TUN)」。

## 本地源码运行 / 自行打包

1. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
2. 将 `mihomo.exe` 及 `geosite.dat`、`geoip.dat`、`geoip.metadb` 放入 `core/` 目录。
3. 运行面板：
   ```bash
   python run_panel.py
   ```
4. 打包单文件 EXE（需安装 `pyinstaller`）：
   ```powershell
   python -m PyInstaller --noconfirm --clean --onefile --windowed `
     --name WarpRelayPanel `
     --add-data "app\static;app\static" `
     --hidden-import webview `
     --hidden-import yaml `
     run_panel.py
   ```
