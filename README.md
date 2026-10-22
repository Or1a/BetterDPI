# BetterDPI

BetterDPI is a LuCI plugin for local traffic analysis on OpenWrt, using Netify to identify device, application, and website traffic.

BetterDPI 是用于 OpenWrt 的本地流量分析 LuCI 插件，通过 Netify 识别设备、应用和网站流量。

## Features

- Analyze traffic by device, application, and website in LuCI, with paginated rankings and drill-down views.
- View download and upload trends in a mobile-friendly interface.
- Bind an actual router interface manually to track its RX/TX traffic separately from device statistics.
- Browse recorded interface history independently of the interface currently being measured.
- Keep statistics locally in `/tmp`; they are cleared on reboot. Set a maximum storage size or leave it unlimited.
- Pause and resume traffic analysis without deleting existing history.
- Follow LuCI's English, Simplified Chinese, or Traditional Chinese language setting.
- Supplement Netify's native identification with community classification rules while preserving their sources.
- Inspect matching rules and reasons for ambiguous or unidentified applications in the application details.
- Use observed protocols to categorize otherwise unidentified traffic, with shared infrastructure distinguished from application identification.
- Filter by identification level, search applications and domains, and focus a traffic group to view its devices and trend. Find devices by name, MAC address, or IP.
- Inspect collection health and troubleshooting guidance, distinguishing unidentified applications from traffic that could not be attributed to devices.
- Manually check for a newer GitHub Release and install it from the page after confirmation, with download verification and upgrade status.

## 功能特性

- 在 LuCI 中按设备、应用和网站分析流量，支持排行榜分页及逐级查看明细。
- 在适配手机的界面中查看下载和上传趋势。
- 手动绑定路由器的实际接口，单独统计其 RX/TX 流量，不与设备统计相加。
- 独立查看已有接口历史，无需切换当前采集接口。
- 统计数据仅保存在本机 `/tmp`，重启后清空；可设置最大存储容量，也可不设上限。
- 可暂停或恢复流量分析，暂停时保留已有历史数据。
- 跟随 LuCI 的英文、简体中文或繁体中文语言设置。
- 使用社区分类规则补充 Netify 的原生识别，并保留规则来源信息。
- 在应用明细中查看命中规则，以及多义规则或未识别结果的原因。
- 扩充 AI 等服务域名规则；无域名流量按已知协议分类，并区分共享基础设施归属与应用识别。
- 按识别层级筛选、搜索应用与域名，聚焦某类流量查看其设备及趋势；支持按名称、MAC 或 IP 查找设备。
- 查看采集状态与排查建议，区分应用未识别和未能计入设备统计的流量。
- 在页面手动检查 GitHub 新版本，确认后校验、安装，并查看升级结果。

The [V0.3.0 release](https://github.com/Or1a/BetterDPI/releases/tag/V0.3.0) includes these changes. Existing installations need one manual upgrade to V0.3.0 before they can use its update button. Both packages were built with their matching official SDK and their published payloads were checked against the tagged source; router upgrade and long-term validation remain pending.

上述变更已纳入 [V0.3.0 Release](https://github.com/Or1a/BetterDPI/releases/tag/V0.3.0)。旧版先手动覆盖安装 V0.3.0 一次，之后即可使用页面升级。两种包均由对应官方 SDK 构建，发布附件已逐文件核对；真实路由器升级与长期验证仍待完成。

Fixed download filenames and an in-app update manifest are available. See the [GitHub installation guide](INSTALL.md) for direct IPK installation, APK download-and-install, and checksum verification.

现在提供固定名称下载链接和应用内更新清单。通过 GitHub 安装 IPK、下载后安装 APK 及校验方法见[便捷安装说明](INSTALL.md)。

## Command-line download

Run the command matching your router's OpenWrt version. It downloads the package to `/tmp` and verifies its SHA-256 checksum; it does not install anything.

OpenWrt 24.10.8 (IPK):

```sh
wget -O /tmp/BetterDPI-0.3.0-openwrt-24.10.8-all.ipk 'https://github.com/Or1a/BetterDPI/releases/download/V0.3.0/BetterDPI-0.3.0-openwrt-24.10.8-all.ipk' && echo 'b782bff6d1af6624ac0389277817fe3e382bb41cd91cf194d7f85fded4c23c93  /tmp/BetterDPI-0.3.0-openwrt-24.10.8-all.ipk' | sha256sum -c -
```

OpenWrt 25.12.5 (APK):

```sh
wget -O /tmp/BetterDPI-0.3.0-openwrt-25.12.5-all.apk 'https://github.com/Or1a/BetterDPI/releases/download/V0.3.0/BetterDPI-0.3.0-openwrt-25.12.5-all.apk' && echo '02a4ffb86146185f5dc4046a193b8135c664fa01b8df605710e16d9ab7ee81c0  /tmp/BetterDPI-0.3.0-openwrt-25.12.5-all.apk' | sha256sum -c -
```

## 命令行下载

在对应版本的 OpenWrt 路由器上运行上方的一条命令。安装包会下载到 `/tmp` 并校验 SHA-256；命令不会自动安装。

## Installation

Connect to the router over SSH as `root`. After downloading and verifying the matching package above, install it with the router's package manager:

OpenWrt 24.10.8 (IPK):

```sh
opkg update && opkg install /tmp/BetterDPI-0.3.0-openwrt-24.10.8-all.ipk
```

OpenWrt 25.12.5 (APK):

```sh
apk update && apk add --allow-untrusted /tmp/BetterDPI-0.3.0-openwrt-25.12.5-all.apk
```

The package is named `luci-app-netify-stats` internally. Its dependencies include `netifyd`, `python3`, `python3-sqlite3`, `python3-urllib`, `python3-openssl`, `ca-bundle`, `luci-base`, and `rpcd`; the package manager resolves them from the configured feeds.

## Netify setup and first use

1. Configure the LAN capture interface in `/etc/config/netifyd`. You can check the LAN device name with `uci -q get network.lan.device`. For manual interface configuration, set these entries in the existing `config netifyd` section, replacing `br-lan` with the actual LAN device:

   ```uci
   option enabled '1'
   option autoconfig '0'
   list internal_if 'br-lan'
   ```

2. Set the following entries in the corresponding sections of `/etc/netifyd.conf`, using the [Netify configuration example](netify-stats/netifyd.conf):

   ```ini
   [netifyd]
   enable_sink = no
   upload_nat_flows = yes
   export_json = yes

   [socket]
   listen_path[0] = /var/run/netifyd/netifyd.sock
   dump_unknown_flows = yes

   [protocols]
   all = include
   ```

3. Apply the Netify configuration:

   ```sh
   /etc/init.d/netifyd enable
   /etc/init.d/netifyd restart
   ```

4. Log in to LuCI and open **Status → DPI Traffic Analysis** (`/cgi-bin/luci/admin/status/netify-stats`). Turn on **Traffic analysis** to start Netify and the statistics collector. Generate some traffic from a LAN device, then refresh the page to view the device, application, and website statistics.
5. To collect interface RX/TX statistics, select the router's actual interface under **Interface traffic** and click **Confirm and save**.

See the [detailed documentation](netify-stats/README.md) for storage settings and statistics behavior, [rule sources and rebuilding](netify-stats/rules/README.md), and [interface configuration in the OpenWrt Netify package](https://github.com/openwrt/packages/blob/openwrt-24.10/net/netifyd/files/netifyd.config).

## 安装

通过 SSH 以 `root` 身份连接路由器。运行上方对应版本的下载命令并通过校验后，使用路由器的包管理器安装：

OpenWrt 24.10.8（IPK）：

```sh
opkg update && opkg install /tmp/BetterDPI-0.3.0-openwrt-24.10.8-all.ipk
```

OpenWrt 25.12.5（APK）：

```sh
apk update && apk add --allow-untrusted /tmp/BetterDPI-0.3.0-openwrt-25.12.5-all.apk
```

软件包内部名称为 `luci-app-netify-stats`，依赖包括 `netifyd`、`python3`、`python3-sqlite3`、`python3-urllib`、`python3-openssl`、`ca-bundle`、`luci-base` 和 `rpcd`；包管理器会从已配置的软件源解析这些依赖。

## 配置 Netify 与首次使用

1. 在 `/etc/config/netifyd` 中配置 LAN 采集接口。可运行 `uci -q get network.lan.device` 查看 LAN 设备名。手动配置接口时，在已有的 `config netifyd` 段中设置以下选项，并将 `br-lan` 替换为实际 LAN 设备名：

   ```uci
   option enabled '1'
   option autoconfig '0'
   list internal_if 'br-lan'
   ```

2. 参照 [Netify 配置示例](netify-stats/netifyd.conf)，在 `/etc/netifyd.conf` 对应段中设置以下项目：

   ```ini
   [netifyd]
   enable_sink = no
   upload_nat_flows = yes
   export_json = yes

   [socket]
   listen_path[0] = /var/run/netifyd/netifyd.sock
   dump_unknown_flows = yes

   [protocols]
   all = include
   ```

3. 应用 Netify 配置：

   ```sh
   /etc/init.d/netifyd enable
   /etc/init.d/netifyd restart
   ```

4. 登录 LuCI，打开 **状态 → DPI 流量分析**（`/cgi-bin/luci/admin/status/netify-stats`），开启 **流量分析**，启动 Netify 与统计采集器。让一台 LAN 设备产生流量后，刷新页面查看设备、应用和网站统计。
5. 如需统计网卡 RX/TX 流量，在 **接口流量** 中选择路由器的实际接口，再点击 **确定保存**。

存储设置与统计口径见 [详细文档](netify-stats/README.md)，分类规则见 [规则来源与重建](netify-stats/rules/README.md)，采集接口配置项见 [OpenWrt Netify 软件包配置](https://github.com/openwrt/packages/blob/openwrt-24.10/net/netifyd/files/netifyd.config)。
