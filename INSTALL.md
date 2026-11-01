# 通过 GitHub Release 安装

安装地址必须指向 GitHub Release 中的安装包，不能使用仓库首页 `https://github.com/Or1a/BetterDPI`。

| OpenWrt | 包格式 | 安装方式 |
| --- | --- | --- |
| 24.10 | IPK | `opkg install` 可以接收完整 HTTPS 安装包地址 |
| 25.12 | APK | 先下载到本地，再运行 `apk add`；该版本不支持直接把 HTTPS 地址作为安装参数 |

Netify 的 LAN 接口、本地 socket 和 JSON 导出仍需按 [README](README.md#netify-setup-and-first-use) 配置。安装插件不会自动修改 Netify 或代理设置。

## V0.4.0 试用版

V0.4.0 包含默认关闭的实验性 Anti-PCDN，已按 **Pre-release** 发布。两个官方 SDK 构建、下载附件与源码核对均已通过，可从 [V0.4.0 发布页](https://github.com/Or1a/BetterDPI/releases/tag/V0.4.0)下载。稳定版仍为 V0.3.2；应用内更新和下文的 `releases/latest` 地址不会自动提供试用版。

| OpenWrt | 试用包固定文件名及下载链接 |
| --- | --- |
| 24.10 | [BetterDPI-openwrt-24.10-all.ipk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.0/BetterDPI-openwrt-24.10-all.ipk) |
| 25.12 | [BetterDPI-openwrt-25.12-all.apk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.0/BetterDPI-openwrt-25.12-all.apk) |

使用下方「下载、校验后安装」命令时，选择与系统对应的包名，并把 `betterdpi_release` 那一行改为：

```sh
betterdpi_release='https://github.com/Or1a/BetterDPI/releases/download/V0.4.0'
```

这样安装包和 `SHA256SUMS` 都来自 V0.4.0；不要使用 V0.3.2 的校验值。已有 BetterDPI 可直接覆盖安装同一包 `luci-app-netify-stats`，无需先卸载或重启路由器。升级会短暂中断采集并重启 rpcd，完成后刷新页面；已保存的流量分析开关和数据仍按原有规则保留。

打开 **状态 → Anti-PCDN**，选择 Netify 已采集的实际 LAN 接口，再启用「仅观察」。该功能依赖 DPI 采集器运行；打开 Anti-PCDN 不会恢复被用户暂停的流量分析。等待至少 5 分钟观察评分和采集缺口，将需要保留的设备或域名加入白名单。需要自动处置时可切换「自动封禁」，默认 **80 分、120 秒**，并保留连接身份、窗口完整性和执行路径检查。

自动处置适用于支持的 fw4/nftables 普通路由路径；已知卸载、TPROXY、DNAT 和不可分离的共享隧道会拒绝新增封禁。真实路由器负载和业务误判尚待试用验证，详细边界见 [Anti-PCDN 说明](docs/anti-pcdn-design.md)。

## 固定下载地址

发布流程会同时生成带版本号的安装包、内容相同的固定名称附件，以及供页面更新器读取的 `update.json`。安装包、固定附件和更新清单都列入 `SHA256SUMS`。固定名称保留 OpenWrt 系列号，避免 IPK 与 APK 混用：

```text
https://github.com/Or1a/BetterDPI/releases/latest/download/BetterDPI-openwrt-24.10-all.ipk
https://github.com/Or1a/BetterDPI/releases/latest/download/BetterDPI-openwrt-25.12-all.apk
```

**当前稳定版为 [V0.3.2](https://github.com/Or1a/BetterDPI/releases/tag/V0.3.2)，上述稳定版固定地址与应用内更新清单已核对指向该版本。** 确定版本的下载地址与校验和见 [README](README.md#command-line-download)。试用 V0.4.0 请使用上方指定标签的地址。

OpenWrt 24.10 可以直接运行：

```sh
opkg update && opkg install 'https://github.com/Or1a/BetterDPI/releases/latest/download/BetterDPI-openwrt-24.10-all.ipk'
```

需要核对发布文件校验和时，可采用下面的下载、校验、安装流程；它同时适用于两种包管理器。

## 下载、校验后安装

在路由器上以 root 运行。将第一行设为与系统匹配的包名；APK 使用 `BetterDPI-openwrt-25.12-all.apk`，IPK 使用 `BetterDPI-openwrt-24.10-all.ipk`：

```sh
(
    set -eu
    betterdpi_package='BetterDPI-openwrt-25.12-all.apk'
    betterdpi_release='https://github.com/Or1a/BetterDPI/releases/latest/download'
    betterdpi_tmp=$(mktemp -d /tmp/betterdpi.XXXXXX)
    trap 'rm -rf "$betterdpi_tmp"' EXIT
    cd "$betterdpi_tmp"
    wget -O "$betterdpi_package" "$betterdpi_release/$betterdpi_package"
    wget -O SHA256SUMS "$betterdpi_release/SHA256SUMS"
    awk -v name="$betterdpi_package" '$2 == name { print }' SHA256SUMS > package.sha256
    test "$(wc -l < package.sha256)" -eq 1
    sha256sum -c package.sha256
    case "$betterdpi_package" in
        *.ipk) opkg update && opkg install "./$betterdpi_package" ;;
        *.apk) apk update && apk add --allow-untrusted "./$betterdpi_package" ;;
    esac
)
```

当前 APK 未配置项目的持久签名密钥，因此仅在上述单次本地安装中使用 `--allow-untrusted`；没有更改系统的签名验证设置。SHA-256 校验可检测下载损坏或文件不匹配，但不替代软件源签名。若下载期间恰好切换最新版本，校验失败会停止安装，可改用确定的 `/releases/download/V版本号/` 地址重试。

固定 URL 不会注册软件源。后续安装新版本仍需重新执行下载安装命令，包的内部版本号也必须递增。若希望直接 `apk add luci-app-netify-stats`、`opkg install luci-app-netify-stats` 并由包管理器发现更新，需要另建带索引与签名的软件源，GitHub 仓库地址本身不能替代它。

## 已安装旧版的机器如何升级

V0.3.0 / V0.3.1 可直接在“应用更新”检查并升级到 V0.3.2。更早的旧版页面没有更新入口，先用上面的下载、校验、安装命令覆盖安装一次。继续安装同一个包 `luci-app-netify-stats` 即可，不需要先卸载，也不需要重启路由器。OpenWrt 24.10 使用 IPK，25.12 使用 APK；这只升级插件，不会升级 OpenWrt 系统本身。

V0.3.1 会把超过 7 天的明细逐步合并为累计统计，保留数字但删除旧域名和小时细节。

更新器不会删除 `/etc/netify-stats.json` 或 `/tmp/netify-stats/stats.db`。采集器启动时会事务迁移支持的旧统计库；安装钩子按已保存的开关恢复采集，原本关闭的分析仍保持关闭。升级过程中采集会短暂中断、rpcd 会重启，页面可能短时显示刷新失败；这不是完全不中断的热更新，也不保证升级窗口内的流量统计连续。不要为了插件升级重启机器，否则 `/tmp` 统计会按原有设计清空。

安装包含更新器的版本后，可在“应用更新”中：

1. 点击“检查更新”，查看当前版本和新版本。
2. 确认升级，页面显示下载、校验和安装状态。
3. 安装完成后刷新页面，加载新版本界面。打开页面和常规流量刷新不会自动访问 GitHub。

更新器仅接受本项目发布的稳定版本和匹配 OpenWrt 系列的包，下载链接固定到已确认的 Release 标签，校验不符时停止安装。网络或安装错误会显示在页面；安装过程被打断时不会自动重复安装。尚不支持的系统系列会提示手动处理。

应用内的 APK 安装禁止包管理器联网，只安装已下载并校验的本地包。若未来版本新增了机器上没有的依赖，请先通过系统的正常软件源补齐依赖，或按上面的手动步骤升级；更新器不会自动放宽全局签名策略或升级整个系统。

命令兼容性依据：[OpenWrt opkg URL 处理](https://github.com/openwrt/opkg-lede/blob/38eccbb1fd694d4798ac1baf88f9ba83d1eac616/libopkg/opkg_download.c#L316)、[OpenWrt 25.12.5 的 apk 版本](https://github.com/openwrt/openwrt/blob/v25.12.5/package/system/apk/Makefile)、[对应 apk add 的本地文件处理](https://github.com/alpinelinux/apk-tools/blob/b5a31c0d865342ad80be10d68f1bb3d3ad9b0866/src/app_add.c)。

V0.3.2 的 WAN 独立账从升级后收到的外部接口增量开始，不会把既往接口差额补入设备统计。若页面没有 WAN 记录，先确认 Netify 已监听真实外部接口，详见 [WAN/VPN 说明](netify-stats/README.md#wan--vpn-独立计量v032)。
