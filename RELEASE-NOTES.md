# BetterDPI V0.4.0 — Anti-PCDN 试用版

本次将独立的 Anti-PCDN 功能纳入主线，以 **Pre-release** 提供试用。**功能默认关闭**，现有流量统计继续使用原有口径；启用后复用当前 Netify 实时事件，不另起抓包，也不把评分观察量加入统计总数。稳定版仍为 V0.3.2，应用内更新和 `releases/latest` 不会自动切换到本试用版。

## 新增功能

- 独立的「状态 → Anti-PCDN」页面、配置、RPC 和简繁中文界面，支持「仅观察」和「自动封禁」。
- 根据短期对端数量、实质上传、持续性、上下行比例及可选域名提示计算滚动评分。四项行为证据可以达到默认 **80 分**；分数不是经过校准的 PCDN 概率。
- 自动处置仅针对符合条件的当前连接。默认期限 **120 秒**，提供设备/域名白名单、提前解除和内核自动到期；不会封整台设备或全部 UDP。
- 累计水位去重、迟到和缺口检查，以及逐连接的封禁重试抑制，防止重复上报加分或靠被封后的重试不断续期。
- 队列、样本、连接和每轮动作均有上限。达到容量上限会报告覆盖损失，证据不完整时暂停对应自动动作。

## 下载与覆盖安装

发布流水线成功后，本标签会提供以下试用附件；以发布页实际生成的附件为准：

| OpenWrt | 下载 |
| --- | --- |
| 24.10（24.10.8 官方 SDK，IPK） | [BetterDPI-openwrt-24.10-all.ipk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.0/BetterDPI-openwrt-24.10-all.ipk) |
| 25.12（25.12.5 官方 SDK，APK） | [BetterDPI-openwrt-25.12-all.apk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.0/BetterDPI-openwrt-25.12-all.apk) |

同时生成带 `0.4.0` 版本号的同内容包、`SHA256SUMS` 和 `update.json`。本次为预发布，试用时需手动选择上述 `V0.4.0` 标签的包及校验文件，不能使用稳定版的校验值。

已有 BetterDPI 可覆盖安装同一包 `luci-app-netify-stats`，无需先卸载或重启路由器；升级期间采集会短暂停止，rpcd 会重启，完成后刷新 LuCI。软件包保留现有配置，不自动开启 Anti-PCDN，也不修改 Netify、代理或加速设置。APK 沿用单次本地安装的 `--allow-untrusted`，不更改全局签名策略。完整命令见 [安装说明](https://github.com/Or1a/BetterDPI/blob/V0.4.0/INSTALL.md#v040-试用版)。

## 开始试用

1. 保持 DPI 流量采集运行，打开 **状态 → Anti-PCDN**，选择 Netify 实际采集的 LAN 接口。
2. 开启「仅观察」，等待至少 5 分钟建立完整窗口，检查评分依据和采集缺口，将需要保留的设备或域名加入白名单。
3. 如需自动处置，切换「自动封禁」并保存。达到阈值后还须通过连接身份、当前上传、窗口完整性和执行路径检查。页面可提前解除临时规则。

关闭功能会清理自有规则；采集停止时该功能一起停止。安装规则成功不等于已经验证实际转发效果，DPI 观察字节也不是成功拦截字节。

## 支持范围和验证

自动处置面向支持的 **fw4/nftables 普通 TCP/UDP 路由路径**。已知流卸载、NSS/SFE 等厂商加速、TPROXY、DNAT、归属不明确或不可分离的共享隧道会拒绝新增封禁。不会为执行功能而全局关闭加速。主动 BT、合法 P2P 分享也可能满足行为条件；真实误判率和路由器 CPU/RAM 仍需试用验证。

- 243 项 Python 回归和 10 个 Node 测试套件通过，覆盖评分、去重、白名单、数据缺口、执行回滚、配置切换、界面及安装清单。
- 隔离的软件网络环境通过 IPv4/IPv6 的 TCP/UDP、双向阻断、无关连接保护、非 DNAT 入站 UDP、提前解除及 30 秒内核自动到期测试。环境为 Linux 6.18.57、nft 1.1.3、模拟 fw4 和空模块清单，不代表 OpenWrt 实机或硬件加速已验收。
- 发布流水线在两种官方 SDK 构建成功后上传安装包、版本清单及 SHA-256 校验文件。源码准备检查保留 `public_release_ready:false`；真实路由器升级和长期运行仍待试用验证。
- 性能测量使用云主机合成事件，达到样本上限时会失去部分判断覆盖，不作为路由器性能保证。

详细条件见 [Anti-PCDN 说明](https://github.com/Or1a/BetterDPI/blob/V0.4.0/docs/anti-pcdn-design.md)，测试方法和开销边界见 [验证记录](https://github.com/Or1a/BetterDPI/blob/V0.4.0/docs/anti-pcdn-validation.md)。
