# BetterDPI V0.4.1 — 状态修复与分钟趋势试用版

V0.4.0 的 Anti-PCDN 页面会把 LuCI 自动附带的会话参数误判为非法参数，导致状态读取、设置保存和解除规则失败。V0.4.1 修复这一兼容问题；读取失败时明确显示未知或过期状态，不再用默认值冒充采集器的实际状态。

本次同时新增真实设备分钟记录，趋势图默认显示最近 60 分钟的上传／下载并列柱状图。继续以 **Pre-release** 提供试用，稳定版仍为 V0.3.2；V0.4.0 用户需手动覆盖升级，应用内更新不会自动提供本版本。

## 本次改动

- 接受 LuCI 注入的 `ubus_rpc_session` 会话字段，恢复 Anti-PCDN 的状态、保存和解除操作；保留其他参数检查。
- 状态读取失败时提示错误；已有成功结果标为旧结果，配置未知时禁用修改，避免错误地显示「已关闭」或虚假的采集器状态。
- 记录已计入设备账的每分钟上传和下载，图表默认展示最近 60 分钟。选择设备后，分钟图也限定到该设备。
- 图表内新增独立时间范围选择：「最近60分钟」使用分钟记录，「所选时间范围」使用小时记录。上方的总量、排行榜继续遵循原有时间范围。
- 缺失分钟和部分采集明确标记，旧小时数据不会拆成虚构的分钟记录。应用、域名和识别筛选使用所选时间范围的小时图，并显示说明。
- 分钟索引最多保留最近 2 小时、32,768 行数字记录，写入缓冲最多 2,048 项；复用现有 `/tmp` 数据库和约 3 秒的提交周期，不新增抓包或独立定时采集。

分钟图是已有设备增量的短期展示，不与原有总量重复相加。Anti-PCDN 仍默认关闭，已有设置保留，自动处置的初始阈值和期限仍为 **80 分／120 秒**。

## 下载与升级

发布流水线在两个官方 SDK 构建成功后上传以下试用包，见 [V0.4.1 发布页](https://github.com/Or1a/BetterDPI/releases/tag/V0.4.1)：

| OpenWrt | 试用包 |
| --- | --- |
| 24.10（IPK） | [BetterDPI-openwrt-24.10-all.ipk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.1/BetterDPI-openwrt-24.10-all.ipk) |
| 25.12（APK） | [BetterDPI-openwrt-25.12-all.apk](https://github.com/Or1a/BetterDPI/releases/download/V0.4.1/BetterDPI-openwrt-25.12-all.apk) |

使用同一 V0.4.1 发布页的 `SHA256SUMS` 校验后，覆盖安装 `luci-app-netify-stats`。无需先卸载或重启路由器；升级会短暂停止采集并重启 rpcd。完成后刷新 LuCI，若仍是旧界面则强制刷新。新分钟记录从升级后的采集开始，升级前的小时统计继续保留。APK 沿用单次本地安装的 `--allow-untrusted`。

安装命令见 [试用版安装说明](https://github.com/Or1a/BetterDPI/blob/V0.4.1/INSTALL.md#v041-试用版)。`releases/latest` 和应用内更新仍指向稳定版，不会提供试用更新。

## 验证与边界

267 项 Python 回归和 10 个 Node 测试套件通过，覆盖 LuCI 会话参数、读取失败状态、设备分钟查询、去重和代理纠正、保留上限、事务失败、缺失标记，以及图表范围与原有统计范围的独立性。SDK 构建结果以本次发布流水线为准。

分钟粒度按采集器的实际记账时间聚合，不代表逐包时间；Netify 延迟上报、采集中断和容量限制仍可能造成部分覆盖。分钟表不保存应用、域名或连接端口维度，因此相关筛选继续使用小时记录。所有统计仍位于 `/tmp`，路由器重启会清空。

Anti-PCDN 的 fw4/nftables 支持范围、卸载和共享隧道限制保持不变。已有隔离软件网络测试不替代 OpenWrt 真机验证，也不证明 PCDN 识别准确率。源码准备检查继续保留 `public_release_ready:false`。

详见 [分钟趋势说明](https://github.com/Or1a/BetterDPI/blob/V0.4.1/docs/minute-trend.md)及 [Anti-PCDN 说明](https://github.com/Or1a/BetterDPI/blob/V0.4.1/docs/anti-pcdn-design.md)。
