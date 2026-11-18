# BetterDPI V0.4.3

### Anti-PCDN

- 对跨端口、多对端上传结合近期分发记录和当前上传增长进行判断。在满足分组证据、连接身份和保护条件后，可提前处理新连接。
- 自动模式在路由器本地记录触发时的上传量、安装前的复核值、未执行或撤回的原因，以及内核首次观测到上行、下行丢包的时间区间。日志保存在 `/tmp/betterdpi-anti-pcdn/`，两份轮替文件合计上限 4 MiB，待写缓冲上限 64 KiB。
- 安装规则期间会重新检查新到的保护信息，减少普通流量更新引起的误撤回。VPN、代理和放行名单优先通行。自动防护默认关闭，启用后按连接执行。整组上传在固定字节数内停止仍待实网验收，内核丢弃字节可能包含重传。

### 流量统计

- WAN 报表将具有明确 Tailscale、ZeroTier 协议标签的连接归入 VPN 隧道。已有小时记录和归档使用相同规则，收发字节总量保持一致。
- LuCI 使用平滑曲线展示上传和下载趋势，区分采集缺口和实际零流量。统计库和运行日志默认保存在路由器的 `/tmp`。

### 安装与升级

| OpenWrt | 安装包 |
| --- | --- |
| 24.10 | [IPK](https://github.com/Or1a/BetterDPI/releases/download/V0.4.3/BetterDPI-openwrt-24.10-all.ipk) |
| 25.12 | [APK](https://github.com/Or1a/BetterDPI/releases/download/V0.4.3/BetterDPI-openwrt-25.12-all.apk) |

带有“应用更新”入口的版本可在 LuCI 中检查并确认升级。手动安装时，请从本页下载对应的包和 `SHA256SUMS`。升级会短暂中断采集，完成后刷新 LuCI。[安装说明](https://github.com/Or1a/BetterDPI/blob/V0.4.3/INSTALL.md)
