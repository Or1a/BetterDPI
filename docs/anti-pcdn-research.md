# Anti-PCDN 项目调研

调研日期：2026-10-31。对应分支：`feature/anti-pcdn`。

本次只读审阅公开源码、说明和 issue，没有安装第三方拦截工具，也没有连接用户路由器。下文的代码结论、作者自述、用户反馈和设计推断分别标注。没有从 star 数、规则数量或单元测试数量推算拦截率。

## 结论

这些项目主要采取域名过滤、按连接行为封端口、终端进程防火墙和远端 IP 清单四种方式。值得复用的是分级规则、短期行为窗口、按设备缩小范围、可撤销规则和资源上限；不能直接照搬的，是用泛化关键词、单一对端数量阈值或整段 UDP 封禁来认定 PCDN。

尤其要区分：**用户从 PCDN 节点下载内容，不等于用户设备在参与 PCDN 上传。** 封住下载节点可以减少某类连接，却也可能直接破坏正常播放。BetterDPI 要治理的是未经用户选择的上传分发行为。

本次审阅材料中，没有找到可用于横向比较这些方案的统一标注数据集、误报率、漏报率和正常业务对照。因此可以判断机制和已知边界，不能诚实地给出“拦截率 99%”之类的结论。

## 项目对照

| 项目 | 代码或说明中的机制 | 效果依据与边界 | 对 BetterDPI 的价值 |
| --- | --- | --- | --- |
| [Womsxd/pcdn-detector](https://github.com/Womsxd/pcdn-detector) / [LuCI 前端](https://github.com/Womsxd/luci-app-pcdn-detector) | AF_PACKET 抓包，默认只看 UDP；同 MAC、本地端口、协议、地址族的对端数量在窗口内达到阈值即告警。默认 60 秒、20 个公网对端；可对接 nftables/iptables 封设备端口 | 源码能核实触发条件；有逻辑测试及内存微基准说明。触发条件没有要求上传量、上传占比或 PCDN 专属协议，BT、P2P 同步等可满足相同条件。尚不能据此证明 PCDN 识别精度 | 借鉴窗口、端口分组、有界状态、可撤销规则。复用 Netify 事件，避免额外逐包抓取；将此行为特征用于告警，不能单独授予自动封禁权限 |
| [ucxn/Ban-PCDN_Anti-P2P](https://github.com/ucxn/Ban-PCDN_Anti-P2P) | 关键词、域名、Hosts、AdGuard 规则，以及按设备使用的高位 UDP 拦截；README 区分不同可信程度的条目 | 有游戏直连、图片和应用访问异常的历史反馈；作者说明部分激进规则容易误伤，并记录过规则回调。部分反馈已修复或建议单独放行 | 借鉴规则可信度和例外管理。关键词不能成为自动封禁依据，也不能整包导入混有去广告、其他网络策略的列表 |
| [PIKACHUIM/luci-app-fuck-pcdn](https://github.com/PIKACHUIM/luci-app-fuck-pcdn) | 按平台选域名，将其写入 `/etc/hosts` 指向 `127.0.0.1`，保存时重启 dnsmasq；内置 25 条域名，支持远程更新 | 机制开销较小，但依赖客户端使用该 DNS 路径；既有连接、缓存、直接 IP、自带解析不一定被切断。README 明示可能影响视频加载。所查 `test.sh` 主要检查文件、JSON 与语法，不能证明识别准确率 | 可以参考平台开关；不据此承诺“强制原始 CDN”必定成功。BetterDPI 不应为了每个检测结果重启 dnsmasq |
| [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) | 汇总广告、追踪、恶意地址、HTTPDNS 和 PCDN 规则，供 DNS/代理规则引擎使用 | 有具体 Bilibili/yt-dlp 下载失败记录；所查当前 domainset 仍含 `+.mcdn.bilivideo.cn`。这是其规则范围选择，不能用来证明本地设备正在上传 | 适合作候选来源，必须按角色拆分“上传控制 / 内容下载 / 共用服务”，并独立核对来源与许可证 |
| [Windows-LPG/Anti-PCDN](https://github.com/Windows-LPG/Anti-PCDN) | 识别一组预设进程名、展示估算上传量，提供手动阻断；Windows 分支调用按可执行文件路径匹配的防火墙规则 | v1.2 源码把系统总上传速率按所监控进程的连接数量分配，属于估算而非逐进程实测；阻断范围是整个程序的出站访问。README 仍写自动识别阻断未完成 | 不能作为精准流量归属或仅阻断 PCDN 子流量的依据；不能把此类分摊方式带进 BetterDPI |
| [unclemcz/ban-pcdn-ip](https://github.com/unclemcz/ban-pcdn-ip) | 作者根据自己网站 CDN 被异常刷量的记录维护来源 IP 段 | 目标是站长侧防刷 CDN 账单，与家庭网关防后台上传不是同一方向；地址复用、动态地址和整段封禁另有波及范围 | 不将此类 IP 段清单直接变成家庭出站封禁表 |

## 能复查的误伤实例

1. [ucxn issue #5](https://github.com/ucxn/Ban-PCDN_Anti-P2P/issues/5)：用户报告高位端口拦截使游戏直连改走中转；作者建议给游戏设备放行，将这种策略限定在不信任的设备。issue 已关闭，不能把关闭理解成该策略对游戏没有影响。
2. [ucxn issue #1](https://github.com/ucxn/Ban-PCDN_Anti-P2P/issues/1)：用户报告关键词规则影响 DeepSeek 及联想应用商店图片的 CNAME 链；作者讨论单独放行，并回复最新版已修复。该记录说明泛关键词及 CNAME 传播可能扩大范围，不代表本次所查版本仍有相同故障。
3. [AdRules issue #217](https://github.com/Cats-Team/AdRules/issues/217)：包含 yt-dlp 从 `mcdn.bilivideo.cn` 下载超时的日志，讨论说明该域名是 PCDN 内容源。issue 转向 yt-dlp 侧处理并关闭。
4. [AdRules issue #262](https://github.com/Cats-Team/AdRules/issues/262)：包含 Mihomo `RuleSet(adrules) using REJECT` 的日志；维护者按重复问题关闭，建议本地放行该域名，或在客户端将地址改写为官方镜像。说明“封 PCDN 内容源”和“避免正常下载受影响”之间存在实际取舍。

以上为公开用户反馈及维护者回复，本次未在同版本客户端和网络上重现，不能据此估算普遍故障率。

## 行为型工具的两个细节

在所查 Womsxd 版本中，`internal/detector/alert.go` 的首次告警只检查窗口内对端数量。上传、下载字节用于记录，不参与首次触发门槛。进入告警后，只要该端口仍有任意流量就延长持续期，不再要求达到原来的对端数量阈值。这对持续 P2P 行为方便，但不应直接变成 BetterDPI 的自动封禁续期策略：封禁后的重试也可能继续出现在 LAN 抓包中。

其 nftables 后端使用 bridge prerouting，按 MAC 和源端口封禁，并有可选元素 TTL；还可选择升级为设备全部 UDP 封禁。BetterDPI 的默认处置需要更小范围：具体连接、有限期限、独立复核，不因换端口自动扩大到整台设备。

该项目的内存说明给出了可复现的 Go 对象基准，但这既不是路由器整机 CPU 数据，也不是识别准确率。本次没有运行其抓包程序或性能基准。

## 流量加速是处置正确性问题

[Linux v6.6 flowtable 文档](https://github.com/torvalds/linux/blob/v6.6/Documentation/networking/nf_flowtable.rst) 明确说明，命中 flowtable 的包会绕过 ingress 之后的经典 IP 转发路径；硬件卸载又有独立路径。普通 forward 链新增 DROP 规则，不足以证明既有加速连接已经停止。

[firewall4 所查模板](https://github.com/openwrt/firewall4/blob/e6f600c458bda7bc2d87b07e78fd06b50c9d7131/root/usr/share/firewall4/templates/ruleset.uc) 包含 ingress flowtable 和 forward 中的 established/related 接受规则。设计必须核实实际设备的规则顺序、卸载路径和双向 NAT 元组，不能直接复制一段 nft 命令就宣称完成精准封禁；也不能为了让拦截生效而默默关闭全局加速。

## 本次固定的源码版本

| 仓库 / 材料 | 所查提交或标签 | 重点位置 |
| --- | --- | --- |
| Womsxd/pcdn-detector | [`c710959b98197e7d58d66cd9429d5c36bcec2ad9`](https://github.com/Womsxd/pcdn-detector/tree/c710959b98197e7d58d66cd9429d5c36bcec2ad9) | `internal/detector/alert.go`、`internal/firewall/nftables.go`、`docs/firewall.md`、`docs/memory.md`；版本 0.0.1-beta.2 |
| Womsxd/luci-app-pcdn-detector | [`dbd0f7e42c31788183fa9bd03b57fd5978c9d8fd`](https://github.com/Womsxd/luci-app-pcdn-detector/tree/dbd0f7e42c31788183fa9bd03b57fd5978c9d8fd) | README；核心程序与 LuCI 前端分别发布 |
| ucxn/Ban-PCDN_Anti-P2P | [`9109f916800f610136c604fd001ad6c94ed4c6f2`](https://github.com/ucxn/Ban-PCDN_Anti-P2P/tree/9109f916800f610136c604fd001ad6c94ed4c6f2) | `README.markdown`、`export/ADGHome.txt`、`License.md` |
| PIKACHUIM/luci-app-fuck-pcdn | [`09f41d8ec17cf81b43363dbb38be96709844253e`](https://github.com/PIKACHUIM/luci-app-fuck-pcdn/tree/09f41d8ec17cf81b43363dbb38be96709844253e) | `banlist.json`、`root/usr/share/rpcd/ucode/fuck-pcdn.uc`、`test.sh` |
| Cats-Team/AdRules 脚本与说明 | [`503b1f034ed882ebbb7fb06a307065a74faa8669`](https://github.com/Cats-Team/AdRules/tree/503b1f034ed882ebbb7fb06a307065a74faa8669) | README、Source.md；脚本和各上游规则的许可证分别适用 |
| Cats-Team/AdRules 生成列表 | [`2d9a7658d0a760ee36242cf360b100f66aed6589`](https://github.com/Cats-Team/AdRules/blob/2d9a7658d0a760ee36242cf360b100f66aed6589/adrules_domainset.txt#L102864) | `adrules_domainset.txt` 中的 `+.mcdn.bilivideo.cn` |
| Windows-LPG/Anti-PCDN | [`c3ab93bb9e5f57fb0219e05d3aadbd5f22c72bf0`](https://github.com/Windows-LPG/Anti-PCDN/blob/c3ab93bb9e5f57fb0219e05d3aadbd5f22c72bf0/Anti-PCDN_v1.2.py) | `update_network_stats`、`block_pid_network`；README 与 v1.2 源码分别核查 |
| unclemcz/ban-pcdn-ip | [`6b181c4707beaeaa07c4dd7bfdf36f469ce4f9a6`](https://github.com/unclemcz/ban-pcdn-ip/tree/6b181c4707beaeaa07c4dd7bfdf36f469ce4f9a6) | README 中的数据来源和适用方向 |
| OpenWrt/firewall4 | [`e6f600c458bda7bc2d87b07e78fd06b50c9d7131`](https://github.com/openwrt/firewall4/tree/e6f600c458bda7bc2d87b07e78fd06b50c9d7131) | `root/usr/share/firewall4/templates/ruleset.uc` |

这里只保存调研结论和引用，没有复制第三方规则库进入发布内容。后续若选用规则，应逐来源核实许可证、保留归属并单独审核用途，不能将汇总项目的脚本许可证视作所有规则的许可证。

具体实现建议见 [Anti-PCDN 设计](anti-pcdn-design.md)。
