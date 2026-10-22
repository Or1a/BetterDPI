# 本地分类规则来源

规则用于“域名归属到应用”的报表分类，不是防火墙或 DNS 拦截规则。不会更改网络放行策略，不会解密连接，也不覆盖数据库原始应用名和主机名。Netify 已识别的原生应用始终优先。

| 来源 | 固定提交 | 纳入规则 | 许可原文 |
| --- | --- | ---: | --- |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | 5b6a77d14fb904a1255f02e2e1b2bcc36ed31f83 | 23,878 | COMMUNITY-LICENSE（MIT） |
| [NextDNS/services](https://github.com/nextdns/services) | 4b73ad9798dc4f75842c9e21c1c45b04be524412 | 17 | NEXTDNS-LICENSE（MIT） |

总计 23,895 条 exact/suffix 规则，比上一版净增 195 条，应用/服务标签由 1,407 增至 1,442 个。JSON 从 717,514 增至 725,429 字节（约 1.1%）。总数不等于应用数量或识别率；多义规则保留候选，不强选应用。JSON 的 sources、default_rule_source、rule_sources 保存来源、固定版本和规则级出处；RPC 返回 rules_sources，悬停信息反映当前查询实际命中的来源。

## 筛选策略与已知收益

DLC 常规导入仍跳过泛分类、广告标记、include/regexp/keyword 等不适合直接做归属的条目。部分 AI 服务仅出现在 `category-ai-cn` 和 `category-ai-!cn` 中，此次通过 `build_rules.py` 的 `REVIEWED_DLC_SERVICES` 定向补入其中 52 条已审查域名，覆盖 Kimi/Moonshot、Qwen、MiniMax、Mistral、OpenRouter、Ollama、Midjourney、GLM、Kling AI、Dify 等服务。未整批导入类别或展开 include；`reviewed_rule_files` 记录每条补充规则的来源文件。若上游删掉白名单域名，构建失败，须重新审查。

NextDNS 本来用于服务拦截，不能整库拿来当归属证据。此次扩充已审查的品牌域名，最终纳入 17 条，覆盖 9GAG、BeReal、eBay、Pinterest、Snap、Steam、TikTok、Tinder。新增规则遇到已有 exact、父 suffix 或更具体的子规则时跳过，保留原归属和歧义。未新增共享 CDN 父域名、广告服务、泛 Fediverse 集合、local 名称、明显笔误或短链接规则。

运行时额外区分已存在的共享基础设施规则：AWS、Cloudflare Workers/Pages/R2、Azure、Akamai、Tencent Cloud 及部分 Google 托管/API 后缀只说明服务商，不代表其租户应用；更具体的独立应用规则和 Netify 原生识别仍优先。只有 IP 或无域名的流量可根据已观测的协议归为 TLS、QUIC、DNS 等，明确保持“应用未识别”；没有证据的仍保留未识别，不按 443 端口、IP 相邻关系或流量大小猜应用。

这些功能不增加网络探测、DNS 查询、规则订阅或后台任务。规则更新也会影响已有历史的报表分类，数据库原始字段不因此改写。已用代表性域名、伪装后缀、协议混合和字节守恒测试验证，尚无本次用户真实流量样本，不能给出实际 Unknown 下降百分比。

## 可重建过程

分别取得上述两个仓库的固定提交，将工作目录指定为 DLC_CHECKOUT 与 NEXTDNS_CHECKOUT。在项目目录运行：

```sh
python3 build_rules.py /path/to/DLC_CHECKOUT /path/to/output-rules \
  --nextdns-source /path/to/NEXTDNS_CHECKOUT
```

脚本从 Git 读取完整提交号。若使用通过固定提交 URL 取得的源码归档而非 Git checkout，额外提供：

```sh
--revision 5b6a77d14fb904a1255f02e2e1b2bcc36ed31f83 \
--nextdns-revision 4b73ad9798dc4f75842c9e21c1c45b04be524412
```

显式版本参数用于记录归档来源，不替代下载来源核验。输出应同时包含 community-rules.json、COMMUNITY-LICENSE、NEXTDNS-LICENSE。未提供 NextDNS 源时只构建 DLC；运行时不联网下载或订阅，不自动信任未来上游变更。更新白名单必须复核冲突、许可和回归测试。
