# 本地分类规则来源

规则用于“域名归属到应用”的报表分类，不是防火墙或 DNS 拦截规则。不会更改网络放行策略，不会解密连接，也不覆盖数据库原始应用名和主机名。Netify 已识别的原生应用始终优先。

| 来源 | 固定提交 | 纳入规则 | 许可原文 |
| --- | --- | ---: | --- |
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | bcea25493ed28c387660fe49ce1ceb242d2efca0 | 23,685 | COMMUNITY-LICENSE（MIT） |
| [NextDNS/services](https://github.com/nextdns/services) | 4b73ad9798dc4f75842c9e21c1c45b04be524412 | 15 | NEXTDNS-LICENSE（MIT） |

总计 23,700 条 exact/suffix 规则。总数不等于应用数量或识别率；多义规则保留候选，不强选应用。JSON 的 sources、default_rule_source、rule_sources 保存来源、固定版本和规则级出处；RPC 返回 rules_sources，悬停信息反映当前查询实际命中的来源。

## 筛选策略与已知收益

DLC 跳过泛分类、广告标记、include/regexp/keyword 等不适合直接做归属的条目。NextDNS 本来用于服务拦截，不能整库拿来当归属证据。本项目只纳入 build_rules.py 中审查过的 15 条白名单，覆盖 9GAG、BeReal、eBay、Pinterest、Snap、Steam、TikTok、Tinder。共享 CDN、广告服务、泛 Fediverse 集合、local 名称、明显笔误和短链接不纳入；现有 DLC 的规则和多义归属均不被覆盖。

当前 DLC 更新相较此前版本新增 4 条；NextDNS 增加 15 条，两份现有流量副本对 NextDNS 新规则的命中均为 0。它补充未来可能遇到的服务，不代表当前 Unknown 会下降。只有 IP、加密隧道或没有域名信息的连接，不能靠增加域名库可靠识别。

## 可重建过程

分别取得上述两个仓库的固定提交，将工作目录指定为 DLC_CHECKOUT 与 NEXTDNS_CHECKOUT。在项目目录运行：

```sh
python3 build_rules.py /path/to/DLC_CHECKOUT /path/to/output-rules \
  --nextdns-source /path/to/NEXTDNS_CHECKOUT
```

脚本从 Git 读取完整提交号。若使用通过固定提交 URL 取得的源码归档而非 Git checkout，额外提供：

```sh
--revision bcea25493ed28c387660fe49ce1ceb242d2efca0 \
--nextdns-revision 4b73ad9798dc4f75842c9e21c1c45b04be524412
```

显式版本参数用于记录归档来源，不替代下载来源核验。输出应同时包含 community-rules.json、COMMUNITY-LICENSE、NEXTDNS-LICENSE。未提供 NextDNS 源时只构建 DLC；运行时不联网下载或订阅，不自动信任未来上游变更。更新白名单必须复核冲突、许可和回归测试。
