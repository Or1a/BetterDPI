# Netify Stats for OpenWrt

本地流量分析 LuCI 页面，当前为 **0.2.8-dev 开发验证版**。源码快照已公开；打包、签名及正式发布仍暂停，不能将此源码当作可安装的稳定版；发布准备见 [RELEASE-PREPARATION.md](RELEASE-PREPARATION.md)。项目源码采用 [GPL-3.0-only](LICENSE)，允许商用，但再分发须遵守 GPL 条款。社区分类规则保留各自许可证和来源信息；v2fly/domain-list-community 与 NextDNS/services 均为 MIT，详见 [规则来源与重建](rules/README.md)。

## 数据与统计口径

界面跟随 LuCI 的语言设置：中文（简体/繁体）使用内置翻译，English 使用英文原文。菜单、图表、分页、设置、提示和内置应用名称一起切换；日期遵循 LuCI 页面的语言。用户设备名与实际域名不翻译。切换语言保存后刷新页面即可，无需插件独立设置。翻译源码与编译说明见 [i18n/README.md](i18n/README.md)。

Netify 在路由器 LAN 接口识别连接，通过本地 socket 交给采集器。采集器按小时存储应用、主机名、设备和收发字节；页面通过 rpcd 查询本地汇总。社区域名规则只辅助应用归类，不增加网络探测，不覆盖原始记录；原生识别优先，不确定的多义规则不强行归类。

- 统计留在 `/tmp/netify-stats/stats.db`，重启即消失。默认查询“全部”，没有 7 天留存限制；“最近7天”仅是筛选。
- 容量设置为 0 时不限；设置 4–4096 MiB 整数时按最早小时回收。字典压缩重复字段，保留原始域名、应用和数值。
- 仅分析开关、容量上限和手动接口绑定保存在 `/etc/netify-stats.json`。关闭分析停止采集并保留历史，重新开启不补算暂停时段的接口流量。
- “接口流量”独立读取用户选定网卡的 RX/TX 计数，不自动绑定 WAN；选择后须“确定保存”，不同接口历史分开。它不与设备排行相加。
- 页面下载在前、上传在后；应用和设备服务端分页；站点明细展示前 5 个但不删除底层记录。
- 已识别的 TCP REDIRECT 连接按原设备归属、校正方向并选取单一方向分支；不解密 VPN。迟到代理映射仍有已知去重边界，见发布准备。

本项目不上传统计到 Netify 云端，也不读取其他带宽监控插件的报表。使用示例配置时须保持 `enable_sink=no`；不要整份覆盖已有 Netify 配置。

## 安装准备

`Makefile` 是待 SDK 实测的 OpenWrt 软件包配方，依赖 Netify、Python 3/SQLite、LuCI 和 rpcd。安装内容以 `packaging/runtime-manifest.json` 核对，包括查询模块和共享生命周期脚本。包不携带默认用户设置，不覆盖已有 `/etc/netify-stats.json`；sysupgrade 保留清单只包含该小配置，不包含统计。

首次安装须自行确认 Netify 的有效 LAN 采集接口、本地 socket 和 JSON 导出配置。参考 `netifyd.conf` 示例，保持本地 socket 路径 `/var/run/netifyd/netifyd.sock`。包不会修改 Netify/OpenClash 配置。共享安装钩子按已保存开关恢复本项目采集器，卸载不删除统计或设置。

**dist 中的 0.2.5-r1 APK 已过期**，不包含本轮修复，不能代表当前源码。它只保留作历史本地测试件，不要用于新安装或发布。

## 无浏览器验证

在本目录运行：

```sh
python3 -m unittest discover -s . -p 'test_*.py'
node test_logic.cjs
node test_interface_ui.cjs
node test_settings_ui.cjs
node test_i18n_ui.cjs
python3 packaging/check_preparation.py
```

检查工具只校验源码，不生成包。`--release` 会明确拒绝尚未满足条件的发布。已知失败场景可单独运行 `python3 reproduce_late_original.py`，当前预期退出 1，不计入通过的测试数。

只通过 SSH、命令行和后端接口验证路由器。历史 `test_ui.cjs` 使用浏览器，已退出当前验证流程，不运行、不纳入后续发布源文件清单。手机视觉布局仍需用户实机确认，静态测试不等于视觉验收。
