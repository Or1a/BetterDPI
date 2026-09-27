## Features

- Analyze traffic by device, application, and website in LuCI, with paginated rankings and drill-down views.
- View download and upload trends in a mobile-friendly interface.
- Bind an actual router interface manually to track its RX/TX traffic separately from device statistics.
- Keep statistics locally in `/tmp`; they are cleared on reboot. Set a maximum storage size or leave it unlimited.
- Pause and resume traffic analysis without deleting existing history.
- Follow LuCI's English, Simplified Chinese, or Traditional Chinese language setting.
- Supplement Netify's native identification with community classification rules while preserving their sources.

## 功能特性

- 在 LuCI 中按设备、应用和网站分析流量，支持排行榜分页及逐级查看明细。
- 在适配手机的界面中查看下载和上传趋势。
- 手动绑定路由器的实际接口，单独统计其 RX/TX 流量，不与设备统计相加。
- 统计数据仅保存在本机 `/tmp`，重启后清空；可设置最大存储容量，也可不设上限。
- 可暂停或恢复流量分析，暂停时保留已有历史数据。
- 跟随 LuCI 的英文、简体中文或繁体中文语言设置。
- 使用社区分类规则补充 Netify 的原生识别，并保留规则来源信息。

## Command-line download

Run the command matching your router's OpenWrt version. It downloads the package to `/tmp` and verifies its SHA-256 checksum; it does not install anything.

OpenWrt 24.10.8 (IPK):

```sh
wget -O /tmp/BetterDPI-0.2.8-openwrt-24.10.8-all.ipk 'https://github.com/Or1a/BetterDPI/releases/download/V0.2.8/BetterDPI-0.2.8-openwrt-24.10.8-all.ipk' && echo 'fa2cf07d645c741b79ca9b823c3ea96138bbf7b5a4fe2cd6a7d30f72c7bc4380  /tmp/BetterDPI-0.2.8-openwrt-24.10.8-all.ipk' | sha256sum -c -
```

OpenWrt 25.12.5 (APK):

```sh
wget -O /tmp/BetterDPI-0.2.8-openwrt-25.12.5-all.apk 'https://github.com/Or1a/BetterDPI/releases/download/V0.2.8/BetterDPI-0.2.8-openwrt-25.12.5-all.apk' && echo '5de4bbd7c31b0d6d9a116e71e4a8d00e6d2aa756558339a6688869a7b3bf7106  /tmp/BetterDPI-0.2.8-openwrt-25.12.5-all.apk' | sha256sum -c -
```

## 命令行下载

在对应版本的 OpenWrt 路由器上运行上方的一条命令。安装包会下载到 `/tmp` 并校验 SHA-256；命令不会自动安装。
