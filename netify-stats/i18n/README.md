# LuCI 语言接入

页面使用 LuCI 标准全局 `_()` 和英文 msgid，不自行读取 UCI 语言或创建第二个语言开关。LuCI 负责每次页面请求的语言选择以及自动模式；页面的 `html.lang` 用于日期格式，避免与浏览器偏好不一致。

| LuCI 语言 | 翻译源 | 运行文件 |
| --- | --- | --- |
| English / en | JS 与菜单中的英文原文 | 不需要英文 LMO，未命中直接显示原文 |
| 简体中文 / zh-cn（配置兼容 zh_cn） | po/zh_Hans/netify-stats.po | netify-stats.zh-cn.lmo |
| 繁體中文 / zh-tw | po/zh_Hant/netify-stats.po | netify-stats.zh-tw.lmo |

LMO 安装到 `/usr/lib/lua/luci/i18n/`，LuCI 会加载当前语言的全部翻译域；菜单英文 title 使用同一目录的翻译。没有额外前端翻译请求、网络字典或云翻译服务。翻译切换只影响显示，不改已有统计。

LuCI 的无上下文 gettext 键为全局共享。Enabled、Previous、应用品牌等已有系统翻译的词可能采用系统目录里的同义译文，而不是本插件PO里的文字；这是与LuCI共用语言机制的行为。接口流量、最近7天、插件菜单等专用文案已在真实安装目录核对。不得为了强制译文覆盖或改写其他插件的语言文件。

每种中文提供109条翻译。插值使用 `%s`，`String.format()` 由 LuCI 提供。内置应用品牌使用稳定的英文标识，来源通过 `source_type/source_names` 渲染；旧 `name/source` 字段继续兼容，原始社区标签、设备自定义名字和域名保持原样。系统提供的原始诊断（如文件路径、命令报错）仍保持原文，不伪造译文。

## 编译与校验

OpenWrt SDK 配方依赖 `luci-base/host`，Build/Compile 使用其官方 `po2lmo`，从PO源码生成LMO，不依赖提交的预编译文件。`i18n/*.lmo` 仅用于当前源码热更新，也纳入清单校验。

本轮热更新使用 OpenWrt LuCI 官方编译器，固定源码提交 `f4f91aee257bab4eb9c6b7de6160cea294217956`：

[官方 po2lmo 源码](https://github.com/openwrt/luci/tree/f4f91aee257bab4eb9c6b7de6160cea294217956/modules/luci-base/src)

编译器源码按原有 Apache-2.0 声明临时下载并编译，未混入项目分发清单。可复现命令（在项目目录，po2lmo已在PATH）：

```sh
msgfmt --check --check-format -o /dev/null po/zh_Hans/netify-stats.po
msgfmt --check --check-format -o /dev/null po/zh_Hant/netify-stats.po
po2lmo po/zh_Hans/netify-stats.po i18n/netify-stats.zh-cn.lmo
po2lmo po/zh_Hant/netify-stats.po i18n/netify-stats.zh-tw.lmo
node test_i18n_ui.cjs
python3 packaging/check_preparation.py
```

不使用浏览器自动化。Node测试使用PO原文验证初次渲染、异步提示、品牌来源和日期语言；路由器通过独立ucode进程加载真实LMO验证，不切换用户的全局语言。翻译文件变动后需刷新页面与LuCI菜单缓存；缓存可自动重建，不属于用户统计。
