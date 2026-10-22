# LuCI translations

The view uses English gettext keys. Simplified Chinese and Traditional Chinese
sources live in `po/zh_Hans/netify-stats.po` and
`po/zh_Hant/netify-stats.po`. Ship the corresponding compiled catalogs in this
directory whenever a translation changes; the router does not compile PO files.
Device names, domain names, rule sources and application identifiers are data,
not translation keys.

From `netify-stats`, build the official LuCI converter outside the checkout and
regenerate both catalogs:

```sh
set -e
luci_revision=0e6537981036ea221a73e497920192179e9f74c3
luci_build="$(mktemp -d)"
curl --fail --location \
  "https://codeload.github.com/openwrt/luci/tar.gz/$luci_revision" \
  -o "$luci_build/luci.tar.gz"
tar -xzf "$luci_build/luci.tar.gz" -C "$luci_build" --strip-components=4 \
  "luci-$luci_revision/modules/luci-base/src"
make -C "$luci_build" po2lmo
"$luci_build/po2lmo" po/zh_Hans/netify-stats.po i18n/netify-stats.zh-cn.lmo
"$luci_build/po2lmo" po/zh_Hant/netify-stats.po i18n/netify-stats.zh-tw.lmo
node test_i18n_ui.cjs
```

This pinned converter reproduced both previously shipped catalogs byte for byte
before the maintenance translations were added. The Node suite checks catalog
coverage, format placeholders, localized UI behavior and preservation of user
data; it is not a visual test of LuCI on a router.
