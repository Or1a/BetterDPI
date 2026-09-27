include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-netify-stats
PKG_VERSION:=0.2.8
PKG_RELEASE:=0
# Development preparation only: package release remains paused pending validation.
PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Netify Stats contributors
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-netify-stats
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Local Netify traffic statistics
  DEPENDS:=+netifyd +python3 +python3-sqlite3 +luci-base +rpcd
  PKGARCH:=all
endef

define Package/luci-app-netify-stats/description
  Local, reboot-volatile per-device and per-application traffic statistics.
  Requires netifyd's local flow socket to be configured separately.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Package/luci-app-netify-stats/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/usr/sbin $(1)/usr/lib/netify-stats
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd $(1)/usr/share/netify-stats
	$(INSTALL_DIR) $(1)/usr/share/licenses/luci-app-netify-stats
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d $(1)/usr/share/luci/menu.d
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/status
	$(INSTALL_BIN) ./netify-stats.init $(1)/etc/init.d/netify-stats
	$(INSTALL_DATA) ./packaging/netify-stats.keep $(1)/lib/upgrade/keep.d/netify-stats
	$(INSTALL_BIN) ./netify_collector.py $(1)/usr/sbin/netify-stats-collector
	$(INSTALL_BIN) ./netify_rpc.py $(1)/usr/libexec/rpcd/netify-stats
	$(INSTALL_BIN) ./packaging/post-install $(1)/usr/lib/netify-stats/package-post-install
	$(INSTALL_BIN) ./packaging/pre-deinstall $(1)/usr/lib/netify-stats/package-pre-deinstall
	$(INSTALL_DATA) ./netify_accounting.py ./netify_classify.py ./netify_control.py ./netify_storage.py ./netify_proxy.py ./netify_query.py $(1)/usr/lib/netify-stats/
	$(INSTALL_DATA) ./rules/community-rules.json ./rules/COMMUNITY-LICENSE ./rules/NEXTDNS-LICENSE $(1)/usr/share/netify-stats/
	$(INSTALL_DATA) ./LICENSE $(1)/usr/share/licenses/luci-app-netify-stats/LICENSE
	$(INSTALL_DATA) ./acl.json $(1)/usr/share/rpcd/acl.d/luci-app-netify-stats.json
	$(INSTALL_DATA) ./menu.json $(1)/usr/share/luci/menu.d/luci-app-netify-stats.json
	$(INSTALL_DATA) ./netify-stats.js $(1)/www/luci-static/resources/view/status/netify-stats.js
	$(INSTALL_DATA) ./i18n/netify-stats.zh-cn.lmo ./i18n/netify-stats.zh-tw.lmo $(1)/usr/lib/lua/luci/i18n/
endef

define Package/luci-app-netify-stats/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
exec /usr/lib/netify-stats/package-post-install
endef

define Package/luci-app-netify-stats/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
exec /usr/lib/netify-stats/package-pre-deinstall
endef

$(eval $(call BuildPackage,luci-app-netify-stats))
