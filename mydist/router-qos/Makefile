# SPDX-License-Identifier: GPL-2.0-only
#
# mydist / router-qos : CAKE on the WAN, one qdisc, no classifier cascade.
#
# Script-only package: no compilation, no eBPF object, nothing to shape but the
# upload. CAKE does its own per-flow fairness, ack filtering and DSCP->tin
# mapping, so "single TC program + CAKE" is taken literally: one root qdisc.
# The point is that it replaces the old HTB + classifier-cascade shape, not that
# it adds another program to the datapath.
#
# The download direction is not shaped. It would need an IFB, and both ways of
# feeding one are wrong on this device -- see the header of files/router-qos.sh
# for the measurement. Briefly: a mirror leaves the real packet unshaped, and a
# redirect either starves router-acl/dpd or changes the interface fw4 matches
# zones on.

include $(TOPDIR)/rules.mk

PKG_NAME:=router-qos
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=mydist

include $(INCLUDE_DIR)/package.mk

define Package/router-qos
  SECTION:=net
  CATEGORY:=Network
  TITLE:=mydist CAKE QoS (single root qdisc on the WAN)
  URL:=https://github.com/kwrum1/openwrt-honk
  DEPENDS:=+kmod-sched-core +kmod-sched-cake +tc-bpf
endef

define Package/router-qos/description
  QoS for the WAN upload, with nothing to configure.

    tc qdisc replace dev <wan> root cake diffserv4 nat

  One qdisc, no classes, no rate, no filter cascade: CAKE does the per-flow
  fairness, the AQM and the DSCP->tin mapping itself. It runs unlimited rather
  than shaped to an operator-supplied bandwidth, because a wrong rate is worse
  than no shaper. If the kernel has no cake module the same script installs
  fq_codel, so fairness and AQM survive.

  Enabled by default; the only uci entries are `enabled` and `wan` (a list, so
  multi-WAN uplinks are covered, automatically including the ones mydist_mwan
  load balances over).

  A root qdisc and the clsact qdisc that router-acl creates are independent
  (clsact lives at handle ffff:), so replacing root does not disturb the
  router-acl (pref 90) or dpd (pref 100) ingress/egress filter chains.

  The download direction is deliberately not shaped. An IFB is needed for that,
  and on this device a mirror leaves the real packet unshaped while a redirect
  either starves router-acl/dpd or breaks fw4's zone matching -- the long
  version, with the measurement, is in files/router-qos.sh.
endef

define Package/router-qos/conffiles
/etc/config/router_qos
endef

# Script-only package. Without this the default Build/Compile runs `make` in a
# directory that has no Makefile at all and the build dies with
# "No targets specified and no makefile found".
define Build/Compile
	true
endef

define Package/router-qos/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DIR) $(1)/usr/libexec

	$(INSTALL_BIN) ./files/router_qos.init $(1)/etc/init.d/router-qos
	$(INSTALL_DATA) ./files/router-qos.sh $(1)/usr/libexec/router-qos.sh
	$(INSTALL_DATA) ./files/router_qos.config $(1)/etc/config/router_qos
	$(INSTALL_DATA) ./files/92-router-qos $(1)/etc/hotplug.d/iface/92-router-qos
endef

$(eval $(call BuildPackage,router-qos))
