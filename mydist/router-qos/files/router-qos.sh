#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# router-qos.sh - shared helpers for the CAKE QoS.
#
# Sourced by:
#   /etc/init.d/router-qos
#   /etc/hotplug.d/iface/92-router-qos
#
# One algorithm, chosen automatically
# -----------------------------------
# There is nothing to configure here and nothing in the UI. The box picks the
# best scheduler the running kernel offers, in this order:
#
#   cake      diffserv4 + nat        full flow isolation, DSCP tins, AQM
#   fq_codel                         per-flow fairness + AQM (no tins)
#
# Whichever one is installed is logged, so the choice is visible in `logread`
# without exposing a knob that can silently make latency worse.
#
# Why there is no `bandwidth` argument
# ------------------------------------
# CAKE with a `bandwidth` is a shaper: it makes the link look slower than it is
# so that its own queue, rather than the driver's, is the one that fills. That
# needs the operator to type their real uplink rate, and a wrong number is worse
# than no shaper at all -- too high and the queue never fills (no effect), too
# low and the link is needlessly throttled.
#
# This firmware does not ask. CAKE runs unlimited: no rate, no per-packet
# framing/MPU arithmetic, just flow isolation and AQM. The queue that matters on
# a home uplink is at the ISP end anyway, and the local queue still needs
# fairness (one bulk transfer must not starve a game) and AQM (drop/mark early
# instead of letting the driver queue grow to seconds). Unlimited CAKE does both.
#
# Why there is no classifier program here
# ---------------------------------------
# The old shape of this was HTB plus a cascade of `tc filter` classifiers, one
# per class, and every new class meant another filter. CAKE replaces all of it
# with a single qdisc that does its own per-flow fairness, its own ack
# filtering and its own DSCP->tin mapping. So the whole QoS is one qdisc:
#
#   tc qdisc replace dev <wan> root cake diffserv4 nat
#
# That is the "single TC program + CAKE" from the plan, taken literally.
#
# Why the download direction is not shaped here
# ---------------------------------------------
# The plan called for a second CAKE on an IFB, fed by a mirror filter in the
# WAN's ingress hook, so both directions would be shaped. That was measured on
# the host with a veth pair and it does not work (build/ifb-probe.sh):
#
#   mirror + pass, cake on the IFB   ping 3/3, IFB saw 4 pkt
#   redirect,      cake on the IFB   ping 3/3, IFB saw 10 pkt
#
# `mirror` copies the packet, so the *original* still goes on to the LAN
# untouched; the IFB only ever shapes the copy. The ping still succeeds, so
# nothing looks broken, but the download is not actually shaped. Only
# `redirect` really shapes, and redirect steals the packet out of the chain.
#
# That matters because on this WAN device the ingress cls_bpf chain is the whole
# datapath:
#
#   einat    TCX links (the kernel runs tcx_run() before tc_run())
#   pref 90  router-acl
#   pref 100 dpd
#
# A redirect would terminate the chain and starve router-acl and dpd. Putting
# the redirect last would keep them running, but an IFB re-injects the packet
# with its own interface as the source, and fw4 matches zones by `iifname` -- so
# the re-injected download would no longer look like it came from the WAN zone
# and fw4 forward would drop it.
#
# So: upload only. On a home link the upload really is the queue this box owns
# -- the downstream is queued at the ISP's end. Fairness and AQM on the half the
# router actually transmits is the honest half, and it is the half that needs no
# IFB, no extra filter and no interference with the eBPF datapath.
#
# Interaction with the other TC users on the WAN device
# ---------------------------------------------------
# A root qdisc and a clsact qdisc are independent: clsact lives at handle
# ffff: and carries the ingress and egress filter chains, while root is the
# device's normal transmit queue. Replacing root does not touch the filters, so
# router-acl (pref 90) and dpd (pref 100) keep working with CAKE installed.
# This is verified in build/qemu-qos.sh.
#
# clsact vs ingress qdisc: the reverse is not true -- a plain `ingress` qdisc
# only carries the ingress hook, so router-acl could not attach its egress
# program later. router-acl creates clsact, so nothing here needs to.

rq_log() {
	logger -t router-qos "$*" 2>/dev/null || true
}

rq_resolve_dev() {
	local want="$1" dev=""

	[ -n "$want" ] || return 1
	[ -e "/sys/class/net/$want" ] && { echo "$want"; return 0; }
	. /lib/functions/network.sh
	network_get_device dev "$want" 2>/dev/null
	[ -n "$dev" ] && { echo "$dev"; return 0; }
	return 1
}

# Every device named by RQ_WAN (space separated, so multi-WAN just lists the
# logical interfaces), resolved and de-duplicated. Missing ones are skipped:
# a PPPoE device does not exist until the link is up, and the hotplug script
# applies the qdisc then.
rq_all_devs() {
	local want dev

	for want in $RQ_WAN; do
		dev="$(rq_resolve_dev "$want")" || continue
		echo "$dev"
	done | awk '!seen[$0]++'
}

# The maintained policy. `nat` keeps both directions of a NATed flow in the same
# tin; `diffserv4` keeps the four tins (Bulk / Best Effort / Video / Voice).
# No `bandwidth`, so this is the unlimited scheduler: fairness and AQM only.
rq_best_opts() {
	printf '%s' 'diffserv4 nat'
}

# When multi-WAN load balancing is on, its uplinks get the same qdisc -- one
# uplink shaped and another not would just move the queue to the unshaped one.
# Run inside $(...) so it cannot disturb the caller's config_load state.
rq_mwan_devs() {
	local on

	config_load mydist_mwan 2>/dev/null || return 0
	config_get on global enabled 0
	[ "$on" = "1" ] || return 0
	config_foreach rq_mwan_one wan
}

rq_mwan_one() {
	local ifn

	config_get ifn "$1" interface
	config_get_bool on "$1" enabled 1
	[ "$on" = "1" ] && [ -n "$ifn" ] && echo "$ifn"
	return 0
}

rq_apply() {
	local dev="$1" opts="$2"

	[ -e "/sys/class/net/$dev" ] || return 1
	if tc qdisc replace dev "$dev" root cake $opts 2>/dev/null; then
		rq_log "apply: cake $opts on $dev"
		return 0
	fi
	# No cake module (or a kernel that rejects the options): keep per-flow
	# fairness instead of leaving the device on its default queue.
	if tc qdisc replace dev "$dev" root fq_codel 2>/dev/null; then
		rq_log "apply: cake unavailable on $dev, fell back to fq_codel"
		return 0
	fi
	rq_log "apply: neither cake nor fq_codel worked on $dev"
	return 1
}

rq_clear() {
	local dev="$1"

	[ -n "$dev" ] || return 0
	[ -e "/sys/class/net/$dev" ] || return 0
	# `qdisc del root` puts the device back on its default (noqueue for a
	# virtual device, the driver default otherwise). It does not touch the
	# clsact qdisc, so the ingress/egress filter chains are unaffected.
	tc qdisc del dev "$dev" root 2>/dev/null
}

rq_enabled_qdisc() {
	local dev="$1"

	[ -e "/sys/class/net/$dev" ] || return 1
	tc qdisc show dev "$dev" 2>/dev/null | grep -qE '(^| )(cake|fq_codel)( |$)'
}

rq_status() {
	local dev="$1"

	echo "--- root qdisc on ${dev:-<unresolved>} ---"
	if [ -z "$dev" ]; then
		echo "  (WAN device not resolved)"
		return 0
	fi
	tc -s qdisc show dev "$dev" 2>/dev/null || echo "  (tc failed)"
	echo "--- clsact filters on $dev (owned by router-acl / dpd, not us) ---"
	tc filter show dev "$dev" ingress 2>/dev/null | grep -E '^filter' || true
	tc filter show dev "$dev" egress 2>/dev/null | grep -E '^filter' || true
}
