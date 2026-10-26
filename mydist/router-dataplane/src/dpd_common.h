/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd_common.h - shared ABI between the dpd_fastpath BPF program and dpdctl.
 *
 * mydist / router-dataplane
 *
 * REDLINES (see docs / 工作计划.md §3-§4). The BPF program:
 *   - does NOT do NAT            (NAT has exactly one owner: einat-ebpf)
 *   - does NOT read einat maps   (no coupling, no shared ABI to rot)
 *   - does NOT depend on conntrack (self-learning only)
 *   - is a TC *ingress* hook only
 *   - returns TC_ACT_UNSPEC on every path that must not take over a packet,
 *     so it always yields to the rest of the filter chain
 *   - has an `enable` killer switch in dpd_cfg
 *
 * Hook layout. Every line below was MEASURED (`bpftool net show` + `tc filter
 * show`) in QEMU x86_64 on 2026-10-17 with the real image, honk running against
 * a real VLESS/REALITY node, einat attached, router-acl at pref 90:
 *
 *   br-lan ingress : honk TCX lan_ingress_l2        -> dpd_fastpath (pref 100)
 *   br-lan egress  : honk TCX lan_egress_l2         <- we are NOT here
 *   eth0  ingress  : honk TCX lan_ingress_l2 (slave) -> dpd (pref 100)
 *   eth1  ingress  : honk TCX wan_ingress_l2
 *                    einat TCX ingress_rev_snat
 *                    router-acl (pref 90)           -> dpd_fastpath (pref 100)
 *   eth1  egress   : honk TCX wan_egress_l2
 *                    einat TCX egress_snat
 *                    router-acl (pref 90)
 *   dae0  ingress  : honk TCX dae0_ingress
 *
 * Two ordering facts make the cascade safe, and neither is a convention we
 * hope upstream keeps:
 *
 *  1. sch_handle_ingress()/sch_handle_egress() run tcx_run() BEFORE tc_run().
 *     Every TCX program (honk's, einat's) therefore sees a packet before every
 *     classic cls_bpf filter (router-acl's, ours). dpd is structurally BEHIND
 *     the interception layer: whatever honk declines falls through to us, and
 *     whatever honk proxies is redirected to dae0 and never reaches us. This is
 *     *why* the acceleration layer and the transparent proxy can coexist.
 *
 *  2. Among classic filters, ordering is by pref: router-acl 90 < dpd 100, so
 *     the policy layer decides before we do.
 *
 * dpd must stay a *classic* filter. Moving it to TCX would jump it in front of
 * honk and it would start stealing proxied flows. files/dpd-fastpath.sh checks
 * at attach time that nothing else sits after us and downgrades to observe if
 * something does.
 *
 * Acceleration is IPv4-only and gated on einat: taking a packet over skips
 * NETFILTER, not just the routing lookup, so the return path of an accelerated
 * flow needs einat's conntrack-free NAT plus the blanket WAN->LAN accept that
 * einat injects into fw4. IPv6 has no NAT in this baseline (no NAT66, by
 * design), so a v6 flow's untracked reply would be rejected by fw4 -- v6 is
 * therefore never accelerated (see dpd_policy / dpd_may_accelerate()).
 */

#ifndef __DPD_COMMON_H
#define __DPD_COMMON_H

#include <linux/types.h>

/* 3: added ST_FRAG_SKIP and ST_DNS_SKIP (see dpd_may_accelerate())
 * 4: added ST_FIB_RETRY -- bpf_fib_lookup() without a neighbour succeeded on a
 *    second pass with BPF_FIB_LOOKUP_SKIP_NEIGH. This is the PPPoE case: a ppp
 *    device has no neighbour table, so the first lookup answers
 *    BPF_FIB_LKUP_RET_NO_NEIGH and, before this, EVERY packet on a PPPoE WAN
 *    failed the lookup (measured 2026-10-18: fib_ok 0 / fib_fail 29) and
 *    nothing was ever accelerated. */
/* 5: added ST_DHCP_SKIP and ST_BCAST_SKIP -- DHCP and every non-unicast
 *    destination must reach the local stack. A DISCOVER (0.0.0.0 ->
 *    255.255.255.255, UDP 68->67) matched the default route and was
 *    redirect_neigh()'d out the WAN, so odhcpd never saw it and LAN clients
 *    got no lease (measured 2026-10-27: fib_ok +2, neigh_ok +2, no lease;
 *    with dpd stopped the same client leased 192.168.10.204 immediately).
 * 6: dpd_flow_val now carries the L2 header (smac next to dmac) and a 32-bit
 *    millisecond timestamp, so the redirect can be a plain bpf_redirect()
 *    instead of bpf_redirect_neigh() -- the latter re-runs the route lookup and
 *    the neighbour lookup for every packet. The value stays 24 bytes, so an
 *    object upgrade can reuse the pinned map (see dpd_flow_val).
 * 7: stateful mode *primes* each direction before it starts redirecting: the
 *    first DPD_FLOW_PRIME+1 packets of a learned flow still traverse netfilter.
 *    Without it a TCP flow's handshake never completes as far as conntrack is
 *    concerned, because the client's final ACK is already taken over: the entry
 *    sticks in SYN_RECV (measured 2026-10-27: packets=1 bytes=60 for a 12.4 GB
 *    download) and dies on the 120 s syn_recv timer while the flow is still
 *    running. Priming costs two packets per flow, makes the entry reach
 *    ESTABLISHED, and keeps nf_conntrack_count / `ct state` rules / the
 *    transition back to the slow path meaningful. No value-layout change: the
 *    counter lives in the spare high byte of dpd_flow_val.flags. */
#define DPD_ABI_VERSION		7

/* name of the TC section in the BPF object; dpdctl/init pass this to tc(8) */
#define DPD_BPF_SECTION		"classifier"

/* TC priority. The interception layer owns TCX (no pref at all), so this pref
 * only orders us among *classic* filters: router-acl owns 90 on the WAN, we own
 * 100 everywhere. Nothing may collide. */
#define DPD_TC_PREF		100
#define DPD_TC_HANDLE		100

/* default object path inside the image */
#define DPD_BPF_OBJECT		"/lib/bpf/dpd_fastpath.bpf.o"
#define DPD_PIN_DIR		"/sys/fs/bpf"

/* dpd_vlans: optional segment allow-list, u16 VLAN id -> u8 1 */
#define DPD_VLAN_MAP_MAX	64

enum dpd_mode {
	DPD_MODE_OFF		= 0,	/* passthrough, still counted	*/
	DPD_MODE_OBSERVE	= 1,	/* fib lookup + counters, never touch   */
	DPD_MODE_STATELESS	= 2,	/* every packet: fib -> redirect_neigh  */
	DPD_MODE_STATEFUL	= 3,	/* learn on miss, redirect on hit       */
	DPD_MODE_NEIGH_PROBE	= 9,	/* #14: answer "does bpf_redirect_neigh
					 *      actually work here?" at runtime */
};

/* Which packets may be taken over (dpd_cfg.policy). */
enum dpd_policy {
	DPD_POLICY_ALLOW_ALL	= 0,	/* every IPv4 forwarding packet	*/
	DPD_POLICY_VLANS_ONLY	= 1,	/* only VLAN ids in dpd_vlans; an
					 * untagged packet is never eligible  */
};

/* how to place the packet on the wire once the FIB says "forward me" */
enum dpd_redirect {
	DPD_REDIR_AUTO		= 0,	/* bpf_redirect() with the header the
					 * FIB lookup already gave us, when the
					 * egress is a plain Ethernet device;
					 * bpf_redirect_neigh() otherwise (ppp,
					 * tunnels, VLAN/lower devices)	*/
	DPD_REDIR_FORCE_NEIGH	= 1,	/* always bpf_redirect_neigh(), i.e. a
					 * route + neighbour lookup per packet.
					 * The pre-ABI-6 behaviour; keep it as
					 * the escape hatch			*/
	DPD_REDIR_FORCE_DEV	= 2,	/* bpf_redirect(ifindex, 0) - ppp / veth */
};

struct dpd_config {
	__u32	abi_version;
	__u32	mode;		/* enum dpd_mode			*/
	__u32	enable;		/* killer switch, 0 = always UNSPEC	*/
	__u32	redirect;	/* enum dpd_redirect			*/
	__u32	flow_ttl_ms;	/* Mode B entry freshness		*/
	__u32	policy;		/* enum dpd_policy			*/
	__u32	flags;		/* reserved				*/
};

enum dpd_stat_idx {
	ST_PKT_TOTAL = 0,	/* every packet entering the program	*/
	ST_BYTES,		/* bytes entering the program		*/
	ST_NON_IP,		/* not IPv4/IPv6 (arp, pppoe ctrl, ...)	*/
	ST_FIB_OK,		/* bpf_fib_lookup -> RET_SUCCESS	*/
	ST_FIB_FAIL,		/* any other fib return code		*/
	ST_REDIRECT_OK,		/* bpf_redirect() accepted the packet	*/
	ST_NEIGH_OK,		/* bpf_redirect_neigh() accepted it	*/
	ST_NEIGH_FAIL,		/* bpf_redirect_neigh() -> SHOT		*/
	ST_FLOW_HIT,		/* Mode B flow map hit			*/
	ST_FLOW_MISS,		/* Mode B flow map miss			*/
	ST_FLOW_WRITE,		/* Mode B entry written			*/
	ST_TTL_DROP,		/* ttl/hop_limit <= 1			*/
	ST_LOCAL,		/* dest is local / not forwarded	*/
	ST_V6_SKIP,		/* eligible-looking IPv6: never accelerated
				 * (no NAT66 -> the reply would have no
				 * conntrack state and fw4 would reject it) */
	ST_VLAN_SKIP,		/* policy=vlans_only and this packet is not in
				 * dpd_vlans (incl. untagged)		*/
	ST_FRAG_SKIP,		/* IPv4 fragment: the L4 header only exists in
				 * the first one, so there is no honest flow key
				 * and nothing to gate the DNS check on. The
				 * whole stream goes to the stack, which is also
				 * what einat needs to build its binding.	*/
	ST_DNS_SKIP,		/* LAN->WAN port 53: netfilter (dns_redirect=1)
				 * would have DNATed it to the router itself. */
	ST_FIB_RETRY,		/* first bpf_fib_lookup said NO_NEIGH (ppp/tunnel:
				 * no neighbour table); a second pass with
				 * BPF_FIB_LOOKUP_SKIP_NEIGH found the route and
				 * the dev emit path delivered (measured on a
				 * PPPoE WAN: redirect_ok +9, peer's access log
				 * recorded the request).			*/
	ST_DHCP_SKIP,		/* UDP 67/68: the DHCP server is local, a
				 * DISCOVER to 255.255.255.255 must never be
				 * redirected. See dpd_is_dhcp().		*/
	ST_BCAST_SKIP,		/* non-unicast destination (limited broadcast,
				 * 224/4, ff00::/8): has to be delivered
				 * locally / flooded, not routed.		*/
	ST__MAX,
};

/* stored per entry in dpd_iface: flags userspace learned from the kernel */
#define DPD_IF_F_NOARP		0x0001	/* IFF_NOARP		*/
#define DPD_IF_F_POINTOPOINT	0x0002	/* IFF_POINTOPOINT	*/
#define DPD_IF_F_UP		0x0004	/* IFF_UP		*/
/* The device is stacked on a lower one (/sys/class/net/X/iflink != X's own
 * index): a VLAN sub-interface, a veth peer, a macvlan, a tunnel. Such a device
 * builds its L2 header in dev_hard_header() -- a VLAN device pushes the 802.1Q
 * tag there -- so writing the header ourselves and calling bpf_redirect() would
 * emit a frame that is wrong (untagged where a tag was owed, or tagged twice).
 * The cheap Ethernet emit path (dpd_emit_l2()) is therefore skipped for them and
 * they keep using bpf_redirect_neigh(). Taught by `dpdctl ifaces`. */
#define DPD_IF_F_LOWER		0x0008

/* dpd_flow_val.flags: Mode B remembered that this egress has no neighbour
 * (a FIB lookup needed BPF_FIB_LOOKUP_SKIP_NEIGH), so the shortcut hit path must
 * use bpf_redirect() rather than bpf_redirect_neigh(). Stored in what used to be
 * padding, so the structure layout is unchanged. */
#define DPD_FLOW_F_NO_NEIGH	0x0001

/* dpd_flow_val.flags bits 8..15: how many packets of this direction have been
 * let through netfilter since the entry was learned (saturating). A hit is only
 * redirected once the counter reaches DPD_FLOW_PRIME, so the first
 * DPD_FLOW_PRIME+1 packets of each direction walk the stack -- which is what
 * lets conntrack see a whole TCP handshake (SYN, SYN-ACK, ACK) instead of
 * stopping at SYN_RECV. See DPD_ABI_VERSION 7. */
#define DPD_FLOW_PRIME_SHIFT	8
#define DPD_FLOW_PRIME_MASK	0xff00
#define DPD_FLOW_PRIME		1	/* extra packets per direction	*/

/*
 * Mode B flow key. Kept at a fixed 48 bytes to keep the LRU hash cheap.
 * IPv4 addresses are stored right-aligned into the 16-byte v6 slots.
 */
struct dpd_flow_key {
	__u32	ifindex;	/* ingress device			*/
	__u8	family;		/* AF_INET / AF_INET6			*/
	__u8	proto;		/* IPPROTO_TCP / UDP / ...		*/
	__u16	_pad;
	__be32	saddr[4];
	__be32	daddr[4];
	__be16	sport;
	__be16	dport;
};

/*
 * Mode B flow value -- 24 bytes, and that size is part of the pinned-map ABI: a
 * bpf_map_update_elem() value that changed size makes libbpf refuse to reuse
 * /sys/fs/bpf/dpd_flows, i.e. `tc filter add` fails after an in-place upgrade
 * until the pin is removed. Keep it at 24.
 *
 * dmac/smac are the pair bpf_fib_lookup() filled in for this flow. Caching them
 * is what lets the hit path emit with bpf_redirect() instead of
 * bpf_redirect_neigh(); see dpd_emit_l2() in the BPF program.
 *
 * last_seen_ms is CLOCK_MONOTONIC in milliseconds (the same clock as
 * bpf_ktime_get_ns()), truncated to 32 bits: it wraps every ~49.7 days, so the
 * freshness test is done on the *signed difference* (age >= 0 && age < ttl),
 * never on an absolute comparison. That buys us 4 bytes for smac without growing
 * the entry.
 *
 * flags carries DPD_FLOW_F_NO_NEIGH in bit 0 and the per-direction prime
 * counter in bits 8..15 (DPD_FLOW_PRIME_*). The counter is the reason a
 * redirect does not start on the first hit; see the ABI 7 note above. */
struct dpd_flow_val {
	__u32	egress_ifindex;
	__u32	last_seen_ms;	/* bpf_ktime_get_ns()/1e6, wraps	*/
	__u8	dmac[6];	/* next hop MAC from the FIB lookup	*/
	__u8	smac[6];	/* egress dev_addr from the FIB lookup	*/
	__u16	flags;		/* DPD_FLOW_F_* | prime counter		*/
};

#endif /* __DPD_COMMON_H */
