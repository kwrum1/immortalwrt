# mydist 源码说明

本仓库是 `VIKINGYFY/immortalwrt` 的 fork，`mydist` 分支 = **上游 `5fda931` + 本项目的源码改动 + `mydist/` 数据面包**。

CI 只对 **X86 / ROCKCHIP** 使用这个分支；IPQ / MTK 仍构建上游的 `main` / `owrt`。

---

## 1. 分支与基线

| 项 | 值 |
|---|---|
| 上游 | `VIKINGYFY/immortalwrt` |
| 基线提交 | `5fda9319c9e671f28ead0959ae872abf63c9ce78`（本固件验证过的提交） |
| 本分支 | `mydist` |
| 用途 | X86 / ROCKCHIP 的“新源码 einat 优化版” |
| 上游 `owrt` | 保持不动，供需要时对比/同步 |

固定基线而不是跟最新，是为了让“能出固件”这件事可复现：所有补丁、包、脚本都在这一个提交上验证过。

---

## 2. 源码改动清单（11 个文件）

| 文件 | 改动 | 为什么 |
|---|---|---|
| `include/target.mk` | `DEFAULT_PACKAGES.router` 去掉 `kmod-nft-offload`；`odhcpd-ipv6only` → `odhcpd` | einat 要求关闭一切 flow offload；DHCPv4 交给 odhcpd（dnsmasq 不再是 DHCP/DNS 权威） |
| `package/base-files/files/bin/config_generate` | LAN 默认 `192.168.10.1`；主机名 `OWRT` | 与 CI 的 `WRT_IP` / `WRT_NAME` 一致，避免首次启动后还要再改 |
| `package/network/config/firewall4/Makefile` | DEPENDS 去掉 `+kmod-nft-offload` | 与 `include/target.mk` 成对，否则包依赖会把模块拉回来 |
| `package/network/config/firewall4/patches/002-default-enable-fullcone.patch` | `flow_offloading=0`、`flow_offloading_hw=0`，保留 `fullcone=1` | offload 的快速路径会绕过 TC；fullcone 供 fw4 兜底使用 |
| `package/network/config/wifi-scripts/files/lib/wifi/mac80211.uc` | 默认 SSID/密码/加密/国家写死为 CI 的值 | CI 仍会再 sed 一次，这里只是让源码默认值自洽 |
| `package/network/services/dnsmasq/files/dhcp.conf` | `config dhcp lan` 加 `option ignore 1`；`dhcpv6` 改 `server` | dnsmasq 不参与 DHCP；odhcpd 同时发 v4 + v6 |
| `package/network/services/odhcpd/files/odhcpd.defaults` | `maindhcp=1`、`dhcpv6=$V6MODE` | 让 odhcpd 成为唯一的地址分配者 |
| `target/linux/x86/Makefile` | 去掉 `i915-firmware-dmc` 与 `DEFAULT_PACKAGES += video-support` | 路由器不用核显，i915 一项约占固件 5% |
| `target/linux/x86/image/64.mk` | 去掉 `kmod-drm-i915` | 同上 |
| `target/linux/x86/image/generic.mk` | 去掉 `kmod-drm-i915` | 同上 |
| `target/linux/x86/image/legacy.mk` | 去掉 `kmod-drm-i915` | 同上 |

> 这些改动是**源码级**的；CI 的 `Handles.sh` 还会对上游树做同样的 sed（幂等），所以同一份补丁既能走 fork，也能走原版源码。

---

## 3. `mydist/` 包清单

`mydist/` 是这棵树的“自有 feed”，构建前由 CI 的 `Scripts/Packages.sh` 拷进 `package/mydist/`。

| 包 | 来源 | 功能 | 替换了什么 | 与“原版”的区别 |
|---|---|---|---|---|
| **einat-ebpf** | `EHfive/einat-ebpf` v0.1.11，上游 release 的静态 musl 二进制（x86_64 / aarch64） | TC 上的 **Full Cone NAT44**（EIM + EIF），不依赖 conntrack | `fw4` 的 `MASQUERADE`（conntrack + 端口受限映射） | 外网可主动回连；NAT 状态对 eBPF 可见；端口段 `20000-29999`；支持 hairpin |
| **router-dataplane**（`dpd-fastpath`） | 本仓库 `src/dpd_fastpath.bpf.c` + `dpdctl.c`，构建期用 host clang 编 BPF | TC **ingress** 快路径：已建立连接的转发走 `bpf_fib_lookup` 直接重定向；`downlink=1` 时 WAN→LAN 回程也加速 | “每个包都过 netfilter 规则链”的路径 | **不做 NAT**、**不共享 einat 的 map/ABI**、**不做 conntrack**；只挂 classic `cls_bpf`（不能改 TCX，否则会抢 honk 的代理流）；honk p1 把 direct 判决交回 classic 后，直连仍可加速 |
| **honk（p1）** | `kwrum1/openwrt-honk`：固定上游 `Glassyiris/honk` commit + `ci/patches/honk-direct-unspec.py`，`core-p1` release（x86_64/aarch64/armv7） | TCX 透明代理；p1 把 direct 出口改为 `TC_ACT_UNSPEC` + `DIRECT_UNSPEC_MARK` | 代理流 redirect 到 `dae0`；直连流进 classic 交给 dpd；NAT 仍是 einat | 上游原版 core（direct 返回 `OK`）时 dpd 自动 `observe`；p1 用 `/usr/share/honk/direct-unspec` 识别 |
| **router-acl** | 本仓库 `src/acl.bpf.c` + `aclctl.c` | WAN 侧 eBPF ACL：挡住无主入站；`bypass` 模式加 mark + `notrack`，把 NAT 流逃离 conntrack | 叠加在 fw4 之上的策略层（fw4 仍兜底） | 比 stock 更严；`mode=guard` 默认开；`import_firewall=1` 同步端口转发 |
| **router-qos** | 本仓库，纯脚本 | WAN 上一条 `root qdisc`，**无限速**（只做逐流公平与 AQM）：≤1 Gbit/s 用 `cake diffserv4 nat`（带 DSCP 分档），更快的链路或无 cake 模块时自动换 `fq_codel`；无 UI、无速率参数、默认开启 | 默认 `fq_codel` / 无整形 | 只做上传方向（下载需要 IFB，实测会破坏 ACL/dpd 的 hook 顺序）；多 WAN 时自动覆盖所有参与负载的链路 |
| **router-tuning** | 本仓库，纯脚本 | 首启按 CPU/内存/网卡选档：BBR、`fq`、sysctl、ring/coalescing、XPS、governor | 不替换 qdisc；只调内核与网卡参数 | 所有写入都在**运行期**，不动 `/etc/config/{network,dhcp,firewall}` |
| **router-dns** | 本仓库，纯脚本 | **SmartDNS 独占 :53**；dnsmasq 端口 0 并停用；`router-dns-sync` 把 DHCP 学到的真实上游（非本机）写成 `server` 段，DoT 作为并行上游；`/tmp/resolv.conf` → `127.0.0.1`；`.lan` 名字写进 `hosts.lan`；honk 的 DNS 交接 | 替换 dnsmasq 的解析角色 | dnsmasq 只保留二进制，不再监听；上游**从租约派生**而不是写死，自身地址一律过滤 |
| **luci-front** | 本仓库；Rust + pingora 0.9，静态 musl，预编译（x86_64 / aarch64） | :80/:443：HTTP/2、TLS、HSTS/CSP/X-Frame-Options/X-Content-Type-Options、静态 ETag/304；`/cgi-bin`、`/ubus` 反代 uhttpd | 替换 uhttpd 的对外监听 | uhttpd 退到 `127.0.0.1:8080`，只保留 Lua CGI 与 ubus 桥 |
| **luci-app-mydist** | 本仓库 | 菜单（DNS/代理/防火墙/多 WAN 负载）、五元组端口控制（单行表格）、多 WAN 负载页、`mydist-posture` | 替换原版 firewall/smartdns/honk 菜单入口 | `rule 999` 默认开启且不在 UI 显示；保存端口行时自动补 `src=wan/dest=lan/target=DNAT` 并丢弃未填完的行 |

---

## 4. 数据面拓扑与端口

```
                 ┌─────────────── LAN (br-lan) ───────────────┐
LAN client ──►  dpd_fastpath (classic TC ingress, pref 100)
                       │  命中已建立连接 → bpf_fib_lookup → 直接 redirect 到 WAN
                       ▼ 未命中 → 交回内核 netfilter（fw4）
                 fw4 (nftables) ── ACCEPT / REDIRECT / rule 999
                       │
WAN ingress ──►  honk TCX (若启用) → einat TCX (reverse SNAT) → router-acl (pref 90) → dpd (pref 100)
WAN egress  ──►  honk TCX → einat TCX (SNAT) → router-acl (pref 90) → CAKE root qdisc
```

| 端口 / 文件 | 归属 |
|---|---|
| `:80`, `:443` | `luci-front`（pingora） |
| `127.0.0.1:8080` | `uhttpd`（仅 CGI/ubus） |
| `:53` | SmartDNS |
| `127.0.0.1:6053` | 仅当旧配置残留时存在；新镜像不使用 |
| `:9527` | honk native API（honk 启用时） |
| `20000-29999` | einat NAT 端口段 |
| `/etc/init.d/{einat,dpd-fastpath,router-acl,router-qos,router-dns,router-tuning,luci-front,mydist-posture}` | 服务 |
| `/etc/uci-defaults/{96-mydist-front,97-mydist-dns,98-mydist-tuning,99-luci-mydist-trim}` | 首启配置 |
| `/usr/sbin/dpdctl`、`/usr/bin/einat`、`/usr/sbin/luci-front` | 工具 |

启动顺序（`START`）：`router-dns`(18) → `dnsmasq`(19) → `mydist-posture`(26) → `router-tuning`(93) → `luci-front`(96) → `honk`(95)。

`mydist-posture` 每次启动都会重写并确认：WAN zone `forward=ACCEPT`、`fullcone=1`、`rule 999` 存在且启用、SmartDNS `:53`、dnsmasq `:0`、`dhcp.lan.ignore=0`、`master=1`。它是运行期唯一的状态权威。

---

## 5. 构建

```sh
# 1. 取源码
git clone https://github.com/kwrum1/immortalwrt.git
cd immortalwrt && git checkout mydist && git log -1   # 应为 5fda931 + 本说明的提交

# 2. 把 mydist/ 放进 package/
cp -a mydist ../package/mydist        # CI 由 Scripts/Packages.sh 完成

# 3. 常规 OpenWrt 构建
./scripts/feeds update -a && ./scripts/feeds install -a
make menuconfig     # 选择目标；X86/ROCKCHIP 用 Config/GENERAL.txt 的包集
make -j$(nproc)
```

依赖要点：

- `dpd-fastpath` / `router-acl` 需要 host `clang`（`CONFIG_BPF_TOOLCHAIN_HOST=y`）与 `libbpf`/`libelf`（由 `ip-full`、`tc-bpf` 带入）。
- `einat-ebpf` 是预编译二进制，`PKG_HASH` 按架构钉死。
- `luci-front` 是预编译二进制，`RSTRIP:=:` / `STRIP:=:`，**不要二次 strip**。

---

## 6. 与上游 ImmortalWrt 的差异汇总

| 维度 | 上游 | 本分支 |
|---|---|---|
| NAT | conntrack + `MASQUERADE` | einat eBPF full-cone NAT |
| 转发快路径 | netfilter / flow offload（若开启） | dpd TC ingress + einat，offload 默认关闭 |
| 入站策略 | fw4 zone/rule | router-acl（叠加）+ fw4（兜底）+ rule 999 默认开 |
| 整形 | 默认 `fq_codel` | WAN `cake`（逐主机公平 + diffserv4） |
| DNS | dnsmasq 解析 | SmartDNS 独占 :53，dnsmasq 端口 0 |
| Web 入口 | uhttpd 直接监听 80/443 | pingora 前端 80/443，uhttpd 退到 127.0.0.1:8080 |
| DHCP | dnsmasq（v4）+ odhcpd-ipv6only | odhcpd 同时 v4 + v6 |
| x86 镜像 | 含 i915/DRM | 去掉 i915/video-support |

---

## 6.1 第 10 轮修复（2026-10-20，`3350e33`）

测试专家在真机上发现并已修复：

| 问题 | 修复 |
|---|---|
| **WAN 拿到路由器自己发的 DHCP 租约**，默认路由指向本机 → 整机无外网 | `mydist-posture` 把本机各接口 MAC 注册成 `dhcp.mydist_self_<iface>``（`option ip 'ignore'`），odhcpd 不再给本机发租约；实测重启后默认路由为真实网关 |
| **SmartDNS 只有两条被封的 DoT 上游**，所有解析失败 | 新增 `/usr/libexec/router-dns-sync`：从 netifd/ubus 与 `resolv.conf.auto` 派生真实上游（本机地址全部过滤），写成显式 `config server` 段；DoT 保留为并行上游；`ifup/ifupdate` 触发 |
| **`/etc/resolv.conf` 指向网关/自己**，路由器自身解析失败 | `/tmp/resolv.conf` 改写为 `nameserver 127.0.0.1` + `search lan`，`/etc/resolv.conf` 用 overlay 文件覆盖；每次 ifup 重写 |
| **`.lan` 主机名不可解析**（dnsmasq 已停用） | 生成 `/var/etc/router-dns/hosts.lan`（本机名 + odhcpd 租约名，含 `.lan` 形式），smartdns `hosts-file` 读取 |
| **honk 的 DNS 上游仍指向 6053** | `honk-dns.sh` 与 honk `mydist` 分支统一为 `udp://127.0.0.1:53` |
| **lab 配置的 `lan.gateway`/`lan.dns` 污染默认路由与 resolv.conf** | `lab-99-test-lab` 删除这两项，跨网段访问只依赖 `network.myadmin` 回程路由 |
| **`accept-full.sh` 的 DNS 断言是假 PASS** | 改为 `grep '^Name:'` + 退出码，并新增“外部客户端查询”“默认网关不是本机地址”断言（现为 62 项） |

回归结果：`accept-full.sh` **62 PASS / 0 FAIL / 1 SKIP**；本机与外部客户端 DNS 均通；重启后姿态保持。

## 7. 已知限制

- `einat-ebpf` 只支持 x86_64 / aarch64；armv7（IPQ60XX）不可用。
- `luci-front` 只有 x86_64 / aarch64 两个预编译二进制。
- dpd 只在“已建立连接 + 有上行 + einat 已挂载”时进入 `stateless`；否则自动 `observe`，这是设计而不是故障。
- 下载方向不做 CAKE：IFB 的 mirror/redirect 都会破坏 ACL/dpd 的 hook 顺序（详见 `mydist/router-qos/files/router-qos.sh` 顶部注释）。

---

## 8. 许可

- `mydist/*` 原创部分：GPL-2.0-only。
- einat：GPL-2.0（上游）。
- 上游 ImmortalWrt：按上游许可。
