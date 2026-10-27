'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require rpc';

/* Network -> 多 WAN: per-flow load balancing across the uplinks that
 * mydist-mwan already owns (routing tables, fwmark rules, dpd_wans, einat).
 *
 * This page only edits /etc/config/mydist_mwan. The dataplane is untouched:
 * saving restarts mydist-mwan (or stops it when the global switch is off), and
 * reconcile rewrites the tables, rules and the dpd_wans map from the new file.
 *
 * Status comes from /var/run/mydist-mwan/wans (one line per reconciled uplink:
 * ifn dev mark table pref weight target flags p1 p2, flags bit 0 = up) and
 * from netifd's device statistics. Counters are cumulative since boot, not a
 * rate: this page is a configuration page, not a realtime monitor.
 */

var callInterfaces = rpc.declare({
	object: 'network.interface',
	method: 'dump',
	expect: { interface: [] }
});

var callDevices = rpc.declare({
	object: 'network.device',
	method: 'status',
	expect: {}
});

function fmtBytes(n) {
	n = parseInt(n, 10) || 0;

	var unit = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var i = 0;

	while (n >= 1024 && i < unit.length - 1) {
		n /= 1024;
		i++;
	}

	return (i ? n.toFixed(1) : String(n)) + ' ' + unit[i];
}

return view.extend({
	load: function() {
		var self = this;

		self.ifaces = [];
		self.devstats = {};
		self.runtime = {};

		return Promise.all([
			uci.load('mydist_mwan'),
			uci.load('network'),
			callInterfaces().catch(function() { return []; }),
			callDevices().catch(function() { return {}; }),
			fs.read('/var/run/mydist-mwan/wans').catch(function() { return ''; })
		]).then(function(res) {
			self.ifaces = res[2] || [];
			self.devstats = res[3] || {};

			(res[4] || '').split('\n').forEach(function(line) {
				var f = line.trim().split(/\s+/);

				if (f.length >= 8)
					self.runtime[f[0]] = {
						dev: f[1],
						flags: parseInt(f[7], 10) || 0
					};
			});
		});
	},

	render: function() {
		var m, s, o;
		var self = this;
		var seen = {};

		m = new form.Map('mydist_mwan', _('多 WAN'),
			_('按流把新建连接分配到多条 WAN，每条 WAN 仍由自己的 einat 实例做 NAT。' +
			  '当前只有 balance（按权重）模式；已有连接在重载后重建。'));

		s = m.section(form.NamedSection, 'global', 'global', _('全局'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('启用多 WAN'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('关闭后恢复单 WAN 行为：清掉 fwmark 规则和 dpd_wans 表。');

		o = s.option(form.Value, 'health_interval', _('健康检查间隔'));
		o.datatype = 'uinteger';
		o.default = '5';
		o.rmempty = false;
		o.placeholder = '5';
		o.description = _('秒。常驻的 health 循环按这个间隔 ping 每条 WAN 的健康目标。');

		s = m.section(form.GridSection, 'wan', _('WAN 接口'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = false;
		s.nodescriptions = true;
		s.sectiontitle = function(sid) {
			return uci.get('mydist_mwan', sid, 'interface') || _('新 WAN');
		};

		o = s.option(form.ListValue, 'interface', _('WAN 接口'));
		o.modalonly = false;
		o.rmempty = false;
		o.editable = true;
		o.placeholder = 'wan';

		function addIface(name, label) {
			if (!name || seen[name])
				return;

			seen[name] = true;
			o.value(name, label || name);
		}

		/* netifd first: this is the authoritative logical name and gives us
		 * the l3_device (pppoe-wan, eth1, ...) as a hint. */
		(this.ifaces || []).forEach(function(iface) {
			if (iface.interface == 'loopback')
				return;

			var dev = iface.l3_device || iface.device || '';
			var label = iface.interface;

			if (dev && dev != iface.interface)
				label += ' (' + dev + ')';
			if (iface.up === false)
				label += ' · ' + _('未连接');

			addIface(iface.interface, label);
		});

		/* Fall back to /etc/config/network so a WAN that netifd has not
		 * brought up yet can still be configured. */
		uci.sections('network', 'interface', function(sec) {
			if (sec['.name'] != 'loopback')
				addIface(sec['.name']);
		});

		/* Values already in mydist_mwan must survive even if netifd and
		 * network no longer know about them (for example a removed WAN). */
		uci.sections('mydist_mwan', 'wan', function(sec) {
			addIface(sec.interface);
		});

		addIface('wan');

		o = s.option(form.Value, 'weight', _('权重'));
		o.modalonly = false;
		o.datatype = 'range(1,8)';
		o.default = '1';
		o.rmempty = false;
		o.placeholder = '1';
		o.description = _('1–8。新流按权重比例选路（1:1 平分，2:1 约为 2/3 与 1/3）。');

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.modalonly = false;
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'health', _('健康目标'));
		o.modalonly = false;
		o.datatype = 'host';
		o.rmempty = true;
		o.placeholder = _('缺省用网关');
		o.description = _('从这条 WAN 的接口 ping 的地址；留空则用 netifd 报告的网关。');

		o = s.option(form.DummyValue, 'status', _('状态'));
		o.modalonly = false;
		o.cfgvalue = function(sid) {
			var ifn = uci.get('mydist_mwan', sid, 'interface');
			var rt = self.runtime[ifn];

			if (!rt)
				return _('未就绪（服务未运行或该 WAN 还没有可用网关）');

			var dev = rt.dev;
			var txt = ((rt.flags & 1) ? _('up') : _('down')) + ' · ' + dev;
			var stats = (self.devstats[dev] || {}).statistics;

			if (stats)
				txt += ' · RX ' + fmtBytes(stats.rx_bytes) +
				       ' / TX ' + fmtBytes(stats.tx_bytes);

			return txt;
		};

		var save = m.save.bind(m);

		m.save = function(cb, silent) {
			return save(cb, silent).then(function() {
				/* Add/Remove in the grid save silently; restarting the
				 * service on every intermediate click would drop flows for
				 * no reason. Only a real Save applies the config. */
				if (silent)
					return;

				return fs.exec('/sbin/uci', [ 'commit', 'mydist_mwan' ])
					.catch(function() {})
					.then(function() {
						var on = uci.get('mydist_mwan', 'global', 'enabled') == '1';

						/* restart, not reload: enabling the feature after it
						 * was stopped has to start the health loop as well,
						 * and disabling has to run cleanup. */
						return fs.exec('/etc/init.d/mydist-mwan',
							[ on ? 'restart' : 'stop' ]).catch(function() {});
					});
			});
		};

		return m.render();
	}
});
