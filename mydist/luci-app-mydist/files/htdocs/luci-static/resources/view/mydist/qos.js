'use strict';
'require view';
'require form';
'require uci';
'require fs';

/* Network -> QoS: CAKE on the uplink.
 *
 * CAKE shapes to the rate you give it, so nothing is installed while upload is
 * 0. Only the upload direction is shaped here: feeding an IFB for the download
 * direction either does not delay the real packet or steals it from
 * router-acl/dpd, so this page stays with the shaper that actually works.
 *
 * The scheduler is not configurable on purpose. There is one maintained policy
 * (/usr/libexec/router-qos.sh: rq_best_opts): diffserv4 for the DSCP tins, NAT
 * accounting on, framing overhead inferred for PPPoE/tunnels, and fq_codel as
 * the fallback when the cake module is missing. Exposing overhead/mpu/wash/nat
 * only produced "why is latency worse after I changed a number I did not
 * understand".
 */

return view.extend({
	load: function() {
		return uci.load('router_qos');
	},

	render: function() {
		var m, s, o;

		m = new form.Map('router_qos', _('QoS'),
			_('在 WAN 出口整形（CAKE），上传速率按实际带宽填写。调度算法由系统统一维护，无需配置。'));

		s = m.section(form.NamedSection, 'global', 'router_qos', _('接口整形'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'wan', _('整形接口'),
			_('netifd 逻辑名（wan / pppoe-wan）或设备名（eth1）'));
		o.default = 'wan';
		o.rmempty = false;
		o.placeholder = 'wan';

		o = s.option(form.Value, 'upload', _('上传速率'),
			_('单位 kbit/s，例如 100000 = 100 Mbit；0 表示不整形'));
		o.datatype = 'uinteger';
		o.default = '0';
		o.rmempty = false;
		o.placeholder = '100000';

		o = s.option(form.DummyValue, 'policy', _('调度策略'));
		o.rawhtml = true;
		o.default = _('CAKE diffserv4 + NAT 记账；PPPoE/隧道自动加 34 字节开销；CAKE 不可用时回退 fq_codel。');

		var save = m.save.bind(m);

		m.save = function(cb, silent) {
			return save(cb, silent).then(function() {
				if (silent)
					return;

				return fs.exec('/etc/init.d/router-qos', [ 'restart' ]).catch(function() {});
			});
		};

		return m.render();
	}
});
