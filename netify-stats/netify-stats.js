'use strict';
'require view';
'require rpc';
'require dom';
'require poll';

var PAGE_SIZE = 10;
var callSummary = rpc.declare({ object: 'netify-stats', method: 'summary', params: [ 'hours', 'device', 'app_page', 'device_page', 'sort', 'direction', 'expanded' ], expect: { } });
var setStorage = rpc.declare({ object: 'netify-stats', method: 'set_storage', params: [ 'max_storage_mib' ], expect: { } });
var setEnabled = rpc.declare({ object: 'netify-stats', method: 'set_enabled', params: [ 'enabled' ], expect: { } });
var setInterface = rpc.declare({ object: 'netify-stats', method: 'set_interface', params: [ 'interface' ], expect: { } });

function bytes(value) {
	value = Number(value || 0);
	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ], i = 0;
	while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
	return (i ? value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2) : value.toFixed(0)) + ' ' + units[i];
}

function esc(value) { return String(value == null ? '' : value); }

function displayDate(date) {
	// LuCI resolves its configured language (including Auto) into the page lang.
	// Use that locale, not an unrelated browser language, for date formatting.
	var locale = (document.documentElement && document.documentElement.lang || 'en').replace(/_/g, '-');
	return date.toLocaleString(locale);
}

function applicationName(item) {
	var known = {
		"Unknown": _("Unknown destination"),
		"community:douyin": _("Douyin"),
		"community:wechat": _("WeChat"),
		"community:tencent": _("Tencent"),
		"community:bilibili": _("Bilibili"),
		"community:huawei": _("Huawei"),
		"community:xiaomi": _("Xiaomi"),
		"community:jd": _("JD.com"),
		"community:taobao": _("Taobao")
	};
	return Object.prototype.hasOwnProperty.call(known, item.id) ? known[item.id] : (item.name_i18n ? _(item.name_i18n) : esc(item.name));
}

function sourceLabel(item) {
	var type = item.source_type || (item.id === 'Unknown' ? 'unknown' : String(item.id).startsWith('community:') ? 'community' : String(item.id).startsWith('domain:') ? 'domain' : 'native');
	var labels = {
		native: _("Native Netify classification"),
		community: _("Community domain rules"),
		domain: _("Domain only"),
		unknown: _("Unidentified")
	};
	var label = Object.prototype.hasOwnProperty.call(labels, type) ? labels[type] : labels.unknown, names = item.source_names || [];
	return names.length ? _("%s (%s)").format(label, names.join(' / ')) : label;
}

function errorMessage(value) {
	var message = esc(value), prefix = 'Analysis setting could not be fully applied: ';
	if (message.indexOf(prefix) === 0)
		return _("Analysis setting could not be fully applied: %s").format(errorMessage(message.slice(prefix.length)));
	var known = {
		"Capacity must be 0 (unlimited) or an integer from 4 to 4096 MiB": _("Capacity must be 0 (unlimited) or an integer from 4 to 4096 MiB"),
		"Settings are being saved. Please try again.": _("Settings are being saved. Please try again."),
		"Statistics migration verification failed; original data was preserved.": _("Statistics migration verification failed; original data was preserved."),
		"Storage cleanup is waiting for active queries to finish.": _("Storage cleanup is waiting for active queries to finish."),
		"Storage cleanup is not finished; oldest hours will continue to be removed.": _("Storage cleanup is not finished; oldest hours will continue to be removed."),
		"Analysis toggle timed out. Please try again.": _("Analysis toggle timed out. Please try again."),
		"Services did not fully start. Please try again.": _("Services did not fully start. Please try again."),
		"Services did not fully stop. Please try again.": _("Services did not fully stop. Please try again."),
		"Another analysis toggle is in progress. Please try again.": _("Another analysis toggle is in progress. Please try again."),
		"Select an interface that exists on this device.": _("Select an interface that exists on this device."),
		"Invalid enabled setting": _("Invalid enabled setting"),
		"enabled must be boolean": _("enabled must be boolean"),
		"Invalid interface setting": _("Invalid interface setting"),
		"Invalid interface name": _("Invalid interface name"),
		"Negative interface counter": _("Negative interface counter")
	};
	// Keep system diagnostics verbatim; never translate device names or paths.
	return Object.prototype.hasOwnProperty.call(known, message) ? known[message] : message;
}

function itemTotal(item) { return Number(item.upload || 0) + Number(item.download || 0); }

function sorted(items, key, direction) {
	items = (items || []).slice();
	items.sort(function(a, b) {
		var av = key === 'total' ? itemTotal(a) : Number(a[key] || 0);
		var bv = key === 'total' ? itemTotal(b) : Number(b[key] || 0);
		return direction === 'asc' ? av - bv : bv - av;
	});
	return items;
}

function stat(title, value, subtitle, cls) {
	return E('div', { 'class': 'ns-stat ' + cls }, [
		E('div', { 'class': 'ns-stat-label' }, title), E('div', { 'class': 'ns-stat-value' }, value), E('div', { 'class': 'ns-stat-sub' }, subtitle)
	]);
}

function trafficValues(item) {
	return E('div', { 'class': 'ns-values' }, [
		E('span', { 'class': 'ns-down' }, [ E('small', {}, _("Download")), E('strong', {}, bytes(item.download)) ]),
		E('span', { 'class': 'ns-up' }, [ E('small', {}, _("Upload")), E('strong', {}, bytes(item.upload)) ])
	]);
}

function trafficBar(item) {
	var total = itemTotal(item), down = total > 0 ? Number((Number(item.download || 0)/total*100).toFixed(2)) : 0;
	return E('div', { 'class': 'ns-bar', 'style': 'background:transparent', 'aria-label': _("Download %s, upload %s").format(bytes(item.download), bytes(item.upload)) }, [
		E('span', { 'class': 'ns-bar-down', 'style': 'width:' + down + '%;flex-shrink:0' }),
		E('span', { 'class': 'ns-bar-up', 'style': 'width:' + (total > 0 ? 100-down : 0) + '%;flex-shrink:0' })
	]);
}

function miniRows(items, labelKey, scrollKey) {
	items = items || [];
	if (!items.length) return E('div', { 'class': 'ns-empty' }, _("No attributable data"));
	return E('div', { 'data-ns-scroll': scrollKey }, items.map(function(item) {
		return E('div', { 'class': 'ns-mini-row' }, [
			E('div', { 'class': 'ns-mini-name', 'title': esc(item[labelKey]) }, esc(item[labelKey])), trafficBar(item), trafficValues(item)
		]);
	}));
}

function applicationRows(items, page, expanded, refresh) {
	if (!items.length) return E('div', { 'class': 'ns-empty' }, _("No data yet. Netify is identifying new connections."));
	var offset = (page - 1) * PAGE_SIZE;
	return E('div', { 'class': 'ns-app-list' }, items.map(function(item, localIndex) {
		var hosts = sorted((item.hosts || []).filter(function(host) { return host.name && host.name.toLowerCase() !== 'unknown'; }), 'total', 'desc').slice(0,5);
		var detail = E('div', { 'class': 'ns-app-detail', 'style': expanded.has(item.id) ? 'display:block' : 'display:none' }, E('div', { 'class': 'ns-detail-grid' }, [
			E('section', {}, [ E('h4', {}, _("Devices generating this traffic")), miniRows(item.devices, 'name', item.id + ':devices') ]),
			E('section', {}, [ E('h4', {}, _("Websites / services")), miniRows(hosts, 'name', item.id + ':hosts') ])
		]));
		var button = E('button', { 'class': 'ns-app-main', 'type': 'button', 'aria-expanded': expanded.has(item.id) ? 'true' : 'false', 'click': function(ev) {
			var open = detail.style.display !== 'none';
			detail.style.display = open ? 'none' : 'block';
			if (open) expanded.delete(item.id); else { expanded.add(item.id); dom.content(detail, E('p', {}, _("Loading details…"))); refresh(); }
			ev.currentTarget.setAttribute('aria-expanded', open ? 'false' : 'true');
		} }, [
			E('span', { 'class': 'ns-rank' }, String(offset + localIndex + 1)),
			E('span', { 'class': 'ns-app-label', 'title': sourceLabel(item) }, E('strong', {}, applicationName(item))),
			E('span', { 'class': 'ns-app-meter' }, trafficBar(item)), trafficValues(item), E('span', { 'class': 'ns-chevron', 'aria-hidden': 'true' }, '⌄')
		]);
		return E('article', { 'class': 'ns-app-item' }, [ button, detail ]);
	}));
}

function pager(current, pages, callback, label) {
	if (pages <= 1) return E('span');
	var children = [ E('button', { 'class': 'btn cbi-button', 'disabled': current === 1 ? '' : null, 'click': function() { callback(current - 1); } }, _("Previous")) ];
	for (var i = 1; i <= pages; i++) {
		if (i !== 1 && i !== pages && Math.abs(i - current) > 2) {
			if (i === current - 3 || i === current + 3) children.push(E('span', {}, '…'));
			continue;
		}
		(function(page) {
			children.push(E('button', { 'class': 'btn cbi-button ' + (page === current ? 'cbi-button-action' : ''), 'aria-current': page === current ? 'page' : null, 'click': function() { callback(page); } }, String(page)));
		})(i);
	}
	children.push(E('button', { 'class': 'btn cbi-button', 'disabled': current === pages ? '' : null, 'click': function() { callback(current + 1); } }, _("Next")));
	return E('nav', { 'class': 'ns-pager', 'aria-label': label || _("Application ranking pages") }, children);
}

function deviceRows(items, page) {
	items = items || [];
	if (!items.length) return E('div', { 'class': 'ns-empty' }, _("No device data"));
	var offset = (page - 1) * PAGE_SIZE;
	return E('div', {}, items.map(function(item, index) {
		return E('div', { 'class': 'ns-device-row' }, [
			E('span', { 'class': 'ns-rank' }, String(offset + index + 1)),
			E('span', { 'class': 'ns-device-label' }, [ E('strong', {}, esc(item.name)), E('small', {}, esc(item.ip) + ' · ' + esc(item.mac)) ]),
			E('span', { 'class': 'ns-device-meter' }, trafficBar(item)), trafficValues(item)
		]);
	}));
}

function timeline(items, step, selection) {
	items = items || [];
	if (!items.length) return E('div', { 'class': 'ns-empty' }, _("No trend data"));
	step = Number(step || 3600);
	var peak = items.reduce(function(value, item) { return Math.max(value, Number(item.download || 0), Number(item.upload || 0)); }, 1);
	var magnitude = Math.pow(10, Math.floor(Math.log10(peak))), max = Math.ceil(peak / magnitude) * magnitude;
	var selected = E('p', { 'class': 'ns-range ns-trend-selection', 'aria-live': 'polite' });
	function description(item) {
		var start = new Date(item.bucket * 1000), end = new Date(Math.min((item.bucket + step)*1000, Date.now()));
		return displayDate(start) + ' — ' + displayDate(end) + ' ｜ ' + _("Download %s · Upload %s").format(bytes(item.download), bytes(item.upload));
	}
	var selectedItem = selection && items.find(function(item) { return item.bucket === selection.bucket; });
	if (selection && !selectedItem) selection.bucket = null;
	dom.content(selected, description(selectedItem || items[items.length-1]));
	function svgNode(tag, attrs) {
		var node = document.createElementNS('http://www.w3.org/2000/svg', tag);
		Object.keys(attrs).forEach(function(key) { node.setAttribute(key, attrs[key]); });
		return node;
	}
	var svg = svgNode('svg', { 'class': 'ns-trend-lines', 'viewBox': '0 0 1000 190', 'preserveAspectRatio': 'none', 'aria-hidden': 'true' });
	['download', 'upload'].forEach(function(key) {
		var color = key === 'download' ? '#4d9de0' : '#ee7a59';
		var points = items.map(function(item, index) { return [((index+0.5)/items.length*1000).toFixed(2), (185-Number(item[key]||0)/max*180).toFixed(2)]; });
		svg.appendChild(svgNode('polyline', { 'points': points.map(function(point) { return point.join(','); }).join(' '), 'fill': 'none', 'stroke': color, 'stroke-width': '2', 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
		if (items.length === 1) svg.appendChild(svgNode('circle', { 'cx':points[0][0], 'cy':points[0][1], 'r':'3', 'fill':color, 'stroke':color, 'vector-effect':'non-scaling-stroke' }));
	});
	return E('div', {}, [
		E('div', { 'class': 'ns-trend-chart' }, [
			E('div', { 'class': 'ns-trend-axis', 'aria-hidden': 'true' }, [ E('span', {}, bytes(max)), E('span', {}, bytes(max/2)), E('span', {}, '0 B') ]),
			E('div', { 'class': 'ns-trend-plot' }, [svg].concat(items.map(function(item, index) {
				var date = new Date(item.bucket * 1000), label = date.getMonth()+1 + '/' + date.getDate() + '\n' + String(date.getHours()).padStart(2,'0') + ':00';
				var showLabel = index % Math.max(1, Math.ceil(items.length/4)) === 0;
				return E('button', { 'type': 'button', 'class': 'ns-trend-group', 'title': description(item), 'aria-label': description(item), 'click': function() { if (selection) selection.bucket = item.bucket; dom.content(selected, description(item)); } }, [
					E('small', { 'class': 'ns-trend-label' }, showLabel ? label : '')
				]);
			})))
		]), selected
	]);
}

return view.extend({
	load: function() { return callSummary(0, '', 1, 1, 'total', 'desc', '[]'); },

	currentSort: function() { return { key: this.sortSelect && this.sortSelect.value || 'total', direction: this.orderSelect && this.orderSelect.value || 'desc' }; },

	updateAnalysis: function(data) {
		if (!this.analysisToggle || this.analysisApplying) return;
		var control = data.control || {}, state = control.actual_state;
		this.analysisToggle.checked = state ? state === 'running' : data.enabled !== false;
		this.analysisToggle.indeterminate = state === 'partial';
		var issue = this.analysisError || control.apply_error || '';
		if (control.applied === false || issue) {
			var actual = state === 'running' ? _("Running") : state === 'stopped' ? _("Stopped") : _("Some services are running");
			dom.content(this.analysisNotice, _("Requested: %s; actual: %s. %s").format(control.enabled !== false ? _('Enabled') : _('Disabled'), actual, issue ? errorMessage(issue) : _('The setting has not been fully applied.')));
			this.analysisRetry.hidden = false;
		} else {
			dom.content(this.analysisNotice, []);
			this.analysisRetry.hidden = true;
		}
	},

	applyAnalysis: function(enabled) {
		if (this.analysisApplying) return;
		this.analysisApplying = true;
		this.analysisToggle.disabled = true;
		this.analysisRetry.disabled = true;
		this.analysisError = '';
		return setEnabled(enabled).then(L.bind(function(result) {
			if (result.control) this.currentData.control = result.control;
			else if (result.actual_state) this.currentData.control = result;
			if (result.error) throw new Error(result.error);
			this.currentData.enabled = result.enabled;
			return this.refresh(true);
		}, this)).catch(L.bind(function(error) {
			this.analysisError = errorMessage(error.message || error);
			return this.refresh(true);
		}, this)).finally(L.bind(function() {
			this.analysisApplying = false;
			this.analysisToggle.disabled = false;
			this.analysisRetry.disabled = false;
			this.updateAnalysis(this.currentData);
		}, this));
	},

	interfacePanel: function(data) {
		var selected = data.selected_interface || '', choices = (data.interface_choices || []).slice();
		if (selected && choices.indexOf(selected) < 0) choices.push(selected);
		var draft = this.interfaceDraft == null ? selected : this.interfaceDraft;
		if (draft && choices.indexOf(draft) < 0) choices.push(draft);
		var select = E('select', { 'aria-label': _("Statistics interface"), 'style': 'max-width:100%', 'disabled': this.interfaceSaving ? '' : null },
			[E('option', { 'value': '' }, _("Not bound"))].concat(choices.map(function(name) {
				return E('option', { 'value': name }, (data.interface_choices || []).indexOf(name) < 0 ? _("%s (currently unavailable)").format(name) : name);
			})));
		select.value = draft;
		var confirm = E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-apply', 'disabled': this.interfaceSaving || draft === selected ? '' : null }, _("Confirm and save"));
		select.addEventListener('change', L.bind(function() {
			this.interfaceDraft = select.value;
			confirm.disabled = this.interfaceSaving || select.value === selected;
		}, this));
		confirm.addEventListener('click', L.bind(function() {
			this.interfaceSaving = true; select.disabled = true;
			confirm.disabled = true;
			var chosen = select.value;
			setInterface(chosen).then(L.bind(function(result) {
				if (result.error) throw new Error(result.error);
				this.interfaceDraft = null;
				this.currentData.selected_interface = chosen;
				this.currentData.active_interfaces = chosen ? [chosen] : [];
				return this.refresh(true);
			}, this)).catch(L.bind(function(error) {
				select.value = selected;
				if (this.errorNode) dom.content(this.errorNode, _("Could not save the interface: %s").format(errorMessage(error.message)));
			}, this)).finally(L.bind(function() { this.interfaceSaving = false; select.disabled = false; this.paint(); }, this));
		}, this));
		var rows = (data.interfaces || []).filter(function(item) { return selected ? item.name === selected : (data.active_interfaces || []).indexOf(item.name) >= 0; });
		return E('details', { 'class': 'ns-section', 'open': this.interfaceExpanded ? '' : null, 'toggle': L.bind(function(ev) { this.interfaceExpanded = ev.currentTarget.open; }, this) }, [
			E('summary', {}, _("Interface traffic")),
			E('div', { 'style': 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0' }, [E('label', {}, [_("Statistics interface") + ' ', select]), confirm]),
			E('p', {}, selected ? _("Bound interface: %s").format(selected) : _("No interface is bound")),
			E('div', {}, rows.length ? rows.map(function(item) { return E('div', {}, [
				E('strong', {}, item.name), trafficBar(item),
				E('div', { 'class': 'ns-values' }, [
					E('span', { 'class': 'ns-down' }, [E('small', {}, _("Receive RX")), E('strong', {}, bytes(item.download))]),
					E('span', { 'class': 'ns-up' }, [E('small', {}, _("Transmit TX")), E('strong', {}, bytes(item.upload))])
				]),
				item.resets ? E('p', { 'role': 'alert' }, _("The interface was reset. Traffic during the reset could not be fully measured.")) : E('span')
			]); }) : E('p', {}, selected ? _("No records for this interface") : _("Select an interface to measure")))
		]);
	},

	renderDashboard: function(data) {
		data = data || {};
		var total = data.total || {}, order = this.currentSort();
		this.expandedApps = this.expandedApps || new Set();
		this.trendSelection = this.trendSelection || { bucket: null };
		var collector = data.collector || {}, unattributed = Number(collector.unattributed_download || 0) + Number(collector.unattributed_upload || 0);
		var applications = sorted(data.applications, order.key, order.direction);
		var devices = sorted(data.devices, order.key, order.direction);
		var pages = Math.max(1, Math.ceil((data.app_count || 0) / PAGE_SIZE));
		this.appPage = Math.min(Math.max(this.appPage || 1, 1), pages);
		var devicePages = Math.max(1, Math.ceil((data.device_count || 0) / PAGE_SIZE));
		this.devicePage = Math.min(Math.max(this.devicePage || 1, 1), devicePages);
		return E('div', { 'class': 'ns-dashboard', 'aria-live': 'polite' }, [
			E('section', { 'class': 'ns-section ns-trend-section' }, [ E('div', { 'class': 'ns-section-head' }, [ E('h3', {}, _("Device traffic trend")), E('div', { 'class': 'ns-legend' }, [ E('span', { 'class': 'download' }, _("Download")), E('span', { 'class': 'upload' }, _("Upload")) ]) ]), timeline(data.timeline, data.timeline_resolution_seconds, this.trendSelection) ]),
			data.rules_error ? E('p', { 'role': 'alert' }, _("Community rules could not be loaded. Showing domains instead.")) : E('span'),
			data.enabled !== false && data.collector && (data.collector.connected !== true || Date.now()/1000 - Number(data.collector.timestamp || 0) > 120) ? E('p', { 'role': 'alert' }, _("Collection is temporarily unavailable. Showing historical data.")) : E('span'),
			collector.proxy_error ? E('p', { 'role': 'alert', 'title': errorMessage(collector.proxy_error) }, _("Proxy connection attribution failed. Some device statistics may be incomplete.")) : E('span'),
			collector.export_error ? E('p', { 'role': 'alert', 'title': errorMessage(collector.export_error) }, _("Connection metadata recovery failed. Some device or application statistics may be incomplete.")) : E('span'),
			unattributed > 0 ? E('p', { 'role': 'status' }, _("%s of traffic could not be attributed to devices during this collection session. Historical statistics are incomplete.").format(bytes(unattributed))) : E('span'),
			E('div', { 'class': 'ns-stats' }, [
				stat(_("Device download"), bytes(total.download), _("Internet → device"), 'download'), stat(_("Device upload"), bytes(total.upload), _("Device → Internet"), 'upload')
			]),
			!data.device ? this.interfacePanel(data) : E('span'),
			data.collector && data.collector.interface_error ? E('p', { 'role': 'alert' }, _("Interface counters are temporarily unavailable.")) : E('span'),
			(data.storage && data.storage.error) || (data.collector && data.collector.storage && data.collector.storage.error) ? E('p', { 'role': 'alert' }, _("Statistics storage maintenance failed. Check the capacity setting and available space.")) : E('span'),
			E('section', { 'class': 'ns-section ns-apps' }, [
				E('div', { 'class': 'ns-section-head' }, [ E('h3', {}, _("Application and website ranking")), E('div', { 'class': 'ns-legend' }, [ E('span', { 'class': 'download' }, _("Download")), E('span', { 'class': 'upload' }, _("Upload")) ]) ]),
				applicationRows(applications, this.appPage, this.expandedApps, L.bind(this.refresh, this)),
				pager(this.appPage, pages, L.bind(function(page) { this.expandedApps.clear(); this.appPage = page; this.refresh(); }, this))
			]),
			E('div', { 'class': 'ns-lower-grid' }, [
				E('section', { 'class': 'ns-section' }, [ E('div', { 'class': 'ns-section-head' }, E('h3', {}, _("Device ranking"))), deviceRows(devices, this.devicePage), pager(this.devicePage, devicePages, L.bind(function(page) { this.devicePage = page; this.refresh(); }, this), _("Device ranking pages")) ])
			])
		]);
	},

	paint: function() {
		if (!this.contentNode || !this.currentData) return;
		var scroll = new Map();
		this.contentNode.querySelectorAll('[data-ns-scroll]').forEach(function(node) { scroll.set(node.getAttribute('data-ns-scroll'), [node.scrollTop, node.scrollLeft]); });
		dom.content(this.contentNode, this.renderDashboard(this.currentData));
		this.contentNode.querySelectorAll('[data-ns-scroll]').forEach(function(node) {
			var position = scroll.get(node.getAttribute('data-ns-scroll'));
			if (position) { node.scrollTop = position[0]; node.scrollLeft = position[1]; }
		});
	},

	refresh: function(force) {
		var hours = Number(this.hoursSelect && this.hoursSelect.value || 0), device = this.deviceSelect && this.deviceSelect.value || '';
		var order = this.currentSort();
		var visible = new Set((this.currentData && this.currentData.applications || []).map(function(item) { return item.id; }));
		var expanded = Array.from(this.expandedApps || []).filter(function(id) { return visible.has(id); });
		var args = [hours, device, this.appPage || 1, this.devicePage || 1, order.key, order.direction, JSON.stringify(expanded)], key = JSON.stringify(args);
		// Polls and repeated clicks share the same in-flight query. If filters
		// change, wait for it and run only the latest requested combination.
		// A successful settings write forces a fresh query after older reads.
		if (this.refreshWorker && force !== true && this.refreshKey === key) return this.refreshWorker;
		this.refreshKey = key;
		this.pendingRefresh = { args: args, id: this.requestId = (this.requestId || 0) + 1 };
		if (!this.refreshWorker) this.refreshWorker = this.runRefresh().finally(L.bind(function() { this.refreshWorker = null; }, this));
		return this.refreshWorker;
	},

	runRefresh: function() {
		var request = this.pendingRefresh, requestId = request.id;
		this.pendingRefresh = null;
		return callSummary.apply(null, request.args).then(L.bind(function(data) {
			if (requestId !== this.requestId) return;
			if (data.error) throw new Error(data.error);
			this.appPage = data.app_page || 1; this.devicePage = data.device_page || 1;
			this.currentData = data; this.paint();
			if (!this.analysisApplying && data.control && data.control.applied && !data.control.apply_error) this.analysisError = '';
			this.updateAnalysis(data);
			if (this.storageUsage) dom.content(this.storageUsage, _("Current record storage: %s (including database and journal)").format(bytes(data.storage && data.storage.used_bytes)));
			if (this.errorNode) dom.content(this.errorNode, []);
			this.updateDeviceChoices(data);
		}, this)).catch(L.bind(function(error) {
			if (requestId === this.requestId && this.errorNode) dom.content(this.errorNode, _("Refresh failed. The previous results have been kept. Please try again."));
		}, this)).then(L.bind(function() {
			if (this.pendingRefresh) return this.runRefresh();
		}, this));
	},

	updateDeviceChoices: function(data) {
		if (!this.deviceSelect) return;
		var selected = this.deviceSelect.value || '';
		var options = [E('option', { 'value': '' }, _("All devices"))];
		var items = data.device_choices || [];
		items.forEach(function(item) { options.push(E('option', { 'value': item.mac }, esc(item.name))); });
		if (selected && !items.some(function(item) { return item.mac === selected; })) options.push(E('option', { 'value': selected }, selected));
		dom.content(this.deviceSelect, options);
		this.deviceSelect.value = selected;
	},

	render: function(data) {
		var style = E('style', {}, [
			'.ns-toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin:16px 0 18px}.ns-field{display:flex;flex-direction:column;gap:5px}.ns-field label{font-size:12px;opacity:.65}.ns-field select{min-width:145px}.ns-stats{display:grid;grid-template-columns:repeat(3,minmax(150px,1fr));gap:12px;margin-bottom:14px}.ns-stat,.ns-section{background:var(--background-color-high,#fff);border:1px solid rgba(127,127,127,.16);border-radius:14px}.ns-stat{padding:16px 18px}.ns-stat-label{font-size:12px;opacity:.62}.ns-stat-value{font-size:27px;font-weight:700;margin:5px 0;font-variant-numeric:tabular-nums}.ns-stat-sub{font-size:12px;opacity:.58}.ns-stat.download .ns-stat-value,.ns-down strong{color:#2f7dd1}.ns-stat.upload .ns-stat-value,.ns-up strong{color:#d96545}.ns-section{padding:16px;margin-bottom:14px}.ns-section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}.ns-section-head h3{font-size:16px;margin:0}.ns-section-head p{font-size:12px;opacity:.58;margin:4px 0 0}.ns-legend{display:flex;gap:15px;font-size:12px;opacity:.72}.ns-legend span:before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}.ns-legend .download:before{background:#4d9de0}.ns-legend .upload:before{background:#ee7a59}.ns-app-item+.ns-app-item{border-top:1px solid rgba(127,127,127,.12)}.ns-app-main{appearance:none;width:100%;border:0;background:transparent;color:inherit;display:grid;grid-template-columns:32px minmax(150px,1.2fr) minmax(120px,1fr) minmax(185px,auto) 20px;gap:12px;align-items:center;padding:12px 4px;text-align:left;cursor:pointer}.ns-app-main:hover{background:rgba(127,127,127,.055)}.ns-rank{width:26px;height:26px;display:inline-flex;align-items:center;justify-content:center;border-radius:8px;background:rgba(127,127,127,.1);font-size:12px;font-variant-numeric:tabular-nums}.ns-app-label,.ns-device-label{min-width:0;display:flex;flex-direction:column;gap:3px}.ns-app-label strong,.ns-device-label strong{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ns-app-label small,.ns-device-label small{font-size:11px;opacity:.56;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ns-bar{display:flex;height:8px;border-radius:8px;background:rgba(127,127,127,.11);overflow:hidden}.ns-bar-down{background:#4d9de0}.ns-bar-up{background:#ee7a59}.ns-values{display:flex;justify-content:flex-end;gap:14px;font-variant-numeric:tabular-nums}.ns-values span{display:flex;flex-direction:column;min-width:78px}.ns-values small{font-size:10px;opacity:.55}.ns-values strong{font-size:12px;font-weight:600}.ns-chevron{font-size:18px;transition:transform .15s}.ns-app-main[aria-expanded="true"] .ns-chevron{transform:rotate(180deg)}.ns-app-detail{padding:4px 4px 16px 48px}.ns-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;padding:14px 16px;background:rgba(127,127,127,.055);border-radius:11px}.ns-detail-grid h4{font-size:13px;margin:0 0 8px}.ns-mini-row{display:grid;grid-template-columns:minmax(110px,1fr) minmax(70px,.8fr) minmax(170px,auto);gap:10px;align-items:center;padding:7px 0}.ns-mini-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}.ns-device-row{display:grid;grid-template-columns:32px minmax(130px,1fr) minmax(90px,.8fr) minmax(180px,auto);gap:10px;align-items:center;padding:10px 3px;border-top:1px solid rgba(127,127,127,.1)}.ns-device-row:first-child{border-top:0}.ns-lower-grid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.ns-timeline{height:225px;display:flex;align-items:end;gap:4px;padding-top:12px;overflow-x:auto}.ns-time-col{height:100%;min-width:15px;flex:1;display:flex;flex-direction:column;justify-content:end}.ns-time-stack{height:190px;display:flex;flex-direction:column;justify-content:end;border-radius:4px 4px 0 0;overflow:hidden}.ns-time-down{background:#4d9de0;min-height:1px}.ns-time-up{background:#ee7a59;min-height:1px}.ns-time-col small{text-align:center;font-size:9px;opacity:.5;margin-top:4px}.ns-pager{display:flex;justify-content:center;gap:6px;flex-wrap:wrap;padding-top:16px;border-top:1px solid rgba(127,127,127,.1);margin-top:8px}.ns-empty{padding:22px;text-align:center;opacity:.55}.ns-refresh{margin-bottom:1px}@media(max-width:1050px){.ns-app-main{grid-template-columns:30px minmax(140px,1fr) minmax(90px,.7fr) minmax(175px,auto) 18px}.ns-lower-grid{grid-template-columns:1fr}.ns-detail-grid{grid-template-columns:1fr}}@media(max-width:720px){.ns-stats{grid-template-columns:1fr}.ns-app-main{grid-template-columns:28px minmax(0,1fr) 18px}.ns-app-meter{grid-column:2/3}.ns-app-main>.ns-values{grid-column:2/3;justify-content:flex-start}.ns-chevron{grid-column:3;grid-row:1/4}.ns-app-detail{padding-left:4px}.ns-mini-row,.ns-device-row{grid-template-columns:minmax(100px,1fr) minmax(145px,auto)}.ns-mini-row>.ns-bar,.ns-device-meter{display:none}.ns-device-row>.ns-values{grid-column:2}.ns-values{gap:8px}.ns-values span{min-width:68px}}'
		]);
		/* Scope overrides above theme button/heading rules, including fixed
		 * button heights used by several LuCI themes on phones. */
		style.appendChild(document.createTextNode(`
.ns-root { min-width:0; color:inherit; }
.ns-root .ns-section-head>h3 { flex:1 1 auto; width:auto!important; min-width:0; }
.ns-root .ns-legend { display:inline-flex!important; flex:0 0 auto; align-items:center; gap:16px; width:auto!important; white-space:nowrap!important; line-height:1.4; }
.ns-root .ns-legend>span { display:inline-flex!important; flex:0 0 auto!important; align-items:center; gap:6px; width:auto!important; min-width:max-content; margin:0!important; padding:0!important; white-space:nowrap!important; word-break:keep-all!important; overflow-wrap:normal!important; letter-spacing:normal; writing-mode:horizontal-tb; }
.ns-root .ns-legend>span:before { display:block; flex:0 0 8px; width:8px; height:8px; margin:0!important; }
.ns-root .ns-stats { grid-template-columns:repeat(2,minmax(0,1fr)); }
.ns-root .ns-lower-grid { grid-template-columns:minmax(0,1fr); }
.ns-root .ns-trend-lines { position:absolute; top:0; left:0; width:100%; height:190px; pointer-events:none; overflow:visible; }
.ns-root input.ns-switch { appearance:none!important; -webkit-appearance:none!important; position:relative; width:44px!important; min-width:44px; height:26px!important; padding:0!important; border:0!important; border-radius:16px; background:#888!important; cursor:pointer; }
.ns-root input.ns-switch:before { content:''; position:absolute; width:20px; height:20px; top:3px; left:3px; border-radius:50%; background:#fff; transition:transform .15s; }
.ns-root input.ns-switch:checked { background:#4d9de0!important; }
.ns-root input.ns-switch:checked:before { transform:translateX(18px); }
.ns-root input.ns-switch:disabled { opacity:.5; cursor:wait; }
.ns-root input.ns-switch:focus-visible { outline:2px solid #4d9de0; outline-offset:3px; }
.ns-root .ns-trend-chart { display:flex; gap:8px; height:220px; margin:18px 0 8px; }
.ns-root .ns-trend-axis { flex:0 0 60px; display:flex; flex-direction:column; justify-content:space-between; padding-bottom:30px; font-size:11px; text-align:right; }
.ns-root .ns-trend-plot { position:relative; display:flex; flex:1; min-width:0; gap:0; padding-bottom:30px; background:repeating-linear-gradient(to top,transparent 0,transparent calc(50% - 1px),rgba(127,127,127,.18) calc(50% - 1px),rgba(127,127,127,.18) 50%); background-size:100% 190px; background-repeat:no-repeat; }
.ns-root button.ns-trend-group { position:relative; flex:1; min-width:0!important; width:auto!important; height:190px!important; min-height:0!important; padding:0!important; margin:0!important; border:0!important; border-radius:0!important; background:transparent!important; color:inherit!important; box-shadow:none!important; cursor:pointer; overflow:visible!important; }
.ns-root button.ns-trend-group:focus-visible { outline:2px solid #4d9de0!important; }
.ns-root .ns-trend-bars { height:100%; display:flex; align-items:flex-end; gap:1px; }
.ns-root .ns-trend-down,.ns-root .ns-trend-up { display:block; flex:1; min-height:0; border-radius:2px 2px 0 0; }
.ns-root .ns-trend-down { background:#4d9de0; }
.ns-root .ns-trend-up { background:#ee7a59; }
.ns-root .ns-trend-label { position:absolute; top:100%; left:0; width:42px; text-align:left; font-size:9px; line-height:1.2; white-space:pre-line; padding-top:6px; }
.ns-root .ns-trend-selection { min-height:3em; overflow-wrap:anywhere; }
.ns-root *, .ns-root *:before, .ns-root *:after { box-sizing:border-box; }
.ns-root .ns-stat, .ns-root .ns-section { background:transparent; color:inherit; min-width:0; }
.ns-root .ns-section h3, .ns-root .ns-detail-grid h4 { background:transparent!important; color:inherit!important; border:0!important; padding:0!important; height:auto!important; line-height:1.5; }
.ns-root .ns-app-main { height:auto!important; min-height:64px; max-height:none!important; white-space:normal!important; line-height:1.4!important; box-shadow:none!important; border:0!important; border-radius:0; background:transparent!important; color:inherit!important; }
.ns-root .ns-app-label, .ns-root .ns-app-meter, .ns-root .ns-device-label, .ns-root .ns-detail-grid section { min-width:0; }
.ns-root .ns-stat-label, .ns-root .ns-stat-sub, .ns-root .ns-values small, .ns-root .ns-app-label small, .ns-root .ns-device-label small { opacity:.8; }
.ns-root .ns-values small, .ns-root .ns-time-col small { font-size:11px; }
.ns-root .ns-detail-grid { grid-template-columns:minmax(0,1fr); }
.ns-root .ns-detail-grid section>div { max-height:360px; overflow-y:auto; }
.ns-root .ns-range { font-size:12px; opacity:.8; }
.ns-root .ns-pager button { min-height:44px; min-width:40px; }
@media(max-width:720px) {
 .ns-root .ns-toolbar { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
 .ns-root .ns-field { min-width:0; }
 .ns-root .ns-field select { width:100%; min-width:0; max-width:100%; min-height:44px; font-size:16px; }
 .ns-root .ns-refresh { grid-column:1/-1; min-height:44px; }
 .ns-root .ns-stats { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
 .ns-root .ns-stat { padding:12px; border-radius:10px; }
 .ns-root .ns-stat-value { font-size:22px; }
 .ns-root .ns-stat.total { grid-column:1/-1; display:flex; align-items:center; flex-wrap:wrap; gap:8px 14px; }
 .ns-root .ns-stat.total .ns-stat-value { font-size:19px; margin:0; }
 .ns-root .ns-section { padding:12px; }
 .ns-root .ns-section-head { flex-wrap:wrap; }
 .ns-root .ns-app-main { grid-template-columns:26px minmax(0,1fr) 18px; gap:8px; padding:14px 0; }
 .ns-root .ns-app-main>.ns-rank { grid-column:1; grid-row:1; }
 .ns-root .ns-app-label { grid-column:2; grid-row:1; }
 .ns-root .ns-app-meter { grid-column:2; grid-row:2; }
 .ns-root .ns-app-main>.ns-values { grid-column:2; grid-row:3; justify-content:flex-start; }
 .ns-root .ns-chevron { grid-column:3; grid-row:1; }
 .ns-root .ns-app-detail { padding:0 0 12px; }
 .ns-root .ns-detail-grid { padding:12px; gap:18px; }
 .ns-root .ns-mini-row { grid-template-columns:minmax(0,1fr); gap:6px; padding:10px 0; border-bottom:1px solid rgba(127,127,127,.18); }
 .ns-root .ns-mini-name { white-space:normal; overflow-wrap:anywhere; font-size:13px; }
 .ns-root .ns-mini-row>.ns-bar { display:flex; }
 .ns-root .ns-mini-row>.ns-values { justify-content:flex-start; gap:24px; }
 .ns-root .ns-device-row { grid-template-columns:26px minmax(0,1fr); gap:8px; }
 .ns-root .ns-device-row>.ns-rank { grid-column:1; grid-row:1; }
 .ns-root .ns-device-label { grid-column:2; grid-row:1; }
 .ns-root .ns-device-row>.ns-values { grid-column:2; grid-row:2; justify-content:flex-start; }
 .ns-root .ns-values { gap:20px; }
 .ns-root .ns-values strong { font-size:13px; }
 .ns-root .ns-pager { gap:5px; }
 .ns-root .ns-timeline { height:170px; }
 .ns-root .ns-time-stack { height:140px; }
}
`));
		var rerender = L.bind(function() { this.expandedApps.clear(); this.appPage = 1; this.devicePage = 1; this.refresh(); }, this);
		var controls = E('div', { 'class': 'ns-toolbar' }, [
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Time range")), E('select', { 'id': 'ns-hours', 'change': L.bind(function() { this.trendSelection = { bucket: null }; this.expandedApps.clear(); this.appPage = 1; this.devicePage = 1; return this.refresh(); }, this) }, [ E('option', { 'value': '0', 'selected': '' }, _("All")), E('option', { 'value': '1' }, _("Last 1 hour")), E('option', { 'value': '5' }, _("Last 5 hours")), E('option', { 'value': '24' }, _("Last 24 hours")), E('option', { 'value': '168' }, _("Last 7 days")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Device")), E('select', { 'id': 'ns-device', 'change': L.bind(function() { this.trendSelection = { bucket: null }; this.expandedApps.clear(); this.appPage = 1; this.devicePage = 1; return this.refresh(); }, this) }, [ E('option', { 'value': '' }, _("All devices")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Sort by")), E('select', { 'id': 'ns-sort', 'change': rerender }, [ E('option', { 'value': 'total' }, _("Total traffic")), E('option', { 'value': 'download' }, _("Download")), E('option', { 'value': 'upload' }, _("Upload")), E('option', { 'value': 'flows' }, _("Connections")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Order")), E('select', { 'id': 'ns-order', 'change': rerender }, [ E('option', { 'value': 'desc' }, _("Highest first")), E('option', { 'value': 'asc' }, _("Lowest first")) ]) ]),
			E('button', { 'class': 'btn cbi-button cbi-button-action ns-refresh', 'click': L.bind(this.refresh, this) }, _("Refresh"))
		]);
		var content = E('div', { 'id': 'ns-content' }), root = E('div', {}, [ style, E('h2', {}, _("DPI Traffic Analysis")), controls, content ]);
		this.analysisToggle = E('input', { 'type': 'checkbox', 'role': 'switch', 'class': 'ns-switch', 'checked': data.enabled !== false ? '' : null, 'change': L.bind(function(ev) {
			return this.applyAnalysis(ev.currentTarget.checked);
		}, this) });
		root.insertBefore(E('label', { 'class': 'ns-controls', 'style': 'min-height:44px;align-items:center' }, [this.analysisToggle, _("Traffic analysis")]), controls);
		this.analysisNotice = E('p', { 'role': 'alert' });
		this.analysisRetry = E('button', { 'type': 'button', 'class': 'btn cbi-button', 'hidden': '', 'click': L.bind(function() {
			var control = this.currentData.control;
			return this.applyAnalysis(control ? control.enabled : this.currentData.enabled !== false);
		}, this) }, _("Retry applying"));
		root.insertBefore(E('div', {}, [this.analysisNotice, this.analysisRetry]), controls);
		var storageInput = E('input', { 'type': 'number', 'min': '0', 'max': '4096', 'step': '1', 'value': String(data.storage && data.storage.max_storage_mib || 0), 'aria-label': _("Record storage limit in MiB") });
		var storageMessage = E('p', { 'role': 'status' });
		this.storageUsage = E('p', { 'class': 'ns-range' }, _("Current record storage: %s (including database and journal)").format(bytes(data.storage && data.storage.used_bytes)));
		var storageSave = E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': L.bind(function() {
			var value = Number(storageInput.value);
			if (!String(storageInput.value).trim() || !Number.isInteger(value) || !(value === 0 || value >= 4 && value <= 4096)) {
				dom.content(storageMessage, _("Enter 0 (unlimited) or an integer from 4 to 4096 MiB.")); return;
			}
			if (value && !window.confirm(_("When the storage limit is reached, the oldest hours of statistics will be deleted first. Save this setting?"))) return;
			storageSave.disabled = true; storageInput.disabled = true;
			return setStorage(value).then(L.bind(function(result) {
				if (result.error) throw new Error(result.error);
				if (!Number.isInteger(result.max_storage_mib)) throw new Error(_("The server did not confirm the saved value. Refresh and try again."));
				storageInput.value = String(result.max_storage_mib);
				dom.content(storageMessage, _("Saved. The collector will apply the setting automatically.")); return this.refresh(true);
			}, this)).catch(function(error) { dom.content(storageMessage, _("Could not save: %s").format(errorMessage(error.message || error))); }).finally(function() { storageSave.disabled = false; storageInput.disabled = false; });
		}, this) }, _("Save storage setting"));
		root.appendChild(E('section', { 'class': 'ns-section ns-storage-settings' }, [ E('div', { 'class': 'ns-section-head' }, E('h3', {}, _("Storage settings"))),
			this.storageUsage,
			E('div', { 'class': 'ns-controls' }, [ E('label', {}, [ _("Record limit (MiB)") + ' ', storageInput ]), storageSave ]),
			E('p', { 'class': 'ns-range' }, _("0 means unlimited. At the limit, the oldest hours are removed first. Writes may temporarily exceed the limit. Records stay in memory and are cleared on reboot; the capacity setting is kept.")), storageMessage
		]));
		root.classList.add('ns-root');
		this.errorNode = E('p', { 'role': 'alert' });
		root.insertBefore(this.errorNode, content);
		this.hoursSelect = controls.querySelector('#ns-hours'); this.deviceSelect = controls.querySelector('#ns-device'); this.sortSelect = controls.querySelector('#ns-sort'); this.orderSelect = controls.querySelector('#ns-order'); this.contentNode = content; this.currentData = data; this.appPage = 1;
		this.updateDeviceChoices(data);
		this.updateAnalysis(data);
		this.paint(); poll.add(L.bind(this.refresh, this), 30); return root;
	},

	handleSaveApply: null, handleSave: null, handleReset: null
});
