'use strict';
'require view';
'require rpc';
'require dom';
'require poll';

var PAGE_SIZE = 10;
var callSummary = rpc.declare({ object: 'netify-stats', method: 'summary', params: [ 'hours', 'device', 'app_page', 'device_page', 'sort', 'direction', 'expanded', 'identification', 'search', 'application' ], expect: { } });
var setStorage = rpc.declare({ object: 'netify-stats', method: 'set_storage', params: [ 'max_storage_mib' ], expect: { } });
var setEnabled = rpc.declare({ object: 'netify-stats', method: 'set_enabled', params: [ 'enabled' ], expect: { } });
var setInterface = rpc.declare({ object: 'netify-stats', method: 'set_interface', params: [ 'interface' ], expect: { } });
var checkUpdate = rpc.declare({ object: 'netify-stats', method: 'check_update', params: [], expect: { } });
var installUpdate = rpc.declare({ object: 'netify-stats', method: 'install_update', params: [ 'version' ], expect: { } });

function updateVersion(value) {
	return typeof value === 'string' && /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/.test(value) ? value : '';
}

function newerUpdate(candidate, installed) {
	if (!updateVersion(candidate) || !updateVersion(installed)) return false;
	var next = candidate.split('.').map(Number), current = installed.split('.').map(Number);
	for (var i = 0; i < 3; i++) if (next[i] !== current[i]) return next[i] > current[i];
	return false;
}

function updateBusy(status) {
	return !!status && (status.busy === true || ['checking', 'downloading', 'installing'].indexOf(status.state) >= 0);
}

function updateStateLabel(state) {
	var labels = {
		idle: _("Updates have not been checked."), checking: _("Checking GitHub Release…"),
		available: _("A newer version is available."), up_to_date: _("No newer version is available."),
		unsupported: _("Updates are not supported on this system."),
		downloading: _("Downloading and verifying the update…"), installing: _("Installing the update… Keep the router powered on."),
		succeeded: _("The package update completed. Reload this page to use the new interface."),
		failed: _("The update request failed."),
		interrupted: _("The update stopped before its result could be confirmed. Check the installed package before trying again.")
	};
	return Object.prototype.hasOwnProperty.call(labels, state) ? labels[state] : _("Update service unavailable. Refresh the page or finish installing the current package.");
}

function updateErrorLabel(code) {
	var messages = {
		unsupported_platform: _("No update package is available for this OpenWrt version."),
		package_manager_missing: _("The required package manager is unavailable."),
		operation_busy: _("Another update or settings operation is running. Refresh the status before trying again."),
		update_not_checked: _("Check for updates before installing."),
		candidate_changed: _("The available update changed. Check again before installing."),
		check_expired: _("The update check expired. Check again before installing."),
		invalid_manifest: _("The release information failed validation. No package was installed."),
		manifest_unavailable: _("This release does not include update information. Try again after a compatible release is published."),
		network_error: _("The download failed. Check the router's Internet connection and try again."),
		download_too_large: _("The download exceeds the permitted size. No package was installed."),
		size_mismatch: _("The download size does not match the release. No package was installed."),
		checksum_mismatch: _("The download checksum does not match the release. No package was installed."),
		installed_version_unknown: _("The installed package version could not be verified. Check the package manager before updating."),
		install_failed: _("The package manager could not finish the update. Check its reported error before trying again."),
		install_verification_failed: _("The installed package does not match the requested version. Check the package manager before trying again."),
		worker_start_failed: _("The update task could not start. Refresh the status and try again."),
		interrupted: _("The update stopped before its result could be confirmed. Check the installed package before trying again."),
		status_invalid: _("The saved update status could not be read. Check the installed package before trying again.")
	};
	return Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : '';
}

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
		"community:taobao": _("Taobao"),
		"protocol:tls": _("TLS / encrypted traffic"),
		"protocol:quic": _("QUIC"),
		"protocol:dns": _("DNS"),
		"protocol:http": _("HTTP / web"),
		"protocol:stun": _("STUN / NAT traversal"),
		"protocol:bittorrent": _("BitTorrent / P2P"),
		"protocol:ssh": _("SSH / remote access"),
		"protocol:vpn": _("VPN protocol"),
		"protocol:tcp": _("TCP"),
		"protocol:udp": _("UDP")
	};
	var name = Object.prototype.hasOwnProperty.call(known, item.id) ? known[item.id] : (item.name_i18n ? _(item.name_i18n) : esc(item.name));
	if (item.source_type === 'infrastructure') return _("%s (infrastructure; application unidentified)").format(name);
	return item.source_type === 'protocol' || String(item.id).startsWith('protocol:') ? _("%s (application unidentified)").format(name) : name;
}

function sourceLabel(item) {
	var type = item.source_type || (item.id === 'Unknown' ? 'unknown' : String(item.id).startsWith('community:') ? 'community' : String(item.id).startsWith('domain:') ? 'domain' : String(item.id).startsWith('protocol:') ? 'protocol' : 'native');
	var labels = {
		native: _("Native Netify classification"),
		community: _("Community domain rules"),
		infrastructure: _("Shared infrastructure"),
		domain: _("Domain only"),
		protocol: _("Protocol only"),
		unknown: _("Unidentified")
	};
	var label = Object.prototype.hasOwnProperty.call(labels, type) ? labels[type] : labels.unknown, names = item.source_names || [];
	return names.length ? _("%s (%s)").format(label, names.join(' / ')) : label;
}

function classificationDetails(item) {
	var explanations = {
		native: _("Netify identified this application directly."),
		protocol: _("Only the protocol is identified; the application remains unknown."),
		community: _("A community domain rule supplied this classification."),
		infrastructure: _("The domain identifies a shared hosting or CDN provider, not a specific application."),
		ambiguous: _("The matching rule names multiple applications; no application was selected."),
		unmatched_domain: _("The domain is known, but no application rule matched."),
		ip_literal: _("Only an IP address is available."),
		missing_host: _("No hostname is available."),
		invalid_host: _("The supplied hostname is not a valid domain."),
		rules_unavailable: _("Community rules are unavailable.")
	};
	var evidence = (item.classification_evidence || []).slice(0, 5);
	return E('section', { 'class': 'ns-classification' }, [
		E('h4', {}, _("Classification details")),
		E('p', {}, sourceLabel(item)),
		E('div', {}, evidence.map(function(entry) {
			var children = [ E('p', {}, explanations[entry.reason] || _("Classification details are unavailable.")) ];
			if (entry.matched_domain) {
				var kind = entry.rule_type === 'exact' ? _("Exact domain rule") : _("Domain suffix rule");
				children.push(E('p', {}, _("%s: %s").format(kind, esc(entry.matched_domain))));
			}
			if (entry.reason === 'protocol' && entry.protocol)
				children.push(E('p', {}, _("Observed protocol: %s").format(esc(entry.protocol))));
			if (entry.source_name) children.push(E('p', {}, _("Rule source: %s").format(esc(entry.source_name))));
			if (entry.reason === 'ambiguous' && Array.isArray(entry.candidates))
				children.push(E('p', {}, _("Candidate applications: %s").format(entry.candidates.slice(0, 5).map(esc).join(', '))));
			if (entry.reason === 'ambiguous' && entry.candidate_count > (entry.candidates || []).length)
				children.push(E('p', {}, _("Only the first %d candidates are shown.").format((entry.candidates || []).length)));
			return E('div', { 'class': 'ns-evidence' }, children);
		})),
		item.classification_evidence_truncated ? E('p', {}, _("Showing a sample of matching rules.")) : E('span')
	]);
}

function classificationCoverage(data) {
	var coverage = data.classification_coverage;
	// Older RPC versions have no breakdown. Never infer it from a ranked page.
	if (!coverage) return E('span');
	var groups = [
		['application', _("Application identified")],
		['domain', _("Domain or infrastructure only")],
		['protocol', _("Protocol only")],
		['unknown', _("Unidentified")]
	];
	var total = itemTotal(data.total || {}), sum = 0;
	var valid = Number.isFinite(total) && total >= 0 && groups.every(function(group) {
		var values = coverage[group[0]], amount = values && itemTotal(values);
		if (!values || !Number.isFinite(amount) || amount < 0) return false;
		group.push(amount); sum += amount; return true;
	});
	// Floating-point parsing of very large JSON byte counters can differ by a
	// rounding unit. Inconsistent data must not turn into invented percentages.
	valid = valid && Math.abs(sum-total) <= Math.max(1, total*Number.EPSILON*8);
	return E('section', { 'class': 'ns-section ns-coverage' }, [
		E('div', { 'class': 'ns-section-head' }, E('h3', {}, _("Traffic identification"))),
		E('p', { 'class': 'ns-range' }, _("Download + upload for the selected time range, devices and traffic filters.")),
		valid ? E('div', { 'class': 'ns-coverage-grid' }, groups.map(function(group) {
			var share = total > 0 ? Math.max(0, Math.min(100, group[2]/total*100)) : 0;
			return E('div', { 'class': 'ns-coverage-item ns-coverage-' + group[0] }, [
				E('strong', {}, group[1]),
				E('div', { 'class': 'ns-coverage-value' }, _("%s · %s%% of traffic").format(bytes(group[2]), share.toFixed(1))),
				E('div', { 'class': 'ns-coverage-bar', 'aria-hidden': 'true' }, E('span', { 'style': 'width:' + share.toFixed(2) + '%' }))
			]);
		})) : E('p', {}, _("The identification breakdown is unavailable."))
	]);
}

function collectionDiagnostics(data, opened, toggle) {
	var collector = data.collector || {}, control = data.control || {}, now = Number(data.generated_at);
	if (!Number.isFinite(now) || now <= 0) now = Date.now()/1000;
	var timestamp = Number(collector.timestamp || 0), age = now-timestamp;
	var fresh = timestamp > 0 && age >= -5 && age <= 120;
	var paused = data.enabled === false && control.actual_state !== 'running' && control.actual_state !== 'partial';
	var partial = control.actual_state === 'partial';
	var unavailable = data.config_error || data.enabled === null || control.actual_state === 'unknown';
	var unattributed = Number(collector.unattributed_upload || 0) + Number(collector.unattributed_download || 0);
	var messages = [], state;
	function issue(message, action, detail) {
		messages.push(E('div', { 'class': 'ns-diagnostic-issue' }, [
			E('p', {}, message), action ? E('p', {}, action) : E('span'),
			detail ? E('pre', {}, errorMessage(detail)) : E('span')
		]));
	}
	if (unavailable) {
		state = _("Collection status unavailable");
		issue(_("Repair the settings before changing analysis state."), '', data.config_error);
	} else if (partial) {
		state = _("Some services are running");
	} else if (data.enabled === false && control.actual_state === 'running') {
		state = _("Collection is still running");
	} else if (paused) {
		state = _("Collection paused");
	} else if (control.actual_state === 'stopped') {
		state = _("Collection stopped unexpectedly");
		issue(_("Analysis is enabled, but its services are stopped."), _("Retry applying the analysis setting and check the Netify service."), control.apply_error);
	} else if (!fresh) {
		state = _("Collector status is stale or unavailable");
		issue(_("The collector has not provided a current status."), _("Check that the statistics collector is running and can write its status file."), collector.last_error);
	} else if (collector.connected !== true) {
		state = _("Waiting for Netify connection");
		issue(_("Collection is temporarily unavailable. Showing historical data."), _("Check that Netify is running and its local socket is enabled."), collector.last_error);
	} else {
		state = _("Collector connected");
		if (collector.last_error) issue(_("The collector reported an error."), _("Check the collector service log for this error."), collector.last_error);
	}
	if (!unavailable && (partial || control.applied === false || control.apply_error || data.enabled === false && control.actual_state === 'running'))
		issue(_("The analysis setting has not been fully applied."), _("Use Retry applying above, then check the service error if the problem continues."), control.apply_error);
	if (collector.proxy_error) issue(_("Proxy connection attribution failed. Some device statistics may be incomplete."), _("Check the proxy mode and conntrack availability."), collector.proxy_error);
	if (collector.export_error) issue(_("Connection metadata recovery failed. Some device or application statistics may be incomplete."), _("Check Netify JSON export and whether the collector can read it."), collector.export_error);
	if (collector.interface_error) issue(_("Interface counters are temporarily unavailable."), _("Check whether the selected statistics interface is available."), collector.interface_error);
	var storageError = data.storage && data.storage.error || collector.storage && collector.storage.error;
	if (storageError) issue(_("Statistics storage maintenance failed. Check the capacity setting and available space."), '', storageError);
	if (unattributed > 0) issue(_("%s of traffic could not be attributed to devices during this collection session. Historical statistics are incomplete.").format(bytes(unattributed)));
	if (Number(collector.invalid_messages || 0) > 0) issue(_("Some Netify messages could not be processed."), _("Check Netify compatibility and the collector service log."));
	var lastEvent = Number(collector.last_event || 0);
	function count(label, value) {
		var number = Number(value || 0);
		return E('div', {}, [E('dt', {}, label), E('dd', {}, Number.isFinite(number) ? String(Math.max(0, Math.floor(number))) : _("Not available"))]);
	}
	return E('details', { 'class': 'ns-section ns-diagnostics', 'open': opened ? '' : null, 'toggle': toggle }, [
		E('summary', {}, [_('Collection diagnostics'), ' · ', E('strong', { 'class': 'ns-diagnostic-state' }, state), messages.length ? ' · ' + _("Attention needed") : '']),
		E('p', { 'class': 'ns-range' }, _("Collector status and counters apply to the whole current collection session, regardless of traffic filters.")),
		E('p', {}, _("Last status update: %s").format(timestamp > 0 ? displayDate(new Date(timestamp*1000)) : _("Not available"))),
		E('p', {}, _("Last traffic event: %s").format(lastEvent > 0 ? displayDate(new Date(lastEvent*1000)) : _("No event received yet"))),
		!paused && fresh && collector.connected === true ? E('p', {}, _("An idle network may produce no traffic events while the collector stays connected.")) : E('span'),
		E('dl', { 'class': 'ns-diagnostic-counts' }, [
			count(_("Recorded traffic events"), collector.events), count(_("Active connection metadata"), collector.active_metadata),
			count(_("Events received without metadata"), collector.missing_metadata), count(_("Events recovered"), collector.recovered_stats),
			count(_("Events awaiting metadata"), collector.pending_stats), count(_("Invalid messages"), collector.invalid_messages)
		]),
		E('p', {}, _("Unidentified application traffic is already counted. Traffic that could not be attributed to a device is a separate statistics gap.")),
		E('div', { 'class': 'ns-diagnostic-issues' }, messages)
	]);
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
		"An application update is being installed. Wait for it to finish before changing analysis.": _("An application update is being installed. Wait for it to finish before changing analysis."),
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

function storageLimitValue(data) {
	var value = data.storage && data.storage.max_storage_mib;
	return value === null ? '' : String(value || 0);
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

function applicationRows(items, page, expanded, refresh, focus, filtered) {
	if (!items.length) return E('div', { 'class': 'ns-empty' }, filtered ? _("No traffic matches these filters.") : _("No data yet. Netify is identifying new connections."));
	var offset = (page - 1) * PAGE_SIZE;
	return E('div', { 'class': 'ns-app-list' }, items.map(function(item, localIndex) {
		var hosts = sorted((item.hosts || []).filter(function(host) { return host.name && host.name.toLowerCase() !== 'unknown'; }), 'total', 'desc').slice(0,5);
		var detail = E('div', { 'class': 'ns-app-detail', 'style': expanded.has(item.id) ? 'display:block' : 'display:none' }, E('div', { 'class': 'ns-detail-grid' }, [
			E('section', {}, [ E('h4', {}, _("Devices generating this traffic")), miniRows(item.devices, 'name', item.id + ':devices') ]),
			E('section', {}, [ E('h4', {}, _("Websites / services")), miniRows(hosts, 'name', item.id + ':hosts') ]),
			classificationDetails(item),
			E('button', { 'type': 'button', 'class': 'btn cbi-button ns-focus-application', 'click': function() { return focus(item); } }, _("View devices and trend for this traffic"))
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

function timeline(items, step, selection, clockAnomaly) {
	items = items || [];
	if (!items.length) return E('div', { 'class': 'ns-empty' }, _("No trend data"));
	step = Number(step || 3600);
	var peak = items.reduce(function(value, item) { return Math.max(value, Number(item.download || 0), Number(item.upload || 0)); }, 1);
	var magnitude = Math.pow(10, Math.floor(Math.log10(peak))), max = Math.ceil(peak / magnitude) * magnitude;
	var selected = E('p', { 'class': 'ns-range ns-trend-selection', 'aria-live': 'polite' });
	function description(item) {
		var start = new Date(item.bucket * 1000), end = new Date(clockAnomaly ? (item.bucket + step)*1000 : Math.max(item.bucket*1000, Math.min((item.bucket + step)*1000, Date.now())));
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
	load: function() { return callSummary(0, '', 1, 1, 'total', 'desc', '[]', '', '', ''); },

	currentSort: function() { return { key: this.sortSelect && this.sortSelect.value || 'total', direction: this.orderSelect && this.orderSelect.value || 'desc' }; },

	paintUpdate: function() {
		if (!this.updatePanel || !this.currentData) return;
		var data = this.currentData, status = data.update || {}, candidate = status.candidate || {};
		var installed = updateVersion(status.current_version) || updateVersion(data.version);
		var offered = updateVersion(candidate.version), validOffer = offered && candidate.tag === 'V' + offered;
		var service = !!data.update && typeof status.state === 'string';
		var busy = !!this.updatePending || updateBusy(status);
		var canInstall = service && !busy && status.state === 'available' && validOffer && newerUpdate(offered, installed);
		var checked = Number(status.checked_at || 0), details = [];
		if (validOffer) details.push(E('p', {}, [_("Release version: %s").format(offered), ' · ',
			E('a', { 'href': 'https://github.com/Or1a/BetterDPI/releases/tag/' + encodeURIComponent(candidate.tag), 'target': '_blank', 'rel': 'noopener noreferrer' }, _("View release notes"))]));
		if (Number.isFinite(checked) && checked > 0) details.push(E('p', {}, _("Last update check: %s").format(displayDate(new Date(checked*1000)))));
		var explanation = updateErrorLabel(status.error);
		if (explanation) details.push(E('p', { 'role': 'alert' }, explanation));
		if (status.error || status.detail) details.push(E('pre', { 'class': 'ns-update-detail' }, [esc(status.error), esc(status.detail)].filter(Boolean).join('\n')));
		if (this.updateError) details.push(E('p', { 'class': 'ns-update-request-error', 'role': 'alert' }, this.updateError));
		dom.content(this.updatePanel, [
			E('div', { 'class': 'ns-section-head' }, E('h3', {}, _("Plugin updates"))),
			E('p', {}, _("Installed version: %s").format(installed || _("Not available"))),
			E('p', { 'class': 'ns-update-state', 'role': 'status' }, this.updatePending ? _("Sending update request…") : updateStateLabel(status.state)),
			E('p', { 'class': 'ns-range' }, _("Checks run only when requested. Updates are downloaded from Or1a/BetterDPI on GitHub.")),
			E('p', { 'class': 'ns-range' }, _("Updating briefly interrupts collection. Settings and retained statistics are kept; the router is not rebooted.")),
			E('div', { 'class': 'ns-update-actions' }, [
				E('button', { 'type': 'button', 'class': 'btn cbi-button ns-update-check', 'disabled': !service || busy ? '' : null, 'click': L.bind(function() { return this.requestUpdate(false); }, this) }, _("Check for updates")),
				E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-apply ns-update-install', 'disabled': canInstall ? null : '', 'click': L.bind(function() { return this.requestUpdate(true); }, this) }, _("Install update")),
				E('button', { 'type': 'button', 'class': 'btn cbi-button ns-update-refresh', 'disabled': this.updatePending ? '' : null, 'click': L.bind(function() { return this.refresh(true); }, this) }, _("Refresh update status")),
				status.state === 'succeeded' ? E('button', { 'type': 'button', 'class': 'btn cbi-button ns-update-reload', 'click': function() {
					if (window.confirm(_("Reload this page? Unsaved settings and current filters will be lost."))) window.location.reload();
				} }, _("Reload page")) : E('span')
			]),
			E('div', {}, details)
		]);
	},

	requestUpdate: function(install) {
		var status = this.currentData && this.currentData.update, candidate = status && status.candidate || {};
		if (!status || this.updatePending || updateBusy(status)) return Promise.resolve();
		var version = updateVersion(candidate.version), current = updateVersion(status.current_version) || updateVersion(this.currentData.version);
		if (install && (status.state !== 'available' || candidate.tag !== 'V' + version || !newerUpdate(version, current))) return Promise.resolve();
		if (install && !window.confirm(_("Install BetterDPI %s? Collection will briefly stop. Settings and retained statistics will be kept, and the router will not reboot.").format(version))) return Promise.resolve();
		this.updatePending = true;
		this.updateError = '';
		// A summary already in flight predates this mutation. It must not put
		// an idle/available snapshot back over an accepted update job.
		this.requestId = (this.requestId || 0) + 1;
		this.refreshKey = null;
		this.paintUpdate();
		return (install ? installUpdate(version) : checkUpdate()).then(L.bind(function(result) {
			if (!result || typeof result.state !== 'string') throw new Error(_("The update service returned an invalid response."));
			this.currentData.update = result;
			// A failed preflight may also prevent saving its status. Keep the
			// RPC error visible when the next summary still has the old state.
			if (result.error) this.updateError = [updateErrorLabel(result.error) || esc(result.error), esc(result.detail)].filter(Boolean).join('\n');
		}, this)).catch(L.bind(function(error) {
			this.updateError = _("Could not contact the update service: %s").format(errorMessage(error.message || error));
		}, this)).finally(L.bind(function() {
			return this.refresh(true).finally(L.bind(function() {
				this.updatePending = false;
				this.paintUpdate();
			}, this));
		}, this));
	},

	updateAnalysis: function(data) {
		if (!this.analysisToggle || this.analysisApplying) return;
		var control = data.control || {}, state = control.actual_state;
		var invalid = !!data.config_error || data.enabled === null || state === 'unknown';
		this.analysisToggle.disabled = invalid;
		this.analysisRetry.disabled = invalid;
		this.analysisToggle.checked = state ? state === 'running' : data.enabled === true;
		this.analysisToggle.indeterminate = state === 'partial' || invalid;
		if (invalid) {
			dom.content(this.analysisNotice, _("Repair the settings before changing analysis state."));
			this.analysisRetry.hidden = true;
			return;
		}
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
		if (this.analysisApplying || this.currentData.config_error || typeof enabled !== 'boolean' || this.currentData.enabled === null) return;
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
		var selected = data.selected_interface || '', invalid = data.selected_interface === null, choices = (data.interface_choices || []).slice();
		if (selected && choices.indexOf(selected) < 0) choices.push(selected);
		var draft = this.interfaceDraft == null ? selected : this.interfaceDraft;
		if (draft && choices.indexOf(draft) < 0) choices.push(draft);
		var select = E('select', { 'aria-label': _("Statistics interface"), 'style': 'max-width:100%', 'disabled': this.interfaceSaving ? '' : null },
			[E('option', { 'value': '' }, _("Not bound"))].concat(choices.map(function(name) {
				return E('option', { 'value': name }, (data.interface_choices || []).indexOf(name) < 0 ? _("%s (currently unavailable)").format(name) : name);
			})));
		select.value = draft;
		var confirm = E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-apply', 'disabled': this.interfaceSaving || (!invalid && draft === selected) ? '' : null }, _("Confirm and save"));
		select.addEventListener('change', L.bind(function() {
			this.interfaceDraft = select.value;
			confirm.disabled = this.interfaceSaving || (!invalid && select.value === selected);
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
		var history = this.historyInterface == null ? selected : this.historyInterface;
		var recorded = Array.from(new Set((data.interfaces || []).map(function(item) { return item.name; })));
		if (history && recorded.indexOf(history) < 0) recorded.push(history);
		recorded.sort();
		var historySelect = E('select', { 'aria-label': _("View interface history"), 'style': 'max-width:100%' },
			[E('option', { 'value': '' }, _("All recorded interfaces"))].concat(recorded.map(function(name) { return E('option', { 'value': name }, name); })));
		historySelect.value = history;
		historySelect.addEventListener('change', L.bind(function() {
			this.historyInterface = historySelect.value;
			this.paint();
		}, this));
		var rows = (data.interfaces || []).filter(function(item) { return !history || item.name === history; });
		return E('details', { 'class': 'ns-section', 'open': this.interfaceExpanded ? '' : null, 'toggle': L.bind(function(ev) { this.interfaceExpanded = ev.currentTarget.open; }, this) }, [
			E('summary', {}, _("Interface traffic")),
			E('div', { 'style': 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0' }, [E('label', {}, [_("Statistics interface") + ' ', select]), confirm]),
			E('p', {}, invalid ? _("The capture interface setting is invalid.") : selected ? _("Bound interface: %s").format(selected) : _("No interface is bound")),
			E('label', { 'class': 'ns-history-selector' }, [ _("View interface history") + ' ', historySelect ]),
			E('div', { 'class': 'ns-interface-history' }, rows.length ? rows.map(function(item) { return E('div', {}, [
				E('strong', {}, item.name), trafficBar(item),
				E('div', { 'class': 'ns-values' }, [
					E('span', { 'class': 'ns-down' }, [E('small', {}, _("Receive RX")), E('strong', {}, bytes(item.download))]),
					E('span', { 'class': 'ns-up' }, [E('small', {}, _("Transmit TX")), E('strong', {}, bytes(item.upload))])
				]),
				item.resets ? E('p', { 'role': 'alert' }, _("The interface was reset. Traffic during the reset could not be fully measured.")) : E('span')
			]); }) : E('p', {}, history ? _("No records for this interface") : _("No interface records in this time range")))
		]);
	},

	renderDashboard: function(data) {
		data = data || {};
		var total = data.total || {}, order = this.currentSort();
		this.expandedApps = this.expandedApps || new Set();
		this.trendSelection = this.trendSelection || { bucket: null };
		var filtered = !!(data.identification || data.search || data.application);
		var applications = sorted(data.applications, order.key, order.direction);
		var devices = sorted(data.devices, order.key, order.direction);
		var pages = Math.max(1, Math.ceil((data.app_count || 0) / PAGE_SIZE));
		this.appPage = Math.min(Math.max(this.appPage || 1, 1), pages);
		var devicePages = Math.max(1, Math.ceil((data.device_count || 0) / PAGE_SIZE));
		this.devicePage = Math.min(Math.max(this.devicePage || 1, 1), devicePages);
		return E('div', { 'class': 'ns-dashboard', 'aria-live': 'polite' }, [
			filtered ? E('p', { 'class': 'ns-result-scope' }, _("Results follow the selected filters. Matching an application name includes its traffic; matching only a domain includes only that domain's records.")) : E('span'),
			E('section', { 'class': 'ns-section ns-trend-section' }, [ E('div', { 'class': 'ns-section-head' }, [ E('h3', {}, _("Device traffic trend")), E('div', { 'class': 'ns-legend' }, [ E('span', { 'class': 'download' }, _("Download")), E('span', { 'class': 'upload' }, _("Upload")) ]) ]), timeline(data.timeline, data.timeline_resolution_seconds, this.trendSelection, data.clock_anomaly) ]),
			data.config_error ? E('p', { 'class': 'ns-config-error', 'role': 'alert' }, _("Settings are invalid. Historical data is still available. %s").format(errorMessage(data.config_error))) : E('span'),
			data.clock_anomaly ? E('p', { 'class': 'ns-clock-warning', 'role': 'alert' }, _("Some records are ahead of the system clock. All history includes them; recent time ranges exclude future hours.")) : E('span'),
			order.key === 'flows' ? E('p', { 'class': 'ns-flow-definition' }, _("A connection active in multiple hours is counted once per hour.")) : E('span'),
			data.rules_error ? E('p', { 'role': 'alert' }, _("Community rules could not be loaded. Showing domains instead.")) : E('span'),
			E('div', { 'class': 'ns-stats' }, [
				stat(_("Device download"), bytes(total.download), _("Internet → device"), 'download'), stat(_("Device upload"), bytes(total.upload), _("Device → Internet"), 'upload')
			]),
			classificationCoverage(data),
			collectionDiagnostics(data, this.diagnosticsExpanded, L.bind(function(ev) { this.diagnosticsExpanded = ev.currentTarget.open; }, this)),
			!data.device && !filtered ? this.interfacePanel(data) : E('span'),
			E('section', { 'class': 'ns-section ns-apps' }, [
				E('div', { 'class': 'ns-section-head' }, [ E('h3', {}, _("Application and website ranking")), E('div', { 'class': 'ns-legend' }, [ E('span', { 'class': 'download' }, _("Download")), E('span', { 'class': 'upload' }, _("Upload")) ]) ]),
				applicationRows(applications, this.appPage, this.expandedApps, L.bind(this.refresh, this), L.bind(this.focusApplication, this), filtered),
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
		if (this.searchTimer != null && force !== true) return this.refreshWorker || Promise.resolve();
		var hours = Number(this.hoursSelect && this.hoursSelect.value || 0), device = this.deviceSelect && this.deviceSelect.value || '';
		var order = this.currentSort();
		var visible = new Set((this.currentData && this.currentData.applications || []).map(function(item) { return item.id; }));
		var expanded = Array.from(this.expandedApps || []).filter(function(id) { return visible.has(id); });
		var args = [hours, device, this.appPage || 1, this.devicePage || 1, order.key, order.direction, JSON.stringify(expanded), this.identificationSelect && this.identificationSelect.value || '', this.searchTerm || '', this.applicationFilter || ''], key = JSON.stringify(args);
		// Polls and repeated clicks share the same in-flight query. If filters
		// change, wait for it and run only the latest requested combination.
		// A successful settings write forces a fresh query after older reads.
		if (this.refreshWorker && force !== true && this.refreshKey === key) return this.refreshWorker;
		this.refreshKey = key;
		if (this.queryNotice) dom.content(this.queryNotice, _("Updating results… Previous results remain visible until the query completes."));
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
			this.paintUpdate();
			this.updateFilterNotice();
			if (!this.analysisApplying && data.control && data.control.applied && !data.control.apply_error) this.analysisError = '';
			this.updateAnalysis(data);
			if (this.storageUsage) dom.content(this.storageUsage, _("Current record storage: %s (including database and journal)").format(bytes(data.storage && data.storage.used_bytes)));
			if (this.storageInput) {
				var limit = storageLimitValue(data);
				// Refresh repaired/external settings without replacing an unsaved draft.
				if (this.storageInput.value === this.storageConfirmed) this.storageInput.value = limit;
				this.storageConfirmed = limit;
			}
			if (this.errorNode) dom.content(this.errorNode, []);
			if (this.queryNotice) dom.content(this.queryNotice, []);
			this.updateDeviceChoices(data);
		}, this)).catch(L.bind(function(error) {
			if (requestId === this.requestId) {
				if (this.errorNode) dom.content(this.errorNode, _("Refresh failed. The previous results have been kept. Please try again."));
				if (this.queryNotice) dom.content(this.queryNotice, []);
			}
		}, this)).then(L.bind(function() {
			if (this.pendingRefresh) return this.runRefresh();
		}, this));
	},

	changeFilters: function(clearApplication) {
		if (this.searchTimer != null) clearTimeout(this.searchTimer);
		this.searchTimer = null;
		this.searchTerm = (this.searchInput && this.searchInput.value || '').trim().slice(0, 128);
		if (clearApplication === true) { this.applicationFilter = ''; this.applicationFilterName = ''; }
		this.trendSelection = { bucket: null };
		this.expandedApps.clear(); this.appPage = 1; this.devicePage = 1;
		this.updateFilterNotice();
		return this.refresh();
	},

	queueSearch: function() {
		if (this.searchTimer != null) clearTimeout(this.searchTimer);
		// Invalidate in-flight results immediately while the user edits. The
		// debounce sends only the final input, and polls do not bypass it.
		this.requestId = (this.requestId || 0) + 1;
		this.pendingRefresh = null;
		this.refreshKey = null;
		if (this.queryNotice) dom.content(this.queryNotice, _("Updating results… Previous results remain visible until the query completes."));
		this.searchTimer = setTimeout(L.bind(function() { this.changeFilters(true); }, this), 350);
	},

	focusApplication: function(item) {
		this.applicationFilter = item.id;
		this.applicationFilterName = applicationName(item);
		return this.changeFilters();
	},

	updateFilterNotice: function() {
		if (!this.filterNotice) return;
		var children = [];
		if (this.applicationFilter) children.push(
			E('span', {}, _("Focused traffic: %s").format(this.applicationFilterName || this.applicationFilter)),
			E('button', { 'type': 'button', 'class': 'btn cbi-button', 'click': L.bind(function() { return this.changeFilters(true); }, this) }, _("Clear traffic focus"))
		);

		dom.content(this.filterNotice, children);
	},

	updateDeviceChoices: function(data) {
		if (!this.deviceSelect) return;
		var selected = this.deviceSelect.value || '', search = (this.deviceSearchInput && this.deviceSearchInput.value || '').trim().toLowerCase();
		var options = [E('option', { 'value': '' }, _("All devices"))];
		var items = data.device_choices || [], selectedFound = false;
		items.forEach(function(item) {
			if (item.mac === selected) selectedFound = true;
			if (item.mac !== selected && search && ![item.name, item.mac, item.ip].some(function(value) { return esc(value).toLowerCase().indexOf(search) >= 0; })) return;
			var label = esc(item.name);
			if (item.ip && item.ip !== item.name) label += ' · ' + esc(item.ip);
			if (item.mac && item.mac !== item.name) label += ' · ' + esc(item.mac);
			options.push(E('option', { 'value': item.mac }, label));
		});
		if (selected && !selectedFound) options.push(E('option', { 'value': selected }, selected));
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
.ns-root .ns-classification, .ns-root .ns-evidence { overflow-wrap:anywhere; }
.ns-root .ns-evidence+.ns-evidence { border-top:1px solid rgba(127,127,127,.16); margin-top:8px; }
.ns-root .ns-history-selector { display:block; margin:12px 0; }
.ns-root .ns-coverage-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; }
.ns-root .ns-coverage-item { min-width:0; overflow-wrap:anywhere; }
.ns-root .ns-coverage-value { margin-top:6px; font-size:12px; font-variant-numeric:tabular-nums; }
.ns-root .ns-coverage-bar { height:6px; margin-top:8px; background:rgba(127,127,127,.16); border-radius:3px; overflow:hidden; }
.ns-root .ns-coverage-bar>span { display:block; height:100%; background:#4d9de0; }
.ns-root .ns-coverage-domain .ns-coverage-bar>span { background:#689b73; }
.ns-root .ns-coverage-protocol .ns-coverage-bar>span { background:#c68b45; }
.ns-root .ns-coverage-unknown .ns-coverage-bar>span { background:#888; }
.ns-root .ns-pager button { min-height:44px; min-width:40px; }
.ns-root .ns-field input { min-width:0; max-width:100%; }
.ns-root .ns-diagnostics summary { cursor:pointer; line-height:1.6; }
.ns-root .ns-diagnostic-counts { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; }
.ns-root .ns-diagnostic-counts dt { font-size:12px; }
.ns-root .ns-diagnostic-counts dd { margin:4px 0; font-weight:600; }
.ns-root .ns-diagnostic-issue { border-top:1px solid rgba(127,127,127,.16); }
.ns-root .ns-diagnostic-issue pre { white-space:pre-wrap; overflow-wrap:anywhere; }
.ns-root .ns-filter-notice { display:flex; align-items:center; flex-wrap:wrap; gap:10px; }
.ns-root .ns-filter-notice p { flex-basis:100%; }
.ns-root .ns-update-actions { display:flex; gap:10px; flex-wrap:wrap; }
.ns-root .ns-update-detail { white-space:pre-wrap; overflow-wrap:anywhere; max-height:240px; overflow:auto; }
@media(max-width:720px) {
 .ns-root .ns-coverage-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
 .ns-root .ns-toolbar { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
 .ns-root .ns-field { min-width:0; }
 .ns-root .ns-diagnostic-counts { grid-template-columns:repeat(2,minmax(0,1fr)); }
 .ns-root .ns-field input { width:100%; min-height:44px; font-size:16px; }
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
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Time range")), E('select', { 'id': 'ns-hours', 'change': L.bind(function() { return this.changeFilters(); }, this) }, [ E('option', { 'value': '0', 'selected': '' }, _("All")), E('option', { 'value': '1' }, _("Last 1 hour")), E('option', { 'value': '5' }, _("Last 5 hours")), E('option', { 'value': '24' }, _("Last 24 hours")), E('option', { 'value': '168' }, _("Last 7 days")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Device")), E('select', { 'id': 'ns-device', 'change': L.bind(function() { return this.changeFilters(); }, this) }, [ E('option', { 'value': '' }, _("All devices")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', { 'for': 'ns-device-search' }, _("Find a device")), E('input', { 'id': 'ns-device-search', 'type': 'search', 'maxlength': '128', 'placeholder': _("Name, MAC or IP address"), 'input': L.bind(function() { this.updateDeviceChoices(this.currentData); }, this) }) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', { 'for': 'ns-identification' }, _("Identification level")), E('select', { 'id': 'ns-identification', 'change': L.bind(function() { return this.changeFilters(true); }, this) }, [
				E('option', { 'value': '' }, _("All identification levels")), E('option', { 'value': 'application' }, _("Application identified")),
				E('option', { 'value': 'domain' }, _("Domain or infrastructure only")), E('option', { 'value': 'protocol' }, _("Protocol only")), E('option', { 'value': 'unknown' }, _("Unidentified"))
			]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', { 'for': 'ns-search' }, _("Find application or domain")), E('input', { 'id': 'ns-search', 'type': 'search', 'maxlength': '128', 'input': L.bind(this.queueSearch, this), 'keydown': L.bind(function(ev) { if (ev.key === 'Enter') { ev.preventDefault(); return this.changeFilters(true); } }, this) }) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Sort by")), E('select', { 'id': 'ns-sort', 'change': rerender }, [ E('option', { 'value': 'total' }, _("Total traffic")), E('option', { 'value': 'download' }, _("Download")), E('option', { 'value': 'upload' }, _("Upload")), E('option', { 'value': 'flows' }, _("Hourly active connections")) ]) ]),
			E('div', { 'class': 'ns-field' }, [ E('label', {}, _("Order")), E('select', { 'id': 'ns-order', 'change': rerender }, [ E('option', { 'value': 'desc' }, _("Highest first")), E('option', { 'value': 'asc' }, _("Lowest first")) ]) ]),
			E('button', { 'class': 'btn cbi-button cbi-button-action ns-refresh', 'click': L.bind(function() { return this.searchTimer != null ? this.changeFilters(true) : this.refresh(); }, this) }, _("Refresh"))
		]);
		this.queryNotice = E('p', { 'class': 'ns-query-notice', 'role': 'status' });
		this.filterNotice = E('div', { 'class': 'ns-filter-notice', 'role': 'status' });
		var content = E('div', { 'id': 'ns-content' }), root = E('div', {}, [ style, E('h2', {}, _("DPI Traffic Analysis")), controls, this.filterNotice, this.queryNotice, content ]);
		this.analysisToggle = E('input', { 'type': 'checkbox', 'role': 'switch', 'class': 'ns-switch', 'checked': data.enabled === true ? '' : null, 'change': L.bind(function(ev) {
			return this.applyAnalysis(ev.currentTarget.checked);
		}, this) });
		root.insertBefore(E('label', { 'class': 'ns-controls', 'style': 'min-height:44px;align-items:center' }, [this.analysisToggle, _("Traffic analysis")]), controls);
		this.analysisNotice = E('p', { 'role': 'alert' });
		this.analysisRetry = E('button', { 'type': 'button', 'class': 'btn cbi-button', 'hidden': '', 'click': L.bind(function() {
			var control = this.currentData.control;
			return this.applyAnalysis(control ? control.enabled : this.currentData.enabled !== false);
		}, this) }, _("Retry applying"));
		root.insertBefore(E('div', {}, [this.analysisNotice, this.analysisRetry]), controls);
		var storageInput = E('input', { 'type': 'number', 'min': '0', 'max': '4096', 'step': '1', 'value': storageLimitValue(data), 'aria-label': _("Record storage limit in MiB") });
		this.storageInput = storageInput; this.storageConfirmed = storageInput.value;
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
		this.updatePanel = E('section', { 'class': 'ns-section ns-update-panel' });
		root.appendChild(this.updatePanel);
		root.classList.add('ns-root');
		this.errorNode = E('p', { 'role': 'alert' });
		root.insertBefore(this.errorNode, content);
		this.hoursSelect = controls.querySelector('#ns-hours'); this.deviceSelect = controls.querySelector('#ns-device'); this.sortSelect = controls.querySelector('#ns-sort'); this.orderSelect = controls.querySelector('#ns-order'); this.contentNode = content; this.currentData = data; this.appPage = 1;
		this.identificationSelect = controls.querySelector('#ns-identification'); this.searchInput = controls.querySelector('#ns-search'); this.deviceSearchInput = controls.querySelector('#ns-device-search');
		this.updateDeviceChoices(data);
		this.updateAnalysis(data);
		this.paintUpdate();
		this.paint(); poll.add(L.bind(this.refresh, this), 30); return root;
	},

	handleSaveApply: null, handleSave: null, handleReset: null
});
