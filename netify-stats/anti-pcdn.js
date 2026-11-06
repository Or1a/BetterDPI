'use strict';
'require view';
'require rpc';
'require dom';
'require poll';

var readStatus = rpc.declare({ object: 'betterdpi-anti-pcdn', method: 'status', expect: {} });
var saveSettings = rpc.declare({ object: 'betterdpi-anti-pcdn', method: 'configure', params: ['settings'], expect: {} });
var releaseLease = rpc.declare({ object: 'betterdpi-anti-pcdn', method: 'release', params: ['id'], expect: {} });
var weights = ['fanout', 'serving_peers', 'sustained', 'upload_ratio', 'domain'];

function text(value) { return value == null ? '' : String(value); }
function list(value) { return Array.isArray(value) ? value : []; }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
function bytes(value) {
	value = Number(value);
	if (!isFinite(value) || value < 0) return '—';
	var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'], index = 0;
	while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
	return value.toFixed(index ? 1 : 0) + ' ' + units[index];
}
function terms(value) { return text(value).split(/[\s,]+/).filter(Boolean); }
function reasonName(code) {
	var names = {
		fanout: _('Peer diversity'), serving_peers: _('Peers receiving uploads'),
		upload_diversity: _('Multiple upload-dominant peers'), active_distribution: _('Repeated upload progress'),
		historical_peers: _('Upload distribution across rotating peers'), historical_distribution: _('Repeated cross-port distribution'),
		sustained: _('Sustained uploads'), upload_ratio: _('Upload ratio'), domain: _('Uploader domain hint')
	};
	return names[code] || text(code);
}
function guardName(code) {
	var names = {
		warming_up: _('Waiting for an observation window'), incomplete_window: _('Observation window is incomplete'),
		allowlisted: _('Allowlisted'), protected_transport: _('Protected transport'),
		unsupported_proxy: _('Proxy attribution is unavailable'), shared_transport: _('Shared transport'),
		not_uploading: _('No current upload evidence'), suppressed: _('Temporarily suppressed'),
		short_window_only: _('Only short observations are retained for this connection group'),
		group_capacity: _('Connection group exceeds the observation limit'),
		identity_unconfirmed: _('Device identity is unconfirmed'), flow_offload: _('Flow offload prevents safe enforcement')
	};
	return names[code] || text(code);
}
function diagnosticName(code) {
	var names = {
		flow_identities: _('Connection identities'), active_groups: _('Full observation windows'),
		closed_cursors: _('Completed connection replay guards'),
		samples: _('Time buckets'), ignored_identities: _('Excluded identities'), recovery_requests: _('Metadata recovery requests'),
		flow_capacity: _('Connection identity limit'), group_capacity: _('Full-window limit'),
		device_group_capacity: _('Per-device full-window limit'), group_flow_capacity: _('Connections per group limit'),
		exclusion_capacity: _('Excluded identity cache limit'), recovery_capacity: _('Metadata recovery limit'),
		sample_drops: _('Sample storage limit'), missing_metadata: _('Missing connection metadata'),
		metadata_recovered: _('Metadata baselines recovered'), metadata_resolved: _('Missing identities resolved'),
		accepted_events: _('Accepted traffic increments'), delayed_events: _('Late or overlong reports'),
		zero_delta_events: _('Zero-byte reports ignored'), expired_delta_events: _('Reports outside the observation window'),
		duplicate_missing_events: _('Repeated unresolved reports'), closed_identities_compacted: _('Completed identities compacted'),
		excluded_identities_released: _('Completed excluded identities released'), closed_cursor_capacity: _('Completed replay guard limit'),
		closed_cursor_conflicts: _('Completed connection counter conflicts'), closed_metadata: _('Repeated completed metadata'),
		incarnations_retained: _('Previous connection evidence retained'),
		global: _('All devices'), group: _('One connection group'), unresolved: _('Identity not yet known')
	};
	return names[code] || text(code);
}
function endpoint(address, port) {
	address = text(address);
	return (address.indexOf(':') >= 0 ? '[' + address + ']' : address) + ':' + text(port);
}
function tuple(row) { return text(row.protocol || row.proto) + ' ' + endpoint(row.ip, row.sport) + ' → ' + endpoint(row.peer, row.dport); }
function table(headers, rows) {
	return E('table', {class: 'table'}, [E('tr', {class: 'tr table-titles'}, headers.map(function(header) {
		return E('th', {class: 'th'}, header);
	}))].concat(rows.length ? rows : [E('tr', {class: 'tr'}, [E('td', {class: 'td', colspan: headers.length}, _('No entries.'))])]));
}
var fieldSequence = 0;
function field(label, input, help) {
	var id = 'ap-field-' + (++fieldSequence);
	input.setAttribute('id', id);
	return E('div', {class: 'cbi-value'}, [E('label', {class: 'cbi-value-title', 'for': id}, label),
		E('div', {class: 'cbi-value-field'}, [input, help ? E('p', {class: 'cbi-value-description'}, help) : ''])]);
}
function integerInput(value, min, max) {
	return E('input', {class: 'cbi-input-text', type: 'number', min: min, max: max, step: 1, value: text(value)});
}
function checkedResponse(result) {
	if (!result || result.error || result.ok !== true) throw new Error(result && result.error || _('The request failed.'));
	return result;
}
function validSettings(settings) {
	settings = object(settings);
	return typeof settings.enabled === 'boolean' && ['observe', 'auto'].includes(settings.mode)
		&& typeof settings.interface === 'string' && settings.interface.length > 0
		&& Number.isInteger(settings.threshold) && settings.threshold >= 1 && settings.threshold <= 100
		&& Number.isInteger(settings.ban_seconds) && settings.ban_seconds >= 30 && settings.ban_seconds <= 600
		&& ['allow_devices', 'allow_domains', 'pcdn_domains'].every(function(key) {
			return Array.isArray(settings[key]) && settings[key].every(function(value) { return typeof value === 'string'; });
		}) && weights.every(function(key) { var value = object(settings.weights)[key]; return Number.isInteger(value) && value >= 0 && value <= 40; })
		&& weights.reduce(function(total, key) { return total + settings.weights[key]; }, 0) === 100;
}
function validStatus(data) {
	return !!data && !data.error && data.ok !== false && validSettings(data.settings)
		&& typeof data.stale === 'boolean' && typeof data.collector_recent === 'boolean'
		&& typeof data.collector_connected === 'boolean' && !!data.runtime
		&& typeof data.runtime === 'object' && !Array.isArray(data.runtime);
}
function checkedStatus(data) {
	if (!validStatus(data)) throw new Error(data && data.error || _('Runtime status is unavailable.'));
	return data;
}
function settingsAvailable(data) { return validStatus(data) && !data.request_error && !data.config_error; }

return view.extend({
	load: function() {
		return readStatus().then(checkedStatus)
			.catch(function(error) { return {request_error: text(error.message || error)}; });
	},
	render: function(data) {
		this.epoch = 0;
		this.sequence = 0;
		this.data = data || {};
		this.inputs = {};
		this.notice = E('p', {'aria-live': 'polite'});
		this.statusPanel = E('div', {class: 'ap-status'});
		this.rowsPanel = E('div', {class: 'ap-table-scroll', tabindex: '0', 'aria-label': _('Scored connections')});
		this.leasesPanel = E('div', {class: 'ap-table-scroll', tabindex: '0', 'aria-label': _('Temporary connection rules')});
		this.diagnosticsPanel = E('div');
		this.devicesPanel = E('div', {class: 'ap-table-scroll', tabindex: '0', 'aria-label': _('Cross-port device observations')});
		this.observationsPanel = E('div', {class: 'ap-table-scroll', tabindex: '0', 'aria-label': _('Shadow decision history')});
		this.saveButton = E('button', {class: 'cbi-button cbi-button-apply', click: this.save.bind(this)}, _('Save Anti-PCDN settings'));
		this.settingsLoaded = settingsAvailable(this.data);
		this.formPanel = E('div', {}, this.settingsForm(object(this.data.settings)));
		this.updateStatus(this.data);
		poll.add(this.refresh.bind(this), 5);
		return E('div', {class: 'cbi-map ap-root'}, [
			E('style', {}, `
.ap-root { min-width:0; line-height:1.6; }
.ap-root * { box-sizing:border-box; }
.ap-root .ap-card { border:1px solid rgba(127,127,127,.22); border-radius:12px; padding:20px; margin:18px 0; min-width:0; background:transparent; }
.ap-root .ap-card h3 { margin:0 0 14px; padding:0; background:transparent; color:inherit; border:0; }
.ap-root .ap-status p { border-left:3px solid #4d9de0; padding:10px 14px; background:rgba(127,127,127,.06); border-radius:4px; overflow-wrap:anywhere; }
.ap-root .ap-status .warning { border-left-color:#c68b45; }
.ap-root .ap-settings { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px 24px; border:0; padding:0; margin:0; background:transparent; }
.ap-root .cbi-value { min-width:0; margin:0; padding:0; background:transparent; }
.ap-root .cbi-value-title { display:block; float:none; width:auto; text-align:left; padding:0 0 6px; font-weight:600; }
.ap-root .cbi-value-field { margin:0; padding:0; }
.ap-root .cbi-value-description { margin:6px 0 0; font-size:12px; line-height:1.6; opacity:.85; }
.ap-root input:not([type=checkbox]), .ap-root select, .ap-root textarea { width:100%; max-width:100%; min-height:40px; }
.ap-root textarea { resize:vertical; font-family:monospace; }
.ap-root input[type=checkbox] { width:22px; height:22px; accent-color:#2f7dd1; }
.ap-root .ap-lists, .ap-root .ap-weights { grid-column:1/-1; display:grid; gap:16px; grid-template-columns:repeat(3,minmax(0,1fr)); padding-top:18px; border-top:1px solid rgba(127,127,127,.18); }
.ap-root .ap-weights { grid-template-columns:repeat(5,minmax(0,1fr)); }
.ap-root .ap-settings>p { grid-column:1/-1; margin:0; font-size:12px; }
.ap-root .ap-actions { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-top:20px; }
.ap-root .ap-actions p:empty { display:none; }
.ap-root button { min-height:40px; }
.ap-root .ap-table-scroll { overflow-x:auto; }
.ap-root table { width:100%; min-width:680px; border-collapse:collapse; font-variant-numeric:tabular-nums; }
.ap-root .th, .ap-root .td { text-align:left; vertical-align:top; padding:12px; overflow-wrap:anywhere; max-width:340px; }
.ap-root .table-titles { background:rgba(127,127,127,.06); }
.ap-root .td { border-top:1px solid rgba(127,127,127,.16); }
.ap-root .td div+div { margin-top:4px; font-size:12px; }
.ap-root :focus-visible { outline:2px solid #4d9de0; outline-offset:3px; }
@media(max-width:720px) {
 .ap-root .ap-card { padding:14px; }
 .ap-root .ap-settings, .ap-root .ap-lists { grid-template-columns:minmax(0,1fr); }
 .ap-root .ap-weights { grid-template-columns:repeat(2,minmax(0,1fr)); }
 .ap-root input:not([type=checkbox]), .ap-root select, .ap-root textarea { font-size:16px; min-height:44px; }
 .ap-root .ap-actions button { width:100%; min-height:44px; }
}
`),
			E('h2', {}, _('Anti-PCDN')),
			E('p', {}, _('Optional short-window scoring for individual LAN connections. Scores indicate suspicion, not proof of PCDN.')),
			E('p', {}, _('This feature requires the DPI collector to be running. Enabling it does not start paused traffic analysis. It does not add its observations to traffic totals.')),
			this.statusPanel,
			E('section', {class: 'ap-card'}, [this.formPanel, E('div', {class: 'ap-actions'}, [this.saveButton, this.notice])]),
			E('section', {class: 'ap-card'}, [E('h3', {}, _('Cross-port device observations')),
				E('p', {}, _('Device scores combine observations across local ports. They do not authorize blocking; individual connections still require complete evidence and all enforcement checks.')), this.devicesPanel]),
			E('section', {class: 'ap-card'}, [E('h3', {}, _('Scored connections')), this.rowsPanel]),
			E('section', {class: 'ap-card'}, [E('h3', {}, _('Shadow decision history')),
				E('p', {}, _('Observation records never install rules. Protected VPN, proxy and allowlisted connections are excluded.')),
				E('p', {}, _('A simulated block is a scoring proposal; firewall enforcement has not been checked. Other records show why a connection was not eligible.')),
				this.observationsPanel]),
			E('section', {class: 'ap-card'}, [E('h3', {}, _('Temporary connection rules')),
				E('p', {}, _('Installed rules are not proof that traffic was successfully blocked. Observed bytes are DPI observations, not blocked bytes.')), this.leasesPanel]),
			E('section', {class: 'ap-card'}, [E('h3', {}, _('Coverage and recent actions')), this.diagnosticsPanel])
		]);
	},
	settingsForm: function(settings) {
		var input = this.inputs;
		input.enabled = E('input', {type: 'checkbox', checked: settings.enabled === true ? '' : null});
		input.mode = E('select', {class: 'cbi-input-select'}, [
			E('option', {value: 'observe', selected: settings.mode !== 'auto' ? '' : null}, _('Observe only')),
			E('option', {value: 'auto', selected: settings.mode === 'auto' ? '' : null}, _('Automatic temporary blocking'))
		]);
		input.threshold = integerInput(settings.threshold == null ? 80 : settings.threshold, 1, 100);
		input.ban_seconds = integerInput(settings.ban_seconds == null ? 120 : settings.ban_seconds, 30, 600);
		input.interface = E('input', {class: 'cbi-input-text', value: settings.interface || 'br-lan', maxlength: 15});
		var fields = [
			field(_('Enable Anti-PCDN'), input.enabled),
			field(_('Mode'), input.mode, _('Observe mode never installs rules. Automatic mode requires both the threshold and all enforcement checks.')),
			field(_('Score threshold (1–100)'), input.threshold),
			field(_('Rule duration (30–600 seconds)'), input.ban_seconds),
			field(_('LAN interface'), input.interface, _('Use the interface where the device and its MAC address are visible.'))
		];
		[['allow_devices', _('Allowed device MAC addresses')], ['allow_domains', _('Allowed domains')], ['pcdn_domains', _('Known uploader domains')]].forEach(function(item) {
			input[item[0]] = E('textarea', {class: 'cbi-input-textarea', rows: 3, maxlength: 33000}, list(settings[item[0]]).join('\n'));
			fields.push(field(item[1], input[item[0]], item[0] === 'allow_devices'
				? _('One MAC address per line; allowed devices are never automatically blocked.')
				: item[0] === 'pcdn_domains'
					? _('Optional upload-specific hostnames, one per line. Hints add points only to the matching connection. Do not use broad CDN domains.')
					: _('One DNS name per line, including subdomains at label boundaries. No URLs or wildcards.')));
		});
		var defaults = [25, 20, 20, 15, 20];
		weights.forEach(function(key, index) {
			input['weight_' + key] = integerInput(object(settings.weights)[key] == null ? defaults[index] : settings.weights[key], 0, 40);
			fields.push(field(reasonName(key), input['weight_' + key], key === 'fanout'
				? _('Unique peers in 60 seconds: 20 can add up to 25 points, 40 up to 35, and 80 up to 40. This weight caps the contribution.') : null));
		});
		fields.push(E('p', {}, _('Each score weight is 0–40; all five weights must total 100. The maximum score is 100.')));
		return E('div', {class: 'cbi-section ap-settings'}, fields.slice(0, 5).concat([
			E('div', {class: 'ap-lists'}, fields.slice(5, 8)),
			E('div', {class: 'ap-weights'}, fields.slice(8, 13)), fields[13]
		]));
	},
	settingsValue: function() {
		var inputs = this.inputs, result = {enabled: inputs.enabled.checked, mode: inputs.mode.value,
			interface: inputs.interface.value.trim(), threshold: Number(inputs.threshold.value),
			ban_seconds: Number(inputs.ban_seconds.value), weights: {}};
		['allow_devices', 'allow_domains', 'pcdn_domains'].forEach(function(key) { result[key] = terms(inputs[key].value); });
		weights.forEach(function(key) { result.weights[key] = Number(inputs['weight_' + key].value); });
		return result;
	},
	save: function() {
		if (this.busy || !settingsAvailable(this.data)) return Promise.resolve();
		this.busy = true;
		this.epoch++;
		this.saveButton.disabled = true;
		dom.content(this.notice, _('Saving settings…'));
		return saveSettings(this.settingsValue()).then(checkedResponse).then(function() {
			dom.content(this.notice, _('Settings saved. The running collector will apply them shortly; paused traffic analysis stays paused.'));
			return this.refresh();
		}.bind(this)).catch(function(error) {
			dom.content(this.notice, _('Could not save settings:') + ' ' + text(error.message || error));
		}.bind(this)).finally(function() {
			this.busy = false;
			this.updateStatus(this.data);
		}.bind(this));
	},
	refresh: function() {
		var epoch = this.epoch, sequence = ++this.sequence;
		return readStatus().then(function(data) {
			if (epoch !== this.epoch || sequence !== this.sequence) return;
			this.data = checkedStatus(data);
			// An initial failed read leaves only disabled placeholders. Populate
			// actual saved values once recovered; normal polls preserve drafts.
			if (!this.settingsLoaded && settingsAvailable(data)) {
				this.inputs = {};
				dom.content(this.formPanel, this.settingsForm(data.settings));
				this.settingsLoaded = true;
			}
			this.updateStatus(data);
		}.bind(this)).catch(function(error) {
			if (epoch !== this.epoch || sequence !== this.sequence) return;
			this.data = Object.assign({}, this.data, {request_error: text(error.message || error)});
			this.updateStatus(this.data);
		}.bind(this));
	},
	release: function(id) {
		if (this.releasing || !validStatus(this.data) || this.data.request_error || this.data.stale !== false || this.data.release_pending) return Promise.resolve();
		this.releasing = true;
		this.epoch++;
		this.updateStatus(this.data);
		return releaseLease(id).then(checkedResponse).then(function(result) {
			this.data.release_pending = {id: id, request_id: result.request_id};
			dom.content(this.notice, _('Release requested. Wait for the runtime acknowledgement in recent actions.'));
			return this.refresh();
		}.bind(this)).catch(function(error) {
			dom.content(this.notice, _('Could not request release:') + ' ' + text(error.message || error));
		}.bind(this)).finally(function() {
			this.releasing = false;
			this.updateStatus(this.data);
		}.bind(this));
	},
	updateStatus: function(data) {
		var runtime = object(data.runtime), settings = object(data.settings), messages = [];
		var available = validStatus(data) && !data.request_error;
		var editable = settingsAvailable(data) && !this.busy;
		this.saveButton.disabled = !editable;
		Object.keys(this.inputs).forEach(function(key) { this.inputs[key].disabled = !editable; }, this);
		if (!available) {
			messages.push(E('p', {class: 'alert-message warning'}, _('Status could not be read. Settings and collector state are unknown; changes are disabled.')));
			if (validStatus(data)) messages.push(E('p', {}, _('Showing the last successful response; current status is unknown.')));
		} else {
			if (data.config_error) messages.push(E('p', {class: 'alert-message warning'}, _('Settings could not be read. Changes are disabled until configuration is available.')));
			else {
				messages.push(E('p', {}, settings.enabled === true ? _('Anti-PCDN is enabled in settings.') : _('Anti-PCDN is disabled in settings.')));
				if (settings.enabled === true && (runtime.enabled !== true || runtime.mode !== settings.mode) || settings.enabled === false && runtime.enabled === true)
					messages.push(E('p', {}, _('Saved settings are awaiting the collector.')));
			}
			if (settings.enabled === true) {
				if (data.collector_recent !== true) messages.push(E('p', {class: 'alert-message warning'}, _('No recent DPI collector heartbeat. Start traffic analysis to collect evidence.')));
				else if (data.collector_connected !== true) messages.push(E('p', {class: 'alert-message warning'}, _('The DPI collector is not connected; evidence may be incomplete.')));
			}
			if (data.stale !== false && (settings.enabled === true || runtime.enabled === true || list(runtime.leases).length))
				messages.push(E('p', {class: 'alert-message warning'}, _('Runtime status is stale or unavailable. Listed rules may have expired; release is disabled.')));
			if (runtime.mode === 'observe') messages.push(E('p', {}, _('Observation only: threshold crossings do not install rules.')));
		}
		(data.request_error ? [data.request_error] : [data.config_error, data.runtime_error, runtime.error, runtime.executor_error, runtime.metadata_error]).filter(Boolean).forEach(function(error) {
			messages.push(E('p', {class: 'alert-message warning'}, text(error)));
		});
		if (available && data.release_pending) messages.push(E('p', {}, _('A release request is pending.')));
		var coverage = object(runtime.coverage);
		var fastPath = object(runtime.fast_path);
		var readiness = object(runtime.execution_readiness);
		if (available && data.stale === false && settings.enabled === true && readiness.supported === false)
			messages.push(E('p', {class: 'alert-message warning'}, _('This forwarding path cannot currently enforce automatic blocks. Scoring and observation continue.') + ' ' + text(readiness.reason)));
		if (runtime.fast_path && available && data.stale === false) {
			messages.push(E('p', {}, _('Fast detection combines ports and checks new bytes every second. Bursts need 8 uploading peers; rotating uploads need 4 peers across 3 networks and 2 MiB of distributed evidence. A 30-minute lookback does not require waiting 30 minutes.')));
			messages.push(E('p', {}, _('History alone cannot trigger a decision: new peers need 512 KiB of current upload, returning qualified peers need 32 KiB, with repeated upload progress. VPN and allowlist protections take priority.')));
			messages.push(E('p', {}, _('Fast peer diversity counts IPv4 addresses and IPv6 /64 prefixes; multiple addresses do not prove multiple machines.')));
			if (fastPath.error) messages.push(E('p', {class: 'alert-message warning'}, _('Fast detection unavailable:') + ' ' + text(fastPath.error)));
			if (object(fastPath.history).error || fastPath.checkpoint_error) messages.push(E('p', {class: 'alert-message warning'}, _('Distribution history unavailable:') + ' ' + text(object(fastPath.history).error || fastPath.checkpoint_error)));
		}
		if (available && data.stale === false && settings.enabled === true &&
			(Number(coverage.global_wait_seconds) > 0 || Number(coverage.unresolved_metadata) > 0))
			messages.push(E('p', {class: 'alert-message warning'}, _('Observation coverage is incomplete. Low scores do not rule out suspicious traffic.')));
		dom.content(this.statusPanel, messages);
		var deviceRows = list(runtime.devices).slice(0, 20).map(function(device) {
			device = object(device);
			var metrics = object(device.metrics);
			return E('tr', {class: 'tr'}, [
				E('td', {class: 'td'}, [E('div', {}, text(device.mac)), E('div', {}, text(device.ip)),
					E('div', {}, (device.proto === 6 ? 'TCP' : device.proto === 17 ? 'UDP' : text(device.proto)) + ' · ' + _('Local ports:') + ' ' + text(device.ports))]),
				E('td', {class: 'td'}, [E('strong', {}, text(device.score) + '/100'),
					E('div', {}, list(device.reasons).map(function(reason) { return reasonName(reason.id) + ': +' + text(reason.points); }).join(', '))]),
				E('td', {class: 'td'}, [E('div', {}, _('Upload:') + ' ' + bytes(metrics.upload)),
					E('div', {}, _('Download:') + ' ' + bytes(metrics.download)), E('div', {}, _('Peers:') + ' ' + text(metrics.peers))]),
				E('td', {class: 'td'}, [E('div', {}, _('Observation only')),
					E('div', {}, !available || data.stale !== false ? _('Runtime status is unavailable.') : device.complete === true && !(Number(coverage.global_wait_seconds) > 0 || Number(coverage.unresolved_metadata) > 0) ? _('Complete observation window') : _('Partial observation'))])
			]);
		});
		dom.content(this.devicesPanel, table([_('Device and connection'), _('Score and evidence'), _('Observed bytes'), _('Decision and guards')], deviceRows));
		var rows = list(runtime.candidates).slice(0, 64).map(function(row) {
			row = object(row);
			var reasons = list(row.reasons).map(function(reason) { return reasonName(reason.id) + ': +' + text(reason.points); }).join(', ');
			var guards = list(row.guards).map(guardName).join(', ');
			var decision = row.threshold_met ? _('Threshold reached') : _('Below threshold');
			if (row.threshold_met) decision += '; ' + (guards ? _('Action guarded') : runtime.mode === 'observe' ? _('Observation only') : _('Awaiting enforcement checks'));
			return E('tr', {class: 'tr'}, [
				E('td', {class: 'td'}, [E('div', {}, text(row.mac)), E('div', {}, tuple(row)), E('div', {}, text(row.host))]),
				E('td', {class: 'td'}, [E('strong', {}, text(row.score) + '/100'), E('div', {}, reasons),
					E('div', {}, row.evidence_source === 'conntrack_fast' ? _('Fast distribution evidence') : '')]),
				E('td', {class: 'td'}, [E('div', {}, _('Upload:') + ' ' + bytes(row.upload)), E('div', {}, _('Download:') + ' ' + bytes(row.download))]),
				E('td', {class: 'td'}, [E('div', {}, decision), E('div', {}, guards),
					Number(row.wait_seconds) > 0 ? E('div', {}, _('Window wait:') + ' ' + Math.ceil(row.wait_seconds) + ' ' + _('seconds remaining')) : '',
					E('div', {}, text(row.execution_error))])
			]);
		});
		dom.content(this.rowsPanel, table([_('Device and connection'), _('Score and evidence'), _('Observed bytes'), _('Decision and guards')], rows));
		var journal = object(runtime.observations), history = [];
		if (journal.error) history.push(E('p', {class: 'alert-message warning'}, _('Observation recording failed:') + ' ' + text(journal.error)));
		if (runtime.observations) {
			history.push(E('p', {}, _('Records written in this session:') + ' ' + text(journal.written)));
			history.push(E('p', {}, _('Local rotating history, up to 8 MiB. Collector restarts keep the files; router reboots clear them. The latest 20 records from this session are shown.')));
			history.push(E('p', {}, _('Groups with at least 40 peers are also recorded without material upload. These watch-only samples cannot qualify for a simulated block.')));
			history.push(E('p', {}, _('Records waiting to be written:') + ' ' + text(journal.pending || 0) + ' · ' + _('Records lost to recording limits:') + ' ' + text(journal.dropped || 0)));
		}
		history.push(table([_('Recorded at'), _('Device and connection'), _('Score and evidence'), _('Shadow decision')], list(journal.recent).slice(-20).reverse().map(function(record) {
			var metrics = object(record.metrics);
			var outcome = {would_block: _('Simulated block; not executed'), evidence_incomplete: _('Threshold reached; evidence incomplete'), below_threshold: _('Below threshold')}[record.outcome] || _('Decision unavailable');
			return E('tr', {class: 'tr'}, [
				E('td', {class: 'td'}, new Date(Number(record.timestamp) * 1000).toLocaleString()),
				E('td', {class: 'td'}, [E('div', {}, text(record.mac)), E('div', {}, tuple(record)), E('div', {}, text(record.host))]),
				E('td', {class: 'td'}, [E('div', {}, text(record.score) + '/100 · ' + _('Score threshold (1–100)') + ': ' + text(record.threshold)),
					E('div', {}, list(record.reasons).map(function(reason) { return reasonName(reason.id) + ': +' + text(reason.points); }).join(', ')),
					E('div', {}, _('Upload:') + ' ' + bytes(metrics.upload) + ' · ' + _('Download:') + ' ' + bytes(metrics.download)),
					E('div', {}, _('Peers:') + ' ' + text(metrics.peers))]),
				E('td', {class: 'td'}, [E('div', {}, outcome),
					object(object(record.coverage).execution_readiness).supported === false ? E('div', {}, _('Platform precheck failed; this score is not an executable block.')) : '',
					E('div', {}, record.sample_type === 'fanout_watch' ? _('High peer count; observation only') : ''),
					record.evidence_source === 'conntrack_fast' ? E('div', {}, _('Fast distribution evidence') + ' · ' +
						_('Seconds observed:') + ' ' + text(record.observed_seconds) + ' · ' +
						_('Connection upload at trigger:') + ' ' + bytes(record.connection_upload_bytes)) : '',
						record.aggregation === 'cross_port' ? E('div', {}, _('Cross-port uploading peers:') + ' ' + text(object(record.history_metrics).serving_peers) + ' · ' +
							_('Distributed upload evidence:') + ' ' + bytes(object(record.history_metrics).distributed_upload)) : '',
					E('div', {}, list(record.guards).map(guardName).join(', '))])
			]);
		})));
		dom.content(this.observationsPanel, history);
		var leaseRows = list(runtime.leases).slice(0, 64).map(function(lease) {
			lease = object(lease);
			var button = E('button', {class: 'cbi-button cbi-button-reset', click: this.release.bind(this, lease.id)}, _('Release rule'));
			button.disabled = !!this.releasing || !available || data.stale !== false || !!data.release_pending;
			var remaining = Number(lease.remaining);
			var ruleState = lease.state === 'installed' ? _('Rule installed; blocking not independently verified')
				: lease.state === 'unverified_cleanup_pending' ? _('Rule verification failed; cleanup pending until kernel expiry')
					: _('Rule state is unconfirmed');
			return E('tr', {class: 'tr'}, [E('td', {class: 'td'}, [E('div', {}, text(lease.mac)), E('div', {}, tuple(lease))]),
				E('td', {class: 'td'}, ruleState),
				E('td', {class: 'td'}, isFinite(remaining) && remaining >= 0 ? Math.ceil(remaining) + ' ' + _('seconds remaining') : _('Expiry unavailable')),
				E('td', {class: 'td'}, button)]);
		}.bind(this));
		dom.content(this.leasesPanel, table([_('Device and connection'), _('Rule state'), _('Time remaining'), _('Action')], leaseRows));
		var diagnostics = [];
		if (runtime.timestamp) diagnostics.push(E('p', {}, _('Last runtime update:') + ' ' + new Date(Number(runtime.timestamp) * 1000).toLocaleString()));
		if (runtime.fast_path) diagnostics.push(E('p', {}, _('Fast counter coverage:') + ' ' + text(fastPath.matched) + ' · ' +
			_('Connections without matching DPI identity:') + ' ' + text(fastPath.unattributed)));
		if (fastPath.history) diagnostics.push(E('p', {}, _('Cross-port history:') + ' ' + text(fastPath.history.peers) + ' ' + _('Peers:') + ' · ' +
			_('Qualified distribution groups:') + ' ' + text(fastPath.history.qualified_cohorts)));
		if (runtime.fast_path) diagnostics.push(E('p', {}, _('Counter sample time:') + ' ' + text(fastPath.last_read_ms) + ' ms · ' +
			_('Failed reads:') + ' ' + text(object(fastPath.counters).read_failures || 0) + ' · ' + _('Recovered reads:') + ' ' + text(object(fastPath.counters).recovered_reads || 0)));
		if (runtime.coverage) {
			diagnostics.push(E('p', {}, _('Unresolved connection metadata:') + ' ' + text(coverage.unresolved_metadata)));
			diagnostics.push(E('p', {}, _('Global window wait:') + ' ' + text(coverage.global_wait_seconds) + ' ' + _('seconds remaining')));
			if (coverage.last_gap) diagnostics.push(E('p', {}, _('Last observation gap:') + ' ' + diagnosticName(coverage.last_gap) + ' · ' + diagnosticName(coverage.last_gap_scope)));
			var resources = object(coverage.resources);
			diagnostics.push(table([_('Resource'), _('In use'), _('Limit')], Object.keys(resources).slice(0, 16).map(function(key) {
				var resource = object(resources[key]);
				return E('tr', {class: 'tr'}, [E('td', {class: 'td'}, diagnosticName(key)), E('td', {class: 'td'}, text(resource.used)), E('td', {class: 'td'}, text(resource.limit))]);
			})));
		}
		var counters = [E('p', {}, _('These are cumulative event counts, not packets or bytes. Categories may overlap.'))];
		Object.keys(object(runtime.counters)).sort().slice(0, 64).forEach(function(key) {
			counters.push(E('div', {}, diagnosticName(key) + ': ' + text(runtime.counters[key])));
		});
		Object.keys(object(runtime.engine_counters)).sort().slice(0, 64).forEach(function(key) {
			counters.push(E('div', {}, diagnosticName(key) + ': ' + text(runtime.engine_counters[key])));
		});
		if (runtime.queue_depth != null) diagnostics.push(E('div', {}, _('Queued observations:') + ' ' + text(runtime.queue_depth)));
		if (Object.keys(object(runtime.counters)).length || Object.keys(object(runtime.engine_counters)).length)
			diagnostics.push(E('details', {}, [E('summary', {}, _('Cumulative diagnostic counters')), E('div', {}, counters)]));
		list(runtime.events).slice(-20).reverse().forEach(function(event) {
			var labels = {released: _('Rule released'), release_failed: _('Rule release failed'), lease_installed: _('Rule installed')};
			diagnostics.push(E('div', {}, labels[event.kind] || text(event.kind)));
			diagnostics.push(E('pre', {}, JSON.stringify(event)));
		});
		dom.content(this.diagnosticsPanel, diagnostics.length ? diagnostics : _('No runtime diagnostics yet.'));
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
