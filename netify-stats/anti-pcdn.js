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
		identity_unconfirmed: _('Device identity is unconfirmed'), flow_offload: _('Flow offload prevents safe enforcement')
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
function field(label, input, help) {
	return E('div', {class: 'cbi-value'}, [E('label', {class: 'cbi-value-title'}, label),
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
		this.statusPanel = E('div');
		this.rowsPanel = E('div');
		this.leasesPanel = E('div');
		this.diagnosticsPanel = E('div');
		this.saveButton = E('button', {class: 'cbi-button cbi-button-apply', click: this.save.bind(this)}, _('Save Anti-PCDN settings'));
		this.settingsLoaded = settingsAvailable(this.data);
		this.formPanel = E('div', {}, this.settingsForm(object(this.data.settings)));
		this.updateStatus(this.data);
		poll.add(this.refresh.bind(this), 5);
		return E('div', {class: 'cbi-map'}, [
			E('h2', {}, _('Anti-PCDN')),
			E('p', {}, _('Optional short-window scoring for individual LAN connections. Scores indicate suspicion, not proof of PCDN.')),
			E('p', {}, _('This feature requires the DPI collector to be running. Enabling it does not start paused traffic analysis. It does not add its observations to traffic totals.')),
			this.statusPanel, this.formPanel, this.saveButton, this.notice,
			E('h3', {}, _('Scored connections')), this.rowsPanel,
			E('h3', {}, _('Temporary connection rules')),
			E('p', {}, _('Installed rules are not proof that traffic was successfully blocked. Observed bytes are DPI observations, not blocked bytes.')),
			this.leasesPanel, E('h3', {}, _('Coverage and recent actions')), this.diagnosticsPanel
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
			fields.push(field(reasonName(key), input['weight_' + key]));
		});
		fields.push(E('p', {}, _('Each score weight is 0–40; all five weights must total 100. The maximum score is 100.')));
		return E('div', {class: 'cbi-section'}, fields);
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
		(data.request_error ? [data.request_error] : [data.config_error, data.runtime_error, runtime.error, runtime.executor_error]).filter(Boolean).forEach(function(error) {
			messages.push(E('p', {class: 'alert-message warning'}, text(error)));
		});
		if (available && data.release_pending) messages.push(E('p', {}, _('A release request is pending.')));
		dom.content(this.statusPanel, messages);
		var rows = list(runtime.candidates).slice(0, 64).map(function(row) {
			row = object(row);
			var reasons = list(row.reasons).map(function(reason) { return reasonName(reason.id) + ': +' + text(reason.points); }).join(', ');
			var guards = list(row.guards).map(guardName).join(', ');
			var decision = row.threshold_met ? _('Threshold reached') : _('Below threshold');
			if (row.threshold_met) decision += '; ' + (guards ? _('Action guarded') : runtime.mode === 'observe' ? _('Observation only') : _('Awaiting enforcement checks'));
			return E('tr', {class: 'tr'}, [
				E('td', {class: 'td'}, [E('div', {}, text(row.mac)), E('div', {}, tuple(row)), E('div', {}, text(row.host))]),
				E('td', {class: 'td'}, [E('strong', {}, text(row.score) + '/100'), E('div', {}, reasons)]),
				E('td', {class: 'td'}, [E('div', {}, _('Upload:') + ' ' + bytes(row.upload)), E('div', {}, _('Download:') + ' ' + bytes(row.download))]),
				E('td', {class: 'td'}, [E('div', {}, decision), E('div', {}, guards), E('div', {}, text(row.execution_error))])
			]);
		});
		dom.content(this.rowsPanel, table([_('Device and connection'), _('Score and evidence'), _('Observed bytes'), _('Decision and guards')], rows));
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
		Object.keys(object(runtime.counters)).sort().slice(0, 64).forEach(function(key) {
			diagnostics.push(E('div', {}, key + ': ' + text(runtime.counters[key])));
		});
		Object.keys(object(runtime.engine_counters)).sort().slice(0, 64).forEach(function(key) {
			diagnostics.push(E('div', {}, _('Scoring:') + ' ' + key + ': ' + text(runtime.engine_counters[key])));
		});
		if (runtime.queue_depth != null) diagnostics.push(E('div', {}, _('Queued observations:') + ' ' + text(runtime.queue_depth)));
		if (runtime.coverage) diagnostics.push(E('pre', {}, JSON.stringify(runtime.coverage, null, 2)));
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
