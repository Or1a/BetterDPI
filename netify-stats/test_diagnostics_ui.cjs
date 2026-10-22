// Status snapshots only: diagnostics must not probe, infer lost bytes or mistake idle traffic for a dead collector.
const assert = require('node:assert/strict');
const {setup, base, text} = require('./test_ui_helpers.cjs');
const healthy = {...base(), generated_at: 2000, collector: {
 connected:true, timestamp:1999, last_event:100, events:21, active_metadata:2,
 missing_metadata:7, recovered_stats:5, pending_stats:2, invalid_messages:0
}};
function panel(data) { return setup(data, {}, {locale:'en'}).root.querySelector('.ns-diagnostics'); }
function state(data) { return text(panel(data).querySelector('.ns-diagnostic-state')); }
assert.equal(state(healthy), 'Collector connected'); // Router and browser clocks differ by years.
assert(text(panel(healthy)).includes('An idle network may produce no traffic events'));
assert(text(panel(healthy)).includes('whole current collection session, regardless of traffic filters'));
assert(text(panel(healthy)).includes('Unidentified application traffic is already counted'));
assert(!text(panel(healthy)).includes('Historical statistics are incomplete'));
assert.equal(state({...healthy, collector:{...healthy.collector,last_event:0}}), 'Collector connected');
assert.equal(state({...healthy, collector:{...healthy.collector,timestamp:1800}}), 'Collector status is stale or unavailable');
assert.equal(state({...healthy, collector:{...healthy.collector,timestamp:2500}}), 'Collector status is stale or unavailable');
assert.equal(state({...healthy, collector:{...healthy.collector,connected:false,last_error:'Socket unavailable'}}), 'Waiting for Netify connection');
assert(text(panel({...healthy,collector:{...healthy.collector,connected:false,last_error:'Socket unavailable'}})).includes('local socket is enabled'));

for (const enabled of [true, false]) {
 for (const actual of ['running','stopped','partial','unknown']) {
  for (const applied of [true,false]) {
   const data={...healthy,enabled,control:{enabled,actual_state:actual,applied}};
   const expected=actual==='unknown'?'Collection status unavailable':actual==='partial'?'Some services are running':
    actual==='stopped'?(enabled?'Collection stopped unexpectedly':'Collection paused'):
    enabled?'Collector connected':'Collection is still running';
   assert.equal(state(data),expected,JSON.stringify({enabled,actual,applied}));
  }
 }
}
const paused={...healthy,enabled:false,control:{enabled:false,actual_state:'stopped',applied:true},collector:{timestamp:1,connected:false}};
assert.equal(state(paused),'Collection paused');
assert(!text(panel(paused)).includes('has not provided a current status'));
assert.equal(state({...healthy,config_error:'Invalid enabled setting'}),'Collection status unavailable');
const invalidConfig={...healthy,enabled:null,config_error:'Invalid enabled setting',control:{actual_state:'unknown',applied:false}};
assert(text(panel(invalidConfig)).includes('Repair the settings'));
assert(!text(panel(invalidConfig)).includes('Use Retry applying above')); // That control is disabled until repaired.
const damaged={...healthy,collector:{...healthy.collector,missing_metadata:10000,recovered_stats:1,pending_stats:17,invalid_messages:3,
 unattributed_upload:1024,unattributed_download:2048,proxy_error:'No conntrack',export_error:'Bad JSON',interface_error:'Missing interface'},
 storage:{error:'No disk space'}};
const explanation=text(panel(damaged));
assert(explanation.includes('3.00 KiB of traffic could not be attributed'));
assert(explanation.includes('10000') && explanation.includes('Events recovered'));
assert(explanation.includes('Netify JSON export') && explanation.includes('conntrack availability'));
assert(explanation.includes('Bad JSON') && explanation.includes('No disk space'));
assert(explanation.includes('Attention needed'));
assert.equal(text(panel({...damaged,device:'aa:bb',search:'example.test',identification:'protocol',application:'protocol:tls'})),explanation);
assert(!text(panel({...healthy,collector:{...healthy.collector,events:'broken'}})).includes('NaN'));
console.log('Diagnostics: actual service states, clock source, idle/stale status, and session counters OK');
