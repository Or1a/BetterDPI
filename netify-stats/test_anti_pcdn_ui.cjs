// Independent LuCI page: local RPC fixtures, no browser or router required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {E: baseE, dom, text, walk, readPo, translator} = require('./test_ui_helpers.cjs');
const source = fs.readFileSync(__dirname + '/anti-pcdn.js', 'utf8');
const id = 'a'.repeat(24);
const defaults = {enabled:false,mode:'observe',interface:'br-lan',threshold:80,ban_seconds:120,
 allow_devices:[],allow_domains:[],pcdn_domains:[],
 weights:{fanout:25,serving_peers:20,sustained:20,upload_ratio:15,domain:20}};
const base = () => ({settings:{...defaults},stale:false,collector_recent:true,collector_connected:true,
 runtime:{timestamp:1000,enabled:false,mode:'observe',candidates:[],leases:[],events:[],counters:{observed:4}}});
function setup(data=base(), handlers={}, locale='en') {
 const calls=[]; const polls=[];
 const E=(tag, attrs, children) => {
  const node=baseE(tag, attrs, children);
  if (tag === 'textarea') node.value=text(node);
  return node;
 };
 const view=new Function('view','rpc','dom','poll','E','_',source)(
  {extend:value=>value},
  {declare:spec=>(...args)=>Promise.resolve().then(()=>{
   calls.push([spec.method,...args]);
   return handlers[spec.method] ? handlers[spec.method](...args) : data;
  })}, dom, {add:(fn,seconds)=>polls.push({fn,seconds})}, E, translator(locale));
 const root=view.render(data);
 return {view,root,calls,polls};
}
const deferred=()=>{let resolve;const promise=new Promise(ok=>{resolve=ok});return {resolve,promise}};
const releaseButton=ui=>ui.view.leasesPanel.querySelector('button');

(async()=>{
 const keys=[...source.matchAll(/_\('([^']*)'\)/g)].map(match=>match[1]);
 // LuCI runtime canonicalizes whitespace, but po2lmo hashes literal PO keys.
 // Keep padding outside gettext so compiled catalogs resolve these keys too.
 for (const key of keys) assert.equal(key,key.trim().replace(/[ \t\n]+/g,' '));
 for (const catalog of ['zh_Hans','zh_Hant']) {
  const messages=readPo(__dirname+'/po/'+catalog+'/netify-stats.po');
  for (const key of keys) assert(messages.get(key),catalog+': missing '+key);
  const localized=setup(base(),{},catalog);
  assert(text(localized.root).includes(translator(catalog)('Save Anti-PCDN settings')));
  assert(!text(localized.root).includes('Save Anti-PCDN settings'));
 }
 // Rendering and polling only read status. The independent settings never
 // start the main collector or touch its settings API.
 const idle=setup();
 assert.deepEqual(idle.calls,[]);
 assert.equal(idle.polls[0].seconds,5);
 await idle.polls[0].fn();
 assert.deepEqual(idle.calls,[['status']]);
 assert.equal(idle.view.inputs.enabled.checked,false);
 assert.equal(idle.view.inputs.mode.value,'observe');
 assert(text(idle.root).includes('does not start paused traffic analysis'));
 assert.deepEqual(idle.view.settingsValue(),defaults);
 const disabledMissing=setup({...base(),stale:true,collector_recent:false,collector_connected:false,runtime:{}});
 assert(text(disabledMissing.view.statusPanel).includes('Anti-PCDN is disabled in settings.'));
 assert(!text(disabledMissing.view.statusPanel).includes('No recent DPI collector heartbeat'));
 assert(!text(disabledMissing.view.statusPanel).includes('Runtime status is stale or unavailable.'));
 assert(!disabledMissing.view.saveButton.disabled);
 const enabledMissing=setup({...base(),settings:{...defaults,enabled:true},stale:true,
  collector_recent:false,collector_connected:false,runtime:{}});
 assert(text(enabledMissing.view.statusPanel).includes('No recent DPI collector heartbeat'));
 assert(text(enabledMissing.view.statusPanel).includes('Runtime status is stale or unavailable.'));

 // Device-level multi-port evidence stays explicitly observational, with
 // connection scores and incomplete coverage independently visible.
 const crossPort=base();
 crossPort.settings={...defaults,enabled:true,mode:'auto'};
 crossPort.runtime.mode='auto';
 crossPort.runtime.devices=[{mac:'02:11:22:33:44:55',ip:'10.0.0.2',proto:17,ports:20,score:80,
  complete:true,observation_only:true,reasons:[{id:'fanout',points:25}],metrics:{upload:8*1024*1024,download:1000,peers:20}}];
 crossPort.runtime.candidates=[{id,score:0,device_score:80,threshold_met:false,guards:['short_window_only'],wait_seconds:15}];
 crossPort.runtime.coverage={global_wait_seconds:200,unresolved_metadata:2,last_gap:'missing_metadata',last_gap_scope:'unresolved',
  resources:{active_groups:{used:1,limit:512},flow_identities:{used:33,limit:2048}}};
 const observed=setup(crossPort);
 assert(text(observed.view.devicesPanel).includes('80/100'));
 assert(text(observed.view.devicesPanel).includes('Observation only'));
 assert(text(observed.root).includes('They do not authorize blocking'));
 assert(text(observed.view.rowsPanel).includes('0/100'));
 assert(text(observed.view.rowsPanel).includes('Below threshold'));
 assert(text(observed.view.rowsPanel).includes('Window wait: 15 seconds remaining'));
 assert(text(observed.view.statusPanel).includes('Low scores do not rule out suspicious traffic'));
 assert(!text(observed.view.devicesPanel).includes('Complete observation window'));
 assert(text(observed.view.diagnosticsPanel).includes('Connection identities'));
 assert(text(observed.view.diagnosticsPanel).includes('2048'));
 assert.deepEqual(observed.calls,[]);
 // Historic shadow outcomes are labelled separately from installed rules.
 const historyData=base();
 historyData.settings.enabled=true;
 historyData.runtime.observations={written:3,recent:[
  {timestamp:1000,outcome:'would_block',score:80,threshold:80,guards:[],metrics:{upload:8000000,peers:20}},
  {timestamp:1001,outcome:'evidence_incomplete',score:80,threshold:80,guards:['incomplete_window']},
  {timestamp:1002,outcome:'below_threshold',score:40,threshold:80,sample_type:'fanout_watch',guards:['not_uploading'],host:'<script>bad</script>'}
 ]};
 historyData.runtime.fast_path={matched:12,unattributed:4,error:''};
 historyData.runtime.observations.recent[0].evidence_source='conntrack_fast';
 historyData.runtime.observations.recent[0].observed_seconds=3;
 historyData.runtime.observations.recent[0].connection_upload_bytes=294912;
 historyData.runtime.execution_readiness={supported:false,reason:'TPROXY fixture',read_only:true};
 historyData.runtime.observations.pending=4;
 historyData.runtime.observations.dropped=2;
 historyData.runtime.observations.recent[0].coverage={execution_readiness:{supported:false}};
 const history=setup(historyData);
 assert(text(history.view.observationsPanel).includes('Simulated block; not executed'));
 assert(text(history.view.observationsPanel).includes('Seconds observed: 3'));
 assert(text(history.view.observationsPanel).includes('Connection upload at trigger: 288.0 KiB'));
 assert(text(history.view.statusPanel).includes('does not require waiting 30 minutes'));
 assert(text(history.view.diagnosticsPanel).includes('Fast counter coverage: 12'));
 assert(text(history.view.statusPanel).includes('TPROXY fixture'));
 assert(text(history.view.observationsPanel).includes('Platform precheck failed; this score is not an executable block.'));
 assert(text(history.view.observationsPanel).includes('Records waiting to be written: 4'));
 assert(text(history.view.observationsPanel).includes('Records lost to recording limits: 2'));

 assert(text(history.view.observationsPanel).includes('Threshold reached; evidence incomplete'));
 assert(text(history.view.observationsPanel).includes('Below threshold'));
 assert(text(history.view.observationsPanel).includes('High peer count; observation only'));
 assert(text(history.root).includes('Unique peers in 60 seconds'));
 assert(text(history.root).includes('Protected VPN, proxy and allowlisted connections are excluded'));
 assert(!walk(history.view.observationsPanel).some(node=>node.tag==='script'||node.attrs.innerHTML));
 assert.deepEqual(history.calls,[]);
 crossPort.stale=true;
 await observed.view.refresh();
 assert(!text(observed.view.devicesPanel).includes('Complete observation window'));
 assert(text(observed.view.devicesPanel).includes('Runtime status is unavailable.'));

 // Evidence strings must remain text nodes; no generated HTML or arbitrary
 // links are used for domains, addresses, scores or daemon error messages.
 const raw='<img src=x onerror=alert(1)>';
 const data=base();
 data.settings={...defaults,enabled:true};
 data.runtime.enabled=true;
 data.runtime.candidates=[{id,mac:'02:11:22:33:44:55',ip:'10.0.0.2',peer:'2001:db8::1',sport:1234,dport:443,
  protocol:'QUIC',host:raw,score:85,threshold_met:true,upload:2048,download:128,
  reasons:[{id:'fanout',points:25}],guards:[]}];
 data.runtime.leases=[{id,state:'installed',mac:'02:11:22:33:44:55',ip:'10.0.0.2',peer:'203.0.113.5',sport:12,dport:34,proto:17,remaining:119.2}];
 const scoring=setup(data);
 assert(text(scoring.view.rowsPanel).includes('Threshold reached; Observation only'));
 assert(text(scoring.view.rowsPanel).includes('85/100'));
 assert(text(scoring.view.rowsPanel).includes('Peer diversity: +25'));
 assert(text(scoring.view.rowsPanel).includes('[2001:db8::1]:443'));
 assert(text(scoring.view.rowsPanel).includes(raw));
 assert(!walk(scoring.root).some(node=>node.tag==='img'||node.attrs.innerHTML));
 assert(text(scoring.view.leasesPanel).includes('blocking not independently verified'));
 assert(text(scoring.view.leasesPanel).includes('120 seconds remaining'));
 data.runtime.leases[0].state='unverified_cleanup_pending';
 await scoring.view.refresh();
 assert(text(scoring.view.leasesPanel).includes('Rule verification failed; cleanup pending'));
 assert(!text(scoring.view.leasesPanel).includes('Rule installed;'));
 data.runtime.candidates[0].guards=['incomplete_window','allowlisted'];
 await scoring.view.refresh();
 assert(text(scoring.view.rowsPanel).includes('Action guarded'));
 assert(text(scoring.view.rowsPanel).includes('Observation window is incomplete, Allowlisted'));
 data.runtime.candidates[0].execution_error='conntrack unavailable '+raw;
 await scoring.view.refresh();
 assert(text(scoring.view.rowsPanel).includes('conntrack unavailable '+raw));
 assert(!walk(scoring.view.rowsPanel).some(node=>node.tag==='img'||node.attrs.innerHTML));

 // Poll refresh preserves form drafts and only saves by explicit button click.
 let saved;
 const configuration=setup(base(),{configure:settings=>{saved=settings;return {ok:true,settings,pending:true}}});
 configuration.view.inputs.enabled.checked=true;
 configuration.view.inputs.mode.value='auto';
 configuration.view.inputs.threshold.value='90';
 configuration.view.inputs.allow_domains.value='allow.example.org\nsecond.example.org';
 await configuration.view.refresh();
 assert.equal(configuration.view.inputs.threshold.value,'90');
 assert.equal(saved,undefined);
 await configuration.view.saveButton.attrs.click();
 assert.equal(saved.enabled,true);
 assert.equal(saved.mode,'auto');
 assert.equal(saved.threshold,90);
 assert.deepEqual(saved.allow_domains,['allow.example.org','second.example.org']);
 assert(text(configuration.view.notice).includes('Settings saved'));
 assert(!configuration.view.saveButton.disabled);
 const failed=setup(base(),{configure:()=>({ok:false,error:'Weights must total 100'})});
 await failed.view.save();
 assert(text(failed.view.notice).includes('Could not save settings: Weights must total 100'));
 assert(!failed.view.saveButton.disabled);

 // A release is queued, never displayed as completed before the runtime ACK.
 let released;
 const releaseData=JSON.parse(JSON.stringify(data));
 const release=setup(releaseData,{
  release:lease=>{released=lease;releaseData.release_pending={id:lease,request_id:'r'};return {ok:true,pending:true,request_id:'r'}}
 });
 await releaseButton(release).attrs.click();
 assert.equal(released,id);
 assert(text(release.view.notice).includes('Wait for the runtime acknowledgement'));
 assert(releaseButton(release).disabled);
 const count=release.calls.length;
 await release.view.release(id);
 assert.equal(release.calls.length,count);

 // Stale or unavailable status disables actions and exposes status failures.
 const stale=setup({...data,stale:true}, {release:()=>{throw new Error('must not be called')}});
 assert(releaseButton(stale).disabled);
 await stale.view.release(id);
 assert.equal(stale.calls.length,0);
 const offline=setup(data,{status:()=>{throw new Error('RPC offline')}});
 const priorRows=text(offline.view.rowsPanel);
 offline.view.inputs.threshold.value='91';
 await offline.view.refresh();
 assert(releaseButton(offline).disabled);
 assert(text(offline.view.statusPanel).includes('RPC offline'));
 assert(text(offline.view.statusPanel).includes('Showing the last successful response; current status is unknown.'));
 assert(!text(offline.view.statusPanel).includes('No recent DPI collector heartbeat'));
 assert(!text(offline.view.statusPanel).includes('Anti-PCDN is disabled in settings.'));
 assert.equal(text(offline.view.rowsPanel),priorRows);
 assert.equal(offline.view.inputs.threshold.value,'91');
 assert(offline.view.saveButton.disabled);
 const beforeSave=offline.calls.length;
 await offline.view.save();
 await offline.view.release(id);
 assert.equal(offline.calls.length,beforeSave);
 const missing=setup({}, {status:()=>({error:'Access denied'})});
 await missing.view.refresh();
 assert(text(missing.view.statusPanel).includes('Access denied'));
 const load=await missing.view.load();
 assert.equal(load.request_error,'Access denied');

 // Failed first read is unknown, never a fabricated disabled/paused state.
 // Placeholders cannot overwrite an existing configuration. The first good
 // poll replaces them with actual settings, and later polls preserve drafts.
 const unavailable=setup({request_error:'Invalid method parameters.'});
 const unavailableText=text(unavailable.view.statusPanel);
 assert(unavailableText.includes('Settings and collector state are unknown'));
 assert(unavailableText.includes('Invalid method parameters.'));
 for (const falseClaim of ['Anti-PCDN is disabled in settings.','No recent DPI collector heartbeat.',
  'Runtime status is stale or unavailable.']) assert(!unavailableText.includes(falseClaim));
 assert(unavailable.view.saveButton.disabled);
 assert(Object.values(unavailable.view.inputs).every(input=>input.disabled));
 await unavailable.view.save();
 assert.deepEqual(unavailable.calls,[]);
 const recoveredData={...base(),settings:{...defaults,enabled:true,mode:'auto',threshold:91,
  allow_domains:['keep.example.org']}};
 const recovery=setup({request_error:'RPC offline'},{status:()=>recoveredData});
 await recovery.view.refresh();
 assert(!recovery.view.saveButton.disabled);
 assert(Object.values(recovery.view.inputs).every(input=>!input.disabled));
 assert.equal(recovery.view.inputs.enabled.checked,true);
 assert.equal(recovery.view.inputs.mode.value,'auto');
 assert.equal(recovery.view.inputs.threshold.value,'91');
 assert.equal(recovery.view.inputs.allow_domains.value,'keep.example.org');
 recovery.view.inputs.threshold.value='92';
 await recovery.view.refresh();
 assert.equal(recovery.view.inputs.threshold.value,'92');
 assert(!text(recovery.view.statusPanel).includes('RPC offline'));

 // A settings read error also must not make returned default values editable.
 const configError=setup({...base(),config_error:'Invalid stored settings'});
 assert(configError.view.saveButton.disabled);
 assert(!text(configError.view.statusPanel).includes('Anti-PCDN is disabled in settings.'));
 await configError.view.save();
 assert.deepEqual(configError.calls,[]);
 const malformed=setup(base(),{status:()=>({})});
 await malformed.view.refresh();
 assert(malformed.view.saveButton.disabled);
 assert(text(malformed.view.statusPanel).includes('Runtime status is unavailable.'));
 assert(!text(malformed.view.statusPanel).includes('No recent DPI collector heartbeat'));

 // Older requests cannot replace new status or a completed settings action.
 const old=deferred(); let reads=0;
 const race=setup(base(),{status:()=>++reads===1?old.promise:{...base(),runtime_error:'newer'}});
 const first=race.view.refresh();
 await Promise.resolve();
 await race.view.refresh();
 old.resolve({...base(),runtime_error:'older'});
 await first;
 assert(text(race.view.statusPanel).includes('newer'));
 assert(!text(race.view.statusPanel).includes('older'));
 console.log('Anti-PCDN UI tests passed');
})().catch(error=>{console.error(error);process.exitCode=1});
