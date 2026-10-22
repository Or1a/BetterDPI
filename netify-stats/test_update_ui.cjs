// Manual updater UI, using local RPC fixtures only; never downloads or installs a package.
const assert = require('node:assert/strict');
const {setup, base, text} = require('./test_ui_helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve, reject; const promise = new Promise((ok, fail) => { resolve=ok; reject=fail; }); return {promise,resolve,reject}; }
const idle = {state:'idle',current_version:'0.3.0',series:'25.12',busy:false,error:'',detail:''};
const available = {...idle,state:'available',checked_at:2000,candidate:{version:'0.3.1',tag:'V0.3.1'}};
const data = update => ({...base(),version:'0.3.0',update});
function button(ui, name) { return ui.view.updatePanel.querySelector('.ns-update-'+name); }

(async () => {
 // Page load and ordinary summary refreshes only read updater status. A user
 // action is required before the check RPC can contact GitHub.
 const calls=[],client=setup(data(idle),{
  summary:()=>{calls.push('summary');return data(idle);},
  check_update:()=>{calls.push('check');return {...idle,state:'checking',busy:true};},
  install_update:version=>{calls.push(['install',version]);return {...available,state:'downloading',busy:true};}
 },{locale:'en'});
 assert.deepEqual(calls,[]);
 await client.view.refresh();
 assert.deepEqual(calls,['summary']);
 assert(!button(client,'check').disabled);assert(button(client,'install').disabled);
 assert(text(client.view.updatePanel).includes('Checks run only when requested'));
 const missing=setup(base(),{check_update:()=>{throw new Error('must not call');}},{locale:'en'});
 assert(button(missing,'check').disabled);assert(button(missing,'install').disabled);
 await missing.view.requestUpdate(false);
 assert(text(missing.view.updatePanel).includes('Update service unavailable'));

 let live={...idle},checks=0;
 const checking=setup(data(idle),{
  check_update:()=>{checks++;live={...idle,state:'checking',busy:true};return live;},
  summary:()=>data(live)
 },{locale:'en'});
 await button(checking,'check').attrs.click();
 assert.equal(checks,1);assert.equal(checking.view.currentData.update.state,'checking');
 assert(button(checking,'check').disabled);assert(button(checking,'install').disabled);
 await checking.view.requestUpdate(false);assert.equal(checks,1);
 live=available;await checking.view.refresh();
 assert(!button(checking,'install').disabled);
 assert(text(checking.view.updatePanel).includes('Installed version: 0.3.0'));
 assert(text(checking.view.updatePanel).includes('Release version: 0.3.1'));
 assert.equal(checking.view.updatePanel.querySelector('a').attrs.href,'https://github.com/Or1a/BetterDPI/releases/tag/V0.3.1');

 let installs=0;const confirmations=[];
 const canceled=setup(data(available),{install_update:()=>{installs++;}},{locale:'en',confirm:message=>{confirmations.push(message);return false;}});
 await button(canceled,'install').attrs.click();
 assert.equal(installs,0);assert(confirmations[0].includes('0.3.1'));
 assert(confirmations[0].includes('briefly stop') && confirmations[0].includes('router will not reboot'));
 let current=available,installedVersion;
 const approved=setup(data(available),{
  install_update:version=>{installedVersion=version;current={...available,state:'downloading',busy:true};return current;},
  summary:()=>data(current)
 },{locale:'en'});
 await button(approved,'install').attrs.click();
 assert.equal(installedVersion,'0.3.1');assert(button(approved,'install').disabled);
 assert(text(approved.view.updatePanel).includes('Downloading and verifying'));
 assert(text(approved.view.updatePanel).includes('Installed version: 0.3.0'));
 current={...available,state:'installing',busy:true};await approved.view.refresh();
 assert(text(approved.view.updatePanel).includes('Keep the router powered on'));
 assert(button(approved,'check').disabled);
 current={...available,state:'failed',busy:false,error:'checksum_mismatch',detail:'Downloaded package does not match the release.'};
 await approved.view.refresh();assert(button(approved,'install').disabled);
 assert(text(approved.view.updatePanel).includes('checksum_mismatch'));
 assert(!button(approved,'check').disabled);

 // Offers cannot enable installation if they are equal, older, malformed or
 // have an unrelated tag. Links are constructed from validated fixed fields.
 for(const candidate of [
  {version:'0.3.0',tag:'V0.3.0'},{version:'0.2.9',tag:'V0.2.9'},
  {version:'0.3.2',tag:'../../evil'}, {version:'https://evil.example',tag:'Vhttps://evil.example'},
  {version:'0.3.2-rc1',tag:'V0.3.2-rc1'}
 ]) {
  let attempted=false;const ui=setup(data({...available,candidate}),{install_update:()=>{attempted=true;}},{locale:'en'});
  assert(button(ui,'install').disabled);await ui.view.requestUpdate(true);assert(!attempted);
  for(const link of ui.view.updatePanel.querySelectorAll('a')) assert(link.attrs.href.startsWith('https://github.com/Or1a/BetterDPI/releases/tag/V'));
 }
 for(const state of ['up_to_date','unsupported','failed','interrupted']) {
  const ui=setup(data({...available,state}),{},{locale:'en'});
  assert(button(ui,'install').disabled);assert(!button(ui,'check').disabled);
 }
 const restored=setup(data({...available,state:'installing',busy:true}),{},{locale:'en'});
 assert(button(restored,'check').disabled && button(restored,'install').disabled);
 assert(text(restored.view.updatePanel).includes('Installing the update'));

 let reloads=0;
 const completed=setup(data({...available,state:'succeeded',current_version:'0.3.1'}),{},{locale:'en',reload:()=>{reloads++;}});
 assert.equal(reloads,0);assert(button(completed,'install').disabled);
 assert(text(completed.view.updatePanel).includes('Installed version: 0.3.1'));
 button(completed,'reload').attrs.click();assert.equal(reloads,1);
 const noReload=setup(data({...available,state:'succeeded'}),{},{locale:'en',confirm:()=>false,reload:()=>{throw new Error('unexpected reload');}});
 button(noReload,'reload').attrs.click();

 // Preserve user drafts and reject summaries that started before an update
 // action, even when those stale responses arrive after the action's result.
 const first=deferred(),rpc=deferred();let summaryCalls=0,installCalls=0;
 const racing=setup(data(available),{
  summary:()=>++summaryCalls===1?first.promise:data({...available,state:'downloading',busy:true}),
  install_update:()=>{installCalls++;return rpc.promise;}
 },{locale:'en'});
 racing.view.storageInput.value='64';racing.view.interfaceDraft='wan-new';racing.view.searchInput.value='draft';
 const worker=racing.view.refresh();await tick();
 const action=racing.view.requestUpdate(true);await tick();
 await racing.view.requestUpdate(true);assert.equal(installCalls,1);
 assert(button(racing,'check').disabled && button(racing,'install').disabled);
 rpc.resolve({...available,state:'downloading',busy:true});await tick();
 first.resolve(data(available));await Promise.all([worker,action]);
 assert.equal(racing.view.currentData.update.state,'downloading');
 assert.equal(racing.view.storageInput.value,'64');assert.equal(racing.view.interfaceDraft,'wan-new');
 assert.equal(racing.view.searchInput.value,'draft');
 assert.equal(summaryCalls,2);
 const bad=setup(data(idle),{check_update:()=>Promise.reject(new Error('Connection closed')),summary:()=>data(idle)},{locale:'en'});
 await bad.view.requestUpdate(false);assert(text(bad.view.updatePanel).includes('Could not contact the update service: Connection closed'));
 const malformed=setup(data(idle),{check_update:()=>({error:'missing method'}),summary:()=>data(idle)},{locale:'en'});
 await malformed.view.requestUpdate(false);assert(text(malformed.view.updatePanel).includes('invalid response'));
 // A failed preflight cannot always write its error to disk. The action's
 // response must remain visible even when the persisted summary stays idle.
 let rejected=true;
 const unwritable=setup(data(idle),{
  check_update:()=>rejected?{...idle,state:'failed',error:'worker_start_failed',detail:'Permission denied'}:idle,
  summary:()=>data(idle)
 },{locale:'en'});
 await unwritable.view.requestUpdate(false);
 assert.equal(unwritable.view.currentData.update.state,'idle');
 assert(text(unwritable.view.updatePanel).includes('The update task could not start.'));
 assert(text(unwritable.view.updatePanel).includes('Permission denied'));
 await unwritable.view.refresh();
 assert(text(unwritable.view.updatePanel).includes('The update task could not start.'));
 rejected=false;await unwritable.view.requestUpdate(false);
 assert(!text(unwritable.view.updatePanel).includes('The update task could not start.'));
 assert(!text(unwritable.view.updatePanel).includes('Permission denied'));
 const hostile=setup(data({...idle,state:'failed',error:'<img src=x onerror=alert(1)>',detail:'<a href="javascript:alert(1)">unsafe</a>'}),{},{locale:'en'});
 assert(text(hostile.view.updatePanel).includes('<img src=x onerror=alert(1)>'));
 assert.equal(hostile.view.updatePanel.querySelectorAll('img').length,0);
 assert.equal(hostile.view.updatePanel.querySelectorAll('a').length,0);
 const badState=setup(data({...idle,state:'toString'}),{},{locale:'en'});
 assert(text(badState.view.updatePanel).includes('Update service unavailable'));
 console.log('Updater UI: manual-only checks, explicit version confirmation, job states, safe links, drafts and response races OK');
})().catch(error=>{console.error(error);process.exit(1);});
