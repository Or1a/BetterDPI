// Browser-free filtering tests: RPC scope, debounce, retained controls and response races.
const assert = require('node:assert/strict');
const {setup, base, text} = require('./test_ui_helpers.cjs');
function deferred() { let resolve; const promise=new Promise(r=>resolve=r);return {promise,resolve}; }
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function timers() {
 let id=0;const pending=new Map();
 return {pending,setTimer(fn,delay){assert.equal(delay,350);pending.set(++id,fn);return id;},cancelTimer(id){pending.delete(id);},fire(){const callbacks=[...pending.values()];pending.clear();for(const fn of callbacks)fn();}};
}
const devices=[{mac:'AA:01',name:'Office phone',ip:'192.168.1.10'}, {mac:'AA:02',name:'TV',ip:'192.168.1.20'}, {mac:'AA:03',name:'Server',ip:'2001:db8::7'}];
const app={id:'protocol:tls',name:'TLS / encrypted traffic',source_type:'protocol',download:123};
const data={...base(),device_choices:devices,applications:[app],app_count:1,interfaces:[{name:'eth0',download:100}],selected_interface:'eth0'};
(async()=>{
 const queries=[],clock=timers();
 const ui=setup(data,{summary:(...args)=>{queries.push(args);return {...data,identification:args[7],search:args[8],application:args[9]};}}, {locale:'en',...clock});
 const {view,root}=ui;
 view.appPage=5;view.devicePage=3;view.expandedApps.add(app.id);
 view.identificationSelect.value='protocol';
 await view.identificationSelect.attrs.change();
 assert.deepEqual(queries.at(-1).slice(2),[1,1,'total','desc','[]','protocol','','']);
 assert(root.querySelector('.ns-result-scope'));
 assert.equal(root.querySelector('.ns-history-selector'),null); // Interface bytes never masquerade as filtered application traffic.
 const input=view.searchInput;
 input.value='a';input.attrs.input();input.value='EXAMPLE.test';input.attrs.input();
 assert.equal(clock.pending.size,1);
 await view.refresh(); // Polling cannot bypass search debounce.
 assert.equal(queries.length,1);
 clock.fire();await view.refreshWorker;
 assert.equal(queries.at(-1)[8],'EXAMPLE.test');
 assert.equal(view.searchInput,input);assert.equal(input.value,'EXAMPLE.test');
 assert(text(root.querySelector('.ns-result-scope')).includes("matching only a domain includes only that domain's records"));
 assert.equal(text(view.queryNotice),'');
 input.value=' x '.repeat(80);input.attrs.input();
 await input.attrs.keydown({key:'Enter',preventDefault(){}});
 assert.equal(clock.pending.size,0);assert.equal(queries.at(-1)[8].length,128);
 input.value='';await view.changeFilters();
 await root.querySelector('.ns-focus-application').attrs.click();
 assert.equal(queries.at(-1)[9],app.id);
 assert(text(view.filterNotice).includes('Focused traffic: TLS'));
 await view.filterNotice.querySelector('button').attrs.click();
 assert.equal(queries.at(-1)[9],'');assert.equal(text(view.filterNotice),'');
 const beforeDeviceSearch=queries.length;
 for (const [search,mac] of [['phone','AA:01'],['aa:02','AA:02'],['DB8','AA:03']]) {
  view.deviceSearchInput.value=search;view.deviceSearchInput.attrs.input();
  assert.deepEqual(view.deviceSelect.children.map(n=>n.attrs.value),['',mac]);
 }
 assert.equal(queries.length,beforeDeviceSearch);
 view.deviceSelect.value='AA:03';view.deviceSearchInput.value='no match';view.deviceSearchInput.attrs.input();
 assert.deepEqual(view.deviceSelect.children.map(n=>n.attrs.value),['','AA:03']);
 assert.equal(view.deviceSelect.value,'AA:03');
 await view.deviceSelect.attrs.change();assert.equal(queries.at(-1)[1],'AA:03');

 const pending=[],requests=[],raceClock=timers();
 const racing=setup(data,{summary:(...args)=>{const answer=deferred();pending.push(answer);requests.push(args);return answer.promise;}},{locale:'en',...raceClock});
 const original=racing.view.currentData,worker=racing.view.refresh();await tick();
 racing.view.searchInput.value='old';racing.view.searchInput.attrs.input();
 racing.view.searchInput.value='latest';racing.view.searchInput.attrs.input();
 raceClock.fire();await tick();assert.equal(requests.length,1);
 pending[0].resolve({...data,search:'',total:{download:999}});await tick();
 assert.equal(requests.length,2);assert.equal(requests[1][8],'latest');
 assert.equal(racing.view.currentData,original);
 assert(text(racing.view.queryNotice).includes('Previous results remain visible'));
 pending[1].resolve({...data,search:'latest',total:{download:42}});await worker;
 assert.equal(racing.view.currentData.total.download,42);assert.equal(text(racing.view.queryNotice),'');
 // Typing away and back to the in-flight search must still schedule a new
 // valid request, since the earlier response was invalidated on input.
 const repeated=racing.view.refresh();await tick();
 racing.view.searchInput.value='temporary';racing.view.searchInput.attrs.input();
 racing.view.searchInput.value='latest';racing.view.searchInput.attrs.input();raceClock.fire();
 pending[2].resolve({...data,search:'latest',total:{download:1}});await tick();
 assert.equal(requests.length,4);assert.equal(requests[3][8],'latest');
 pending[3].resolve({...data,search:'latest',total:{download:43}});await repeated;
 assert.equal(racing.view.currentData.total.download,43);assert.equal(text(racing.view.queryNotice),'');
 const latest=racing.view.currentData;
 racing.view.searchInput.value='failed';racing.view.searchInput.attrs.input();raceClock.fire();await tick();
 pending[4].resolve({error:'query failed'});await racing.view.refreshWorker;
 assert.equal(racing.view.currentData,latest);assert(text(racing.view.errorNode).includes('previous results have been kept'));
 console.log('Filters: full RPC scope, local device search, debounce, focus and stale-response rejection OK');
})().catch(error=>{console.error(error);process.exit(1);});
