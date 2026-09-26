// In-memory nodes exercise user events and asynchronous RPCs. No browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/netify-stats.js', 'utf8');
const {walk, text, setup, base} = require('./test_ui_helpers.cjs');
function deferred() {let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
(async()=>{
 const pending=deferred(), writes=[], data=base();
 const {root}=setup(data,{set_storage:value=>{writes.push(value);return pending.promise;}});
 const input=walk(root).find(n=>n.attrs['aria-label']==='记录容量上限 MiB');
 const save=walk(root).find(n=>n.tag==='button' && text(n)==='保存容量设置');
 input.value='4';
 const saving=save.attrs.click();
 assert.equal(input.disabled,true);
 assert.equal(save.disabled,true);
 // Even a programmatic value change cannot make the success label confirm 16.
 input.value='16';
 pending.resolve({max_storage_mib:4});
 await saving;
 assert.deepEqual(writes,[4]);
 assert.equal(input.value,'4');
 assert.equal(input.disabled,false);
 assert.equal(save.disabled,false);

 const failed=base();
 const toggles=[];
 const control=setup(failed,{set_enabled:enabled=>{
  toggles.push(enabled);
  failed.enabled=enabled;
  failed.control={enabled,actual_state:'partial',applied:false,apply_error:'停止失败'};
  return {error:'停止失败',control:failed.control};
 }}).view;
 await control.applyAnalysis(false);
 assert.equal(control.analysisToggle.checked,false);
 assert.equal(control.analysisToggle.indeterminate,true);
 assert.equal(control.analysisRetry.hidden,false);
 assert(text(control.analysisNotice).includes('目标：关闭；实际：部分服务在运行'));
 await control.analysisRetry.attrs.click();
 assert.deepEqual(toggles,[false,false]);

 const trend=base();
 trend.timeline=[{bucket:1700000000,download:100,upload:0},{bucket:1700003600,download:50,upload:25}];
 trend.applications=[{id:'app',name:'App',devices:[{name:'Phone'}],hosts:[{name:'example.test'}]}];
 trend.app_count=1;
 const plotted=setup(trend).view;
 plotted.contentNode.querySelectorAll('.ns-trend-group')[0].attrs.click();
 const selection=text(plotted.contentNode.querySelector('.ns-trend-selection'));
 const scrolling=plotted.contentNode.querySelectorAll('[data-ns-scroll]')[0];
 scrolling.scrollTop=120;
 plotted.paint();
 assert.equal(text(plotted.contentNode.querySelector('.ns-trend-selection')),selection);
 assert.equal(plotted.contentNode.querySelectorAll('[data-ns-scroll]')[0].scrollTop,120);

 const anomalies=base();
 anomalies.collector={connected:true,timestamp:Date.now()/1000,proxy_error:'conntrack unavailable',export_error:'bad export',unattributed_upload:1024};
 const warnings=text(setup(anomalies).root);
 assert(warnings.includes('代理连接归属失败'));
 assert(warnings.includes('连接信息恢复失败'));
 assert(warnings.includes('本轮采集累计有 1.00 KiB'));

 const snapshots=[], queries=[], queued=setup(base(),{summary:(...args)=>{
  const result=deferred();queries.push(args);snapshots.push(result);return result.promise;
 }}).view;
 const initial=queued.currentData, firstRefresh=queued.refresh();
 assert.equal(queued.refresh(),firstRefresh); // Repeated polling shares the read.
 for (const hours of ['1','5','24','168']) {
  queued.hoursSelect.value=hours;
  assert.equal(queued.refresh(),firstRefresh);
 }
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(queries.length,1);
 snapshots[0].resolve({...base(),hours:0});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(queries.length,2);
 assert.equal(queries[1][0],168);
 assert.equal(queued.currentData,initial); // Old filters must not repaint.
 snapshots[1].resolve({...base(),hours:168});
 await firstRefresh;
 assert.equal(queued.currentData.hours,168);
 assert.equal(queued.refreshWorker,null);

 // A settings write needs a post-write read even if its filters are unchanged.
 const beforeSave=queued.refresh();
 queued.refresh(true);
 await new Promise(resolve=>setImmediate(resolve));
 snapshots[2].resolve({...base(),selected_interface:'eth0'});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(queries.length,4);
 snapshots[3].resolve({...base(),selected_interface:'br-lan'});
 await beforeSave;
 assert.equal(queued.currentData.selected_interface,'br-lan');
 const valid=queued.currentData, failedRefresh=queued.refresh();
 await new Promise(resolve=>setImmediate(resolve));
 snapshots[4].resolve({error:'database temporarily unavailable'});
 await failedRefresh;
 assert.equal(queued.currentData,valid);
 assert(text(queued.errorNode).includes('已保留上次结果'));
 console.log('Settings, service state, polling/refresh coalescing, and anomaly notices OK');
})().catch(error=>{console.error(error);process.exit(1);});
