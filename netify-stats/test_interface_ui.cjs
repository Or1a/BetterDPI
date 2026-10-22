// Plain-object UI state test. No browser or browser automation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/netify-stats.js', 'utf8');
const {translator, setup, base, walk, text} = require('./test_ui_helpers.cjs');
let writes = [];
function E(tag, attrs = {}, children = []) {
 return {tag, attrs, children, listeners:{}, addEventListener(name, fn) {this.listeners[name]=fn;}};
}
const view = new Function('view','rpc','dom','poll','L','E','_', source)(
 {extend:x=>x}, {declare:spec=>async value=>{if(spec.method==='set_interface')writes.push(value);return {};}},
 {content(){}}, {}, {bind:(fn,self)=>fn.bind(self)}, E, translator('zh-Hans'));
function nodes(node, tag) {
 if (!node || typeof node !== 'object') return [];
 return (node.tag===tag?[node]:[]).concat((Array.isArray(node.children)?node.children:[node.children]).flatMap(n=>nodes(n,tag)));
}
(async()=>{
 const data={selected_interface:'eth0',interface_choices:['eth0','br-lan'],interfaces:[]};
 view.currentData=data;view.paint=()=>{};view.refresh=async()=>{};
 let panel=view.interfacePanel(data), select=nodes(panel,'select')[0];
 select.value='br-lan';select.listeners.change();
 assert.equal(writes.length,0);
 panel=view.interfacePanel(data); // Poll-driven redraw preserves unconfirmed choice.
 assert.equal(nodes(panel,'select')[0].value,'br-lan');
 nodes(panel,'button')[0].listeners.click();
 await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(writes,['br-lan']);
 assert.equal(data.selected_interface,'br-lan');
 assert.equal(view.interfaceDraft,null);
 assert.equal(view.interfaceSaving,false);
 // History selection never changes which interface is being measured. Even a
 // removed interface remains viewable while its data is retained.
 const historyWrites=[], summaries=[], historyData={...base(),selected_interface:'wanB',interface_choices:['wanB'],
  interfaces:[{name:'wanA',download:100,upload:10},{name:'wanB',download:200,upload:20}]};
 const historyView=setup(historyData,{set_interface:value=>{historyWrites.push(value);return {};},summary:()=>{summaries.push(true);return historyData;}}).view;
 const panelSelect=label=>walk(historyView.contentNode).find(n=>n.tag==='select' && n.attrs['aria-label']===label);
 assert.equal(panelSelect('查看接口历史').value,'wanB');
 assert(text(historyView.contentNode.querySelector('.ns-interface-history')).includes('wanB'));
 assert(!text(historyView.contentNode.querySelector('.ns-interface-history')).includes('wanA'));
 panelSelect('查看接口历史').value='wanA';
 panelSelect('查看接口历史').listeners.change();
 assert.equal(historyData.selected_interface,'wanB');
 assert.deepEqual(historyWrites,[]);
 assert.deepEqual(summaries,[]);
 assert(text(historyView.contentNode.querySelector('.ns-interface-history')).includes('wanA'));
 assert(!text(historyView.contentNode.querySelector('.ns-interface-history')).includes('wanB'));
 historyView.paint();
 assert.equal(panelSelect('查看接口历史').value,'wanA');
 historyData.interfaces=[];historyView.paint();
 assert.equal(panelSelect('查看接口历史').value,'wanA');
 assert(panelSelect('查看接口历史').children.some(option=>option.attrs.value==='wanA'));
 assert(text(historyView.contentNode.querySelector('.ns-interface-history')).includes('该接口暂无记录'));
 historyData.interfaces=[{name:'wanA',download:100},{name:'wanB',download:200}];
 panelSelect('查看接口历史').value='';panelSelect('查看接口历史').listeners.change();
 const allHistory=text(historyView.contentNode.querySelector('.ns-interface-history'));
 assert(allHistory.includes('wanA') && allHistory.includes('wanB'));
 assert.equal(historyData.selected_interface,'wanB');
 assert.deepEqual(historyWrites,[]);
 console.log('Interface confirmation, independent history selection, and draft persistence OK');
})().catch(e=>{console.error(e);process.exit(1);});
