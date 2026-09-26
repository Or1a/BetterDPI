// Plain-object UI state test. No browser or browser automation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/netify-stats.js', 'utf8');
const {translator} = require('./test_ui_helpers.cjs');
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
 console.log('Interface confirmation and draft persistence OK');
})().catch(e=>{console.error(e);process.exit(1);});
