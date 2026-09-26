// Pure Node regression checks: no browser, DOM, or browser automation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/netify-stats.js', 'utf8');
const {translator, setup, base, walk, text} = require('./test_ui_helpers.cjs');
const svgDocument = {documentElement:{lang:'zh-Hans'},createElementNS:(ns,tag)=>({ns,tag,attrs:{},children:[],setAttribute(key,value){this.attrs[key]=value;},appendChild(child){this.children.push(child);}})};
const helpers = new Function('rpc','dom','E','document','_',source.split('return view.extend({')[0] + '\nreturn {timeline, trafficBar};')(
 {declare:()=>{}}, {content:(node,value)=>{node.children=value;}}, (tag,attrs,children)=>({tag,attrs,children}),svgDocument,translator('zh-Hans'));
const chart = helpers.timeline([{bucket:1700000000,download:100,upload:0},{bucket:1700003600,download:50,upload:25}],3600);
const plot = chart.children[0].children[1];
for (const item of [{download:1,upload:2},{download:100,upload:0},{download:0,upload:100}]) {
 const bar=helpers.trafficBar(item,99999);
 const widths=bar.children.map(n=>parseFloat(n.attrs.style.slice(6)));
 assert.equal(widths[0]+widths[1],100);
}
assert(!source.includes('实际起点'));
assert(!source.includes('末组尚未结束'));
assert(!source.includes('每组 '));
assert.equal(plot.children.length,3);
assert.equal(plot.children[0].tag,'svg');
assert.equal(plot.children[0].ns,'http://www.w3.org/2000/svg');
assert.equal(plot.children[0].children.filter(n=>n.tag==='polyline').length,2);
assert.equal(plot.children[0].children[0].attrs.points,'250.00,5.00 750.00,95.00');
assert.equal(plot.children[0].children[1].attrs.points,'250.00,185.00 750.00,140.00');
assert.equal(plot.children[1].tag,'button');
plot.children[1].attrs.click();
assert(chart.children[1].children.includes('100 B'));
assert(!source.includes('设备总流量'));
assert(!source.includes('连接小时记录'));
assert(!source.includes('含路由器自身'));
const rendered = setup(base()).root;
assert(walk(rendered).some(node=>node.tag==='option' && node.attrs.value==='168' && text(node)==='最近7天'));
assert(source.includes("E('section', { 'class': 'ns-section ns-storage-settings' }"));
assert(!source.includes("E('summary', {}, '存储设置')"));
assert(source.includes('white-space:nowrap!important; word-break:keep-all!important;'));
const single=helpers.timeline([{bucket:1700000000,download:0,upload:0}],3600);
assert.equal(single.children[0].children[1].children[0].children.filter(n=>n.tag==='circle').length,2);
const sections = walk(rendered);
assert(sections.findIndex(node=>node.attrs.class==='ns-section ns-trend-section')<sections.findIndex(node=>node.attrs.class==='ns-stat download'));
let args;
const view = new Function('view','rpc','dom','poll','L','E','_',source)(
 {extend:x=>x}, {declare:()=>async(...values)=>{args=values;return {app_page:2,device_page:1,applications:[],devices:[],device_choices:[]};}},
 {}, {}, {bind:(fn,self)=>fn.bind(self)}, ()=>{},translator('zh-Hans'));
(async()=>{
 view.paint=()=>{};view.updateDeviceChoices=()=>{};
 view.currentData={applications:[{id:'current'}]};
 view.expandedApps=new Set([...Array.from({length:15},(_,i)=>'old'+i),'current']);
 view.appPage=2;
 await view.refresh();
 assert.deepEqual(JSON.parse(args[6]),['current']);
 assert.equal(args[2],2);
 assert.equal(args[0],0);
 view.hoursSelect={value:'168'};
 await view.refresh();
 assert.equal(args[0],168);
 view.hoursSelect={value:'0'};
 await view.load();
 assert.equal(args[0],0);
 assert(!source.includes('最多7天'));
 assert(!source.includes('展开查看设备与网站'));
 assert(!source.includes('点击一项，查看对应设备和访问目标'));
 console.log('Node logic: visible-page drilldown and removed subtitles OK');
})().catch(e=>{console.error(e);process.exit(1);});
