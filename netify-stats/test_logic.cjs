// Pure Node regression checks: no browser, DOM, or browser automation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(__dirname + '/netify-stats.js', 'utf8');
const {translator, setup, base, walk, text} = require('./test_ui_helpers.cjs');
const chartDocument = {documentElement:{lang:'zh-Hans'}};
const helpers = new Function('rpc','dom','E','document','_',source.split('return view.extend({')[0] + '\nreturn {timeline, trafficBar};')(
 {declare:()=>{}}, {content:(node,value)=>{node.children=value;}}, (tag,attrs,children)=>({tag,attrs,children}),chartDocument,translator('zh-Hans'));
const chart = helpers.timeline([{bucket:1700000000,download:100,upload:0},{bucket:1700003600,download:50,upload:25}],3600);
const scroll = chart.children[0].children[1], plot = scroll.children[0];
for (const item of [{download:1,upload:2},{download:100,upload:0},{download:0,upload:100}]) {
 const bar=helpers.trafficBar(item,99999);
 const widths=bar.children.map(n=>parseFloat(n.attrs.style.slice(6)));
 assert.equal(widths[0]+widths[1],100);
}
assert(!source.includes('实际起点'));
assert(!source.includes('末组尚未结束'));
assert(!source.includes('每组 '));
assert.equal(scroll.attrs['data-ns-scroll'],'traffic-trend');
assert.equal(plot.children.length,2);
assert.equal(plot.children[0].tag,'button');
assert.equal(plot.children[0].children[0].attrs.class,'ns-trend-bars');
assert.deepEqual(plot.children.map(column=>column.children[0].children.map(bar=>bar.attrs.style)),
 [['height:100%','height:0%'],['height:50%','height:25%']]);
assert.equal(plot.children[0].attrs.title,plot.children[0].attrs['aria-label']);
plot.children[0].attrs.click();
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
assert.deepEqual(single.children[0].children[1].children[0].children[0].children[0].children.map(bar=>bar.attrs.style),
 ['height:0%','height:0%']);
// Dense minute windows retain real zero buckets and each direction; no hourly
// interpolation or fabricated nonzero minimum height is introduced by the view.
const start = Math.floor(1700000000 / 60) * 60;
const minuteRows=Array.from({length:60},(_,index)=>({bucket:start+index*60,download:index===15?100:0,upload:index===45?50:0}));
const minuteSelection={bucket:start+15*60};
const minuteChart=helpers.timeline(minuteRows,60,minuteSelection), minutePlot=minuteChart.children[0].children[1].children[0];
assert.equal(minutePlot.children.length,60);
assert.equal(minutePlot.attrs.style,'min-width:720px');
assert.equal(minutePlot.children[15].children[0].children[0].attrs.style,'height:100%');
assert.equal(minutePlot.children[45].children[0].children[1].attrs.style,'height:50%');
assert.equal(minutePlot.children[14].children[0].children[0].attrs.style,'height:0%');
const minuteLabels=minutePlot.children.map(column=>column.children[1].children).filter(Boolean);
assert(minuteLabels.length>=6 && minuteLabels.length<=12);
const firstTime=new Date(start*1000);
assert(minuteLabels[0].endsWith(String(firstTime.getHours()).padStart(2,'0')+':'+String(firstTime.getMinutes()).padStart(2,'0')));
minutePlot.children[45].attrs.click();
assert.equal(minuteSelection.bucket,start+45*60);
assert(minuteChart.children[1].children.includes('50 B'));
const denseUi=setup({...base(),timeline:minuteRows,timeline_resolution_seconds:60});
denseUi.root.querySelector('.ns-trend-scroll').scrollLeft=360;
denseUi.view.paint();
assert.equal(denseUi.root.querySelector('.ns-trend-scroll').scrollLeft,360);
const coverageData={...base(),timeline_source:'device_minutes',timeline_resolution_seconds:60,
 timeline_range_start:start,timeline_range_end:start+180,minute_history_available:true,
 timeline:[{bucket:start,download:null,upload:null,covered:false,coverage:'missing'},
  {bucket:start+60,download:0,upload:0,covered:true,coverage:'complete'},
  {bucket:start+120,download:100,upload:25,covered:true,coverage:'partial'}]};
const coverageUi=setup(coverageData,{},{locale:'en'});
const coverageColumns=coverageUi.root.querySelectorAll('.ns-trend-group');
assert(coverageColumns[0].querySelector('.ns-trend-gap'));
assert.equal(coverageColumns[0].querySelector('.ns-trend-down'),null);
assert(coverageColumns[0].attrs['aria-label'].includes('No observation'));
assert(!coverageColumns[0].attrs['aria-label'].includes('0 B'));
assert(coverageColumns[1].attrs['aria-label'].includes('Download 0 B'));
assert(coverageColumns[2].attrs['aria-label'].includes('Partial observation'));
assert.equal(coverageColumns[2].querySelector('.ns-trend-up').attrs.style,'height:25%');
assert(text(coverageUi.root.querySelector('.ns-trend-scope')).includes('Totals and rankings use the time range selected above'));
assert(text(coverageUi.root.querySelector('.ns-minute-coverage')).includes('unknown traffic, not zero'));
coverageColumns[0].attrs.click();
assert(text(coverageUi.root.querySelector('.ns-trend-selection')).includes('No observation'));
const unavailable=setup({...coverageData,minute_history_available:false,timeline:[]},{},{locale:'en'}).root;
assert(text(unavailable.querySelector('.ns-minute-history')).includes('earlier minutes cannot be reconstructed'));
assert.equal(unavailable.querySelector('.ns-trend-down'),null);
const connectionUi=setup(base(),{},{locale:'en'});
assert.equal(text(connectionUi.root.querySelector('#ns-sort').children.find(option=>option.attrs.value==='flows')),'Hourly active connections');
connectionUi.view.sortSelect.value='flows';connectionUi.view.paint();
assert.equal(text(connectionUi.root.querySelector('.ns-flow-definition')),'A connection active in multiple hours is counted once per hour.');
class BackwardClock extends Date {
 static now() {return 1700000000000;}
 toLocaleString() {return String(this.getTime());}
}
const futureUi=setup({...base(),clock_anomaly:true,timeline:[{bucket:2200000000,upload:10,download:20}],timeline_resolution_seconds:3600},{},{locale:'en',DateClass:BackwardClock});
assert(text(futureUi.root.querySelector('.ns-clock-warning')).includes('ahead of the system clock'));
assert(text(futureUi.root.querySelector('.ns-trend-selection')).includes('2200000000000 — 2200003600000'));
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
 assert.equal(args[10],'recent');
 // The chart window is independent of totals, device and application filters;
 // it survives periodic paints without replacing a choice with server data.
 const chartQueries=[];
 const controlled=setup({...coverageData,device_choices:[{mac:'AA:01',name:'Phone'}]},
  {summary:(...query)=>{chartQueries.push(query);return {...coverageData,hours:query[0],device:query[1],
   identification:query[7],search:query[8],application:query[9],app_page:query[2],device_page:query[3],
   timeline_source:'hourly',trend_fallback:query[10]==='recent'?'filtered':undefined};}}, {locale:'en'});
 controlled.view.hoursSelect.value='24';controlled.view.deviceSelect.value='AA:01';
 controlled.view.identificationSelect.value='protocol';controlled.view.searchTerm='example';
 controlled.view.applicationFilter='protocol:tls';controlled.view.appPage=2;controlled.view.devicePage=3;
 let control=controlled.root.querySelector('#ns-trend-window');
 assert.equal(control.value,'recent');
 control.value='range';await control.attrs.change({target:control});
 assert.deepEqual(chartQueries.at(-1).slice(0,4),[24,'AA:01',2,3]);
 assert.deepEqual(chartQueries.at(-1).slice(7),['protocol','example','protocol:tls','range']);
 controlled.view.paint();
 assert.equal(controlled.root.querySelector('#ns-trend-window').value,'range');
 control=controlled.root.querySelector('#ns-trend-window');control.value='recent';
 await control.attrs.change({target:control});
 assert.equal(chartQueries.at(-1)[10],'recent');
 assert(text(controlled.root.querySelector('.ns-trend-fallback')).includes('filters use hourly bars'));
 assert.equal(controlled.root.querySelector('.ns-trend-scope'),null);
 assert(!source.includes('最多7天'));
 assert(!source.includes('展开查看设备与网站'));
 assert(!source.includes('点击一项，查看对应设备和访问目标'));
 console.log('Node logic: visible-page drilldown and removed subtitles OK');
})().catch(e=>{console.error(e);process.exit(1);});

// Compacted totals must never masquerade as dated trend/hostname records.
for (const locale of ['en', 'zh-Hans', 'zh-Hant']) {
 const data = {...base(),history_compacted:true,archive_included:true,
  archived_total:{upload:1024,download:2048},
  applications:[{id:'archive:domain',name:'Historical domain traffic',name_i18n:'Historical domain traffic',
   source_type:'archived_domain',has_archived_data:true,upload:1024,download:2048,flows:1}], app_count:1};
 const {root} = setup(data, {}, {locale});
 assert(root.querySelector('.ns-archive-notice'));
 assert(text(root.querySelector('.ns-archive-totals')).includes('2'));
 assert(root.querySelector('.ns-archive-detail'));
 const recent = setup({...data,hours:168,archive_included:false}, {}, {locale}).root;
 assert(recent.querySelector('.ns-archive-notice'));
 assert.equal(recent.querySelector('.ns-archive-totals'),null);
}
