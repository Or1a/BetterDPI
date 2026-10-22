// Offline UI tests: coverage is a traffic breakdown, never detection confidence.
const assert = require('node:assert/strict');
const {translator, setup, base, text} = require('./test_ui_helpers.cjs');

for (const locale of ['en', 'zh-Hans', 'zh-Hant']) {
 const _ = translator(locale);
 const data = {...base(), total:{download:600,upload:400,flows:12}, app_count:35,
  classification_coverage:{
   application:{download:300,upload:100,flows:4},
   domain:{download:100,upload:200,flows:3},
   protocol:{download:150,upload:100,flows:3},
   unknown:{download:50,upload:0,flows:2}
  }, applications:[
   {id:'protocol:tls',name:'TLS / encrypted traffic',source_type:'protocol',download:150,upload:100,
    classification_evidence:[{reason:'protocol',protocol:'TLSv1.3',category:'tls',application_identified:false}]},
   {id:'infrastructure:aws',name:'AWS',source_type:'infrastructure',download:100,upload:200,
    classification_evidence:[{reason:'infrastructure',matched_domain:'cloudfront.net',rule_type:'suffix',source_name:'DLC'}]}
  ]};
 const ui = setup(data, {}, {locale});
 const coverage = text(ui.root.querySelector('.ns-coverage'));
 assert(coverage.includes(_('Application identified')));
 assert(coverage.includes(_('Domain or infrastructure only')));
 assert(coverage.includes(_('Protocol only')));
 assert(coverage.includes('40.0%') && coverage.includes('30.0%') && coverage.includes('25.0%') && coverage.includes('5.0%'));
 const rendered = text(ui.root.querySelector('#ns-content'));
 assert(rendered.includes(_('%s (application unidentified)').format(_('TLS / encrypted traffic'))));
 assert(rendered.includes(_('%s (infrastructure; application unidentified)').format('AWS')));
 assert(rendered.includes(_('Observed protocol: %s').format('TLSv1.3')));
 assert(rendered.includes(_('The domain identifies a shared hosting or CDN provider, not a specific application.')));
 assert(rendered.includes('cloudfront.net'));
 // A new ranked page must not alter the all-results coverage denominator.
 ui.view.currentData={...data,applications:[]};ui.view.paint();
 assert.equal(text(ui.root.querySelector('.ns-coverage')),coverage);
 const empty = setup({...data,total:{},classification_coverage:{application:{},domain:{},protocol:{},unknown:{}}},{},{locale});
 assert(!text(empty.root.querySelector('.ns-coverage')).includes('NaN'));
 assert(text(empty.root.querySelector('.ns-coverage')).includes('0.0%'));
 const broken = setup({...data,total:{download:123}},{},{locale});
 assert(text(broken.root.querySelector('.ns-coverage')).includes(_('The identification breakdown is unavailable.')));
 const old = setup(base(),{},{locale});
 assert.equal(old.root.querySelector('.ns-coverage'),null);
}
console.log('Classification coverage, protocol-only and infrastructure labels, and translations OK');
