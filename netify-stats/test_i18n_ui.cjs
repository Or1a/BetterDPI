// Bilingual LuCI regression checks. Plain-object UI only: no browser or server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {readPo, translator, setup, base, walk, text} = require('./test_ui_helpers.cjs');

function visible(root) {
 return walk(root).filter(node => node.tag !== 'style').flatMap(node => [
  ...node.children.filter(child => typeof child === 'string'),
  node.attrs.title || '', node.attrs['aria-label'] || ''
 ]).join('\n');
}
function button(root, label) { return walk(root).find(node => node.tag === 'button' && text(node) === label); }
const source = fs.readFileSync(path.join(__dirname, 'netify-stats.js'), 'utf8');
const menu = JSON.parse(fs.readFileSync(path.join(__dirname, 'menu.json'), 'utf8'));
const chinese = /[\u3400-\u9fff]/u;

(async () => {
 // Every static UI key must be present in the shipping Chinese catalogs, not
 // merely in a test-only dictionary. Matching placeholders protects formatting.
 const keys = [...source.matchAll(/_\(\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*\)/g)]
  .map(match => match[1].startsWith('"') ? JSON.parse(match[1]) : JSON.parse('"' + match[1].slice(1, -1).replace(/\\'/g, "'").replace(/"/g, '\\"') + '"'));
 assert(keys.length > 50, 'The UI must use LuCI gettext for its fixed text');
 const menuTitle = menu['admin/status/netify-stats'].title;
 assert(!chinese.test(menuTitle), 'The LuCI menu needs an English translation key');
 keys.push(menuTitle);
 for (const catalog of ['zh_Hans', 'zh_Hant']) {
  const filename = path.join(__dirname, 'po', catalog, 'netify-stats.po');
  assert(!/^#,.*\bfuzzy\b/m.test(fs.readFileSync(filename, 'utf8')), catalog + ': unfinished fuzzy translations');
  const messages = readPo(filename);
  for (const key of keys) {
   assert(messages.get(key), catalog + ': missing translation for ' + key);
   assert.deepEqual((messages.get(key).match(/%[sd]/g) || []).sort(), (key.match(/%[sd]/g) || []).sort(), catalog + ': changed format placeholders for ' + key);
  }
 }

 for (const locale of ['en', 'zh-Hans', 'zh-Hant', 'zh_Hans', 'zh_Hant']) {
  const _ = translator(locale), dates = [];
  class DateProbe extends Date {
   toLocaleString(language, options) { dates.push(language); return super.toLocaleString(language, options); }
   toLocaleDateString(language, options) { dates.push(language); return super.toLocaleDateString(language, options); }
   toLocaleTimeString(language, options) { dates.push(language); return super.toLocaleTimeString(language, options); }
  }
  const data = {...base(), selected_interface: 'missing0', interface_choices: ['eth0'],
   interfaces: [{name: 'missing0', download: 1024, upload: 512, resets: 1}],
   timeline: [{bucket: 1700000000, download: 100, upload: 30}],
   app_count: 11, device_count: 11};
  const {root, view} = setup(data, {}, {locale, DateClass: DateProbe});
  assert.equal(text(root.querySelector('h2')), _(menuTitle));
  assert.equal(text(root.querySelector('#ns-hours').children.find(node => node.attrs.value === '168')), _('Last 7 days'));
  assert(button(root, _('Confirm and save')), locale + ': interface confirmation button');
  assert(visible(root).includes(_('Interface traffic')));
  assert(dates.length > 0, 'Trend dates must be formatted');
  assert(dates.every(language => language === locale.replace(/_/g, '-')), 'Dates must follow LuCI, not the browser locale: ' + JSON.stringify(dates));
  assert.equal(root.querySelector('.ns-storage-settings').tag, 'section');
  assert(button(root, _('Previous')) && button(root, _('Next')), 'Both pagers stay translated');
  if (locale === 'en') assert(!chinese.test(visible(root)), 'English UI leaked fixed Chinese text');
  if (locale === 'zh-Hans') {
   assert(visible(root).includes('接口流量'));
   assert(button(root, '确定保存'));
   assert(visible(root).includes('最近7天'));
  }

  // Invalid settings, confirmation prompts, success, and rejected writes all
  // remain localized, including async redraws rather than just first render.
  const input = walk(root).find(node => node.tag === 'input' && node.attrs.type === 'number');
  const save = button(root, _('Save storage setting'));
  assert(save, locale + ': storage button');
  input.value = '3';
  await save.attrs.click();
  assert(visible(root).includes(_('Enter 0 (unlimited) or an integer from 4 to 4096 MiB.')));
  const failed = setup(base(), {summary: () => ({error: 'Temporary database failure'})}, {locale});
  const original = failed.view.currentData;
  await failed.view.refresh();
  assert(text(failed.view.errorNode).length > 10);
  if (locale === 'en') assert(!chinese.test(text(failed.view.errorNode)));
  else assert(chinese.test(text(failed.view.errorNode)));
  assert.equal(failed.view.currentData, original);

  const anomalies = {...base(), rules_error: 'missing rules',
   collector: {connected: false, timestamp: 0, proxy_error: 'missing conntrack', export_error: 'invalid JSON', interface_error: 'missing interface', unattributed_upload: 1024},
   storage: {error: 'disk full', max_storage_mib: 0},
   control: {enabled: false, actual_state: 'partial', applied: false, apply_error: 'Service command failed'}};
  const warnings = setup(anomalies, {}, {locale}).root;
  if (locale === 'en') assert(!chinese.test(visible(warnings)), 'English warnings leaked fixed Chinese text');
  else assert(chinese.test(visible(warnings)), 'Chinese warnings were not translated');

  const rejected = setup(base(), {set_storage: () => ({error: 'Settings are being saved. Please try again.'})}, {locale});
  const rejectedInput = walk(rejected.root).find(node => node.tag === 'input' && node.attrs.type === 'number');
  rejectedInput.value = '4';
  await button(rejected.root, _('Save storage setting')).attrs.click();
  assert(visible(rejected.root).includes(_('Could not save: %s').format(_('Settings are being saved. Please try again.'))));

  const confirmations = [], writes = [];
  const saved = setup(base(), {set_storage: value => { writes.push(value); return {max_storage_mib: value}; }}, {
   locale, confirm: message => { confirmations.push(message); return true; }
  });
  walk(saved.root).find(node => node.tag === 'input' && node.attrs.type === 'number').value = '4';
  await button(saved.root, _('Save storage setting')).attrs.click();
  assert.deepEqual(writes, [4]);
  assert.deepEqual(confirmations, [_('When the storage limit is reached, the oldest hours of statistics will be deleted first. Save this setting?')]);
  assert(visible(saved.root).includes(_('Saved. The collector will apply the setting automatically.')));

  const nested = {...base(), control: {enabled: false, actual_state: 'partial', applied: false,
   apply_error: 'Analysis setting could not be fully applied: Services did not fully stop. Please try again.'}};
  const nestedUi = setup(nested, {}, {locale});
  assert(text(nestedUi.view.analysisNotice).includes(_('Analysis setting could not be fully applied: %s').format(_('Services did not fully stop. Please try again.'))));
 }

 // Names supplied by devices and rules are data, not gettext keys. Even a name
 // identical to a UI key (or written in Chinese) must not be silently renamed.
 for (const locale of ['en', 'zh-Hans']) {
  const data = {...base(), app_count: 1, device_count: 1,
   applications: [{id: 'custom', name: '自定义应用 Download', source_type: 'community', source_names: ['NextDNS'],
    devices: [{name: '家里的手机', download: 20}], hosts: [{name: '中文.example.test', download: 20}], download: 20}],
   devices: [{name: '家里的手机', ip: '192.0.2.1', mac: '02:00:00:00:00:01', download: 20}],
   device_choices: [{name: 'Download', mac: '02:00:00:00:00:01'}]};
  const {root} = setup(data, {}, {locale});
  assert.equal(text(root.querySelector('.ns-app-label').querySelector('strong')), '自定义应用 Download');
  assert.equal(text(root.querySelector('.ns-device-label').querySelector('strong')), '家里的手机');
  assert.equal(text(root.querySelector('#ns-device').children[1]), 'Download');
  assert(visible(root).includes('中文.example.test'));
 }
 for (const locale of ['en', 'zh-Hans', 'zh-Hant']) {
  const _ = translator(locale);
  const data = {...base(), app_count: 4, applications: [
   {id: 'Unknown', name: '未知目的地', name_i18n: 'Unknown destination', source: '未识别', source_type: 'unknown'},
   {id: 'community:wechat', name: '微信', name_i18n: 'WeChat', source: '社区域名规则', source_type: 'community', source_names: ['v2fly/domain-list-community', 'NextDNS Services']},
   {id: 'NetifyApp', name: 'NetifyApp', source: '原生识别', source_type: 'native'},
   {id: 'domain:example.test', name: 'example.test', source: '仅识别域名', source_type: 'domain'}]};
  const {root} = setup(data, {}, {locale});
  const labels = root.querySelectorAll('.ns-app-label');
  assert.equal(text(labels[0]), _('Unknown destination'));
  assert.equal(labels[0].attrs.title, _('Unidentified'));
  assert.equal(text(labels[1]), _('WeChat'));
  assert.equal(labels[1].attrs.title, _('%s (%s)').format(_('Community domain rules'), 'v2fly/domain-list-community / NextDNS Services'));
  assert.equal(labels[2].attrs.title, _('Native Netify classification'));
  assert.equal(labels[3].attrs.title, _('Domain only'));
  if (locale === 'en') assert(!chinese.test(visible(root)), 'Legacy Chinese compatibility metadata leaked into English UI');
 }
 console.log('LuCI English/Simplified/Traditional UI, catalog completeness, locale dates, async errors, and data names OK');
})().catch(error => { console.error(error); process.exit(1); });
