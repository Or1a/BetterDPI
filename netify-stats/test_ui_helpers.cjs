// Minimal LuCI UI test fixtures. These are plain objects, not a browser DOM.
const fs = require('node:fs');
const path = require('node:path');

function readPo(filename) {
 const entries = new Map();
 let id = null, value = null, field = null;
 const flush = () => {
  if (id != null && id !== '' && value != null) {
   if (entries.has(id)) throw new Error('Duplicate translation: ' + id);
   entries.set(id, value);
  }
  id = value = field = null;
 };
 for (const line of fs.readFileSync(filename, 'utf8').split(/\r?\n/)) {
  if (!line.trim()) { flush(); continue; }
  if (line.startsWith('#')) continue;
  const entry = /^(msgid|msgstr)\s+(".*")$/.exec(line);
  if (entry) {
   if (entry[1] === 'msgid') {
    if (id != null) flush();
    id = JSON.parse(entry[2]); field = 'id';
   } else {
    value = JSON.parse(entry[2]); field = 'value';
   }
  } else if (/^"/.test(line) && field) {
   if (field === 'id') id += JSON.parse(line);
   else value += JSON.parse(line);
  } else throw new Error('Unsupported PO entry: ' + line);
 }
 flush();
 return entries;
}

function translator(locale = 'en') {
 const catalog = /^zh[-_]Hans$/i.test(locale) || locale === 'zh-CN' || locale === 'zh-cn'
  ? 'zh_Hans' : /^zh[-_]Hant$/i.test(locale) || locale === 'zh-TW' || locale === 'zh-tw'
  ? 'zh_Hant' : null;
 const dictionary = catalog ? readPo(path.join(__dirname, 'po', catalog, 'netify-stats.po')) : new Map();
 return message => dictionary.get(message) || message;
}

// LuCI extends strings with printf-like formatting. This fixture implements the
// string and integer placeholders used by this view, including numbered ones.
if (!String.prototype.format) Object.defineProperty(String.prototype, 'format', {
 configurable: true,
 value: function(...args) {
  let next = 0;
  return this.replace(/%(?:(\d+)\$)?([sd%])/g, (_all, position, kind) => {
   if (kind === '%') return '%';
   const index = position ? Number(position) - 1 : next++;
   if (index >= args.length) throw new Error('Missing string-format argument');
   return kind === 'd' ? String(Math.trunc(Number(args[index]))) : String(args[index]);
  });
 }
});

const list = value => Array.isArray(value) ? value : value == null ? [] : [value];
function walk(node) { return !node || typeof node !== 'object' ? [] : [node].concat(list(node.children).flatMap(walk)); }
function text(node) { return typeof node === 'string' || typeof node === 'number' ? String(node) : list(node?.children).map(text).join(''); }
function E(tag, attrs = {}, children = []) {
 const node = {tag, attrs, children: list(children), listeners: {}, value: attrs.value || '',
  disabled: attrs.disabled != null, checked: attrs.checked != null, hidden: attrs.hidden != null,
  scrollTop: 0, scrollLeft: 0, style: {}, classList: {add() {}},
  addEventListener(name, fn) { this.listeners[name] = fn; },
  setAttribute(key, value) { this.attrs[key] = value; }, getAttribute(key) { return this.attrs[key]; },
  appendChild(child) { this.children.push(child); },
  insertBefore(child, before) { this.children.splice(this.children.indexOf(before), 0, child); },
  querySelectorAll(selector) { return walk(this).slice(1).filter(n => selector[0] === '#' ? n.attrs.id === selector.slice(1) : selector[0] === '.' ? (n.attrs.class || '').split(' ').includes(selector.slice(1)) : selector === '[data-ns-scroll]' ? n.attrs['data-ns-scroll'] != null : n.tag === selector); },
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
 };
 if (tag === 'select') node.value = node.children.find(n => n.attrs.selected != null)?.attrs.value || node.children[0]?.attrs.value || '';
 return node;
}

const dom = {content(node, value) { node.children = list(value); }};
function setup(data, handlers = {}, {locale = 'zh-Hans', DateClass = Date, confirm = () => true} = {}) {
 const source = fs.readFileSync(path.join(__dirname, 'netify-stats.js'), 'utf8');
 const view = new Function('view', 'rpc', 'dom', 'poll', 'L', 'E', 'document', 'window', '_', 'Date', source)(
  {extend: x => x}, {declare: spec => (...args) => Promise.resolve().then(() => handlers[spec.method] ? handlers[spec.method](...args) : data)},
  dom, {add() {}}, {bind: (fn, self) => fn.bind(self), env: {lang: locale}}, E,
  {documentElement: {lang: locale}, createElementNS: (ns, tag) => E(tag), createTextNode: value => value},
  {confirm}, translator(locale), DateClass);
 return {view, root: view.render(data)};
}

function base() { return {enabled: true, control: {enabled: true, actual_state: 'running', applied: true}, storage: {max_storage_mib: 0}, applications: [], devices: [], device_choices: [], timeline: []}; }
module.exports = {readPo, translator, list, E, walk, text, dom, setup, base};
