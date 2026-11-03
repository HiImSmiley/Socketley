// generated from socketley/runtime/storage/storage_ui_page.inc -- the storage UI's own; do not edit
// ─── helpers ────────────────────────────────────────────────────────────────
const $ = (s, r = document) => r.querySelector(s);
// The page's words in the reader's language where the page filled SAY with them, each `%` taking an argument in turn.
const SAY = {};
function say(s, ...a) { const w = SAY[s] || s; let i = 0; return a.length ? w.replace(/%/g, () => a[i++]) : w; }
function el(t, a, ...kids) {
  const e = document.createElement(t);
  for (const [k, v] of Object.entries(a || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'text') e.textContent = v;
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k);
  return e;
}
const P = {
  play: '<path d="M7 4.5v15l13-7.5z"/>', pause: '<path d="M6.5 4h4v16h-4zM13.5 4h4v16h-4z"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  text: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
  code: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="9" cy="10" r="2"/><path d="m21 16-5-5-10 9"/>',
  video: '<rect x="2.5" y="5" width="15" height="14" rx="2.5"/><path d="m17.5 10 4-2.5v9l-4-2.5"/>',
  music: '<path d="M9 18V5.5l11-2V16"/><circle cx="6" cy="18" r="3"/><circle cx="17" cy="16" r="3"/>',
  shuffle: '<path d="M16 4h4v4M4 20 20 4M20 16v4h-4M15 15l5 5M4 4l5 5"/>',
  pdf: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M8.5 16.5h1.5a1.5 1.5 0 0 0 0-3H8.5v5M14 13.5v5"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9M10 13h4"/>',
  bucket: '<ellipse cx="12" cy="5.5" rx="8" ry="2.8"/><path d="M4 5.5v13c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8v-13M4 12c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8"/>',
  upload: '<path d="M12 15V4m-4.5 4.5L12 4l4.5 4.5M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15"/>',
  download: '<path d="M12 4v11m-4.5-4.5L12 15l4.5-4.5M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15"/>',
  share: '<circle cx="18" cy="5.5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="18.5" r="2.5"/><path d="m8.2 10.8 7.6-4.1m-7.6 6.5 7.6 4.1"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4.5h6V7"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
  more: '<circle cx="5" cy="12" r="1.4"/><circle cx="12" cy="12" r="1.4"/><circle cx="19" cy="12" r="1.4"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>', plus: '<path d="M12 5v14M5 12h14"/>',
  grid: '<rect x="4" y="4" width="7" height="7" rx="1.8"/><rect x="13" y="4" width="7" height="7" rx="1.8"/><rect x="4" y="13" width="7" height="7" rx="1.8"/><rect x="13" y="13" width="7" height="7" rx="1.8"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
  restore: '<path d="M4 12a8 8 0 1 0 2.3-5.6L4 8.7"/><path d="M4 4v4.7h4.7"/>',
  back10: '<path d="M4 12a8 8 0 1 0 2.3-5.6L4 8.7"/><path d="M4 4v4.7h4.7M10 10v5M13 10h2.5v5H13z"/>',
  fwd10: '<path d="M20 12a8 8 0 1 1-2.3-5.6L20 8.7"/><path d="M20 4v4.7h-4.7M8.5 10v5M11.5 10H14v5h-2.5z"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  cc: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M10.5 10.2a2.5 2.5 0 1 0 0 3.6M17 10.2a2.5 2.5 0 1 0 0 3.6"/>',
  vol: '<path d="M4 9.5h3.5L12 5.5v13l-4.5-4H4z"/><path d="M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11"/>',
  mute: '<path d="M4 9.5h3.5L12 5.5v13l-4.5-4H4z"/><path d="m16 9.5 5 5m0-5-5 5"/>',
  fs: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>', fsx: '<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>',
  pip: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><rect x="12" y="11.5" width="6" height="4.5" rx="1"/>',
  prev: '<path d="M6 5v14M19 5.5 9 12l10 6.5z"/>', next: '<path d="M18 5v14M5 5.5 15 12 5 18.5z"/>',
  out: '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 16l-4-4 4-4M6 12h10"/>',
  home: '<path d="M4 11 12 4l8 7M6 9.5V20h12V9.5"/><path d="M10 20v-5h4v5"/>',
  chev: '<path d="m9 6 6 6-6 6"/>', left: '<path d="m15 6-6 6 6 6"/>', check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  save: '<path d="M5 4h11l3 3v12a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/>',
  newfolder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 11v6M9 14h6"/>',
  newfile: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 11v6M9 14h6"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  bell: '<path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
  sync: '<path d="M20 11a8 8 0 0 0-14.3-4.9L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.3 4.9L20 16"/><path d="M20 20v-4h-4"/>',
  eyeoff: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
  wrap: '<path d="M4 6h16M4 12h13a3 3 0 0 1 0 6h-4m2-2-2 2 2 2M4 18h5"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>', clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  spark: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  send: '<path d="M21 3 10.5 13.5M21 3l-6.5 18-4-7.5L3 9.5z"/>',
  git: '<circle cx="6" cy="5.5" r="2.2"/><circle cx="6" cy="18.5" r="2.2"/><circle cx="18" cy="8.5" r="2.2"/><path d="M6 7.7v8.6M18 10.7c0 4-6 3.3-11 6.2"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>',
  shield: '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6"/>',
  fire: '<path d="M12 21c-3.9 0-7-2.9-7-6.6 0-2.8 1.6-4.6 3.2-6.3.3 1.8 1.3 3 2.6 3.4C10.4 8 12 5.2 14.5 3c.3 3.2 4.5 5.6 4.5 11.1 0 3.9-3.1 6.9-7 6.9z"/><path d="M12 21c-1.7 0-3-1.3-3-3 0-1.9 1.6-2.9 3-4.5 1.4 1.6 3 2.6 3 4.5 0 1.7-1.3 3-3 3z"/>'
};
const THEMES = [['aurora', 'Aurora', '#c084fc', '#f472b6', '#fb923c'], ['ocean', 'Ocean', '#67e8f9', '#60a5fa', '#818cf8'], ['neon', 'Neon', '#bef264', '#22d3ee', '#f0abfc'], ['ember', 'Ember', '#fb7185', '#fb923c', '#fde047'], ['mono', 'Mono', '#fafafa', '#a1a1aa', '#52525b']];
function theme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem('skl-theme', t); } catch (e) {} paintThemes(); }
function paintThemes() {
  const T = document.getElementById('themes'); if (!T) return; T.textContent = '';
  const cur = document.documentElement.dataset.theme || 'aurora';
  for (const [id, name, a, b, c] of THEMES) T.append(el('button', { class: cur === id ? 'on' : '', title: name + ' theme', 'aria-label': name + ' theme', style: 'background:conic-gradient(' + a + ',' + b + ',' + c + ',' + a + ')', onclick: () => theme(id) }));
}
try { document.documentElement.dataset.theme = localStorage.getItem('skl-theme') || 'aurora'; } catch (e) {}
const SVGNS = 'http://www.w3.org/2000/svg';
function ico(n, cls) { const s = document.createElementNS(SVGNS, 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'i' + (cls ? ' ' + cls : '')); s.innerHTML = P[n] || P.file; if (n === 'more') s.style.fill = 'currentColor'; return s; }
function ibtn(n, title, fn, cls) { return el('button', { class: 'ib' + (cls ? ' ' + cls : ''), title, 'aria-label': title, onclick: fn }, ico(n)); }
function btn(n, label, fn, cls) { return el('button', { class: 'btn' + (cls ? ' ' + cls : ''), onclick: fn }, n ? ico(n) : null, el('span', { text: label })); }
const sleep = ms => new Promise(r => setTimeout(r, ms));
const enc = p => p.map(encodeURIComponent).join('/');
const dav = (segs, dir) => '/~dav/' + enc(segs) + (dir && segs.length ? '/' : '');
const human = n => { n = +n || 0; if (n < 1000) return n + ' B'; const u = ['KB', 'MB', 'GB', 'TB', 'PB']; let i = -1; do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1); return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + ' ' + u[i]; };
const clock = s => { if (!isFinite(s) || s < 0) s = 0; s = Math.floor(s); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(x).padStart(2, '0'); };
const when = d => { if (!d) return ''; const t = new Date(d), s = (Date.now() - t) / 1000; if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + ' min ago'; if (s < 86400) return Math.floor(s / 3600) + ' h ago'; if (s < 86400 * 7) return Math.floor(s / 86400) + ' d ago'; return t.toLocaleDateString(); };
const hue = s => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
const store = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }, del(k) { try { localStorage.removeItem(k); } catch (e) {} } };
const ext = n => (n.match(/\.([^./]+)$/) || ['', ''])[1].toLowerCase();
const TEXT = 'txt md markdown json jsonc csv tsv log xml yml yaml toml lua c h cc cpp cxx hpp hh js mjs cjs ts tsx jsx py rb go rs java kt kts swift cs php pl sh bash zsh fish ps1 bat ini conf cfg env sql html htm css scss sass less vue svelte srt vtt ass nfo gitignore dockerignore editorconfig properties gradle cmake mk makefile dockerfile tex rst adoc diff patch'.split(' ');
function kind(n, t) {
  const e = ext(n); t = t || '';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'bmp', 'heic', 'heif', 'svg', 'ico', 'tif', 'tiff'].includes(e) || t.startsWith('image/')) return 'image';
  if (['mp4', 'mkv', 'webm', 'mov', 'avi', 'm4v', 'ts', 'm2ts', 'wmv', 'flv', 'mpg', 'mpeg', '3gp', 'ogv'].includes(e) || t.startsWith('video/')) return 'video';
  if (['mp3', 'flac', 'ogg', 'oga', 'opus', 'm4a', 'wav', 'aac', 'wma', 'alac', 'aiff'].includes(e) || t.startsWith('audio/')) return 'audio';
  if (e === 'pdf') return 'pdf';
  if (['zip', 'tar', 'gz', 'tgz', '7z', 'rar', 'xz', 'zst', 'bz2', 'iso', 'dmg'].includes(e)) return 'archive';
  if (TEXT.includes(e) || t.startsWith('text/') || /json|xml|javascript/.test(t) || /^(readme|license|licence|makefile|dockerfile|changelog|authors|notice|todo)$/i.test(n)) return 'text';
  return 'file';
}
const ICON = { dir: 'folder', bucket: 'bucket', image: 'image', video: 'video', audio: 'music', text: 'text', pdf: 'pdf', archive: 'archive', file: 'file' };
const MIME = { txt: 'text/plain', md: 'text/markdown', json: 'application/json', csv: 'text/csv', html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript', xml: 'application/xml', svg: 'image/svg+xml', yml: 'text/yaml', yaml: 'text/yaml', srt: 'text/plain', vtt: 'text/vtt' };
const keyOf = it => it.segs.join('/') + (it.dir ? '/' : '');

// ─── toasts, menus, dialogs ─────────────────────────────────────────────────
// Where a dialog, a menu or a toast goes: into the element shown full screen, which hides everything outside it.
const host = () => document.fullscreenElement || document.body;
document.addEventListener('fullscreenchange', () => host().append($('#toasts')));
function toast(msg, kind = 'ok', ms = 3200) {
  const t = el('div', { class: 'toast ' + kind }, ico(kind === 'bad' ? 'info' : kind === 'ok' ? 'check' : 'spark'), el('span', { text: msg }));
  host().append($('#toasts')); $('#toasts').append(t);
  setTimeout(() => { t.style.transition = 'opacity .3s'; t.style.opacity = 0; setTimeout(() => t.remove(), 300); }, ms);
  return t;
}
const fail = e => toast(e.message || String(e), 'bad', 5000);
let openPop = null;
function closePop() { if (openPop) { openPop.remove(); openPop = null; } }
function popup(at, entries) {
  closePop();
  const m = el('div', { class: 'pop', role: 'menu' });
  for (const x of entries) {
    if (!x) continue;
    if (x === '-') { m.append(el('hr')); continue; }
    if (x.head) { m.append(el('div', { class: 'hd', text: x.head })); continue; }
    m.append(el('button', { class: x.bad ? 'bad' : '', onclick: () => { closePop(); x.fn(); } }, ico(x.icon), el('span', { text: x.label }), x.key ? el('span', { class: 'k', text: x.key }) : null));
  }
  host().append(m);
  let x, y;
  if (at instanceof Element) { const r = at.getBoundingClientRect(); x = r.right - m.offsetWidth; y = r.bottom + 6; if (x < 8) x = r.left; }
  else { x = at.x; y = at.y; }
  x = Math.max(8, Math.min(x, innerWidth - m.offsetWidth - 8));
  if (y + m.offsetHeight > innerHeight - 8) y = Math.max(8, (at instanceof Element ? at.getBoundingClientRect().top - 6 : y) - m.offsetHeight);
  m.style.left = x + 'px'; m.style.top = y + 'px';
  openPop = m;
}
document.addEventListener('mousedown', e => { if (openPop && !openPop.contains(e.target)) closePop(); });
window.addEventListener('blur', closePop);
// A select's list is drawn by the page, in its theme, since the one the system draws ignores it.
(() => {
  let list = null;
  const close = () => { if (list) { list.remove(); list = null; } };
  const show = s => {
    close();
    const m = el('div', { class: 'optlist', role: 'listbox' });
    for (const o of s.options)
      m.append(el('button', { type: 'button', role: 'option', class: o.value === s.value ? 'on' : '', disabled: o.disabled, onclick: () => {
        close(); s.focus();
        if (s.value !== o.value) { s.value = o.value; s.dispatchEvent(new Event('input', { bubbles: true })); s.dispatchEvent(new Event('change', { bubbles: true })); }
      } }, el('span', { text: o.text })));
    host().append(m);
    const r = s.getBoundingClientRect();
    m.style.minWidth = r.width + 'px';
    let y = r.bottom + 6;
    if (y + m.offsetHeight > innerHeight - 8) y = Math.max(8, r.top - 6 - m.offsetHeight);
    m.style.left = Math.max(8, Math.min(r.left, innerWidth - m.offsetWidth - 8)) + 'px';
    m.style.top = y + 'px';
    m._sel = s; list = m;
    (m.querySelector('.on') || m.firstChild)?.focus({ preventScroll: true });
    m.querySelector('.on')?.scrollIntoView({ block: 'nearest' });
  };
  document.addEventListener('mousedown', e => {
    if (list && list.contains(e.target)) return;
    const s = e.target.closest ? e.target.closest('select.inp') : null;
    if (!s || s.disabled || e.button !== 0) { close(); return; }
    e.preventDefault();
    if (list && list._sel === s) { close(); s.focus(); } else show(s);
  }, true);
  document.addEventListener('keydown', e => {
    if (list) {
      const bs = [...list.querySelectorAll('button:not([disabled])')], i = bs.indexOf(document.activeElement);
      if (e.key === 'Escape' || e.key === 'Tab') { const s = list._sel; close(); s.focus(); if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); } return; }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); (bs[Math.max(0, Math.min(bs.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))] || bs[0])?.focus(); return; }
      return;
    }
    const s = e.target.closest ? e.target.closest('select.inp') : null;
    if (s && (e.key === ' ' || e.key === 'Enter' || (e.altKey && e.key === 'ArrowDown'))) { e.preventDefault(); show(s); }
  }, true);
  addEventListener('blur', close);
  addEventListener('resize', close);
  addEventListener('hashchange', close);
  document.addEventListener('scroll', e => { if (list && !list.contains(e.target)) close(); }, true);
})();
const layers = [];
function modal(title, body, foot, wide) {
  const box = el('div', { class: 'dlg' + (wide ? ' wide' : ''), role: 'dialog' });
  const s = el('div', { class: 'scrim' }, box);
  const close = () => { s.remove(); const i = layers.indexOf(L); if (i >= 0) layers.splice(i, 1); if (L.onclose) L.onclose(); };
  const L = { close, esc: close, box };
  box.append(el('div', { class: 'dh' }, el('h3', { text: title }), ibtn('close', say('Close'), close)), el('div', { class: 'db' }, body));
  if (foot) box.append(el('div', { class: 'df' }, foot));
  s.addEventListener('mousedown', e => { if (e.target === s) close(); });
  host().append(s); layers.push(L);
  return L;
}
function ask({ title, text, input, value, ok = 'OK', danger }) {
  return new Promise(res => {
    let done = false;
    const inp = input ? el('input', { class: 'inp', value: value || '', placeholder: input, spellcheck: 'false', style: 'width:100%' }) : null;
    const finish = v => { if (done) return; done = true; L.close(); res(v); };
    const go = () => finish(inp ? inp.value.trim() || null : true);
    const L = modal(title, [text ? el('p', { text }) : null, inp], [btn(null, say('Cancel'), () => finish(null)), btn(null, ok, go, danger ? 'badf' : 'pri')]);
    L.onclose = () => { if (!done) { done = true; res(null); } };
    L.box.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
    if (inp) { inp.focus(); const dot = (value || '').lastIndexOf('.'); inp.setSelectionRange(0, dot > 0 ? dot : (value || '').length); }
    else setTimeout(() => L.box.querySelector('.df .btn:last-child').focus(), 0);
  });
}

