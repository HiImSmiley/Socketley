// The page of the web interface, whole: markup, style and script, with nothing fetched from elsewhere.
constexpr std::string_view ui_page = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>socketley files</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2329;--mut:#69737d;--card:#fff;--line:#e3e6ea;--acc:#2563eb;--bad:#c62828;--hov:#eef2f8}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e6e9ec;--mut:#98a2ad;--card:#1c2026;--line:#2c323a;--acc:#5b8cff;--bad:#ef5350;--hov:#242a32}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:.5rem;align-items:center;padding:.6rem 1rem;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;flex-wrap:wrap}
header b{font-size:15px;margin-right:.5rem}
main{max-width:72rem;margin:0 auto;padding:1rem}
button,select,input{font:inherit;color:inherit}
button{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.3rem .7rem;cursor:pointer}
button:hover{background:var(--hov)}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff}
button.bad{color:var(--bad)}
input,select{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.35rem .5rem}
.sp{flex:1}
.crumbs a{color:var(--acc);text-decoration:none;cursor:pointer}
.crumbs span{color:var(--mut);margin:0 .3rem}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:.45rem .7rem;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:500;font-size:12px}
td.n{white-space:normal;word-break:break-all;width:100%}
tr:hover td{background:var(--hov)}
td.a{text-align:right}
td.a button{padding:.15rem .45rem;margin-left:.2rem;font-size:12px}
.nm{cursor:pointer;display:flex;align-items:center;gap:.55rem}
.ic{width:32px;height:32px;border-radius:4px;object-fit:cover;flex:none;display:inline-flex;align-items:center;justify-content:center;background:var(--hov);font-size:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.7rem}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;cursor:pointer}
.tile .th{height:110px;display:flex;align-items:center;justify-content:center;background:var(--hov);font-size:38px}
.tile .th img,.ic img{width:100%;height:100%;object-fit:cover;border-radius:inherit}
.tile .tn{padding:.35rem .5rem;font-size:12px;word-break:break-all}
.mut{color:var(--mut)}
#drop{position:fixed;inset:0;background:rgba(37,99,235,.15);border:3px dashed var(--acc);display:none;align-items:center;justify-content:center;font-size:20px;z-index:20}
.dlg{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:30;padding:1rem}
.box{background:var(--card);border-radius:10px;padding:1rem 1.2rem;max-width:min(60rem,100%);width:100%;max-height:92vh;overflow:auto}
.box h3{margin:.2rem 0 .8rem}
.row{display:flex;gap:.5rem;align-items:center;margin:.45rem 0;flex-wrap:wrap}
.row label{min-width:9rem;color:var(--mut)}
.view{display:flex;justify-content:center;align-items:center;background:#000;border-radius:6px;min-height:200px}
.view img,.view video{max-width:100%;max-height:75vh}
pre{white-space:pre-wrap;word-break:break-word;background:var(--hov);padding:.7rem;border-radius:6px;max-height:70vh;overflow:auto}
#bar{position:fixed;right:1rem;bottom:1rem;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem;min-width:16rem;display:none;z-index:25}
#bar progress{width:100%}
#login{max-width:22rem;margin:12vh auto;background:var(--card);padding:1.4rem;border-radius:10px;border:1px solid var(--line)}
#login input{width:100%;margin:.3rem 0 .7rem}
.err{color:var(--bad);min-height:1.2em}
</style>
</head>
<body>
<div id="login" hidden>
  <h2 style="margin-top:0">socketley</h2>
  <form id="lf">
    <div class="mut">Access key</div><input id="lk" autocomplete="username" required>
    <div class="mut">Secret</div><input id="ls" type="password" autocomplete="current-password" required>
    <div class="err" id="le"></div>
    <button class="pri" style="width:100%">Sign in</button>
  </form>
</div>
<div id="app" hidden>
<header>
  <b>socketley</b>
  <div class="crumbs" id="crumbs"></div>
  <div class="sp"></div>
  <button id="bNew">New folder</button>
  <button id="bUp" class="pri">Upload</button>
  <button id="bTrash">Trash</button>
  <button id="bShares">Links</button>
  <button id="bView" title="List or grid">▦</button>
  <button id="bOut">Sign out</button>
  <input type="file" id="fi" multiple hidden>
</header>
<main><div id="list"></div></main>
</div>
<div id="drop">Drop files to upload</div>
<div id="bar"><div id="barT"></div><progress id="barP" max="1" value="0"></progress></div>
<script>
'use strict';
const $ = s => document.querySelector(s);
const el = (t, a = {}, ...kids) => { const e = document.createElement(t); for (const [k, v] of Object.entries(a)) { if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (k === 'text') e.textContent = v; else e.setAttribute(k, v); } for (const k of kids) e.append(k); return e; };
let auth = sessionStorage.getItem('skl-auth') || '';
let path = [];
let grid = localStorage.getItem('skl-grid') === '1';
const enc = p => p.map(encodeURIComponent).join('/');
const human = n => { const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };
const ext = n => (n.match(/\.([^.]+)$/) || ['', ''])[1].toLowerCase();
const kind = (n, t) => {
  const e = ext(n);
  if ((t || '').startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'bmp', 'heic'].includes(e)) return 'image';
  if ((t || '').startsWith('video/') || ['mp4', 'mkv', 'webm', 'mov', 'avi', 'm4v', 'ts', 'wmv', 'flv'].includes(e)) return 'video';
  if ((t || '').startsWith('audio/') || ['mp3', 'flac', 'ogg', 'opus', 'm4a', 'wav', 'aac'].includes(e)) return 'audio';
  if ((t || '').startsWith('text/') || ['txt', 'md', 'json', 'csv', 'log', 'xml', 'yml', 'yaml', 'lua', 'c', 'h', 'cpp', 'js', 'py', 'sh', 'ini', 'conf'].includes(e)) return 'text';
  if (e === 'pdf') return 'pdf';
  return 'file';
};
const icon = k => ({ dir: '📁', bucket: '🗄️', image: '🖼️', video: '🎬', audio: '🎵', text: '📄', pdf: '📕', file: '📦' })[k];

async function api(method, url, opt = {}) {
  const h = Object.assign({ 'Authorization': auth, 'X-Socketley-UI': '1' }, opt.headers || {});
  const r = await fetch(url, { method, headers: h, body: opt.body });
  if (r.status === 401) { signOut(); throw new Error('Signed out'); }
  return r;
}
async function must(r) { if (!r.ok) throw new Error((await r.text()).trim() || r.status + ' ' + r.statusText); return r; }
function fail(e) { alert(e.message || e); }

function signOut() { auth = ''; sessionStorage.removeItem('skl-auth'); $('#app').hidden = true; $('#login').hidden = false; }
$('#lf').addEventListener('submit', async ev => {
  ev.preventDefault();
  auth = 'Basic ' + btoa($('#lk').value.trim() + ':' + $('#ls').value);
  const r = await fetch('/~dav/', { method: 'PROPFIND', headers: { 'Authorization': auth, 'Depth': '0', 'X-Socketley-UI': '1' } });
  if (r.status === 401) { $('#le').textContent = 'Those credentials are not known.'; return; }
  sessionStorage.setItem('skl-auth', auth);
  $('#le').textContent = '';
  start();
});
$('#bOut').onclick = signOut;

function go(p) { location.hash = '#/' + enc(p) + (p.length ? '/' : ''); }
function fromHash() { path = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent); }
window.addEventListener('hashchange', () => { fromHash(); load(); });

async function propfind(p) {
  const r = await must(await api('PROPFIND', '/~dav/' + enc(p) + (p.length ? '/' : ''), { headers: { Depth: '1' } }));
  const doc = new DOMParser().parseFromString(await r.text(), 'application/xml');
  const D = 'DAV:';
  const out = [];
  const rs = doc.getElementsByTagNameNS(D, 'response');
  for (let i = 1; i < rs.length; i++) {
    const x = rs[i];
    const g = n => { const e = x.getElementsByTagNameNS(D, n)[0]; return e ? e.textContent : ''; };
    const href = g('href');
    const dir = x.getElementsByTagNameNS(D, 'collection').length > 0;
    const segs = href.replace(/^\/~dav\//, '').split('/').filter(Boolean).map(decodeURIComponent);
    out.push({ name: g('displayname') || segs[segs.length - 1], segs, dir, size: +g('getcontentlength') || 0, type: g('getcontenttype'), mod: g('getlastmodified') });
  }
  out.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name, undefined, { numeric: true }));
  return out;
}

function crumbs() {
  const c = $('#crumbs'); c.textContent = '';
  c.append(el('a', { text: 'Home', onclick: () => go([]) }));
  path.forEach((s, i) => { c.append(el('span', { text: '/' }), el('a', { text: s, onclick: () => go(path.slice(0, i + 1)) })); });
  $('#bTrash').hidden = !path.length;
  $('#bUp').hidden = !path.length;
  $('#bNew').textContent = path.length ? 'New folder' : 'New bucket';
}

// Thumbnails are fetched with the user's credentials as they scroll into view, a few at a time.
let thumbQ = [], thumbBusy = 0;
const io = 'IntersectionObserver' in window ? new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting) { io.unobserve(e.target); thumbQ.push(e.target); pump(); } }) : null;
function pump() {
  while (thumbBusy < 4 && thumbQ.length) {
    const w = thumbQ.shift(); thumbBusy++;
    api('GET', w.dataset.src).then(r => r.ok ? r.blob() : null).then(b => {
      if (!b) return;
      const img = el('img', { alt: '', src: URL.createObjectURL(b) });
      w.textContent = ''; w.append(img);
    }).catch(() => {}).finally(() => { thumbBusy--; pump(); });
  }
}
function thumb(it, k, big) {
  const w = el(big ? 'div' : 'span', { class: big ? 'th' : 'ic', text: icon(k) });
  if (k === 'image' || k === 'video') {
    w.dataset.src = '/~media/thumb-' + (big ? 320 : 64) + '/' + enc(it.segs);
    io ? io.observe(w) : (thumbQ.push(w), pump());
  }
  return w;
}

async function load() {
  crumbs();
  const L = $('#list'); L.textContent = '';
  let items;
  try { items = await propfind(path); } catch (e) { L.append(el('p', { class: 'err', text: e.message })); return; }
  if (!items.length) { L.append(el('p', { class: 'mut', text: path.length ? 'This folder is empty. Drop files here to upload.' : 'No buckets yet: make one with New bucket.' })); return; }
  thumbQ = [];
  const open = it => it.dir ? go(it.segs) : preview(it);
  if (grid) {
    const G = el('div', { class: 'grid' });
    for (const it of items) {
      const k = it.dir ? (path.length ? 'dir' : 'bucket') : kind(it.name, it.type);
      G.append(el('div', { class: 'tile', onclick: () => open(it) }, thumb(it, k, true), el('div', { class: 'tn', text: it.name })));
    }
    L.append(G);
    return;
  }
  const T = el('table', {}, el('tr', {}, el('th', { text: 'Name' }), el('th', { text: 'Size' }), el('th', { text: 'Modified' }), el('th', {})));
  for (const it of items) {
    const k = it.dir ? (path.length ? 'dir' : 'bucket') : kind(it.name, it.type);
    const acts = el('td', { class: 'a' });
    if (!it.dir) acts.append(el('button', { text: '⬇', title: 'Download', onclick: () => download(it) }));
    acts.append(el('button', { text: 'Share', onclick: () => shareDlg(it) }));
    if (path.length) acts.append(el('button', { text: 'Rename', onclick: () => rename(it) }));
    acts.append(el('button', { text: '✕', title: 'Delete', class: 'bad', onclick: () => del(it) }));
    T.append(el('tr', {},
      el('td', { class: 'n' }, el('span', { class: 'nm', onclick: () => open(it) }, thumb(it, k, false), el('span', { text: it.name + (it.dir ? '/' : '') }))),
      el('td', { class: 'mut', text: it.dir ? '' : human(it.size) }),
      el('td', { class: 'mut', text: it.mod ? new Date(it.mod).toLocaleString() : '' }),
      acts));
  }
  L.append(T);
}

$('#bView').onclick = () => { grid = !grid; localStorage.setItem('skl-grid', grid ? '1' : '0'); load(); };
$('#bNew').onclick = async () => {
  const n = prompt(path.length ? 'Folder name' : 'Bucket name (lowercase letters, digits, dashes)');
  if (!n) return;
  try { await must(await api('MKCOL', '/~dav/' + enc([...path, n]) + '/')); load(); } catch (e) { fail(e); }
};
async function del(it) {
  if (!confirm('Delete ' + it.name + (it.dir ? ' and everything in it' : '') + '?')) return;
  try { await must(await api('DELETE', '/~dav/' + enc(it.segs) + (it.dir ? '/' : ''))); load(); } catch (e) { fail(e); }
}
async function rename(it) {
  const n = prompt('New name', it.name);
  if (!n || n === it.name) return;
  const dst = location.origin + '/~dav/' + enc([...it.segs.slice(0, -1), n]) + (it.dir ? '/' : '');
  try { await must(await api('MOVE', '/~dav/' + enc(it.segs) + (it.dir ? '/' : ''), { headers: { Destination: dst, Overwrite: 'F' } })); load(); } catch (e) { fail(e); }
}

// A link the page makes for itself, to hand a player or a download what it cannot sign.
async function tempLink(it, seconds) {
  const r = await must(await api('POST', '/~share', { body: JSON.stringify({ bucket: it.segs[0], key: it.segs.slice(1).join('/'), expires_in: seconds, note: 'player' }) }));
  return (await r.json()).id;
}
async function download(it) {
  try { const id = await tempLink(it, 600); location.href = '/~share/' + id + '?download'; } catch (e) { fail(e); }
}

// The master's streams through Media Source Extensions, for every browser that has them: the stream the bandwidth
// carries chosen at every segment, positions kept in seconds so that the copied stream and the renditions, whose
// segments begin at different times, follow one another, and a seek begun where it lands.
class MsePlayer {
  constructor(video, master, choice) { this.v = video; this.master = master; this.choice = choice; this.alive = true; this.lists = {}; }
  stop() { this.alive = false; if (this.ctl) this.ctl.abort(); this.v.removeAttribute('src'); this.v.load(); }
  static source() { return window.ManagedMediaSource || window.MediaSource; }
  async start(at) {
    const MS = MsePlayer.source();
    const text = await (await fetch(this.master)).text();
    const lines = text.split('\n');
    this.levels = [];
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].startsWith('#EXT-X-STREAM-INF:') || !lines[i + 1]) continue;
      const bw = +(/BANDWIDTH=(\d+)/.exec(lines[i]) || [0, 0])[1];
      const codecs = (/CODECS="([^"]+)"/.exec(lines[i]) || [0, ''])[1];
      const h = +(/RESOLUTION=\d+x(\d+)/.exec(lines[i]) || [0, 0])[1];
      const copy = lines[i + 1].includes('/hls-copy/');
      const rung = +(/\/hls-(\d+)\//.exec(lines[i + 1]) || [0, 0])[1];
      if (MS.isTypeSupported('video/mp4; codecs="' + codecs + '"'))
        this.levels.push({ bw, codecs, h, rung, copy, url: new URL(lines[i + 1], location.href).href });
    }
    if (!this.levels.length) return false;
    this.levels.sort((a, b) => a.bw - b.bw);
    const pick = c => this.levels.findIndex(c);
    // The copied picture where the browser takes it and the line plausibly carries it, which costs the server
    // almost nothing; else 720p or the largest rendition below about 4.5 Mbit/s.
    if (this.choice === 'copy') this.level = Math.max(0, pick(l => l.copy));
    else if (this.choice !== 'auto') this.level = Math.max(0, pick(l => l.rung === +this.choice));
    else this.level = pick(l => l.copy && l.bw <= 12000000) >= 0 ? pick(l => l.copy) : this.levels.reduce((best, l, i) => !l.copy && l.bw <= 4500000 ? i : best, 0);
    this.fixed = this.choice !== 'auto';
    let first = await this.list(this.level);
    // The film's length is a rendition's, written whole up front; a copied stream's playlist is only as long as the
    // remux has come.
    const whole = this.levels.findIndex(l => !l.copy);
    if (!first.ended && whole >= 0) first = await this.list(whole);
    this.ms = new MS();
    if (window.ManagedMediaSource) this.v.disableRemotePlayback = true;
    this.v.src = URL.createObjectURL(this.ms);
    await new Promise(r => this.ms.addEventListener('sourceopen', r, { once: true }));
    this.ms.duration = first.total;
    this.sb = this.ms.addSourceBuffer('video/mp4; codecs="' + this.levels[this.level].codecs + '"');
    this.inited = -1;
    this.v.addEventListener('seeking', () => { if (this.ctl) this.ctl.abort(); });
    // A hole of a few milliseconds where two of the server's jobs meet is stepped over rather than stalled in.
    this.v.addEventListener('waiting', () => {
      const b = this.sb.buffered, t = this.v.currentTime;
      for (let i = 0; i < b.length; i++) if (b.start(i) > t && b.start(i) - t < 0.5) { this.v.currentTime = b.start(i) + 0.01; break; }
    });
    if (at) this.v.currentTime = at;
    this.v.play().catch(() => {});
    this.pump();
    return true;
  }
  // A stream's playlist as segments with their start times; a copied stream's grows, and is read again until it ends.
  async list(level) {
    const known = this.lists[level];
    if (known && known.ended) return known;
    const url = this.levels[level].url;
    const text = await (await fetch(url, { cache: 'no-cache' })).text();
    const segs = []; let t = 0, init = null, dur = 0;
    for (const l of text.split('\n')) {
      if (l.startsWith('#EXT-X-MAP:')) init = new URL((/URI="([^"]+)"/.exec(l) || [0, 'init.mp4'])[1], url).href;
      else if (l.startsWith('#EXTINF:')) dur = parseFloat(l.slice(8));
      else if (l && !l.startsWith('#')) { segs.push({ url: new URL(l, url).href, start: t, dur }); t += dur; }
    }
    const ended = text.includes('#EXT-X-ENDLIST');
    const out = { segs, init, total: ended ? t : Math.max(t, this.ms ? this.ms.duration : 0), ended, at: performance.now() };
    this.lists[level] = out;
    return out;
  }
  bufferedEnd() { const b = this.sb.buffered, t = this.v.currentTime; for (let i = 0; i < b.length; i++) if (b.start(i) <= t + 0.3 && b.end(i) > t) return b.end(i); return t; }
  async append(data) {
    for (let tries = 0; ; tries++) {
      try { this.sb.appendBuffer(data); break; }
      catch (e) {
        // A full buffer gives up what lies well behind the playhead, and takes the segment after.
        if (e.name !== 'QuotaExceededError' || tries > 2) throw e;
        const keep = Math.max(0, this.v.currentTime - 10);
        if (keep <= 0) throw e;
        this.sb.remove(0, keep);
        await new Promise(r => this.sb.addEventListener('updateend', r, { once: true }));
      }
    }
    await new Promise(r => this.sb.addEventListener('updateend', r, { once: true }));
  }
  async pump() {
    // A player whose dialog was closed stops with it.
    while (this.alive && this.v.isConnected) {
      const end = this.bufferedEnd();
      if (end - this.v.currentTime > 30 || this.sb.updating) { await new Promise(r => setTimeout(r, 300)); continue; }
      let level = this.level;
      try {
        this.ctl = new AbortController();
        let list = await this.list(level);
        // The copied stream is remuxed from the start; a place it has not reached yet is played from a rendition,
        // which the server begins anywhere at once, and the copy is taken up again once it has caught up.
        if (this.levels[level].copy && !list.ended && end + 1 > list.total) {
          const fb = this.levels.reduce((best, l, i) => !l.copy && l.bw <= 4500000 ? i : best, -1);
          const any = this.levels.findIndex(l => !l.copy);
          if (fb >= 0 || any >= 0) { level = fb >= 0 ? fb : any; list = await this.list(level); }
        }
        const lvl = this.levels[level];
        let seg = list.segs.find(s => s.start + s.dur > end + 0.05);
        if (!seg) {
          if (list.ended || end >= list.total - 0.1) {
            if (this.ms.readyState === 'open' && end >= this.ms.duration - 0.5) { this.ms.endOfStream(); return; }
            await new Promise(r => setTimeout(r, 500)); continue;
          }
          // A copied stream not yet made this far is read again in a moment.
          await new Promise(r => setTimeout(r, 1000)); delete this.lists[level]; continue;
        }
        // The init of a stream just switched to is fetched beside its first segment, not before it.
        const t0 = performance.now();
        const want = [fetch(seg.url, { signal: this.ctl.signal })];
        if (this.inited !== level) want.push(fetch(list.init, { signal: this.ctl.signal }));
        const [res, ires] = await Promise.all(want);
        const t1 = performance.now();
        const data = await res.arrayBuffer();
        const bps = data.byteLength * 8 / Math.max(0.05, (performance.now() - t1) / 1000);
        if (ires) {
          if (this.sb.changeType) this.sb.changeType('video/mp4; codecs="' + lvl.codecs + '"');
          await this.append(await ires.arrayBuffer());
          this.inited = level;
        }
        await this.append(data);
        // Up when the next stream fits the measured rate twice over and answers at once; down when this one does not
        // fit it, or the server takes more than half a segment to answer, as it does when it cannot keep up.
        if (!this.fixed && level === this.level) {
          const ttfb = (t1 - t0) / 1000;
          const up = this.levels[level + 1];
          if (up && bps > up.bw * 2 && ttfb < seg.dur / 4) this.level = level + 1;
          else if (level > 0 && (bps < lvl.bw * 1.1 || ttfb > seg.dur / 2)) this.level = level - 1;
        }
        const t = this.v.currentTime;
        if (t > 90 && !this.sb.updating) { this.sb.remove(0, t - 60); await new Promise(r => this.sb.addEventListener('updateend', r, { once: true })); }
      } catch (e) {
        if (e.name !== 'AbortError') await new Promise(r => setTimeout(r, 1000));
      }
    }
  }
}

function dialog(title, ...kids) {
  const d = el('div', { class: 'dlg' });
  const close = () => { d.remove(); document.removeEventListener('keydown', esc); d.querySelectorAll('video,audio').forEach(v => { v.pause(); v.removeAttribute('src'); v.load(); }); };
  const esc = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', esc);
  d.addEventListener('click', e => { if (e.target === d) close(); });
  const box = el('div', { class: 'box' }, el('div', { class: 'row' }, el('h3', { text: title, style: 'flex:1;margin:0' }), el('button', { text: '✕', onclick: close })), ...kids);
  d.append(box); document.body.append(d);
  return { d, box, close };
}

async function preview(it) {
  const k = kind(it.name, it.type);
  const view = el('div', { class: 'view' });
  const info = el('div', { class: 'row mut', text: human(it.size) + (it.mod ? ' · ' + new Date(it.mod).toLocaleString() : '') });
  const acts = el('div', { class: 'row' }, el('button', { text: 'Download', onclick: () => download(it) }), el('button', { text: 'Share', onclick: () => shareDlg(it) }));
  const dl = dialog(it.name, view, info, acts);
  try {
    if (k === 'image') {
      const r = await must(await api('GET', '/~dav/' + enc(it.segs)));
      view.append(el('img', { src: URL.createObjectURL(await r.blob()), alt: it.name }));
    } else if (k === 'video' || k === 'audio') {
      const id = await tempLink(it, 4 * 3600);
      const m = el(k === 'video' ? 'video' : 'audio', { controls: '', autoplay: '', playsinline: '' });
      if (k === 'audio') view.style.minHeight = '80px';
      view.append(m);
      const base = '/~share/' + id;
      let meta = null;
      try { const r = await fetch('/~media/info' + base); if (r.ok) meta = await r.json(); } catch (e) {}
      const MS = MsePlayer.source();
      const native = m.canPlayType('application/vnd.apple.mpegurl') !== '';
      const streams = meta && meta.video && (MS || native);
      const q = el('select', {}, el('option', { value: 'orig', text: 'Original file' }));
      if (streams) {
        q.append(el('option', { value: 'auto', text: 'Auto' }));
        if (meta.copy && (MS ? MS.isTypeSupported('video/mp4; codecs="' + meta.copy + '"') : native))
          q.append(el('option', { value: 'copy', text: 'Original quality (stream)' }));
        for (const h of meta.renditions) q.append(el('option', { value: String(h), text: h + 'p' }));
      }
      // Text subtitles as tracks, which the file itself and every stream show alike.
      if (meta) for (const s of meta.subtitles || [])
        m.append(el('track', { kind: 'subtitles', src: '/~media/sub-' + s.index + base + '/subs.vtt?v=' + meta.version,
                               srclang: (s.lang || 'und').slice(0, 3), label: s.title || s.lang || 'Track ' + s.index }));
      let player = null;
      const setSrc = async () => {
        const t = m.currentTime || 0;
        if (player) { player.stop(); player = null; }
        const v = q.value;
        if (v === 'orig') m.src = base;
        // The browser's own HLS only where it has no Media Source at all: Chrome's says it plays HLS and fails on some.
        else if (!MS) m.src = '/~media/' + (v === 'auto' ? 'hls' + base + '/master.m3u8' : (v === 'copy' ? 'hls-copy' : 'hls-' + v) + base + '/index.m3u8');
        else { player = new MsePlayer(m, '/~media/hls' + base + '/master.m3u8', v); if (!(await player.start(t))) { q.value = 'orig'; m.src = base; } return; }
        if (t) m.currentTime = t;
        m.play().catch(() => {});
      };
      q.onchange = setSrc;
      // The file itself where the browser plays it, which costs the server nothing; a stream where it does not.
      const direct = meta ? meta.mime && m.canPlayType(meta.mime) !== '' : m.canPlayType(it.type || 'video/mp4') !== '';
      q.value = direct || !streams ? 'orig' : 'auto';
      setSrc();
      acts.append(el('span', { class: 'mut', text: 'Quality' }), q);
      if (meta) acts.append(el('span', { class: 'mut', text: (meta.width ? meta.width + '×' + meta.height + ' ' : '') + (meta.video || '') + (meta.hdr ? ' HDR' : '') + ((meta.subtitles || []).length ? ' · subtitles' : '') }));
    } else if (k === 'text' && it.size < 1 << 20) {
      const r = await must(await api('GET', '/~dav/' + enc(it.segs)));
      view.style.background = 'none';
      view.append(el('pre', { text: await r.text(), style: 'width:100%' }));
    } else if (k === 'pdf') {
      const id = await tempLink(it, 3600);
      view.append(el('iframe', { src: '/~share/' + id, style: 'width:100%;height:75vh;border:0;background:#fff' }));
    } else {
      view.style.minHeight = '120px';
      view.append(el('div', { style: 'font-size:48px', text: icon(k) }));
    }
  } catch (e) { view.append(el('p', { class: 'err', text: e.message })); }
}

function shareDlg(it) {
  const exp = el('select', {}, ...[['0', 'Never'], ['3600', '1 hour'], ['86400', '1 day'], ['604800', '7 days'], ['2592000', '30 days']].map(([v, t]) => el('option', { value: v, text: t })));
  exp.value = '604800';
  const pw = el('input', { type: 'password', placeholder: 'none', autocomplete: 'new-password' });
  const max = el('input', { type: 'number', min: '0', placeholder: 'unlimited', style: 'width:8rem' });
  const up = el('input', { type: 'checkbox' });
  const out = el('div');
  const rows = [el('div', { class: 'row' }, el('label', { text: 'Expires' }), exp), el('div', { class: 'row' }, el('label', { text: 'Password' }), pw)];
  if (!it.dir) rows.push(el('div', { class: 'row' }, el('label', { text: 'Download limit' }), max));
  if (it.dir) rows.push(el('div', { class: 'row' }, el('label', { text: 'Others may upload' }), up));
  const make = async () => {
    const key = it.segs.slice(1).join('/') + (it.dir && it.segs.length > 1 ? '/' : '');
    const body = { bucket: it.segs[0], key, expires_in: +exp.value, password: pw.value, max_downloads: +max.value || 0, upload: up.checked };
    try {
      const r = await must(await api('POST', '/~share', { body: JSON.stringify(body) }));
      const j = await r.json();
      const url = location.origin + j.url;
      const inp = el('input', { value: url, readonly: '', style: 'flex:1' });
      out.textContent = '';
      out.append(el('div', { class: 'row' }, inp, el('button', { class: 'pri', text: 'Copy', onclick: () => { inp.select(); navigator.clipboard ? navigator.clipboard.writeText(url) : document.execCommand('copy'); } })));
    } catch (e) { out.textContent = e.message; }
  };
  dialog('Share ' + it.name, ...rows, el('div', { class: 'row' }, el('button', { class: 'pri', text: 'Create link', onclick: make })), out);
}

$('#bShares').onclick = async () => {
  const T = el('table');
  const dl = dialog('Links', T);
  const fill = async () => {
    T.textContent = '';
    T.append(el('tr', {}, el('th', { text: 'What' }), el('th', { text: 'Expires' }), el('th', { text: 'Downloads' }), el('th', {})));
    let ls;
    try { ls = await (await must(await api('GET', '/~share'))).json(); } catch (e) { T.append(el('tr', {}, el('td', { text: e.message }))); return; }
    ls = ls.filter(s => s.note !== 'player');
    if (!ls.length) T.append(el('tr', {}, el('td', { class: 'mut', text: 'No links yet.' })));
    for (const s of ls) {
      const url = location.origin + s.url;
      T.append(el('tr', {},
        el('td', { class: 'n' }, el('a', { href: url, target: '_blank', text: s.bucket + '/' + s.key }), el('span', { class: 'mut', text: (s.password ? ' · password' : '') + (s.upload ? ' · upload' : '') })),
        el('td', { class: 'mut', text: s.expires ? new Date(s.expires).toLocaleString() : 'never' }),
        el('td', { class: 'mut', text: s.downloads + (s.max_downloads ? ' / ' + s.max_downloads : '') }),
        el('td', { class: 'a' }, el('button', { text: 'Copy', onclick: () => navigator.clipboard && navigator.clipboard.writeText(url) }),
          el('button', { class: 'bad', text: 'Revoke', onclick: async () => { try { await must(await api('DELETE', '/~share/' + s.id)); fill(); } catch (e) { fail(e); } } }))));
    }
  };
  fill();
};

$('#bTrash').onclick = async () => {
  const T = el('table');
  dialog('Trash of ' + path.join('/'), el('p', { class: 'mut', text: 'Files deleted from a bucket that keeps versions. Restoring brings back the last version before the deletion.' }), T);
  const fill = async () => {
    T.textContent = '';
    let ls;
    try { ls = await (await must(await api('GET', '/~dav/' + enc(path) + '/?trash'))).json(); } catch (e) { T.append(el('tr', {}, el('td', { text: e.message }))); return; }
    if (!ls.length) T.append(el('tr', {}, el('td', { class: 'mut', text: 'Nothing here. A bucket keeps deleted files only with versioning on.' })));
    for (const f of ls) {
      T.append(el('tr', {}, el('td', { class: 'n', text: f.key }), el('td', { class: 'mut', text: human(f.size) }), el('td', { class: 'mut', text: new Date(f.deleted).toLocaleString() }),
        el('td', { class: 'a' }, el('button', { text: 'Restore', onclick: async () => { try { await must(await api('POST', '/~dav/' + enc([path[0], ...f.key.split('/')]) + '?restore')); fill(); load(); } catch (e) { fail(e); } } }))));
    }
  };
  fill();
};

// Uploads, one at a time, with their progress; a dropped folder brings its own subfolders.
const queue = []; let uploading = false;
function enqueue(file, rel) { queue.push({ file, segs: [...path, ...rel.split('/').filter(Boolean)] }); if (!uploading) next(); }
function next() {
  const job = queue.shift();
  if (!job) { uploading = false; $('#bar').style.display = 'none'; load(); return; }
  uploading = true;
  $('#bar').style.display = 'block';
  $('#barT').textContent = job.segs[job.segs.length - 1] + (queue.length ? ' (+' + queue.length + ' more)' : '');
  const x = new XMLHttpRequest();
  x.open('PUT', '/~dav/' + enc(job.segs));
  x.setRequestHeader('Authorization', auth);
  x.setRequestHeader('X-Socketley-UI', '1');
  if (job.file.type) x.setRequestHeader('Content-Type', job.file.type);
  x.upload.onprogress = e => { if (e.lengthComputable) $('#barP').value = e.loaded / e.total; };
  x.onloadend = () => { if (x.status >= 300) alert('Upload of ' + job.file.name + ' failed: ' + x.status + ' ' + (x.responseText || '').trim()); $('#barP').value = 0; next(); };
  x.send(job.file);
}
$('#bUp').onclick = () => $('#fi').click();
$('#fi').onchange = () => { for (const f of $('#fi').files) enqueue(f, f.name); $('#fi').value = ''; };
async function walkEntry(entry, prefix) {
  if (entry.isFile) { await new Promise(res => entry.file(f => { enqueue(f, prefix + f.name); res(); }, res)); return; }
  if (entry.isDirectory) {
    const rd = entry.createReader();
    for (;;) {
      const batch = await new Promise(res => rd.readEntries(res, () => res([])));
      if (!batch.length) break;
      for (const e of batch) await walkEntry(e, prefix + entry.name + '/');
    }
  }
}
let dragDepth = 0;
window.addEventListener('dragenter', e => { if (path.length && e.dataTransfer.types.includes('Files')) { dragDepth++; $('#drop').style.display = 'flex'; } });
window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#drop').style.display = 'none'; } });
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', async e => {
  e.preventDefault(); dragDepth = 0; $('#drop').style.display = 'none';
  if (!path.length) return;
  const items = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (items.length) { for (const it of items) await walkEntry(it, ''); } else for (const f of e.dataTransfer.files) enqueue(f, f.name);
});

function start() { $('#login').hidden = true; $('#app').hidden = false; fromHash(); load(); }
if (auth) start(); else signOut();
</script>
</body>
</html>
)HTML";
