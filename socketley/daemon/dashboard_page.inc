// The daemon's dashboard, whole: markup, its own style and script. The storage interface's stylesheet and helpers go
// in at /*STYLE*/ and /*KIT*/ (dashboard.cpp), so the two look and behave as one.
constexpr std::string_view dashboard_page = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#07080c">
<title>socketley · daemon</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x2='1' y2='1'%3E%3Cstop stop-color='%238b5cf6'/%3E%3Cstop offset='1' stop-color='%2306b6d4'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='24' height='24' rx='6' fill='url(%23g)'/%3E%3Cpath d='M9 7v10l8-5z' fill='white'/%3E%3C/svg%3E">
<style>
/*STYLE*/
/* ── the dashboard's own ── */
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;margin:6px 0 26px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px 16px 12px;position:relative;overflow:hidden}
.tile .k{font-size:12px;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.tile .v{font-size:26px;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.tile .s{font-size:12.5px;color:var(--mut);margin-top:2px;font-variant-numeric:tabular-nums}
.tile svg.spark{display:block;width:100%;height:42px;margin-top:8px}
.tile svg.spark path.l{fill:none;stroke:var(--a1);stroke-width:1.8}
.tile svg.spark path.f{fill:url(#sg);stroke:none;opacity:.35}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}
.dot.running{background:var(--ok);box-shadow:0 0 10px var(--ok)}.dot.stopped,.dot.created{background:var(--dim)}.dot.failed{background:var(--bad);box-shadow:0 0 10px var(--bad)}
.rt{width:100%;border-collapse:separate;border-spacing:0 8px}
.rt td{background:var(--panel);padding:12px 12px;font-size:13.5px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.rt td:first-child{border-left:1px solid var(--line);border-radius:12px 0 0 12px}.rt td:last-child{border-right:1px solid var(--line);border-radius:0 12px 12px 0;white-space:nowrap;text-align:right}
.rt tr{cursor:pointer}.rt tr:hover td{background:var(--hov)}
.rt th{font-size:11.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;font-weight:600;text-align:left;padding:0 12px}
.rt .nm{font-weight:600}.rt .ty{font-size:12px;color:var(--mut)}
.num{font-variant-numeric:tabular-nums}
.types{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.ty-card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px;cursor:pointer;text-align:left;color:inherit;font:inherit;transition:border-color .15s,transform .15s}
.ty-card:hover{border-color:rgba(var(--glow),.6);transform:translateY(-2px)}
.ty-card b{display:flex;align-items:center;gap:8px;font-size:15px}.ty-card p{margin:6px 0 0;font-size:12.5px;color:var(--mut)}
.form{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px 14px}
.fld2{display:flex;flex-direction:column;gap:5px;font-size:12.5px}
.fld2>span{color:var(--mut);display:flex;gap:6px;align-items:center}
.fld2 .h{font-size:11.5px;color:var(--dim);line-height:1.35}
.fsec{margin:18px 0 8px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.fsec::after{content:"";flex:1;border-top:1px solid var(--line)}
.sw{position:relative;width:38px;height:22px;flex:none}.sw input{opacity:0;width:0;height:0}
.sw i{position:absolute;inset:0;border-radius:11px;background:rgba(255,255,255,.12);transition:background .15s;cursor:pointer}
.sw i::after{content:"";position:absolute;left:3px;top:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .15s}
.sw input:checked+i{background:var(--grad)}.sw input:checked+i::after{transform:translateX(16px)}
.swrow{display:flex;align-items:center;gap:10px;min-height:38px}
.cmd{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:10px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;color:var(--mut)}
.kv{display:grid;grid-template-columns:minmax(150px,max-content) 1fr;gap:6px 18px;font-size:13px}
.kv .k{color:var(--mut)}.kv .v{font-family:var(--mono);word-break:break-all}
pre.out{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:10px;padding:12px;white-space:pre-wrap;max-height:340px;overflow:auto;margin:0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;margin-bottom:18px}
.panel h3{margin:0 0 12px;font-size:14px;display:flex;align-items:center;gap:8px}
.acts{display:flex;gap:8px;flex-wrap:wrap}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 6px}
.filters button{border:1px solid var(--line);background:transparent;color:var(--mut);border-radius:20px;padding:5px 12px;font:inherit;font-size:12.5px;cursor:pointer}
.filters button.on{background:var(--grad);color:var(--on);border-color:transparent}
textarea.inp{height:auto;min-height:260px;padding:12px;font-family:var(--mono);font-size:12.5px;line-height:1.5;width:100%;resize:vertical}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute"><defs><linearGradient id="sg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--a1)"/><stop offset="1" stop-color="var(--a1)" stop-opacity="0"/></linearGradient></defs></svg>
<div id="aurora"><i></i><i></i><i></i></div>
<div id="login" hidden>
  <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
  <form class="lcard" id="lf">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>socketley</div>
    <h1>Daemon</h1>
    <p class="mut" id="lsub">Sign in with an admin's access key.</p>
    <label for="lk">Access key</label><input class="inp" id="lk" autocomplete="username" required spellcheck="false">
    <label for="ls">Secret</label><input class="inp" id="ls" type="password" autocomplete="current-password" required>
    <div class="err" id="le"></div>
    <button class="btn pri">Sign in</button>
  </form>
</div>
<div id="app" hidden>
  <aside id="side">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>socketley</div>
    <button class="nav" id="nOver"></button>
    <button class="nav" id="nRts"></button>
    <button class="nav" id="nNew"></button>
    <div class="sh">Runtimes</div>
    <div id="rlist"></div>
    <div class="themes" id="themes"></div>
    <button class="nav" id="nOut"></button>
  </aside>
  <div id="main">
    <div id="top">
      <button class="ib" id="menuB"></button>
      <nav class="crumbs" id="crumbs"></nav>
      <div class="search" id="srch"><input class="inp" id="q" placeholder="Filter runtimes" spellcheck="false"></div>
      <button class="btn pri" id="bNew"></button>
    </div>
    <div id="scroll"><div id="content"></div></div>
  </div>
</div>
<div id="toasts"></div>
<script>
'use strict';
/*KIT*/
// ─── the dashboard ──────────────────────────────────────────────────────────
Object.assign(P, {
  pulse: '<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',
  server: '<rect x="3.5" y="4" width="17" height="6.5" rx="1.8"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.8"/><path d="M7 7.2h.01M7 16.8h.01"/>',
  client: '<path d="M4 17V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10"/><path d="M2 19h20"/>',
  proxy: '<circle cx="5" cy="12" r="2.2"/><circle cx="19" cy="6" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M7.2 12h4M11.2 12l5.8-5.2M11.2 12l5.8 5.2"/>',
  cache: '<path d="M13 3 4 14h7l-1 7 9-11h-7z"/>',
  storage: '<ellipse cx="12" cy="5.5" rx="8" ry="2.8"/><path d="M4 5.5v13c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8v-13M4 12c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8"/>',
  dns: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.6 5.4 3.6 8.5s-1.1 5.9-3.6 8.5c-2.5-2.6-3.6-5.4-3.6-8.5S9.5 6.1 12 3.5z"/>',
  play: '<path d="M7 5.5v13l11-6.5z"/>', stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  restart: '<path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/>', edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
  gauge: '<path d="M12 14l4-4"/><path d="M4.5 18a9 9 0 1 1 15 0"/>', cpu: '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>'
});
const TYPES = {
  server: ['server', 'Server', 'TCP, UDP or WebSocket: messages, static files, scripts.'],
  client: ['client', 'Client', 'Connects to a server and relays what it hears.'],
  proxy: ['proxy', 'Proxy', 'HTTP or TCP to backends, the entrance, auth and redirects.'],
  cache: ['cache', 'Cache', 'A key-value store that speaks Redis, persistent and sharded.'],
  storage: ['storage', 'Storage', 'S3-compatible object storage with this interface.'],
  dns: ['dns', 'DNS', 'An authoritative name server, with an entrance on 443.']
};
// The configuration key `show` and `import` name each flag by.
const KEY = { '-p': 'port', '-g': 'group', '--lua': 'lua_script', '--bind': 'bind', '--listen': 'listen', '--shards': 'shards', '--domain': 'domain', '--cpus': 'cpus',
  '--tls': 'tls', '--cert': 'cert_path', '--key': 'key_path', '--ca': 'ca_path', '--acme': 'acme_domains', '--acme-email': 'acme_email', '--max-connections': 'max_connections',
  '--rate-limit': 'rate_limit', '--global-rate-limit': 'global_rate_limit', '--idle-timeout': 'idle_timeout', '--read-buffer': 'read_buffer', '--write-buffer': 'write_buffer',
  '--drain': 'drain', '--reconnect': 'reconnect', '--log': 'log_file', '-w': 'write_file', '-b': 'bash_output', '-bp': 'bash_prefix', '-bt': 'bash_timestamp',
  '--send-to': 'send_to', '--udp': 'udp', '--http': 'http_dir', '--http-cache': 'http_cache', '--master-pw': 'master_pw', '--cache': 'cache_name', '-u': 'upstreams', '-t': 'target',
  '--backend': 'backends', '--protocol': 'protocol', '--strategy': 'strategy', '--auth': 'auth', '--redirect-https': 'redirect_https', '--backend-timeout': 'backend_timeout',
  '--retry': 'retry_count', '--retry-all': 'retry_all', '--health-check': 'health_check', '--health-interval': 'health_interval', '--health-path': 'health_path',
  '--health-threshold': 'health_threshold', '--circuit-threshold': 'circuit_threshold', '--circuit-timeout': 'circuit_timeout', '--client-ca': 'mesh_client_ca',
  '--client-cert': 'mesh_client_cert', '--client-key': 'mesh_client_key', '--persistent': 'persistent_path', '--persistent-interval': 'persistent_interval', '--maxmemory': 'max_memory',
  '--eviction': 'eviction', '--resp': 'resp_forced', '--replicate': 'replicate_target', '--public': 'public', '--cluster': 'cluster', '--dir': 'dir', '--credentials': 'credentials',
  '--access-key': 'access_key', '--secret-key': 'secret_key', '--anonymous': 'anonymous', '--website-domain': 'website_domain', '--tls-offloaded': 'tls_offloaded',
  '--max-bytes': 'max_bytes', '--fsync': 'fsync', '--fsync-interval': 'fsync_interval', '--scrub': 'scrub', '--compress': 'compress', '--mpu-expire': 'mpu_expire',
  '--sse-key-file': 'sse_key_file', '--acls': 'acls', '--notify-targets': 'notify_targets', '--replication-targets': 'replication_targets', '--tiers': 'tiers',
  '--federation': 'federation', '--nodes': 'nodes', '--zone': 'zones', '--publish': 'publish', '--proxy': 'proxy', '--transfer': 'transfer', '--notify': 'notify', '--rrl': 'rrl' };
const confKey = (f, type) => f.flag === '--mode' ? (type === 'cache' ? 'cache_mode' : 'mode') : KEY[f.flag];
const ARRAYS = new Set(['backends', 'upstreams']);
const HEALTH = ['', 'tcp', 'http'];
// Durations as the flags take them and seconds as the configuration keeps them; sizes alike in bytes.
const toSec = v => { const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i.exec(String(v).trim()); if (!m) return null; const n = +m[1], u = (m[2] || 's').toLowerCase(); return Math.round(n * { ms: .001, s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[u]); };
const fromSec = s => { s = +s; if (!s) return '0'; for (const [u, n] of [['w', 604800], ['d', 86400], ['h', 3600], ['m', 60]]) if (s % n === 0) return s / n + u; return s + 's'; };
const toBytes = v => { const m = /^(\d+(?:\.\d+)?)\s*([kmgt])?b?$/i.exec(String(v).trim()); if (!m) return null; return Math.round(+m[1] * Math.pow(1024, ' kmgt'.indexOf((m[2] || ' ').toLowerCase()))); };
const fromBytes = b => { b = +b; for (const [u, n] of [['T', 2 ** 40], ['G', 2 ** 30], ['M', 2 ** 20], ['K', 1024]]) if (b >= n && b % n === 0) return b / n + u; return String(b); };
const rate = n => human(n).replace(' ', ' ') + '/s';
const count = n => { n = +n || 0; return n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(0) + 'k' : String(Math.round(n)); };
const ago = s => { s = Math.floor(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + 'd ' + h + 'h' : h ? h + 'h ' + m + 'm' : m + 'm ' + (s % 60) + 's'; };

let me = null, schema = null, view = { at: 'over' }, rts = [], meta = {}, over = null, timer = 0, filterType = '';
const hist = { msg: [], conn: [], bin: [], bout: [], cpu: [] };
const prev = { t: 0, msg: 0, bin: 0, bout: 0, cpu: 0, per: {} };

async function api(method, url, body) {
  const r = await fetch(url, { method, headers: { 'X-Socketley-Dashboard': '1', 'Content-Type': 'application/json' }, body: body == null ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  if (r.status === 401) { signedOut(); throw new Error('Your session ended: sign in again'); }
  return r;
}
async function must(r) { if (!r.ok) { let t = ''; try { t = (await r.text()).trim(); } catch (e) {} throw new Error(t.slice(0, 300) || r.status + ' ' + r.statusText); } return r; }
// One CLI command through the daemon, its output and exit status.
async function run(...args) {
  const r = await (await must(await api('POST', '/api/run', { args }))).json();
  return r;
}
async function act(args, ok) {
  try {
    const r = await run(...args);
    if (r.code) { toast((r.out || 'Failed').trim().split('\n').slice(0, 3).join(' '), 'bad', 7000); return false; }
    if (ok) toast(ok);
    return true;
  } catch (e) { fail(e); return false; }
}

// ─── signing in ─────────────────────────────────────────────────────────────
function signedOut() { me = null; clearTimeout(timer); $('#app').hidden = true; $('#login').hidden = false; while (layers.length) layers[layers.length - 1].close(); }
async function signOut() { try { await fetch('/api/session', { method: 'DELETE' }); } catch (e) {} signedOut(); }
$('#lf').addEventListener('submit', async ev => {
  ev.preventDefault();
  const basic = 'Basic ' + btoa(unescape(encodeURIComponent($('#lk').value.trim() + ':' + $('#ls').value)));
  let r;
  try { r = await fetch('/api/session', { method: 'POST', headers: { 'Authorization': basic, 'X-Socketley-Dashboard': '1' } }); }
  catch (e) { $('#le').textContent = 'The daemon cannot be reached.'; return; }
  if (r.status === 401) { $('#le').textContent = 'That is no admin’s access key and secret.'; return; }
  if (r.status === 429) { $('#le').textContent = 'Too many failed sign-ins from here; try again in ' + Math.ceil((+r.headers.get('Retry-After') || 900) / 60) + ' min.'; return; }
  if (!r.ok) { $('#le').textContent = (await r.text()).trim() || 'Signing in failed: ' + r.status; return; }
  me = await r.json(); $('#ls').value = ''; $('#le').textContent = '';
  start();
});

// ─── navigation ─────────────────────────────────────────────────────────────
function go(h) { location.hash = h; }
function route() {
  const h = location.hash.replace(/^#\/?/, '');
  if (h.startsWith('runtime/')) view = { at: 'rt', name: decodeURIComponent(h.slice(8)) };
  else if (h === 'runtimes') view = { at: 'rts' };
  else if (h.startsWith('new')) view = { at: 'new', type: decodeURIComponent(h.slice(4)) || '' };
  else view = { at: 'over' };
  while (layers.length) layers[layers.length - 1].close();
  $('#side').classList.remove('open');
  render(true);
}
window.addEventListener('hashchange', () => { if (me) route(); });

function side() {
  const nav = (b, icon, label, on, fn) => { b.textContent = ''; b.append(ico(icon), el('span', { text: label })); b.classList.toggle('on', on); b.onclick = fn; };
  nav($('#nOver'), 'pulse', 'Overview', view.at === 'over', () => go('#/'));
  nav($('#nRts'), 'server', 'Runtimes', view.at === 'rts', () => go('#/runtimes'));
  nav($('#nNew'), 'plus', 'New runtime', view.at === 'new', () => go('#/new'));
  nav($('#nOut'), 'out', me && me.user ? 'Sign out · ' + me.user : 'Sign out', false, signOut);
  $('#nNew').hidden = !(me && me.user);
  paintThemes();
  const L = $('#rlist'); L.textContent = '';
  for (const r of rts.slice().sort((a, b) => a.name.localeCompare(b.name)))
    L.append(el('button', { class: 'nav' + (view.at === 'rt' && view.name === r.name ? ' on' : ''), onclick: () => go('#/runtime/' + encodeURIComponent(r.name)) },
      el('span', { class: 'dot ' + r.state }), el('span', { text: r.name, title: r.name + ' · ' + r.type })));
  if (!rts.length) L.append(el('div', { class: 'dim', style: 'padding:6px 12px;font-size:13px', text: 'No runtimes yet' }));
}
function crumbs(parts) {
  const c = $('#crumbs'); c.textContent = '';
  c.append(el('button', { text: 'Daemon', onclick: () => go('#/') }));
  for (const [t, h] of parts) c.append(ico('chev'), el('button', { text: t, onclick: () => h && go(h) }));
  const b = $('#bNew'); b.textContent = ''; b.append(ico('plus'), el('span', { text: 'New runtime' })); b.onclick = () => go('#/new'); b.hidden = !(me && me.user);
  $('#srch').hidden = view.at !== 'rts';
}

// ─── figures ────────────────────────────────────────────────────────────────
async function poll() {
  clearTimeout(timer);
  try {
    const [o, r] = await Promise.all([api('GET', '/api/overview').then(must).then(x => x.json()), api('GET', '/api/runtimes').then(must).then(x => x.json())]);
    const now = Date.now() / 1000, dt = prev.t ? now - prev.t : 0;
    if (dt > 0) {
      const push = (k, v) => { hist[k].push(Math.max(0, v)); if (hist[k].length > 90) hist[k].shift(); };
      push('msg', (o.messages_total - prev.msg) / dt); push('bin', (o.bytes_in - prev.bin) / dt); push('bout', (o.bytes_out - prev.bout) / dt);
      push('cpu', 100 * (o.cpu_seconds - prev.cpu) / dt / (o.cpus || 1)); push('conn', o.connections_active);
      for (const x of r) { const p = prev.per[x.name]; x.msg_s = p ? Math.max(0, (x.messages_total - p.m) / dt) : 0; x.in_s = p ? Math.max(0, (x.bytes_in - p.i) / dt) : 0; x.out_s = p ? Math.max(0, (x.bytes_out - p.o) / dt) : 0; x.cpu_p = p ? Math.max(0, 100 * (x.cpu_seconds - p.c) / dt) : 0; }
    }
    prev.t = now; prev.msg = o.messages_total; prev.bin = o.bytes_in; prev.bout = o.bytes_out; prev.cpu = o.cpu_seconds;
    prev.per = Object.fromEntries(r.map(x => [x.name, { m: x.messages_total, i: x.bytes_in, o: x.bytes_out, c: x.cpu_seconds }]));
    over = o; rts = r;
    render(false);
  } catch (e) { if (me) toast(e.message, 'bad'); }
  if (me) timer = setTimeout(poll, 2000);
}
// The owners, groups and ages `ls` knows, which the figures do not carry.
async function loadMeta() {
  try { const r = await run('ls', '--json'); if (!r.code) for (const x of JSON.parse(r.out)) meta[x.name] = x; } catch (e) {}
}
function spark(vals) {
  const s = document.createElementNS(SVGNS, 'svg'); s.setAttribute('class', 'spark'); s.setAttribute('viewBox', '0 0 100 30'); s.setAttribute('preserveAspectRatio', 'none');
  if (vals.length < 2) return s;
  const top = Math.max(...vals) || 1, n = vals.length;
  const pts = vals.map((v, i) => [(i / (n - 1)) * 100, 28 - (v / top) * 26]);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(2) + ' ' + p[1].toFixed(2)).join('');
  s.innerHTML = '<path class="f" d="' + d + 'L100 30L0 30Z"/><path class="l" d="' + d + '"/>';
  return s;
}
function tile(icon, k, v, s, vals) {
  return el('div', { class: 'tile' }, el('div', { class: 'k' }, ico(icon), el('span', { text: k })), el('div', { class: 'v', text: v }), s ? el('div', { class: 's', text: s }) : null, vals ? spark(vals) : null);
}
const last = a => a.length ? a[a.length - 1] : 0;

// ─── views ──────────────────────────────────────────────────────────────────
function render(full) {
  side();
  if (view.at === 'over') return overview();
  if (view.at === 'rts') return runtimes();
  if (view.at === 'rt') return detail(full);
  if (view.at === 'new' && full) return create();
}
function overview() {
  crumbs([]);
  const C = $('#content'); C.textContent = '';
  if (!over) { C.append(el('div', { class: 'spin' })); return; }
  const running = rts.filter(r => r.state === 'running').length, failed = rts.filter(r => r.state === 'failed').length;
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('pulse')), el('span', { text: 'Daemon' }), el('span', { class: 'n', text: 'v' + over.version + ' · up ' + ago(over.uptime_seconds) }))),
    el('div', { class: 'tiles' },
      tile('server', 'Runtimes', running + ' / ' + over.runtimes_total, failed ? failed + ' failed' : running === over.runtimes_total ? 'all running' : (over.runtimes_total - running) + ' stopped'),
      tile('users', 'Connections', count(over.connections_active), count(over.connections_total) + ' since start', hist.conn),
      tile('send', 'Messages', count(last(hist.msg)) + '/s', count(over.messages_total) + ' since start', hist.msg),
      tile('download', 'In', rate(last(hist.bin)), human(over.bytes_in) + ' since start', hist.bin),
      tile('upload', 'Out', rate(last(hist.bout)), human(over.bytes_out) + ' since start', hist.bout),
      tile('cpu', 'CPU', last(hist.cpu).toFixed(1) + ' %', over.cpus + ' CPUs · ' + over.processes + ' processes', hist.cpu),
      tile('gauge', 'Memory', human(over.rss_bytes), 'resident, daemon and workers')));
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('server')), el('span', { text: 'Runtimes' }), el('span', { class: 'n', text: String(rts.length) }))), table(rts));
}
function runtimes() {
  crumbs([['Runtimes', '#/runtimes']]);
  const C = $('#content'); C.textContent = '';
  const q = $('#q').value.trim().toLowerCase();
  const types = [...new Set(rts.map(r => r.type))].sort();
  C.append(el('div', { class: 'filters' }, el('button', { class: filterType ? '' : 'on', text: 'All', onclick: () => { filterType = ''; runtimes(); } }),
    ...types.map(t => el('button', { class: filterType === t ? 'on' : '', text: (TYPES[t] || [t, t])[1], onclick: () => { filterType = t; runtimes(); } }))));
  C.append(table(rts.filter(r => (!filterType || r.type === filterType) && (!q || r.name.toLowerCase().includes(q) || r.type.includes(q)))));
}
$('#q').addEventListener('input', () => runtimes());
function controls(r, small) {
  const n = r.name, cls = small ? 'sm' : '';
  const on = r.state === 'running';
  const b = [];
  if (!me || !me.user) return b;
  if (on) b.push(btn('stop', 'Stop', async e => { e && e.stopPropagation(); if (await act(['stop', n], n + ' stopped')) poll(); }, cls),
    btn('restart', 'Restart', async e => { e && e.stopPropagation(); if (await act(['stop', n]) && await act(['start', n], n + ' restarted')) poll(); }, cls));
  else b.push(btn('play', 'Start', async e => { e && e.stopPropagation(); if (await act(['start', n], n + ' started')) poll(); }, cls + ' pri'));
  if (!small) b.push(btn('restart', 'Reload Lua', async () => { await act(['reload-lua', n], 'Lua of ' + n + ' reloaded'); }, cls),
    btn('edit', 'Edit', () => editDlg(r), cls),
    btn('trash', 'Remove', async () => {
      if (!await ask({ title: 'Remove ' + n + '?', text: 'It stops and is gone, with its configuration. Its data (a storage directory, a cache file) stays where it is.', ok: 'Remove', danger: true })) return;
      if (await act(['remove', n], n + ' removed')) { delete meta[n]; go('#/runtimes'); poll(); }
    }, cls + ' bad'));
  return b;
}
function table(list) {
  if (!list.length) return el('div', { class: 'empty' }, el('div', { class: 'big' }, ico('server')), el('h3', { text: 'No runtimes here' }), el('div', { text: 'Make one with New runtime.' }));
  const T = el('table', { class: 'rt' });
  T.append(el('tr', {}, ...['', 'Runtime', 'Port', 'Connections', 'Messages', 'In / out', 'CPU', ''].map(t => el('th', { text: t }))));
  for (const r of list.slice().sort((a, b) => (a.state !== 'running') - (b.state !== 'running') || a.name.localeCompare(b.name))) {
    const m = meta[r.name] || {};
    T.append(el('tr', { onclick: () => go('#/runtime/' + encodeURIComponent(r.name)) },
      el('td', { style: 'width:28px' }, el('span', { class: 'dot ' + r.state, title: r.state })),
      el('td', {}, el('div', { class: 'nm', text: r.name }), el('div', { class: 'ty', text: (TYPES[r.type] || [r.type, r.type])[1] + (m.group ? ' · @' + m.group : '') + (m.owner && m.owner !== '-' ? ' · of ' + m.owner : '') + (r.state !== 'running' ? ' · ' + r.state : '') })),
      el('td', { class: 'num', text: r.port ? String(r.port) : '—' }),
      el('td', { class: 'num', text: count(r.connections) }),
      el('td', { class: 'num', text: count(r.msg_s || 0) + '/s' }),
      el('td', { class: 'num', text: rate(r.in_s || 0) + ' · ' + rate(r.out_s || 0) }),
      el('td', { class: 'num', text: (r.cpu_p || 0).toFixed(1) + ' %' }),
      el('td', {}, el('div', { class: 'acts', style: 'justify-content:flex-end' }, ...controls(r, true)))));
  }
  return T;
}

// ─── one runtime ────────────────────────────────────────────────────────────
let shown = null;
async function detail(full) {
  const r = rts.find(x => x.name === view.name);
  crumbs([['Runtimes', '#/runtimes'], [view.name, null]]);
  const C = $('#content');
  if (!r) { if (full) { C.textContent = ''; C.append(el('p', { class: 'mut', text: 'No runtime ' + view.name + '.' })); } return; }
  if (full || !shown || shown.name !== r.name) {
    shown = { name: r.name, conf: null, stats: '' };
    C.textContent = '';
    C.append(el('div', { id: 'dHead' }), el('div', { class: 'tiles', id: 'dTiles' }),
      el('div', { class: 'panel' }, el('h3', {}, ico('edit'), el('span', { text: 'Configuration' })), el('div', { id: 'dConf', class: 'kv' })),
      el('div', { class: 'panel' }, el('h3', {}, ico('info'), el('span', { text: 'Stats' })), el('div', { class: 'kv', id: 'dStats' })));
    if (me && me.user) {
      run('show', r.name).then(x => { if (!x.code) { try { shown.conf = JSON.parse(x.out); } catch (e) {} paintConf(); } });
      statsText(r.name);
    }
  }
  const t = TYPES[r.type] || [r.type, r.type];
  const H = $('#dHead'); H.textContent = '';
  H.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico(t[0])), el('span', { text: r.name }), el('span', { class: 'n' }, el('span', { class: 'dot ' + r.state }), ' ' + r.state + ' · ' + t[1] + (r.port ? ' · port ' + r.port : '')))),
    el('div', { class: 'acts', style: 'margin:-4px 0 18px' }, ...controls(r, false)));
  const D = $('#dTiles'); D.textContent = '';
  D.append(tile('users', 'Connections', count(r.connections), count(r.connections_total) + ' since start'),
    tile('send', 'Messages', count(r.msg_s || 0) + '/s', count(r.messages_total) + ' since start'),
    tile('download', 'In', rate(r.in_s || 0), human(r.bytes_in) + ' since start'),
    tile('upload', 'Out', rate(r.out_s || 0), human(r.bytes_out) + ' since start'),
    tile('cpu', 'CPU', (r.cpu_p || 0).toFixed(1) + ' %', r.processes + ' process' + (r.processes === 1 ? '' : 'es')),
    tile('gauge', 'Memory', human(r.rss_bytes), 'resident'));
  if (!full && shown.stamp && Date.now() - shown.stamp > 5000) statsText(r.name);
}
async function statsText(name) {
  shown.stamp = Date.now();
  try {
    const x = await run('stats', name); const S = $('#dStats');
    if (!S || !shown || shown.name !== name) return;
    S.textContent = '';
    // `key:value` lines, the name and type left out as the head says them.
    for (const line of (x.out || '').split('\n')) {
      const c = line.indexOf(':'); if (c < 1) continue;
      const k = line.slice(0, c), v = line.slice(c + 1);
      if (k === 'name' || k === 'type') continue;
      S.append(el('div', { class: 'k', text: k.replace(/_/g, ' ') }), el('div', { class: 'v', text: /^\d{4,}$/.test(v) && /bytes/.test(k) ? human(+v) + ' (' + v + ')' : v }));
    }
  } catch (e) {}
}
function paintConf() {
  const K = $('#dConf'); if (!K || !shown.conf) return; K.textContent = '';
  const skip = new Set(['name', 'id', 'type', 'was_running']);
  for (const [k, v] of Object.entries(shown.conf)) {
    if (skip.has(k)) continue;
    K.append(el('div', { class: 'k', text: label(k) }), el('div', { class: 'v', text: Array.isArray(v) ? v.join(', ') : String(v) }));
  }
}
// A key's label: the flag's own where the schema has it.
function label(k) {
  if (schema) for (const f of schema.flags) if (KEY[f.flag] === k || (f.flag === '--mode' && (k === 'mode' || k === 'cache_mode'))) return f.label;
  return k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
}

// ─── editing ────────────────────────────────────────────────────────────────
// The runtime's settings as the form of its type shows them, filled with what `show` says; a save imports what changed.
async function editDlg(r) {
  let conf;
  try { const x = await run('show', r.name); if (x.code) throw new Error(x.out); conf = JSON.parse(x.out); } catch (e) { fail(e); return; }
  const fields = form(r.type, conf, true);
  const raw = el('textarea', { class: 'inp', spellcheck: 'false' }); raw.value = JSON.stringify(conf, null, 2);
  const rawBox = el('div', { hidden: true }, el('p', { class: 'mut', style: 'font-size:12.5px', text: 'The whole configuration as import takes it. What a running runtime cannot change while it runs is refused: stop it first.' }), raw);
  let rawOn = false;
  const toggle = btn(null, 'JSON', () => { rawOn = !rawOn; rawBox.hidden = !rawOn; fields.box.hidden = rawOn; toggle.querySelector('span').textContent = rawOn ? 'Form' : 'JSON'; }, '');
  const save = async () => {
    let doc;
    if (rawOn) { try { doc = JSON.parse(raw.value); } catch (e) { toast('That is no JSON: ' + e.message, 'bad'); return; } }
    else { doc = fields.changes(); if (!Object.keys(doc).length) { L.close(); return; } }
    if (await act(['import', r.name, JSON.stringify(doc)], r.name + ' saved')) { L.close(); poll(); if (view.at === 'rt') detail(true); }
  };
  const L = modal('Edit ' + r.name, [el('p', { class: 'mut', style: 'font-size:12.5px;margin-top:0', text: 'Only what you change is sent. Some settings take effect at the next start.' }), fields.box, rawBox], [toggle, el('span', { style: 'flex:1' }), btn(null, 'Cancel', () => L.close()), btn(null, 'Save', save, 'pri')], true);
}

// The fields of `type`, sectioned as the schema says; `conf` fills them for an edit.
function form(type, conf, editing) {
  const box = el('div');
  const vals = new Map();
  const sections = new Map();
  for (const f of schema.flags) {
    if (f.hidden || !f.types.includes(type)) continue;
    if (editing && (!confKey(f, type) || f.flag === '-s')) continue;
    if (!sections.has(f.section)) sections.set(f.section, []);
    sections.get(f.section).push(f);
  }
  const OPEN = new Set(['Basics', 'Network', TYPES[type] ? TYPES[type][1] : '', 'Server', 'Client', 'Proxy', 'Cache', 'Storage', 'DNS']);
  // Basics first, then what only this type has, then what every type has.
  const COMMON = ['Basics', 'Network', 'TLS', 'Limits', 'Output'];
  const order = [...sections.keys()].sort((a, b) => (a === 'Basics' ? -1 : b === 'Basics' ? 1 : COMMON.includes(a) - COMMON.includes(b)));
  for (const sec of order) {
    const fs = sections.get(sec);
    const grid = el('div', { class: 'form' });
    let open = OPEN.has(sec) || (editing && fs.some(f => conf && conf[confKey(f, type)] != null));
    const head = el('div', { class: 'fsec', onclick: () => { open = !open; grid.hidden = !open; head.firstChild.textContent = (open ? '▾ ' : '▸ ') + sec; } }, el('span', { text: (open ? '▾ ' : '▸ ') + sec }));
    grid.hidden = !open;
    for (const f of fs) {
      const key = confKey(f, type);
      let cur = conf && key ? conf[key] : undefined;
      if (f.flag === '--health-check' && typeof cur === 'number') cur = HEALTH[cur] || '';
      let input, get;
      if (f.kind === 'switch') {
        const c = el('input', { type: 'checkbox' }); c.checked = cur === true || (!editing && f.flag === '-s');
        input = el('div', { class: 'swrow' }, el('label', { class: 'sw' }, c, el('i')), el('span', { class: 'h', text: f.help }));
        get = () => c.checked;
      } else if (f.kind === 'choice') {
        const s = el('select', { class: 'inp' }, el('option', { value: '', text: '—' }), ...f.choices.split(',').map(c => el('option', { value: c, text: c })));
        s.value = cur == null ? '' : String(cur);
        input = s; get = () => s.value;
      } else {
        const i = el('input', { class: 'inp', placeholder: f.placeholder || '', spellcheck: 'false', autocomplete: 'off' });
        if (cur != null) i.value = Array.isArray(cur) ? cur.join(', ') : f.kind === 'duration' && typeof cur === 'number' ? fromSec(cur) : f.kind === 'size' && typeof cur === 'number' ? fromBytes(cur) : String(cur);
        if (f.kind === 'int') i.inputMode = 'numeric';
        input = i; get = () => i.value.trim();
      }
      const initial = get();
      vals.set(f, { get, initial, key });
      grid.append(el('label', { class: 'fld2', title: f.flag }, el('span', {}, el('b', { text: f.label, style: 'font-weight:600;color:var(--fg)' }), el('code', { class: 'dim', style: 'font-size:11px', text: f.flag })), input, f.kind !== 'switch' ? el('div', { class: 'h', text: f.help }) : null));
    }
    box.append(head, grid);
  }
  return {
    box,
    // The CLI words of what was filled in, for a create.
    words() {
      const w = [];
      for (const [f, v] of vals) {
        const x = v.get();
        if (f.kind === 'switch') { if (x) w.push(f.flag); continue; }
        if (x === '' || x == null) continue;
        w.push(f.flag, f.kind === 'list' ? x.split(/[\s,]+/).filter(Boolean).join(',') : x);
      }
      return w;
    },
    // The configuration keys changed, as import takes them, for an edit.
    changes() {
      const d = {};
      for (const [f, v] of vals) {
        const x = v.get();
        if (x === v.initial || !v.key) continue;
        if (f.kind === 'switch') d[v.key] = x;
        else if (x === '') d[v.key] = f.kind === 'int' || f.kind === 'duration' || f.kind === 'size' ? 0 : ARRAYS.has(v.key) ? [] : '';
        else if (f.kind === 'int') d[v.key] = +x;
        else if (f.kind === 'duration') d[v.key] = toSec(x) ?? x;
        else if (f.kind === 'size') d[v.key] = toBytes(x) ?? x;
        else if (f.flag === '--health-check') d[v.key] = HEALTH.indexOf(x);
        else if (f.kind === 'list') { const a = x.split(/[\s,]+/).filter(Boolean); d[v.key] = ARRAYS.has(v.key) ? a : a.join(','); }
        else d[v.key] = x;
      }
      return d;
    }
  };
}

// ─── creating ───────────────────────────────────────────────────────────────
function create() {
  crumbs([['New runtime', '#/new']].concat(view.type ? [[(TYPES[view.type] || [0, view.type])[1], null]] : []));
  const C = $('#content'); C.textContent = '';
  if (!me || !me.user) { C.append(el('p', { class: 'mut', text: 'Sign in to make runtimes.' })); return; }
  if (!TYPES[view.type]) {
    C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('plus')), el('span', { text: 'What should it be?' }))),
      el('div', { class: 'types' }, ...Object.entries(TYPES).map(([k, [i, n, d]]) => el('button', { class: 'ty-card', onclick: () => go('#/new/' + k) }, el('b', {}, ico(i), el('span', { text: n })), el('p', { text: d })))));
    return;
  }
  const type = view.type;
  const name = el('input', { class: 'inp', placeholder: 'my-' + type, spellcheck: 'false', autocomplete: 'off' });
  const f = form(type, null, false);
  const preview = el('div', { class: 'cmd' });
  const out = el('pre', { class: 'out', hidden: true });
  const paint = () => { preview.textContent = 'socketley create ' + type + ' ' + (name.value.trim() || '<name>') + ' ' + f.words().join(' '); };
  C.addEventListener('input', paint); C.addEventListener('change', paint);
  const make = async () => {
    const n = name.value.trim();
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(n) || n.startsWith('.')) { toast('A name is letters, digits, - _ and ., up to 128.', 'bad'); name.focus(); return; }
    out.hidden = true;
    let r;
    try { r = await run('create', type, n, ...f.words()); } catch (e) { fail(e); return; }
    if (r.code) { out.hidden = false; out.textContent = r.out.trim() || 'Failed (' + r.code + ')'; out.scrollIntoView({ block: 'nearest' }); return; }
    toast(n + ' made');
    await loadMeta(); await poll();
    go('#/runtime/' + encodeURIComponent(n));
  };
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico(TYPES[type][0])), el('span', { text: 'New ' + TYPES[type][1].toLowerCase() }), el('span', { class: 'n', text: TYPES[type][2] }))),
    el('div', { class: 'panel' }, el('label', { class: 'fld2', style: 'max-width:360px' }, el('span', {}, el('b', { text: 'Name', style: 'color:var(--fg)' })), name), f.box,
      el('div', { class: 'fsec', style: 'cursor:default' }, el('span', { text: 'Command' })), preview, out,
      el('div', { class: 'acts', style: 'margin-top:14px;justify-content:flex-end' }, btn(null, 'Cancel', () => go('#/new')), btn('plus', 'Create', make, 'pri'))));
  paint(); name.focus();
}

// ─── start ──────────────────────────────────────────────────────────────────
async function start() {
  $('#login').hidden = true; $('#app').hidden = false;
  $('#menuB').textContent = ''; $('#menuB').append(ico('menu')); $('#menuB').onclick = () => $('#side').classList.toggle('open');
  try { schema = await (await must(await api('GET', '/api/schema'))).json(); } catch (e) { fail(e); }
  if (me && me.user) loadMeta();
  route();
  poll();
}
(async () => {
  let s;
  try { s = await (await fetch('/api/session')).json(); } catch (e) { $('#login').hidden = false; return; }
  // Without credentials configured the page only shows, and says how to change that.
  if (!s.configured) { me = { user: null }; start(); toast('Read only: set daemon.dashboard_credentials to sign in and change runtimes.', 'spark', 9000); return; }
  if (s.user) { me = { user: s.user }; start(); return; }
  $('#login').hidden = false; $('#lk').focus();
})();
</script>
</body>
</html>)HTML";
