// The daemon's dashboard, whole: markup, its own style and script. The storage interface's stylesheet and helpers go
// in at /*STYLE*/ and /*KIT*/ (dashboard.cpp), so the two look and behave as one.
constexpr std::string_view dashboard_page = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#07080c">
<title>socketley · daemon</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x2='1' y2='1'%3E%3Cstop stop-color='%23c084fc'/%3E%3Cstop offset='.55' stop-color='%23f472b6'/%3E%3Cstop offset='1' stop-color='%23fb923c'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='24' height='24' rx='6' fill='url(%23g)'/%3E%3Cpath d='M4 12h3.5l2-5 4 10 2-5H20' fill='none' stroke='%23fff' stroke-width='1.9' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
/*STYLE*/
/* ── the dashboard's own ── */
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;margin:6px 0 26px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px 16px 12px;position:relative;overflow:hidden}
.tile .k{font-size:12px;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.tile .v{font-size:26px;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.tile .s{font-size:12.5px;color:var(--mut);margin-top:2px;font-variant-numeric:tabular-nums}
@media(min-width:900px){.tiles.t3{grid-template-columns:repeat(3,1fr)}}
.tile svg.spark{display:block;width:100%;height:42px;margin-top:8px}
.tile svg.spark path.l{fill:none;stroke:var(--a1);stroke-width:1.8}
.tile svg.spark path.f{fill:url(#sg);stroke:none;opacity:.35}
.tile svg.spark line.x{stroke:var(--fg);stroke-width:1;opacity:.45;vector-effect:non-scaling-stroke}
.tile .tip{position:absolute;right:12px;top:12px;font-size:12px;background:rgba(0,0,0,.55);border:1px solid var(--line);border-radius:8px;padding:3px 9px;pointer-events:none;font-variant-numeric:tabular-nums;white-space:nowrap}
.tile .tip i{font-style:normal;color:var(--mut)}
.nav .cnt{margin-left:auto;font-size:11px;font-weight:700;min-width:20px;text-align:center;padding:1px 7px;border-radius:999px;background:var(--warn);color:#1a1300}
.nav .cnt.crit{background:var(--bad);color:#fff}
.kv.prose .v{font-family:inherit;font-size:13.5px}
.al{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:12px;background:rgba(251,191,36,.06);margin-bottom:8px}
.al.critical{border-left-color:var(--bad);background:rgba(251,88,118,.07)}
.al .i{flex:none;color:var(--warn);margin-top:1px}.al.critical .i{color:var(--bad)}
.al b{display:block;font-size:14px}.al .d{font-size:12.5px;color:var(--mut);margin-top:3px;word-break:break-word}
.al .w{margin-left:auto;font-size:12px;color:var(--dim);white-space:nowrap}
.al.clear{border-left-color:var(--ok);background:rgba(52,211,153,.05)}.al.clear .i{color:var(--ok)}
.rng{display:inline-flex;margin-left:auto;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:rgba(255,255,255,.03)}
.rng button{background:none;border:0;color:var(--mut);font:inherit;font-size:12.5px;font-weight:600;padding:6px 12px;cursor:pointer}
.rng button.on{background:rgba(255,255,255,.1);color:var(--fg)}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}
.nav .dot{padding:0;margin:0 0 0 auto}
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
.log{font-family:var(--mono);font-size:12.3px;line-height:1.55;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:12px;padding:10px 0;overflow:auto;max-height:calc(100vh - 240px);min-height:200px}
.log div{padding:0 14px;white-space:pre-wrap;word-break:break-word}
.log div:hover{background:rgba(255,255,255,.04)}
.log .warn{color:var(--warn)}.log .error{color:var(--bad)}.log .debug{color:var(--dim)}
.log .rt{color:var(--a1);margin-right:8px}
.log.short{max-height:320px}
.why{font-size:12px;color:var(--bad);margin-top:3px;max-width:520px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:8px}
.st{background:rgba(255,255,255,.035);border:1px solid var(--line);border-radius:10px;padding:8px 11px;min-width:0}
.st b{display:block;font-size:15px;font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.st span{display:block;font-size:11.5px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.st.zero b{color:var(--dim)}.st.bad b{color:var(--bad)}
.sgh{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:14px 0 7px}.sgh:first-child{margin-top:0}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.chips span{font-size:12px;border:1px solid var(--line);border-radius:20px;padding:3px 10px;color:var(--mut)}.chips b{color:var(--fg);font-weight:600}
.certs{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px;margin-bottom:26px}
.cert .nm2{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.cert .nm2 span{font-family:var(--mono);font-size:12px;background:rgba(255,255,255,.06);border:1px solid var(--line);border-radius:8px;padding:2px 8px}
.mtbl th{white-space:nowrap}
.ok2{color:var(--ok)}.warn2{color:var(--warn)}.bad2{color:var(--bad)}
.logbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 12px}
.logbar .inp{height:34px}
textarea.inp{height:auto;min-height:260px;padding:12px;font-family:var(--mono);font-size:12.5px;line-height:1.5;width:100%;resize:vertical}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute"><defs><linearGradient id="sg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--a1)"/><stop offset="1" stop-color="var(--a1)" stop-opacity="0"/></linearGradient></defs></svg>
<div id="aurora"><i></i><i></i><i></i></div>
<div id="login" hidden>
  <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
  <form class="lcard" id="lf">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M4 12h3.5l2-5 4 10 2-5H20" stroke-linecap="round" stroke-linejoin="round"/></svg></div>socketley</div>
    <h1>Daemon</h1>
    <p class="mut" id="lsub">Sign in with an admin's access key.</p>
    <a class="btn pri" id="lidp" hidden>Sign in with your account</a>
    <div class="or" id="lor" hidden>or with an access key</div>
    <label for="lk">Access key</label><input class="inp" id="lk" autocomplete="username" required spellcheck="false">
    <label for="ls">Secret</label><input class="inp" id="ls" type="password" autocomplete="current-password" required>
    <div class="err" id="le"></div>
    <button class="btn pri" id="lsb">Sign in</button>
  </form>
</div>
<div id="app" hidden>
  <aside id="side">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M4 12h3.5l2-5 4 10 2-5H20" stroke-linecap="round" stroke-linejoin="round"/></svg></div>socketley</div>
    <button class="nav" id="nOver"></button>
    <button class="nav" id="nRts"></button>
    <button class="nav" id="nNew"></button>
    <button class="nav" id="nLogs"></button>
    <button class="nav" id="nDom"></button>
    <button class="nav" id="nAl"></button>
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
  bell: '<path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2.2 2.2 0 0 0 4 0"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  server: '<rect x="3.5" y="4" width="17" height="6.5" rx="1.8"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="1.8"/><path d="M7 7.2h.01M7 16.8h.01"/>',
  client: '<path d="M4 17V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10"/><path d="M2 19h20"/>',
  proxy: '<circle cx="5" cy="12" r="2.2"/><circle cx="19" cy="6" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M7.2 12h4M11.2 12l5.8-5.2M11.2 12l5.8 5.2"/>',
  cache: '<path d="M13 3 4 14h7l-1 7 9-11h-7z"/>',
  storage: '<ellipse cx="12" cy="5.5" rx="8" ry="2.8"/><path d="M4 5.5v13c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8v-13M4 12c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8"/>',
  dns: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.6 5.4 3.6 8.5s-1.1 5.9-3.6 8.5c-2.5-2.6-3.6-5.4-3.6-8.5S9.5 6.1 12 3.5z"/>',
  play: '<path d="M7 5.5v13l11-6.5z"/>', stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  restart: '<path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/>', edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
  idp: '<rect x="5" y="10.5" width="14" height="9.5" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2"/>',
  db: '<rect x="4" y="4" width="16" height="16" rx="2.5"/><path d="M4 9.5h16M4 15h16M9.5 9.5V20"/>',
  mqtt: '<circle cx="12" cy="12" r="2"/><path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M5.5 18.5a9.2 9.2 0 0 1 0-13M18.5 5.5a9.2 9.2 0 0 1 0 13"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  tunnel: '<path d="M3.5 20v-8a8.5 8.5 0 0 1 17 0v8"/><path d="M8.5 20v-7a3.5 3.5 0 0 1 7 0v7"/><path d="M2.5 20h19"/>',
  metrics: '<path d="M3.5 20.5h17"/><path d="M5 16.5l4.5-5 3.5 3 6-7.5"/><circle cx="19" cy="7" r="1.3"/>',
  web: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M3 9h18M6.5 6.8h.01M9 6.8h.01"/><path d="M7.5 13h9M7.5 16h5.5"/>',
  mcp: '<path d="M8 4v4M16 4v4"/><rect x="5.5" y="8" width="13" height="6" rx="2"/><path d="M12 14v6"/>',
  sync: '<path d="M4 11a8 8 0 0 1 13.7-5.6L20 7.5"/><path d="M20 13a8 8 0 0 1-13.7 5.6L4 16.5"/><path d="M20 3.5V7.5h-4M4 20.5v-4h4"/>',
  open: '<path d="M14 3.5h6.5V10"/><path d="M20.5 3.5 11 13"/><path d="M17.5 14v5.2a1.3 1.3 0 0 1-1.3 1.3H4.8a1.3 1.3 0 0 1-1.3-1.3V7.8a1.3 1.3 0 0 1 1.3-1.3H10"/>',
  gauge: '<path d="M12 14l4-4"/><path d="M4.5 18a9 9 0 1 1 15 0"/>', cpu: '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>'
});
const TYPES = {
  server: ['server', 'Server', 'TCP, UDP or WebSocket: messages, static files, scripts.'],
  client: ['client', 'Client', 'Connects to a server and relays what it hears.'],
  proxy: ['proxy', 'Proxy', 'HTTP or TCP to backends, the entrance, auth and redirects.'],
  cache: ['cache', 'Cache', 'A key-value store that speaks Redis, persistent and sharded.'],
  storage: ['storage', 'Storage', 'S3-compatible object storage with this interface.'],
  dns: ['dns', 'DNS', 'An authoritative name server, with an entrance on 443.'],
  sync: ['sync', 'Sync', 'Carries a directory to a storage as its files change.'],
  idp: ['idp', 'Sign-in', 'One sign-in, with a storage\'s users, for apps and for routes behind a proxy.'],
  db: ['db', 'Database', 'JSON documents for apps, each owned by an account of the sign-in.'],
  mqtt: ['mqtt', 'MQTT', 'A broker for devices, apps and browsers, whose sessions wait for clients that went away.'],
  mail: ['mail', 'Mail', 'A mail server for its domains and users: SMTP, a spool, DKIM, mailboxes in a storage, IMAP.'],
  tunnel: ['tunnel', 'Tunnel', 'Reaches a machine with no public address: an edge here, or an agent that dials one.'],
  metrics: ['metrics', 'Metrics', 'Every figure of this daemon and the endpoints it scrapes, kept for years and read by PromQL, as Grafana reads a Prometheus.'],
  mcp: ['mcp', 'MCP', 'A Model Context Protocol server: an AI client is offered the tools its script declares.'],
  web: ['web', 'Web', 'A site of files for browsers: its pages, their caching and compression, a new release seen at once.']
};
const ARRAYS = new Set(['backends', 'upstreams']);
const TUNNEL_AGENT = new Set(['--to', '--join', '--offer']);
const TUNNEL_EDGE = new Set(['-p', '--bind', '--domain', '--forward', '--idp', '--idp-audience']);
const HEALTH = ['', 'tcp', 'http'];
// Durations as the flags take them and seconds as the configuration keeps them; sizes alike in bytes.
const toSec = v => { const m = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i.exec(String(v).trim()); if (!m) return null; const n = +m[1], u = (m[2] || 's').toLowerCase(); return Math.round(n * { ms: .001, s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[u]); };
const fromSec = s => { s = +s; if (!s) return '0'; for (const [u, n] of [['w', 604800], ['d', 86400], ['h', 3600], ['m', 60]]) if (s % n === 0) return s / n + u; return s + 's'; };
const toBytes = v => { const m = /^(\d+(?:\.\d+)?)\s*([kmgt])?b?$/i.exec(String(v).trim()); if (!m) return null; return Math.round(+m[1] * Math.pow(1024, ' kmgt'.indexOf((m[2] || ' ').toLowerCase()))); };
const fromBytes = b => { b = +b; for (const [u, n] of [['T', 2 ** 40], ['G', 2 ** 30], ['M', 2 ** 20], ['K', 1024]]) if (b >= n && b % n === 0) return b / n + u; return String(b); };
// Whole bytes: a rate is two counters' difference over the time between two polls, and its fractions mean nothing.
const rate = n => human(Math.round(+n || 0)) + '/s';
// A size to a tenth of its unit past 100, finer than `human`, for the hover over a gauge drawn to a tenth of its value.
const exact = n => { n = +n || 0; if (n < 1000) return Math.round(n) + ' B'; const u = ['KB', 'MB', 'GB', 'TB', 'PB']; let i = -1; do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1); return n.toFixed(n >= 100 ? 1 : 2) + ' ' + u[i]; };
const count = n => { n = +n || 0; return n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(0) + 'k' : String(Math.round(n)); };
const ago = s => { s = Math.floor(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + 'd ' + h + 'h' : h ? h + 'h ' + m + 'm' : m + 'm ' + (s % 60) + 's'; };

let problemsAt = 0;
// Each runtime's latest warning or error, from the log: what a failed one says about why.
const why = {};
async function problems() {
  try {
    const d = await (await must(await api('GET', '/api/logs?level=warn&max=1000'))).json();
    for (const l of d.lines) {
      const m = l.rt || (/'([^']+)'/.exec(l.text) || [])[1];
      if (m) why[m] = l;
    }
  } catch (e) {}
}
let me = null, schema = null, view = { at: 'over' }, rts = [], meta = {}, over = null, timer = 0, filterType = '';
// The daemon's rates now, from the last two polls.
const cur = { msg: 0, bin: 0, bout: 0, cpu: 0 };
// The daemon's history of the chosen range, by runtime and '' for the daemon, as /api/history gives it.
const RANGES = [[900, '15m'], [3600, '1h'], [21600, '6h'], [86400, '24h'], [604800, '7d'], [2592000, '30d'], [31536000, '1y']];
let range = +localStorage.getItem('skl_range') || 900, hover = null;
const series = {};
let alerts = { active: [], recent: [], webhook: false };
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
async function signOut() {
  try { await fetch('/api/session', { method: 'DELETE' }); } catch (e) {}
  // An admin the identity provider signed in is signed out there, for every application it signed in.
  if (me && me.idp_logout) { location.href = me.idp_logout; return; }
  signedOut();
}
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
  else if (h.startsWith('logs')) view = { at: 'logs', runtime: decodeURIComponent(h.slice(5)) };
  else if (h === 'domains') view = { at: 'dom' };
  else if (h === 'alerts') view = { at: 'al' };
  else if (h.startsWith('new')) view = { at: 'new', type: decodeURIComponent(h.slice(4)) || '' };
  else view = { at: 'over' };
  while (layers.length) layers[layers.length - 1].close();
  $('#side').classList.remove('open');
  const sc = $('#scroll'); if (sc) sc.scrollTop = 0;
  hover = null;
  render(true);
  if (over && (view.at === 'over' || view.at === 'rt')) loadSeries(view.at === 'rt' ? view.name : '');
}
window.addEventListener('hashchange', () => { if (me) route(); });

function side() {
  const nav = (b, icon, label, on, fn) => { b.textContent = ''; b.append(ico(icon), el('span', { text: label })); b.classList.toggle('on', on); b.onclick = fn; };
  nav($('#nOver'), 'pulse', 'Overview', view.at === 'over', () => go('#/'));
  nav($('#nRts'), 'server', 'Runtimes', view.at === 'rts', () => go('#/runtimes'));
  nav($('#nNew'), 'plus', 'New runtime', view.at === 'new', () => go('#/new'));
  nav($('#nLogs'), 'text', 'Logs', view.at === 'logs', () => go('#/logs'));
  nav($('#nDom'), 'dns', 'Domains', view.at === 'dom', () => go('#/domains'));
  nav($('#nAl'), 'bell', 'Alerts', view.at === 'al', () => go('#/alerts'));
  if (alerts.active.length) $('#nAl').append(el('span', { class: 'cnt' + (alerts.active.some(a => a.level === 'critical') ? ' crit' : ''), text: String(alerts.active.length) }));
  nav($('#nOut'), 'out', me && me.user ? 'Sign out · ' + me.user : 'Sign out', false, signOut);
  $('#nNew').hidden = !(me && me.user);
  paintThemes();
  const L = $('#rlist'); L.textContent = '';
  for (const r of rts.slice().sort((a, b) => a.name.localeCompare(b.name)))
    L.append(el('button', { class: 'nav' + (view.at === 'rt' && view.name === r.name ? ' on' : ''), onclick: () => go('#/runtime/' + encodeURIComponent(r.name)), oncontextmenu: e => rtMenu(r, e) },
      ico(r.type), el('span', { text: r.name, title: r.name + ' · ' + r.type }), el('span', { class: 'dot ' + r.state, title: r.state })));
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
  // A tab nobody looks at asks for nothing, and asks at once when it is looked at again.
  if (document.hidden) return;
  try {
    const lv = await (await must(await api('GET', '/api/live'))).json();
    const o = lv.overview, r = lv.runtimes;
    alerts = lv.alerts || alerts;
    const now = Date.now() / 1000, dt = prev.t ? now - prev.t : 0;
    if (dt > 0) {
      cur.msg = Math.max(0, (o.messages_total - prev.msg) / dt); cur.bin = Math.max(0, (o.bytes_in - prev.bin) / dt); cur.bout = Math.max(0, (o.bytes_out - prev.bout) / dt);
      cur.cpu = Math.max(0, 100 * (o.cpu_seconds - prev.cpu) / dt / (o.cpus || 1));
      for (const x of r) {
        const p = prev.per[x.name]; x.msg_s = p ? Math.max(0, (x.messages_total - p.m) / dt) : 0; x.in_s = p ? Math.max(0, (x.bytes_in - p.i) / dt) : 0; x.out_s = p ? Math.max(0, (x.bytes_out - p.o) / dt) : 0; x.cpu_p = p ? Math.max(0, 100 * (x.cpu_seconds - p.c) / dt) : 0;
      }
    }
    prev.t = now; prev.msg = o.messages_total; prev.bin = o.bytes_in; prev.bout = o.bytes_out; prev.cpu = o.cpu_seconds;
    prev.per = Object.fromEntries(r.map(x => [x.name, { m: x.messages_total, i: x.bytes_in, o: x.bytes_out, c: x.cpu_seconds }]));
    over = o; rts = r;
    if (now - problemsAt > 6) { problemsAt = now; problems(); }
    loadHosts();
    if (view.at === 'over' || view.at === 'rt') loadSeries(view.at === 'rt' ? view.name : '');
    render(false);
  } catch (e) { if (me) toast(e.message, 'bad'); }
  if (me) timer = setTimeout(poll, 2000);
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && me) poll(); });
// The names an entrance sends to each runtime, read seldom: routes change with a configuration, not with the figures.
let hosts = {}, hostsAt = 0;
// A wildcard stands for every host under it and names no page of its own, so it opens nothing.
function hostsOf(d) {
  const m = {};
  for (const e of d.entrances || []) for (const r of e.routes || []) {
    if (r.name.startsWith('*.')) continue;
    for (const t of r.to || []) if (t.runtime && !(m[t.runtime] || []).includes(r.name)) (m[t.runtime] = m[t.runtime] || []).push(r.name);
  }
  return m;
}
async function loadHosts() {
  if (Date.now() - hostsAt < 30000) return;
  hostsAt = Date.now();
  try {
    hosts = hostsOf(await (await must(await api('GET', '/api/edge'))).json());
    render(false);
  } catch (e) {}
}
// A link out of the dashboard to where `name` is served, or null when no entrance sends anything there.
function openLink(name, small) {
  const h = (hosts[name] || [])[0];
  if (!h) return null;
  const a = el('a', { class: 'btn' + (small ? ' sm' : ''), href: 'https://' + h + '/', target: '_blank', rel: 'noopener',
    title: 'Open https://' + h + '/' + ((hosts[name] || []).length > 1 ? ', one of ' + hosts[name].length + ' names' : '') });
  a.append(ico('open'), el('span', { text: small ? 'Open' : 'Open ' + h }));
  a.onclick = e => e.stopPropagation();
  return a;
}
// The owners, groups and ages `ls` knows, which the figures do not carry.
async function loadMeta() {
  try { const r = await run('ls', '--json'); if (!r.code) for (const x of JSON.parse(r.out)) meta[x.name] = x; } catch (e) {}
}
// One runtime's history, or the daemon's for '', asked again once the daemon has taken a new point.
async function loadSeries(name) {
  const had = series[name];
  if (had && had.range === range && Date.now() - had.at < 10000) return;
  if (had && had.loading) return;
  series[name] = Object.assign(had || {}, { loading: true });
  // What the page holds is added to: the buckets after its last, and the few before it, which may have filled since.
  const old = had && had.range === range && had.d ? had.d : null, pts = Math.max(10, Math.min(180, range / 10));
  const keys = ['conn', 'msg', 'in', 'out', 'cpu', 'rss'];
  try {
    const d = await (await must(await api('GET', '/api/history?runtime=' + encodeURIComponent(name) + '&range=' + range + '&points=' + pts +
      (old ? '&since=' + (old.from + old.step * old.msg.length) : '')))).json();
    let got = d.from ? d : null;
    if (old && got && got.step === old.step && got.from >= old.from) {
      const m = Object.assign({}, old);
      for (const k of keys) m[k] = old[k].slice();
      for (let j = 0; j < got.msg.length; j++) {
        const i = (got.from - m.from) / m.step + j;
        for (const k of keys) m[k][i] = got[k][j];
      }
      const over = m.msg.length - pts;
      if (over > 0) { for (const k of keys) m[k] = m[k].slice(over); m.from += over * m.step; }
      got = m;
    }
    series[name] = { at: Date.now(), range, d: got || old };
    render(false);
  } catch (e) { series[name] = { at: Date.now(), range, d: old }; }
}
function rangePick() {
  return el('div', { class: 'rng' }, ...RANGES.map(([v, t]) => el('button', { class: v === range ? 'on' : '', text: t, title: 'The last ' + t,
    onclick: () => { range = v; localStorage.setItem('skl_range', v); for (const k in series) delete series[k]; render(false); loadSeries(view.at === 'rt' ? view.name : ''); } })));
}
// A line of `name`'s history: `key`'s values, a rate drawn from zero and a gauge (`span`) between its least and
// greatest value, `fmt` saying a value for the hover; null while there is none.
function line(name, key, fmt, span, scale) {
  const h = series[name];
  if (!h || !h.d) return null;
  const vals = h.d[key].map(v => v === null ? null : v * (scale || 1));
  return { vals, from: h.d.from, step: h.d.step, fmt, span };
}
function spark(ln) {
  const s = document.createElementNS(SVGNS, 'svg'); s.setAttribute('class', 'spark'); s.setAttribute('viewBox', '0 0 100 30'); s.setAttribute('preserveAspectRatio', 'none');
  const vals = ln.vals, n = vals.length, some = vals.filter(v => v !== null);
  if (some.length < 2) return s;
  // A gauge spans at least a tenth of its greatest value, so a change of a few hundred kilobytes in 116 MB stays flat.
  const mx = Math.max(...some), mn = Math.min(...some), want = Math.max(mx - mn, mx * 0.1);
  const lo = ln.span ? Math.max(0, mn - (want - (mx - mn)) / 2) : 0, top = ln.span ? Math.max(want, mx - lo) : mx;
  const y = v => top ? 28 - ((v - lo) / top) * 26 : ln.span ? 15 : 28;
  // A stretch without points is a gap in the line, not a fall to zero.
  let d = '', f = '', run = [];
  const flush = () => {
    if (!run.length) return;
    const seg = run.map(([i, v], j) => (j ? 'L' : 'M') + (i / (n - 1) * 100).toFixed(2) + ' ' + y(v).toFixed(2)).join('');
    d += seg; f += seg + 'L' + (run[run.length - 1][0] / (n - 1) * 100).toFixed(2) + ' 30L' + (run[0][0] / (n - 1) * 100).toFixed(2) + ' 30Z';
    run = [];
  };
  vals.forEach((v, i) => { if (v === null) flush(); else run.push([i, v]); });
  flush();
  s.innerHTML = '<path class="f" d="' + f + '"/><path class="l" d="' + d + '"/>';
  return s;
}
// The time under the pointer: the hour for a day or less, the day beside it for longer ranges.
const hhmm = t => range > 86400 ? new Date(t * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
function tile(icon, k, v, s, ln) {
  const T = el('div', { class: 'tile' }, el('div', { class: 'k' }, ico(icon), el('span', { text: k })), el('div', { class: 'v', text: v }), s ? el('div', { class: 's', text: s }) : null);
  if (!ln) return T;
  const S = spark(ln);
  T.append(S);
  // The value under the pointer, kept across the redraw every poll makes.
  const show = x => {
    T.querySelector('.tip')?.remove(); S.querySelector('line')?.remove();
    const n = ln.vals.length;
    // The point nearest the pointer, on either side.
    const i = Math.round(x * (n - 1));
    let at = -1;
    for (let d = 0; d < n && at < 0; d++) at = ln.vals[i - d] != null ? i - d : ln.vals[i + d] != null ? i + d : -1;
    if (at < 0) return;
    const L = document.createElementNS(SVGNS, 'line'); const px = (at / (n - 1) * 100).toFixed(2);
    L.setAttribute('class', 'x'); L.setAttribute('x1', px); L.setAttribute('x2', px); L.setAttribute('y1', 0); L.setAttribute('y2', 30); S.append(L);
    T.append(el('div', { class: 'tip' }, ln.fmt(ln.vals[at]) + ' ', el('i', { text: hhmm(ln.from + (at + 0.5) * ln.step) })));
  };
  T.onmousemove = e => { const r = S.getBoundingClientRect(); hover = { k, x: Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)) }; show(hover.x); };
  T.onmouseleave = () => { hover = null; T.querySelector('.tip')?.remove(); S.querySelector('line')?.remove(); };
  if (hover && hover.k === k) show(hover.x);
  return T;
}

// ─── views ──────────────────────────────────────────────────────────────────
function render(full) {
  side();
  if (view.at === 'over') return overview();
  if (view.at === 'rts') return runtimes();
  if (view.at === 'rt') return detail(full);
  if (view.at === 'new' && full) return create();
  if (view.at === 'logs' && full) return logsView();
  if (view.at === 'dom' && full) return domains();
  if (view.at === 'al') return alertsView();
}
function overview() {
  crumbs([]);
  const C = $('#content'); C.textContent = '';
  if (!over) { C.append(el('div', { class: 'spin' })); return; }
  const running = rts.filter(r => r.state === 'running').length, failed = rts.filter(r => r.state === 'failed').length;
  const cpus = over.cpus || 1, pct = v => v.toFixed(1) + ' %';
  if (alerts.active.length) C.append(el('section', { class: 'sec' }, ...alerts.active.slice(0, 4).map(a => alertRow(a)),
    alerts.active.length > 4 ? el('button', { class: 'btn sm', onclick: () => go('#/alerts') }, el('span', { text: 'All ' + alerts.active.length + ' alerts' })) : null));
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('pulse')), el('span', { text: 'Daemon' }), el('span', { class: 'n', text: 'v' + over.version + ' · up ' + ago(over.uptime_seconds) }), rangePick())),
    el('div', { class: 'tiles' },
      tile('server', 'Runtimes', running + ' / ' + over.runtimes_total, failed ? failed + ' failed' : running === over.runtimes_total ? 'all running' : (over.runtimes_total - running) + ' stopped'),
      tile('users', 'Connections', count(over.connections_active), count(over.connections_total) + ' since start', line('', 'conn', count)),
      tile('send', 'Messages', count(cur.msg) + '/s', count(over.messages_total) + ' since start', line('', 'msg', v => count(v) + '/s')),
      tile('download', 'In', rate(cur.bin), human(over.bytes_in) + ' since start', line('', 'in', rate)),
      tile('upload', 'Out', rate(cur.bout), human(over.bytes_out) + ' since start', line('', 'out', rate)),
      tile('cpu', 'CPU', pct(cur.cpu), cpus + ' CPUs · ' + over.processes + ' processes', line('', 'cpu', pct, false, 1 / cpus)),
      tile('gauge', 'Memory', human(over.memory_bytes), 'held, daemon and workers', line('', 'rss', exact, true))));
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
// What may be done to `r`, for its buttons and its menu alike; `full` ones are not offered in a table's row.
function actions(r) {
  const n = r.name;
  if (!me || !me.user) return [];
  const on = r.state === 'running';
  return [
    on ? { icon: 'stop', label: 'Stop', fn: async () => { if (await act(['stop', n], n + ' stopped')) poll(); } }
       : { icon: 'play', label: 'Start', pri: true, fn: async () => { if (await act(['start', n], n + ' started')) poll(); } },
    // One command and not a stop and a start: the runtime being restarted may be the entrance this page is
    // reached through, and then the stop arrives and the start never does.
    on ? { icon: 'restart', label: 'Restart', fn: async () => { if (await act(['restart', n], n + ' restarted')) poll(); } } : null,
    { icon: 'restart', label: 'Reload Lua', full: true, fn: async () => { await act(['reload-lua', n], 'Lua of ' + n + ' reloaded'); } },
    // An edge's agents and shares, known to be an edge once its configuration has been read.
    r.type === 'tunnel' && shown && shown.name === n && shown.conf && shown.conf.mode !== 'agent'
      ? { icon: 'users', label: 'Agents', full: true, fn: () => tunnelDlg(r) } : null,
    { icon: 'edit', label: 'Edit', full: true, fn: () => editDlg(r) },
    { icon: 'trash', label: 'Remove', full: true, bad: true, fn: async () => {
      if (!await ask({ title: 'Remove ' + n + '?', text: 'It stops and is gone, with its configuration. Its data (a storage directory, a cache file) stays where it is.', ok: 'Remove', danger: true })) return;
      if (await act(['remove', n], n + ' removed')) { delete meta[n]; go('#/runtimes'); poll(); }
    } }
  ].filter(Boolean);
}
function controls(r, small) {
  const cls = small ? 'sm' : '';
  return actions(r).filter(x => !small || !x.full).map(x => btn(x.icon, x.label, e => { e && e.stopPropagation(); x.fn(); },
    cls + (x.pri ? ' pri' : '') + (x.bad ? ' bad' : '')));
}
// The runtime's actions at the pointer, as its page offers them, with where it is served first.
function rtMenu(r, ev) {
  ev.preventDefault();
  const h = (hosts[r.name] || [])[0];
  const acts = actions(r);
  const list = [h ? { icon: 'open', label: 'Open ' + h, fn: () => window.open('https://' + h + '/', '_blank', 'noopener') } : null,
    h && acts.length ? '-' : null, ...acts].filter(Boolean);
  if (list.length) popup({ x: ev.clientX, y: ev.clientY }, list);
}
function table(list) {
  if (!list.length) return el('div', { class: 'empty' }, el('div', { class: 'big' }, ico('server')), el('h3', { text: 'No runtimes here' }), el('div', { text: 'Make one with New runtime.' }));
  const T = el('table', { class: 'rt' });
  T.append(el('tr', {}, ...['', 'Runtime', 'Port', 'Connections', 'Messages', 'In / out', 'CPU', 'Memory', ''].map(t => el('th', { text: t }))));
  for (const r of list.slice().sort((a, b) => (a.state !== 'running') - (b.state !== 'running') || a.name.localeCompare(b.name))) {
    const m = meta[r.name] || {};
    T.append(el('tr', { onclick: () => go('#/runtime/' + encodeURIComponent(r.name)) },
      el('td', { style: 'width:28px' }, el('span', { class: 'dot ' + r.state, title: r.state })),
      el('td', {}, el('div', { class: 'nm', text: r.name }), el('div', { class: 'ty', text: (TYPES[r.type] || [r.type, r.type])[1] + (m.group ? ' · @' + m.group : '') + (m.owner && m.owner !== '-' ? ' · of ' + m.owner : '') + (r.state !== 'running' ? ' · ' + r.state : '') + (m.restarts ? ' · ' + m.restarts + ' restart' + (m.restarts === 1 ? '' : 's') : '') }),
        r.state === 'failed' && why[r.name] ? el('div', { class: 'why', title: why[r.name].text, text: clean(why[r.name].text) }) : null),
      el('td', { class: 'num', text: r.port ? String(r.port) : '—' }),
      el('td', { class: 'num', text: count(r.connections) }),
      el('td', { class: 'num', text: count(r.msg_s || 0) + '/s' }),
      el('td', { class: 'num', text: rate(r.in_s || 0) + ' · ' + rate(r.out_s || 0) }),
      el('td', { class: 'num', text: (r.cpu_p || 0).toFixed(1) + ' %' }),
      // What the runtime costs the machine, every shard of it: a page it shares counted by the share it holds.
      el('td', { class: 'num', title: r.processes > 1 ? human(r.rss_bytes || 0) + ' resident over ' + r.processes + ' shards' : '',
                 text: r.state === 'running' ? human(r.memory_bytes || 0) : '—' }),
      el('td', {}, el('div', { class: 'acts', style: 'justify-content:flex-end' }, openLink(r.name, true), ...controls(r, true)))));
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
    shown = { name: r.name, conf: null };
    C.textContent = '';
    C.append(el('div', { id: 'dHead' }), el('div', { class: 'tiles t3', id: 'dTiles' }),
      el('div', { class: 'panel' }, el('h3', {}, ico('edit'), el('span', { text: 'Configuration' })), el('div', { id: 'dConf', class: 'kv' })),
      el('div', { class: 'panel' }, el('h3', {}, ico('text'), el('span', { text: 'Log' }), el('span', { style: 'flex:1' }), btn(null, 'Open full log', () => go('#/logs/' + encodeURIComponent(r.name)), 'sm')), el('div', { class: 'log short', id: 'dLog' })),
      el('div', { class: 'panel' }, el('h3', {}, ico('info'), el('span', { text: 'Stats' })), el('div', { id: 'dStats' })));
    shown.logNext = 0;
    if (me && me.user) {
      const mine = shown;
      run('show', r.name).then(x => { if (shown === mine && !x.code) { try { shown.conf = JSON.parse(x.out); } catch (e) {} paintConf(); } });
      statsText(r.name);
    }
  }
  const t = TYPES[r.type] || [r.type, r.type];
  const H = $('#dHead'); H.textContent = '';
  H.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico(t[0])), el('span', { text: r.name }), el('span', { class: 'n' }, el('span', { class: 'dot ' + r.state }), ' ' + r.state + ' · ' + t[1] + (r.port ? ' · port ' + r.port : '')))),
    el('div', { class: 'acts', style: 'margin:-4px 0 18px' }, openLink(r.name), ...controls(r, false), rangePick()));
  const D = $('#dTiles'); D.textContent = '';
  const n = r.name, pct = v => v.toFixed(1) + ' %';
  D.append(tile('users', 'Connections', count(r.connections), count(r.connections_total) + ' since start', line(n, 'conn', count)),
    tile('send', 'Messages', count(r.msg_s || 0) + '/s', count(r.messages_total) + ' since start', line(n, 'msg', v => count(v) + '/s')),
    tile('download', 'In', rate(r.in_s || 0), human(r.bytes_in) + ' since start', line(n, 'in', rate)),
    tile('upload', 'Out', rate(r.out_s || 0), human(r.bytes_out) + ' since start', line(n, 'out', rate)),
    tile('cpu', 'CPU', pct(r.cpu_p || 0), r.processes + ' process' + (r.processes === 1 ? '' : 'es'), line(n, 'cpu', pct)),
    tile('gauge', 'Memory', human(r.memory_bytes), 'held, every shard', line(n, 'rss', exact, true)));
  if (!full && shown.stamp && Date.now() - shown.stamp > 5000) statsText(r.name);
  tailInto($('#dLog'), shown, r.name, 300);
  if (r.state === 'failed' && why[r.name]) H.append(el('div', { id: 'dWhy', class: 'panel', style: 'border-color:rgba(251,88,118,.4)' }, el('h3', {}, ico('info'), el('span', { text: 'Why it failed' })), el('div', { class: 'kv' }, el('div', { class: 'k', text: new Date(why[r.name].at).toLocaleString() }), el('div', { class: 'v', text: clean(why[r.name].text) }))));
}
// A line without its clock and tag, which the view says by itself.
const clean = t => t.replace(/^\[\d\d:\d\d:\d\d\] \[[A-Z]+\] /, '');
function logLine(l, withRt) {
  const t = new Date(l.at);
  // A worker's line names its runtime, which the view says already.
  const text = l.rt ? clean(l.text).replace(/^\w+ '[^']*'( shard \d+)?: /, '') : clean(l.text);
  return el('div', { class: l.lv }, el('span', { class: 'dim', text: t.toLocaleTimeString() + ' ' }), withRt && l.rt ? el('span', { class: 'rt', text: l.rt }) : null, el('span', { text }));
}
// New lines into `box`, from where `st.logNext` says; kept to `keep`, following the bottom unless scrolled away.
// What strangers on the internet cause on any open port: failed TLS handshakes, connections that never finished
// one, and request heads that stopped arriving.
const NOISE = /inbound handshakes? failed in the last|did not finish a TLS handshake within|answered 408 to \d+ connection/;
async function tailInto(box, st, runtime, keep, level, text, quiet) {
  if (!box || st.logBusy) return;
  st.logBusy = true;
  const gen = st.gen || 0;
  try {
    const d = await (await must(await api('GET', '/api/logs?since=' + (st.logNext || 0) + '&max=' + (st.logNext ? 500 : keep) + (runtime ? '&runtime=' + encodeURIComponent(runtime) : '') + (level ? '&level=' + level : '')))).json();
    // A filter changed meanwhile, so these lines are of the old one.
    if ((st.gen || 0) !== gen) { st.logBusy = false; return; }
    st.logNext = d.next;
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const q = (text || '').toLowerCase();
    for (const l of d.lines) if ((!q || l.text.toLowerCase().includes(q)) && !(quiet && NOISE.test(l.text))) box.append(logLine(l, !runtime));
    while (box.childElementCount > keep) box.firstElementChild.remove();
    if (!box.childElementCount) box.append(el('div', { class: 'dim', text: 'Nothing logged yet.' }));
    else if (box.firstElementChild.classList.contains('dim') && box.firstElementChild.textContent === 'Nothing logged yet.' && box.childElementCount > 1) box.firstElementChild.remove();
    if (atBottom) box.scrollTop = box.scrollHeight;
  } catch (e) {}
  st.logBusy = false;
}

// ─── domains ────────────────────────────────────────────────────────────────
const daysOf = s => Math.floor(s / 86400);
// One alert: what, why, since when -- or, in the history, when it was raised or cleared -- and its runtime's page a
// click away.
function alertRow(a, ev) {
  const R = el('div', { class: 'al ' + (ev && !ev.raised ? 'clear' : a.level) }, ico(ev && !ev.raised ? 'check' : 'bell'),
    el('div', { style: 'min-width:0' }, el('b', { text: a.title + (ev ? ev.raised ? ' — raised' : ' — cleared' : '') }), a.detail && !(ev && !ev.raised) ? el('div', { class: 'd', text: clean(a.detail) }) : null),
    el('span', { class: 'w', text: ev ? new Date(ev.at * 1000).toLocaleString() : 'since ' + ago(Date.now() / 1000 - a.since) }));
  if (a.runtime && rts.some(r => r.name === a.runtime)) { R.style.cursor = 'pointer'; R.onclick = () => go('#/runtime/' + encodeURIComponent(a.runtime)); }
  return R;
}
function alertsView() {
  crumbs([['Alerts', null]]);
  const C = $('#content'); C.textContent = '';
  const test = async () => {
    try {
      const r = await api('POST', '/api/alerts/test', {});
      if (r.ok) toast('Sent: look for it where the hook posts.', 'check'); else toast(await r.text(), 'bad');
    } catch (e) { fail(e); }
  };
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('bell')), el('span', { text: 'Alerts' }), el('span', { class: 'n', text: String(alerts.active.length) })),
    alerts.active.length ? el('div', {}, ...alerts.active.map(a => alertRow(a))) : el('p', { class: 'mut', text: 'Nothing is wrong.' })));
  C.append(el('div', { class: 'panel' }, el('h3', {}, ico('info'), el('span', { text: 'What is watched' })),
    el('div', { class: 'kv prose' },
      el('div', { class: 'k', text: 'Runtimes' }), el('div', { class: 'v', text: 'one that failed, and one started again three times within the hour' }),
      el('div', { class: 'k', text: 'Certificates' }), el('div', { class: 'v', text: 'one that ends within two weeks, critical within three days' }),
      el('div', { class: 'k', text: 'Space' }), el('div', { class: 'v', text: 'a storage runtime’s disk, the state directory’s and the host’s memory at 90 %, critical at 95 %' }),
      el('div', { class: 'k', text: 'Limits' }), el('div', { class: 'v', text: 'a storage runtime at 90 % of --max-bytes, a cache that refuses writes at 90 % of its --maxmemory' }),
      el('div', { class: 'k', text: 'Git' }), el('div', { class: 'v', text: 'a repository whose last pull failed' }),
      el('div', { class: 'k', text: 'Webhook' }), el('div', { class: 'v' }, alerts.webhook ? 'set: each alert raised and cleared is posted to it' : 'none: set daemon.alert_webhook to a Discord, Slack, Telegram or any JSON hook',
        alerts.webhook && me && me.user ? el('div', { style: 'margin-top:8px' }, btn('send', 'Send a test', test, 'sm')) : null))));
  if (alerts.recent.length) C.append(el('section', { class: 'sec', style: 'margin-top:22px' }, el('h2', {}, el('span', { class: 'hb' }, ico('text')), el('span', { text: 'Recently' })),
    ...alerts.recent.slice(0, 30).map(e => alertRow(e.alert, e))));
}
async function domains() {
  crumbs([['Domains', '#/domains']]);
  const C = $('#content'); C.textContent = '';
  let d;
  try { d = await (await must(await api('GET', '/api/edge'))).json(); } catch (e) { C.append(el('p', { class: 'mut', text: e.message })); return; }
  if (view.at !== 'dom') return;
  const rtLink = n => el('a', { href: '#/runtime/' + encodeURIComponent(n), text: n, style: 'color:var(--a1)' });
  // ── certificates
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('lock')), el('span', { text: 'Certificates' }), el('span', { class: 'n', text: String(d.certs.length) }))));
  const G = el('div', { class: 'certs' });
  for (const c of d.certs.sort((a, b) => (a.expires_in || 0) - (b.expires_in || 0))) {
    const days = daysOf(c.expires_in || 0);
    const state = c.missing ? ['bad2', 'no certificate yet'] : c.self_signed ? ['warn2', c.auto ? 'a placeholder, until the CA has issued one' : 'self-signed: browsers warn about it'] : days < 7 ? ['bad2', 'ends in ' + days + ' days'] : days < 30 ? ['warn2', 'ends in ' + days + ' days, renewal due'] : ['ok2', 'valid for ' + days + ' more days'];
    const failed = c.acme_log && /fail|error|refused|invalid/i.test(c.acme_log);
    G.append(el('div', { class: 'panel cert', style: 'margin:0' },
      el('h3', {}, ico('lock'), rtLink(c.runtime), el('span', { class: 'mut', style: 'font-weight:400;font-size:12.5px', text: c.issuer ? ' · ' + c.issuer : '' })),
      el('div', { class: state[0], style: 'font-size:13px;font-weight:600', text: state[1] }),
      el('div', { class: 'nm2' }, ...(c.names || []).map(n => el('span', { text: n }))),
      el('div', { class: 'mut', style: 'font-size:12px', text: c.auto ? 'Issued and renewed by itself' + (c.partial ? '; the wildcard waits for the zone to be delegated here' : '') : 'From ' + c.path }),
      failed ? el('div', { class: 'bad2', style: 'font-size:12px;margin-top:6px', text: 'Last attempt: ' + c.acme_log }) : null));
  }
  if (!d.certs.length) G.append(el('p', { class: 'mut', text: 'No runtime serves TLS.' }));
  C.append(G);
  // ── routes
  for (const e of d.entrances) {
    C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('proxy')), el('span', { text: 'Entrance ' }), rtLink(e.name), el('span', { class: 'n', text: e.zones.join(', ') || 'no zone' }))));
    const T = el('table', { class: 'mtbl', style: 'margin-bottom:26px' });
    T.append(el('tr', {}, el('th', { text: 'Name' }), el('th', { text: 'Goes to' })));
    for (const r of e.routes) T.append(el('tr', {}, el('td', { class: 'w', style: 'font-family:var(--mono)' },
      r.name.startsWith('*.') ? el('span', { text: r.name, title: 'A name for every host under it: there is no one page behind it.' })
        : el('a', { href: 'https://' + r.name + '/', target: '_blank', rel: 'noopener', text: r.name, style: 'color:var(--fg)' })),
      el('td', {}, ...r.to.flatMap((t, i) => [i ? ', ' : null, t.runtime ? rtLink(t.runtime) : el('span', { class: 'mut', text: t.address })]))));
    if (!e.routes.length) T.append(el('tr', {}, el('td', { class: 'mut', colspan: '2', text: 'No runtime has a name here yet: give one --domain.' })));
    C.append(T);
  }
  // ── zones
  if (d.zones.length) {
    C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('dns')), el('span', { text: 'Zones' }), el('span', { class: 'n', text: String(d.zones.length) }))));
    const T = el('table', { class: 'mtbl' });
    T.append(el('tr', {}, el('th', { text: 'Zone' }), el('th', { text: 'Served by' }), el('th', { text: 'Serial' }), el('th')));
    for (const z of d.zones) T.append(el('tr', {}, el('td', { class: 'w' }, el('b', { text: z.origin || z.path }), z.error ? el('div', { class: 'bad2', style: 'font-size:12px', text: z.error }) : null),
      el('td', {}, rtLink(z.runtime)), el('td', { class: 'mut num', text: String(z.serial || '—') }),
      el('td', { class: 'r' }, me && me.user ? btn('edit', 'Edit records', () => zoneDlg(z), 'sm') : null)));
    C.append(T);
  }
}
// A zone file in an editor: checked by the daemon as its dns runtime reads it, the serial raised when it was not.
async function zoneDlg(z) {
  let text;
  try { text = await (await must(await api('GET', '/api/zone?runtime=' + encodeURIComponent(z.runtime) + '&path=' + encodeURIComponent(z.path)))).text(); } catch (e) { fail(e); return; }
  const ta = el('textarea', { class: 'inp', spellcheck: 'false', style: 'min-height:420px' }); ta.value = text;
  const err = el('div', { class: 'bad2', style: 'font-size:12.5px;min-height:18px;margin-top:6px' });
  const SOA = /(\bSOA\s+\S+\s+\S+\s+)(\d+)/;
  const save = async () => {
    let t = ta.value;
    const before = SOA.exec(text), now = SOA.exec(t);
    // An edit that left the serial alone gets the next one, or secondaries would never take it.
    if (t !== text && before && now && before[2] === now[2]) {
      const d = new Date(), stamp = +(d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0') + '00');
      t = t.replace(SOA, (m, a, n) => a + String(Math.max(+n + 1, stamp + 1)));
    }
    const r = await api('PUT', '/api/zone', { runtime: z.runtime, path: z.path, text: t });
    if (!r.ok) { err.textContent = (await r.text()).trim(); return; }
    toast((z.origin || 'The zone') + ' saved; served within a second'); L.close(); domains();
  };
  const L = modal('Records of ' + (z.origin || z.path), [el('p', { class: 'mut', style: 'font-size:12.5px;margin-top:0', text: 'RFC 1035 master format, as the dns runtime reads it. The names of runtimes need no line here: they are published by themselves. The serial is raised on save when you leave it as it was.' }), ta, err],
    [btn(null, 'Cancel', () => L.close()), btn(null, 'Save', save, 'pri')], true);
}

// ─── the log ────────────────────────────────────────────────────────────────
let logState = null;
function logsView() {
  crumbs([['Logs', '#/logs']].concat(view.runtime ? [[view.runtime, null]] : []));
  const C = $('#content'); C.textContent = '';
  const st = logState = { logNext: 0, paused: false };
  const rt = el('select', { class: 'inp' }, el('option', { value: '', text: 'All runtimes and the daemon' }), ...rts.map(r => r.name).sort().map(n => el('option', { value: n, text: n })));
  rt.value = view.runtime || '';
  const lv = el('select', { class: 'inp' }, el('option', { value: '', text: 'Every line' }), el('option', { value: 'warn', text: 'Warnings and errors' }), el('option', { value: 'error', text: 'Errors' }));
  const q = el('input', { class: 'inp', placeholder: 'Find in the log', spellcheck: 'false' });
  const quiet = el('input', { type: 'checkbox' }); quiet.checked = localStorage.getItem('skl-dash-quiet') !== '0';
  const quietRow = el('div', { class: 'swrow', title: 'Failed TLS handshakes, connections that never finished one and request heads that stopped arriving: what scanners cause on any open port' },
    el('label', { class: 'sw' }, quiet, el('i')), el('span', { class: 'h', text: 'Hide scanner noise' }));
  const box = el('div', { class: 'log' });
  const restart = () => { box.textContent = ''; st.logNext = 0; st.gen = (st.gen || 0) + 1; tick(); };
  rt.onchange = () => { view.runtime = rt.value; history.replaceState(null, '', '#/logs' + (rt.value ? '/' + encodeURIComponent(rt.value) : '')); restart(); };
  lv.onchange = restart; q.oninput = () => { clearTimeout(st.qt); st.qt = setTimeout(restart, 250); };
  quiet.onchange = () => { try { localStorage.setItem('skl-dash-quiet', quiet.checked ? '1' : '0'); } catch (e) {} restart(); };
  const pause = btn('stop', 'Pause', () => { st.paused = !st.paused; pause.querySelector('span').textContent = st.paused ? 'Follow' : 'Pause'; if (!st.paused) tick(); }, 'sm');
  C.append(el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('text')), el('span', { text: 'Log' }), el('span', { class: 'n', text: 'the daemon and every runtime, newest at the bottom' }))),
    el('div', { class: 'logbar' }, rt, lv, q, quietRow, pause), box);
  const tick = async () => {
    if (logState !== st || view.at !== 'logs') return;
    if (!st.paused && !document.hidden) await tailInto(box, st, rt.value, 2000, lv.value, q.value, quiet.checked);
    clearTimeout(st.t); st.t = setTimeout(tick, 2000);
  };
  tick();
}
async function statsText(name) {
  shown.stamp = Date.now();
  let x;
  try { x = await run('stats', name); } catch (e) { return; }
  const S = $('#dStats');
  if (!S || !shown || shown.name !== name) return;
  paintStats(S, x.out || '');
}
// `stats` read for the page: the text values, each counter once -- added over the shards as the metrics endpoint adds
// them, but for those every shard holds a whole copy of or counts for itself alone -- under the part of the runtime
// its prefix names, and each shard's own figures.
const COPY = /^(buckets|max_bytes|max_memory|tls|shards|mesh_links|peer_links)$/;
const PART = /^(shard|mesh|peer|journal|replication|tier|error|errors|tls|ws|lua|acme|git|hot|pool|zone|upstream|backend)$/;
function readStats(text) {
  const head = {}, shards = [];
  let cur = head;
  for (const line of text.split('\n')) {
    if (/^\[shard \d+\]$/.test(line.trim())) { cur = {}; shards.push(cur); continue; }
    const c = line.indexOf(':'); if (c < 1) continue;
    cur[line.slice(0, c)] = line.slice(c + 1);
  }
  const nums = new Map(), texts = new Map();
  const take = (k, v) => {
    if (!/^-?\d+(\.\d+)?$/.test(v)) { texts.set(k, v); return; }
    if (!nums.has(k)) nums.set(k, []);
    nums.get(k).push(+v);
  };
  // What the tiles above show already, what names the runtime and a setting the Configuration panel names are left
  // out, and a number that stands for a word is the word.
  const SHOWN = /^(name|type|port|connections|total_connections|total_messages|bytes_in|bytes_out|mode|eviction|shard_index)$/;
  const WORDS = { repl_role: ['', 'leader', 'follower'] };
  const own = /^shard_(connections|total_connections|total_messages|bytes_in|bytes_out)$/;
  for (const part of [head, ...shards])
    for (const [k, v] of Object.entries(part)) {
      if (SHOWN.test(k) || own.test(k) || (part !== head && head.hasOwnProperty(k))) continue;
      if (WORDS[k]) { if (WORDS[k][+v]) texts.set(k.replace('repl_', 'replication '), WORDS[k][+v]); }
      else if (k === 'pid' || k === 'shard_pids') texts.set(k === 'pid' ? k : 'pids', v);
      else take(k, v);
    }
  const counters = [...nums].map(([k, a]) => ({ k, v: COPY.test(k) ? Math.max(...a) : a.reduce((x, y) => x + y, 0), a }));
  // A counter goes under its prefix when two shown share it and the prefix names a part of the runtime, or three do.
  const pre = k => k.includes('_') ? k.slice(0, k.indexOf('_')) : '';
  const many = {};
  for (const x of counters) if (x.v) many[pre(x.k)] = (many[pre(x.k)] || 0) + 1;
  for (const x of counters) {
    const p = pre(x.k);
    x.group = p && many[p] >= 2 && (PART.test(p) || many[p] >= 3) ? p : '';
    x.label = (x.group ? x.k.slice(x.group.length + 1) : x.k).replace(/_/g, ' ');
    x.bad = !!x.v && (/^errors?$/.test(x.group) || /error|fail|drop|reject/.test(x.k));
  }
  return { texts: [...texts], counters, shards: shards.length > 1 ? shards : [] };
}
function paintStats(S, text) {
  const st = readStats(text);
  const fmt = (k, v) => /bytes|_size$|memory/.test(k) ? human(v) : v >= 1e5 ? count(v) : v.toLocaleString();
  S.textContent = '';
  if (st.texts.length) S.append(el('div', { class: 'chips' }, ...st.texts.map(([k, v]) => el('span', {}, k.replace(/_/g, ' ') + ' ', el('b', { text: v })))));
  const groups = new Map([['', []]]);
  const zeros = el('div', { class: 'sgrid', hidden: true, style: 'margin-top:8px' });
  let nz = 0;
  for (const x of st.counters) {
    const t = el('div', { class: 'st' + (!x.v ? ' zero' : x.bad ? ' bad' : ''), title: x.k + ': ' + x.v + (x.a.length > 1 ? ' (' + x.a.join(', ') + ')' : '') },
      el('b', { text: fmt(x.k, x.v) }), el('span', { text: x.label }));
    if (!x.v) { zeros.append(t); nz++; continue; }
    if (!groups.has(x.group)) groups.set(x.group, []);
    groups.get(x.group).push(t);
  }
  for (const [g, ts] of groups) {
    if (!ts.length) continue;
    if (groups.size > 1) S.append(el('div', { class: 'sgh', text: g ? { shard: 'shards', error: 'errors', hot: 'hot tier' }[g] || g : 'general' }));
    S.append(el('div', { class: 'sgrid' }, ...ts));
  }
  if (nz) S.append(el('div', { style: 'margin-top:10px' }, btn(null, 'Show ' + nz + ' at zero', e => { zeros.hidden = !zeros.hidden; e.currentTarget.querySelector('span').textContent = zeros.hidden ? 'Show ' + nz + ' at zero' : 'Hide those at zero'; }, 'sm')), zeros);
  if (st.shards.length) {
    const T = el('table', { class: 'mtbl', style: 'margin-top:16px' });
    T.append(el('tr', {}, ...['Shard', 'Connections', 'Since start', 'Messages', 'In', 'Out'].map(t => el('th', { text: t }))));
    st.shards.forEach((sh, i) => T.append(el('tr', {}, el('td', { text: String(sh.shard_index ?? i) }), el('td', { class: 'num', text: sh.shard_connections || '0' }), el('td', { class: 'num', text: count(+sh.shard_total_connections || 0) }),
      el('td', { class: 'num', text: count(+sh.shard_total_messages || 0) }), el('td', { class: 'num', text: human(+sh.shard_bytes_in || 0) }), el('td', { class: 'num', text: human(+sh.shard_bytes_out || 0) }))));
    S.append(T);
  }
}
function paintConf() {
  const K = $('#dConf'); if (!K || !shown.conf) return; K.textContent = '';
  const skip = new Set(['name', 'id', 'type', 'was_running']);
  for (const [k, v] of Object.entries(shown.conf)) {
    if (skip.has(k)) continue;
    // A size in bytes is shown as the size, the exact figure beside it.
    const sz = typeof v === 'number' && v >= 1024 && /memory|bytes|size/.test(k);
    K.append(el('div', { class: 'k', text: label(k) }), el('div', { class: 'v', text: Array.isArray(v) ? v.join(', ') : sz ? human(v) + ' (' + v + ')' : String(v) }));
  }
}
// A key's label: the flag's own where the schema has it.
function label(k) {
  if (schema) for (const f of schema.flags) if (f.key === k) return f.label;
  return k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
}

// ─── editing ────────────────────────────────────────────────────────────────
// The runtime's settings as the form of its type shows them, filled with what `show` says; a save imports what changed.
async function editDlg(r) {
  let conf;
  try { const x = await run('show', r.name); if (x.code) throw new Error(x.out); conf = JSON.parse(x.out); } catch (e) { fail(e); return; }
  const running = r.state === 'running';
  const fields = form(r.type, conf, true, running);
  // Its name, which import changes with the rest; a running one is stopped for it and started under the new one.
  const nameIn = el('input', { class: 'inp', spellcheck: 'false', autocomplete: 'off' }); nameIn.value = r.name;
  const nameBox = el('div', { class: 'form', style: 'margin-bottom:4px' }, el('label', { class: 'fld2' },
    el('span', {}, el('b', { text: 'Name', style: 'font-weight:600;color:var(--fg)' }),
      running ? el('span', { class: 'chip', style: 'font-size:10.5px;margin-left:6px;padding:1px 7px', title: 'A running runtime is stopped to be renamed', text: 'restart' }) : null),
    nameIn, el('div', { class: 'h', text: 'Letters, digits, - _ and ., up to 128, not beginning with a dot.' })));
  let renamed = '';
  const LIVE = new Set((schema && schema.live) || []);
  const raw = el('textarea', { class: 'inp', spellcheck: 'false' }); raw.value = JSON.stringify(conf, null, 2);
  const rawBox = el('div', { hidden: true }, el('p', { class: 'mut', style: 'font-size:12.5px', text: 'The whole configuration as import takes it. What a running runtime cannot change while it runs is refused: stop it first.' }), raw);
  let rawOn = false;
  const toggle = btn(null, 'JSON', () => { rawOn = !rawOn; rawBox.hidden = !rawOn; fields.box.hidden = nameBox.hidden = rawOn; toggle.querySelector('span').textContent = rawOn ? 'Form' : 'JSON'; }, '');
  // A renamed runtime is shown under its new name, its old one no longer there to show.
  const done = msg => {
    toast(renamed ? msg.replace(r.name, r.name + ' → ' + renamed) : msg); L.close();
    if (renamed && renamed !== r.name) { delete meta[r.name]; go('#/runtime/' + encodeURIComponent(renamed)); }
    poll(); if (view.at === 'rt' && !renamed) detail(true);
  };
  const doc = () => {
    let d;
    if (rawOn) { try { d = JSON.parse(raw.value); } catch (e) { toast('That is no JSON: ' + e.message, 'bad'); return null; } }
    else {
      d = fields.changes();
      const n = nameIn.value.trim();
      if (n !== r.name) {
        if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/.test(n)) { toast('A name is letters, digits, - _ and ., up to 128, not beginning with a dot', 'bad'); return null; }
        d.name = n;
      }
    }
    renamed = typeof d.name === 'string' && d.name !== r.name ? d.name : '';
    return d;
  };
  // Stopped, saved and started again, for what a running runtime refuses or takes only at a start.
  const cycle = async d => {
    // The daemon stops it, saves and starts it again, so a page reached through the very runtime being restarted
    // cannot be cut off between the three -- which left an entrance proxy stopped and unchanged.
    const out = await run('import', r.name, '--restart', JSON.stringify(d));
    if (out.code) { toast('Not saved: ' + (out.out || '').trim(), 'bad', 9000); poll(); return; }
    done(r.name + ' saved and restarted');
  };
  const save = async restart => {
    const d = doc(); if (!d) return;
    if (!Object.keys(d).length) { L.close(); return; }
    if (restart && running) return cycle(d);
    const out = await run('import', r.name, JSON.stringify(d));
    if (!out.code) {
      const later = running ? Object.keys(d).filter(k => !LIVE.has(k)) : [];
      if (!later.length) return done(r.name + ' saved');
      // Saved, and some of it waits for a start: offered now rather than left to be found later.
      if (await ask({ title: 'Restart ' + r.name + ' now?', text: 'Saved. ' + later.join(', ') + (later.length === 1 ? ' takes' : ' take') + ' effect at the next start; a restart drops its connections.', ok: 'Restart now' })) {
        const b = await run('restart', r.name);
        if (b.code) { toast((b.out || 'Restart failed').trim(), 'bad', 7000); poll(); return; }
        return done(r.name + ' saved and restarted');
      }
      return done(r.name + ' saved; the rest at its next start');
    }
    const why = (out.out || 'Failed').trim();
    // What a running runtime may not change is offered as a stop, a save and a start.
    if (running && /while running|stop it first|stop, import, and start/.test(why)) {
      if (await ask({ title: 'Stop ' + r.name + ' to change this?', text: why.split('\n')[0] + '. It can be stopped, saved and started again now; its connections drop.', ok: 'Stop, save and start' })) return cycle(d);
      return;
    }
    toast(why.split('\n').slice(0, 3).join(' '), 'bad', 7000);
  };
  const L = modal('Edit ' + r.name, [el('p', { class: 'mut', style: 'font-size:12.5px;margin-top:0', text: running ? 'Only what you change is sent. Limits take effect at once; a field marked restart waits for the next start, which Save & restart does now.' : 'Only what you change is sent; it takes effect at the next start.' }), nameBox, fields.box, rawBox],
    [toggle, el('span', { style: 'flex:1' }), btn(null, 'Cancel', () => L.close()), running ? btn('restart', 'Save & restart', () => save(true), '') : null, btn(null, 'Save', () => save(false), 'pri')], true);
}

// ─── a tunnel edge's agents and shares ──────────────────────────────────────
// A service as list writes it: name[=auth] for HTTP, name:[address:]port for TCP, the same with /udp for UDP; an
// auth may hold a colon of its own, and a port never has an =.
const svcKind = s => s.includes('=') ? 'http' : s.endsWith('/udp') ? 'udp' : s.includes(':') ? 'tcp' : 'http';
function copyText(text, what) {
  const ok = () => toast(what + ' copied');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(ok, () => toast('Copy it from the box', 'bad'));
  else toast('Copy it from the box', 'bad');
}
// The services of an agent, to invite one or to change them: HTTP, TCP and UDP, each a comma list.
function servicesForm(have) {
  const of = k => have.filter(x => svcKind(x) === k).map(x => k === 'udp' ? x.slice(0, -4) : x).join(', ');
  const field = (label, ph, help, v) => { const i = el('input', { class: 'inp', placeholder: ph, spellcheck: 'false', autocomplete: 'off' }); i.value = v;
    return [i, el('label', { class: 'fld2' }, el('span', {}, el('b', { text: label, style: 'font-weight:600;color:var(--fg)' })), i, el('div', { class: 'h', text: help }))]; };
  const [h, hb] = field('HTTP', 'home=idp:auth, nas', 'Reached at <name> beside the edge; =<auth> asks visitors for it, as a proxy’s --auth.', of('http'));
  const [t, tb] = field('TCP', 'mc:25565, nas:127.0.0.1:9000', 'A port on the edge each, on 127.0.0.1 alone for the edge’s own runtimes.', of('tcp'));
  const [u, ub] = field('UDP', 'bedrock:19132', 'A UDP port on the edge each, every visitor a flow of its own.', of('udp'));
  const words = () => { const w = []; for (const [f, i] of [['--http', h], ['--tcp', t], ['--udp', u]]) { const v = i.value.split(/[\s,]+/).filter(Boolean).join(','); if (v) w.push(f, v); } return w; };
  return { box: el('div', { class: 'form' }, hb, tb, ub), words, names: () => [h, t, u].flatMap(i => i.value.split(/[\s,]+/).filter(Boolean)).map(x => x.split(/[=:]/)[0]) };
}
// What an edge holds: its agents, with their services changed or the agent revoked, an invitation for a new one, and
// the ports people share at it now.
async function tunnelDlg(r) {
  // Where agents dial it: a name the entrance routes to it, else its own --domain, else for the person to fill in.
  const own = shown && shown.name === r.name && shown.conf ? String(shown.conf.domain || '').split(',').map(x => x.trim()).find(x => x.includes('.') && !x.startsWith('*')) : '';
  const edge = r.name, host = (hosts[edge] || [])[0] || own || '';
  // Services are named beside the edge, as the edge's routes name them; an edge named as a whole domain has none.
  const beside = host.split('.').length > 2 ? host.slice(host.indexOf('.')) : '';
  const body = el('div');
  const L = modal('Agents and shares of ' + edge, [body], [el('span', { style: 'flex:1' }), btn(null, 'Close', () => L.close())], true);
  const act = async (args, said) => { const x = await run('tunnel', edge, ...args); if (x.code || (x.out || '').startsWith('error')) { toast((x.out || 'Failed').trim(), 'bad', 8000); return null; } if (said) toast(said); return x.out || ''; };
  const editDlgFor = (name, have) => {
    const f = servicesForm(have);
    const D = modal('Services of ' + name, [el('p', { class: 'mut', style: 'font-size:12.5px;margin-top:0', text: 'What the edge serves for this agent; its key is kept, and what it offers at home is set where it runs.' }), f.box],
      [el('span', { style: 'flex:1' }), btn(null, 'Cancel', () => D.close()), btn(null, 'Save', async () => { if (await act(['set', name, ...f.words()], name + '’s services saved') !== null) { D.close(); paint(); } }, 'pri')], true);
  };
  const inviteDlg = () => {
    const name = el('input', { class: 'inp', placeholder: 'pi', spellcheck: 'false', autocomplete: 'off' });
    const f = servicesForm([]);
    const out = el('div');
    const D = modal('Invite an agent to ' + edge, [el('div', { class: 'form' }, el('label', { class: 'fld2' }, el('span', {}, el('b', { text: 'Name', style: 'font-weight:600;color:var(--fg)' })), name, el('div', { class: 'h', text: 'Lower-case letters, digits and -, as the machine is known.' }))), f.box, out],
      [el('span', { style: 'flex:1' }), btn(null, 'Close', () => D.close()), btn('plus', 'Invite', async () => {
        const n = name.value.trim(); if (!n) { toast('An agent needs a name', 'bad'); return; }
        const inv = (await act(['invite', n, ...f.words()]) || '').trim(); if (!inv) return;
        // What to run on the machine at home, its offers to be pointed at the ports the services are there.
        const cmd = 'socketley create tunnel ' + n + ' --mode agent --to https://' + (host || 'EDGE-ADDRESS') + ' --join ' + inv + ' --offer ' + f.names().map(x => x + '=127.0.0.1:PORT').join(',') + ' -s';
        const box = el('textarea', { class: 'inp', readonly: true, spellcheck: 'false', rows: '3', style: 'height:auto;min-height:0;font-family:var(--mono);font-size:12px' }); box.value = cmd;
        out.textContent = '';
        out.append(el('p', { class: 'mut', style: 'font-size:12.5px', text: 'Run this on the machine at home, each PORT the one the service listens on there; the invitation is used once and holds 24 hours.' }), box,
          el('div', { class: 'acts', style: 'margin-top:8px' }, btn('copy', 'Copy command', () => copyText(cmd, 'Command')), btn('copy', 'Copy invitation', () => copyText(inv, 'Invitation'))));
        paint();
      }, 'pri')], true);
  };
  const paint = async () => {
    const [a, s] = await Promise.all([run('tunnel', edge, 'list'), run('tunnel', edge, 'shares')]);
    body.textContent = '';
    body.append(el('div', { class: 'fsec', style: 'cursor:default' }, el('span', { text: 'Agents' })));
    const T = el('table', { class: 'mtbl' });
    T.append(el('tr', {}, ...['Agent', 'Services', ''].map(t => el('th', { text: t }))));
    const rows = a.code ? [] : (a.out || '').split('\n').filter(Boolean).map(l => l.split('\t'));
    for (const [name, state, svcs] of rows) {
      const have = (svcs || '').split(',').filter(Boolean);
      const chip = x => { const k = svcKind(x), n = x.split(/[=:]/)[0];
        return k === 'http' && beside ? el('a', { class: 'chip', href: 'https://' + n + beside + '/', target: '_blank', rel: 'noopener', title: x, text: 'http ' + n })
          : el('span', { class: 'chip', title: x, text: k + ' ' + (k === 'http' ? x : x.replace(/\/udp$/, '')) }); };
      T.append(el('tr', {}, el('td', {}, el('b', { text: name }), el('div', { class: state === 'joined' ? 'dim' : 'mut', style: 'font-size:12px', text: state })),
        el('td', { class: 'w' }, el('div', { style: 'display:flex;flex-wrap:wrap;gap:6px' }, ...have.map(chip))),
        el('td', { style: 'white-space:nowrap' }, btn('edit', 'Services', () => editDlgFor(name, have), 'sm'), ' ',
          btn('trash', 'Revoke', async () => { if (!await ask({ title: 'Revoke ' + name + '?', text: 'Its link is cut at once and its services are served no more; it joins again only with a new invitation.', ok: 'Revoke', danger: true })) return; if (await act(['revoke', name], name + ' revoked') !== null) paint(); }, 'sm bad'))));
    }
    if (!rows.length) T.append(el('tr', {}, el('td', { class: 'mut', colspan: '3', text: a.code ? (a.out || 'The agents could not be read').trim() : 'No agent yet: invite one, or run socketley tunnel join on the machine at home.' })));
    body.append(T, el('div', { class: 'acts', style: 'margin:10px 0 4px' }, btn('plus', 'Invite an agent', inviteDlg, 'pri')));
    body.append(el('div', { class: 'fsec', style: 'cursor:default' }, el('span', { text: 'Shares' })));
    const S = el('table', { class: 'mtbl' });
    S.append(el('tr', {}, ...['Address', 'Who may visit', 'Shared by', 'Until'].map(t => el('th', { text: t }))));
    const shares = s.code ? [] : (s.out || '').split('\n').filter(Boolean).map(l => l.split('\t'));
    for (const [name, who, by, until] of shares)
      S.append(el('tr', {}, el('td', { class: 'w', style: 'font-family:var(--mono)' }, beside ? el('a', { href: 'https://' + name + beside + '/', target: '_blank', rel: 'noopener', text: name + beside, style: 'color:var(--fg)' }) : el('span', { text: name })),
        el('td', { text: who === 'public' ? 'everyone' : 'those signed in' }), el('td', { text: by }), el('td', { text: new Date(+until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) })));
    if (!shares.length) S.append(el('tr', {}, el('td', { class: 'mut', colspan: '4', text: 'Nothing shared now; socketley tunnel share <edge> <port> shares a port of a machine, until Ctrl+C.' })));
    body.append(S);
  };
  paint();
}

// The fields of `type`, sectioned as the schema says; `conf` fills them for an edit.
function form(type, conf, editing, running) {
  const box = el('div');
  // What a running runtime takes at once; the rest of an edit waits for its next start, and says so.
  const LIVE = new Set((schema && schema.live) || []);
  const vals = new Map();
  const sections = new Map();
  // A tunnel being edited is an edge or an agent already, and the other's fields are ones it refuses.
  const other = type === 'tunnel' && editing && conf ? (conf.mode === 'agent' ? TUNNEL_EDGE : TUNNEL_AGENT) : null;
  for (const f of schema.flags) {
    if (f.hidden || !f.types.includes(type)) continue;
    if (editing && (!f.key || f.flag === '-s')) continue;
    if (other && other.has(f.flag)) continue;
    if (!sections.has(f.section)) sections.set(f.section, []);
    sections.get(f.section).push(f);
  }
  const OPEN = new Set(['Basics', 'Network', TYPES[type] ? TYPES[type][1] : '', 'Server', 'Client', 'Proxy', 'Cache', 'Storage', 'DNS', 'Sync', 'Identity', 'MQTT', 'Metrics', 'MCP', 'Web']);
  // Basics first, then what only this type has, then what every type has.
  const COMMON = ['Basics', 'Network', 'TLS', 'Limits', 'Output'];
  const order = [...sections.keys()].sort((a, b) => (a === 'Basics' ? -1 : b === 'Basics' ? 1 : COMMON.includes(a) - COMMON.includes(b)));
  for (const sec of order) {
    const fs = sections.get(sec);
    const grid = el('div', { class: 'form' });
    let open = OPEN.has(sec) || (editing && fs.some(f => conf && conf[f.key] != null));
    const head = el('div', { class: 'fsec', onclick: () => { open = !open; grid.hidden = !open; head.firstChild.textContent = (open ? '▾ ' : '▸ ') + sec; } }, el('span', { text: (open ? '▾ ' : '▸ ') + sec }));
    grid.hidden = !open;
    for (const f of fs) {
      const key = f.key;
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
      const later = editing && running && key && !LIVE.has(key);
      grid.append(el('label', { class: 'fld2', title: f.flag }, el('span', {}, el('b', { text: f.label, style: 'font-weight:600;color:var(--fg)' }), el('code', { class: 'dim', style: 'font-size:11px', text: f.flag }),
        later ? el('span', { class: 'chip', style: 'font-size:10.5px;margin-left:6px;padding:1px 7px', title: 'A running runtime takes this at its next start', text: key === 'lua_script' ? 'reload' : 'restart' }) : null), input, f.kind !== 'switch' ? el('div', { class: 'h', text: f.help }) : null));
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
  for (const n of [name, f.box]) { n.addEventListener('input', paint); n.addEventListener('change', paint); }
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
  if (s.user) { me = { user: s.user, idp_logout: s.idp_logout }; start(); return; }
  if (s.idp_login) { $('#lidp').href = s.idp_login; $('#lidp').hidden = $('#lor').hidden = false; $('#lsb').classList.remove('pri'); }
  $('#login').hidden = false; $('#lk').focus();
})();
</script>
</body>
</html>)HTML";
