'use strict';
// The documentation: reference.json is generated from man/socketley.1 and runtime_schema.cpp, bench.json from the
// benchmark runs, and content/*.html is the prose written for this site, which places the generated parts with
// <x-man>, <x-entry>, <x-flags>, <x-bench> and <x-cards>.

Object.assign(P, {
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"/>',
  client: '<rect x="4" y="5" width="16" height="11" rx="2"/><path d="M2 19.5h20"/>',
  proxy: '<path d="M3 12h6l4-6h8M13 18h8M9 12l4 6"/><path d="m18 3 3 3-3 3M18 15l3 3-3 3"/>',
  cache: '<path d="M13 2.5 4.5 14H11l-1 7.5L18.5 10H12z"/>',
  db: '<path d="M8 3H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h1M16 3h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-1"/>',
  dns: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  idp: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M16.5 6.5l3 3M14.5 8.5l2 2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/>',
  mqtt: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19 5a10 10 0 0 1 0 14M5 19A10 10 0 0 1 5 5"/>',
  metrics: '<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/>',
  tunnel: '<path d="M3 20v-9a9 9 0 0 1 18 0v9"/><path d="M7.5 20v-8a4.5 4.5 0 0 1 9 0v8M2 20h20"/>',
  mcp: '<rect x="4" y="6" width="16" height="12" rx="3"/><path d="M9 11h.01M15 11h.01M9.5 14.5h5M12 6V3.5M8 21h8"/>',
  storage: '<ellipse cx="12" cy="5.5" rx="8" ry="2.8"/><path d="M4 5.5v13c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8v-13M4 12c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8"/>',
  term: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  book: '<path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v17H6.5A2.5 2.5 0 0 0 4 21.5z"/><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>',
  rocket: '<path d="M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2M9 15l-3-3c1-4 5-9 12-9 0 7-5 11-9 12z"/><circle cx="15" cy="9" r="1.5"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  nodes: '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M11 7.3 6.3 15.7M13 7.3l4.7 8.4M7.5 18h9"/>',
  bars: '<path d="M5 20V11M10.5 20V5M16 20v-6M21.5 20H2.5"/>',
  pkg: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>',
});

const RT = [
  ['server', 'TCP, UDP, WebSocket and HTTP on one port, answered by Lua or by a built-in path', 'nginx'],
  ['client', 'Dials a server and holds the connection: TCP, UDP or a unix socket, over TLS, reconnecting', ''],
  ['proxy', 'HTTP and TCP reverse proxy: routes by name and path, health checks, retries, mTLS, FastCGI', 'HAProxy, nginx'],
  ['cache', 'In-memory store on the Redis protocol: strings, lists, sets, hashes, sorted sets, streams, pub/sub', 'Redis, Valkey'],
  ['storage', 'S3 object storage over a directory, with versioning, replication, a web drive and git', 'MinIO'],
  ['db', 'JSON documents owned by accounts, over HTTP, with indexes, queries, replicas and backups', 'MongoDB, PocketBase'],
  ['dns', 'Authoritative name server for its zones, over UDP and TCP, with DNSSEC and transfers', 'NSD, Knot'],
  ['idp', 'OpenID Connect provider with its own accounts, second factors, passkeys and SSH certificates', 'Keycloak'],
  ['mail', 'Mail server: SMTP, submission, IMAP, POP3, JMAP and webmail, mailboxes in a storage', ''],
  ['mqtt', 'MQTT 3.1, 3.1.1 and 5.0 broker on TCP, TLS and WebSocket, with sessions and rules', 'Mosquitto'],
  ['metrics', 'Time series for years, answered with PromQL over the Prometheus API, with alert rules and logs', 'Prometheus, VictoriaMetrics'],
  ['sync', 'One job that carries a directory to a storage, from it, or both ways', 'rclone'],
  ['tunnel', 'Makes a machine without an address of its own reachable through an edge it dials', 'frp'],
  ['mcp', 'A Model Context Protocol server: the tools, resources and prompts its script declares, for AI clients', ''],
];
const RTI = Object.fromEntries(RT.map(r => [r[0], r]));
// Why a runtime has no comparison on the benchmarks page.
const NOBENCH = {
  client: 'A client runtime holds one connection to somebody else\'s server; there is no other program doing that to set beside it.',
  mail: 'Postfix and Dovecot start their master processes as root, which the measuring machine does not give; not measured.',
  mcp: 'No MCP server is established enough to measure against on equal terms.',
};

const NAV = [
  ['Start', [['', 'Overview', 'home'], ['install', 'Install', 'download'], ['tour', 'Ten-minute tour', 'rocket'], ['concepts', 'Concepts', 'layers']]],
  ['Runtimes', RT.map(r => ['rt/' + r[0], r[0], r[0]])],
  ['Guides', [['lua', 'Lua scripting', 'code'], ['deploy', 'Deployment', 'shield'], ['cluster', 'Cluster', 'nodes'], ['sdk', 'C++ SDK', 'pkg'], ['examples', 'Examples', 'folder']]],
  ['Reference', [['cli', 'CLI', 'term'], ['flags', 'All flags', 'list'], ['env', 'Environment & files', 'gear'], ['man', 'Manual', 'book']]],
  ['Performance', [['bench', 'Benchmarks', 'bars']]],
];
const TITLES = Object.fromEntries(NAV.flatMap(g => g[1]).map(([h, t]) => [h, t]));

let REF = null, BENCH = null;
const SEC = new Map();      // section id -> section
const FRAG = new Map();     // section id -> parsed DocumentFragment of its html
const PAGE = new Map();     // content path -> html

const KEEP = new Set(['DNS', 'IDP', 'DB', 'MQTT', 'TLS', 'SDK', 'C++', 'IPC', 'JSON', 'HTTP', 'RESP', 'S3', 'CLI', 'API', 'CORS', 'IAM', 'SSE', 'UDP', 'TCP', 'MTLS']);
// The man page's section titles are capitals; on the page they read as a sentence with their acronyms kept.
const nice = t => t === t.toUpperCase() ? t.split(' ').map((w, i) => KEEP.has(w) ? w : w === 'LUA' ? 'Lua' : i ? w.toLowerCase() : w[0] + w.slice(1).toLowerCase()).join(' ') : t;
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (v, unit) => {
  if (v == null) return '–';
  if (unit === 'µs' || unit === 'ms' || unit === 's') return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' ' + unit;
  if (unit === 'B' || unit === 'MB' || unit === 'KB') return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + unit;
  const a = Math.abs(v);
  const n = a >= 1e9 ? (v / 1e9).toFixed(2) + ' G' : a >= 1e6 ? (v / 1e6).toFixed(2) + ' M' : a >= 1e4 ? (v / 1e3).toFixed(0) + ' K' : a >= 1e3 ? (v / 1e3).toFixed(1) + ' K' : v.toFixed(a >= 100 ? 0 : 1);
  return n + (unit ? ' ' + unit.replace(/^ops\/s$/, '/s') : '');
};

async function getJSON(u) { const r = await fetch(u); if (!r.ok) throw new Error(u + ': ' + r.status); return r.json(); }
async function content(p) {
  if (PAGE.has(p)) return PAGE.get(p);
  const r = await fetch('content/' + p + '.html');
  const h = r.ok ? await r.text() : '';
  PAGE.set(p, h);
  return h;
}

// ─── the man page ──────────────────────────────────────────────────────────────────────────────────────────────────
const TITLE2SEC = new Map();
function frag(id) {
  if (!FRAG.has(id)) {
    const t = document.createElement('template');
    t.innerHTML = SEC.get(id)?.html || '';
    FRAG.set(id, t.content);
  }
  return FRAG.get(id);
}
// Bold section names in the text become links to the section, as a reader of the man page would look them up.
function linkify(root) {
  for (const b of root.querySelectorAll('b')) {
    const t = b.textContent.trim().replace(/\s+/g, ' ');
    const sid = TITLE2SEC.get(t);
    if (sid && !b.closest('a,code')) {
      const a = el('a', { href: '#/man/' + sid }); b.replaceWith(a); a.append(b);
    }
  }
  for (const p of root.querySelectorAll('pre.code')) addCopy(p);
  nowrapFlags(root);
  return root;
}
// A short flag is not broken after its hyphens.
function nowrapFlags(root) {
  for (const c of root.querySelectorAll('code')) if (c.textContent.length < 32 && /^-/.test(c.textContent)) c.classList.add('nw');
}
function addCopy(p) {
  if (p.querySelector('.cp')) return;
  const b = el('button', { class: 'ib cp', title: 'Copy', 'aria-label': 'Copy', onclick: e => {
    e.stopPropagation();
    navigator.clipboard?.writeText(p.innerText.replace(/\n?$/, '')).then(() => toast('Copied'), fail);
  } }, ico('copy'));
  p.append(b);
}
function manBody(id) {
  const d = el('div', { class: 'man' });
  d.append(frag(id).cloneNode(true));
  return linkify(d);
}
function entryNode(ref) {
  const [sid] = ref.split('/');
  const n = frag(sid).querySelector('[id="' + CSS.escape(ref) + '"]');
  if (!n) return null;
  const d = el('div', { class: 'man' });
  const c = n.cloneNode(true);
  c.querySelector('details')?.setAttribute('open', '');
  d.append(c);
  return linkify(d);
}
function subsOf(id) { return REF.sections.filter(s => s.parent === id && s.level === 2); }
function foldSec(s, open) {
  const n = s.entries.length;
  const d = el('details', { class: 'msec', id: 'sec:' + s.id },
    el('summary', {}, ico('chev'), el('span', { text: nice(s.title) }),
      el('span', { class: 'n', text: n ? n + (n === 1 ? ' entry' : ' entries') : Math.max(1, Math.round(s.words / 220)) + ' min read' })));
  if (open) d.open = true;
  let filled = false;
  const fill = () => { if (!filled) { filled = true; d.append(manBody(s.id)); } };
  d.addEventListener('toggle', () => d.open && fill());
  if (open) fill();
  return d;
}

// ─── flags ─────────────────────────────────────────────────────────────────────────────────────────────────────────
const LETTER = { server: 'S', client: 'C', proxy: 'P', cache: 'K', storage: 'T', dns: 'D', sync: 'Y', idp: 'I', db: 'B', mqtt: 'M', mail: 'E', tunnel: 'U', metrics: 'R', mcp: 'X' };
function flagRow(f, rt, opts = {}) {
  const ref = rt ? f.ref[rt] : (Object.values(f.ref).find(Boolean) || '');
  const extra = el('div', {},
    el('div', { class: 'lb', text: f.label }),
    el('div', { class: 'hp', text: f.help }),
    f.choices.length ? el('div', { class: 'ch' }, f.choices.map(c => el('span', { text: c }))) : null,
    f.placeholder && !f.choices.length ? el('div', { class: 'eg', text: 'e.g. ' + f.flag + (f.kind === 'switch' ? '' : ' ' + f.placeholder) }) : null);
  const tr = el('tr', { class: 'f', id: 'flag:' + (rt || 'all') + ':' + f.flag, 'data-q': (f.flag + ' ' + f.aliases.join(' ') + ' ' + f.label + ' ' + f.help + ' ' + f.group).toLowerCase() },
    el('td', { class: 'fl' }, el('code', { text: f.flag }), f.aliases.length ? el('span', { class: 'al', text: f.aliases.join(' ') }) : null),
    el('td', {}, el('span', { class: 'kind', text: f.kind })),
    el('td', {}, extra),
    opts.matrix ? el('td', { class: 'hp2' }, el('div', { class: 'tmx' }, RT.map(([t]) => el('i', { class: f.types.includes(t) ? 'on' : '', title: t, text: LETTER[t] })))) : null);
  let x = null;
  tr.onclick = () => {
    if (x) { x.remove(); x = null; return; }
    const n = ref ? entryNode(ref) : null;
    x = el('tr', { class: 'x' }, el('td', { colspan: opts.matrix ? 4 : 3 },
      n || el('p', { class: 'mut', text: 'No entry of its own in the manual.' }),
      ref ? el('p', { class: 'src' }, el('a', { href: '#/man/' + ref, text: 'In the manual: ' + nice(SEC.get(ref.split('/')[0])?.title || '') })) : null));
    tr.after(x);
  };
  return tr;
}
function flagTable(rt, opts = {}) {
  const rows = REF.flags.filter(f => !f.hidden && (!rt || f.types.includes(rt)));
  const box = el('div', {});
  const q = el('input', { class: 'inp', placeholder: rt ? 'Filter ' + rows.length + ' flags of ' + rt : 'Filter ' + rows.length + ' flags', spellcheck: 'false' });
  const cnt = el('span', { class: 'n' });
  box.append(el('div', { class: 'fbar' }, q, cnt));
  const groups = [];
  for (const f of rows) { let g = groups.find(g => g[0] === f.group); if (!g) groups.push(g = [f.group, []]); g[1].push(f); }
  const parts = [];
  for (const [g, fs] of groups) {
    const h = el('div', { class: 'fgrp', text: g });
    const t = el('table', { class: 'ftbl' }, el('tbody', {}, fs.map(f => flagRow(f, rt, opts))));
    parts.push([h, t]); box.append(h, t);
  }
  const apply = () => {
    const s = q.value.trim().toLowerCase(); let n = 0;
    for (const [h, t] of parts) {
      let any = 0;
      for (const tr of t.querySelectorAll('tr.f')) { const on = !s || tr.dataset.q.includes(s); tr.hidden = !on; if (tr.nextSibling?.classList?.contains('x')) tr.nextSibling.hidden = !on; any += on; }
      h.hidden = t.hidden = !any; n += any;
    }
    cnt.textContent = s ? n + ' of ' + rows.length : rows.length + ' flags';
  };
  q.oninput = apply; apply();
  box.filter = v => { q.value = v; apply(); };
  return box;
}

// ─── benchmarks ────────────────────────────────────────────────────────────────────────────────────────────────────
function ratioBar(r, lo, hi) {
  const L = Math.log2;
  const x = v => ((L(v) - L(lo)) / (L(hi) - L(lo)) * 100).toFixed(1) + '%';
  const b = el('div', { class: 'rbar' });
  b.innerHTML = '<div class="ax" style="left:' + x(1) + '"></div><div class="w" style="left:' + x(Math.max(lo, r[1])) + ';width:calc(' + x(Math.min(hi, r[2])) + ' - ' + x(Math.max(lo, r[1])) + ')"></div>' +
    '<div class="m' + (r[0] < 1 ? ' dn' : '') + '" style="left:' + x(Math.min(hi, Math.max(lo, r[0]))) + '"></div>';
  return b;
}
function benchSet(s) {
  const arms = s.arms;
  const rs = s.rows.flatMap(r => (r.r || []).flat()).filter(v => v > 0);
  const lo = Math.min(0.5, ...rs) * 0.9, hi = Math.max(2, ...rs) * 1.1;
  const head = el('tr', {}, el('th', { text: s.cols?.[0] || 'Test' }), arms.map(a => el('th', { text: a })),
    arms.slice(1).map((a, k) => el('th', { text: arms.length > 2 ? '× ' + a.split(' ')[0] : 'socketley ÷ ' + a.split(' ')[0] })),
    el('th', { class: 'bar', text: 'ratio' }));
  const body = s.rows.map(r => el('tr', {}, el('td', { text: r.name }),
    arms.map((a, k) => el('td', { class: k ? '' : 'us' }, fmt(r.v[k], r.unit || s.unit),
      r.cpu?.[k] != null ? el('div', { class: 'cpu', text: r.cpu[k].toFixed(2) + ' cores' }) : null)),
    arms.slice(1).map((a, k) => {
      const q = r.r?.[k];
      if (!q) return el('td', { text: '–' });
      const cls = q[1] > 1 ? 'up' : q[2] < 1 ? 'dn' : 'eq';
      return el('td', { class: 'rt ' + cls }, q[0].toFixed(2) + '×', el('span', { class: 'ci', text: '[' + q[1].toFixed(2) + ', ' + q[2].toFixed(2) + ']' }));
    }),
    el('td', { class: 'bar' }, r.r?.[0] ? ratioBar(r.r[0], lo, hi) : null)));
  const meta = [s.tool, s.passes ? s.passes + ' interleaved passes' : '', s.pin, s.date, s.commit ? 'socketley ' + s.commit : ''].filter(Boolean);
  return el('div', { class: 'bset', id: 'bench:' + s.id },
    el('h3', {}, el('span', { text: s.title }), s.vs?.length ? el('span', { class: 'vs', text: 'against ' + s.vs.join(', ') }) : null),
    el('div', { class: 'meta', text: meta.join(' · ') }),
    el('div', { class: 'mtw' }, el('table', { class: 'btbl' }, el('thead', {}, head), el('tbody', {}, body))),
    s.note ? (() => { const p = el('p', { class: 'bnote' }); p.innerHTML = s.note; return p; })() : null);
}
function benchFor(rt) {
  const sets = (BENCH?.sets || []).filter(s => !rt || s.runtime === rt);
  const box = el('div', {});
  if (!sets.length) {
    box.append(el('div', { class: 'bnone', text: NOBENCH[rt] || (RTI[rt]?.[2] ? 'Not measured on the current build yet. The comparison planned is against ' + RTI[rt][2] + '.' : 'No comparison is published for this runtime.') }));
    return box;
  }
  box.append(el('div', { class: 'legend' },
    el('span', {}, el('b', { text: 'Ratio' }), ' median of per-pass ratios, [range across passes]'),
    el('span', { class: 'ok2', text: 'green: every pass ahead' }), el('span', { class: 'mut', text: 'grey: range spans 1.00×' }), el('span', { class: 'bad2', text: 'red: every pass behind' })));
  for (const s of sets) box.append(benchSet(s));
  return box;
}

// ─── pages ─────────────────────────────────────────────────────────────────────────────────────────────────────────
async function place(root) {
  for (const x of root.querySelectorAll('x-man')) {
    const id = x.getAttribute('s'), s = SEC.get(id);
    if (!s) { x.replaceWith(el('p', { class: 'bad2', text: 'missing section ' + id })); continue; }
    const out = el('div', {});
    if (x.hasAttribute('fold')) out.append(foldSec(s, x.hasAttribute('open')));
    else if (!x.hasAttribute('subs-only')) out.append(manBody(id));
    if (x.hasAttribute('subs') || x.hasAttribute('subs-only')) for (const c of subsOf(id)) out.append(foldSec(c, false));
    x.replaceWith(out);
  }
  for (const x of root.querySelectorAll('x-entry')) x.replaceWith(entryNode(x.getAttribute('e')) || el('p', { class: 'bad2', text: 'missing entry ' + x.getAttribute('e') }));
  for (const x of root.querySelectorAll('x-flags')) x.replaceWith(flagTable(x.getAttribute('rt') || '', { matrix: !x.getAttribute('rt') }));
  for (const x of root.querySelectorAll('x-bench')) x.replaceWith(benchFor(x.getAttribute('rt') || ''));
  for (const x of root.querySelectorAll('x-cards')) x.replaceWith(rtCards());
  for (const x of root.querySelectorAll('x-glance')) x.replaceWith(glance());
  for (const x of root.querySelectorAll('x-index')) {
    const sid = x.getAttribute('s');
    const top = (SEC.get(sid)?.entries || []).filter(e => !/^(-|type$|name$|port$|path$)/.test(e.term));
    x.replaceWith(el('div', { class: 'chips' }, top.map(e => el('a', { href: '#/man/' + sid + '/' + e.id, title: e.summary, onclick: ev => {
      const n = document.getElementById(sid + '/' + e.id);
      if (n) { ev.preventDefault(); n.scrollIntoView({ block: 'start' }); n.classList.add('hl'); }
    } }, el('span', {}, el('b', { text: e.term.split(/\s+[\[<|]/)[0].slice(0, 40) }))))));
  }
  for (const p of root.querySelectorAll('pre.code')) addCopy(p);
  nowrapFlags(root);
}
// One row of each runtime's benchmarks, the one its set names as its headline, chosen before the numbers were in.
function glance() {
  const tiles = el('div', { class: 'tiles' });
  for (const s of BENCH?.sets || []) {
    if (s.headline == null) continue;
    const r = s.rows[s.headline], q = r?.r?.[0];
    if (!q) continue;
    tiles.append(el('a', { class: 'tile', href: '#/bench/' + s.runtime },
      el('div', { class: 'k', text: s.runtime + ' · ' + r.name }),
      el('div', { class: 'v ' + (q[1] > 1 ? 'ok2' : q[2] < 1 ? 'bad2' : 'eq2') }, q[0].toFixed(2) + '×'),
      el('div', { class: 's', text: '[' + q[1].toFixed(2) + ', ' + q[2].toFixed(2) + '] against ' + s.arms[1] }),
      s.caveat ? el('div', { class: 's', style: 'color:var(--warn)', text: s.caveat }) : null));
  }
  return tiles.children.length ? tiles : el('p', { class: 'mut', text: 'Benchmarks are being measured.' });
}
function rtCards() {
  return el('div', { class: 'cards' }, RT.map(([id, d, vs]) => el('a', { class: 'tcard', href: '#/rt/' + id },
    el('b', {}, el('span', { class: 'hb' }, ico(id)), id), el('p', { text: d }), vs ? el('div', { class: 'ref', text: 'Benchmarked against ' + vs }) : null)));
}
function hero(kick, title, sub, chips = []) {
  return el('div', { class: 'hero' }, el('div', { class: 'kick', text: kick }), el('h1', { text: title }),
    sub ? el('p', { class: 'mut', style: 'margin:0 0 14px;max-width:760px;font-size:16px', text: sub }) : null,
    chips.length ? el('div', { class: 'stats' }, chips.map(c => el('span', { class: 'chip' }, el('span', { text: c })))) : null);
}
function sec(title, icon, id, ...kids) {
  return el('section', { class: 'sec', id: id || null }, el('h2', {}, el('span', { class: 'hb' }, ico(icon)), el('span', { text: title })), ...kids);
}
function prose(h) { const d = el('div', { class: 'prose' }); d.innerHTML = h; return d; }

async function pageHome(C) {
  const nflags = REF.flags.filter(f => !f.hidden).length;
  C.append(hero('Documentation', 'socketley', 'One Linux daemon and CLI for long-living network runtimes — servers, proxies, a Redis-compatible cache, S3 storage, documents, DNS, sign-in, MQTT, mail, metrics, tunnels and MCP — each its own process on io_uring, scripted in Lua, clustered across machines.',
    [RT.length + ' runtime types', nflags + ' flags', 'io_uring', 'Lua 5.1 / LuaJIT', 'Linux only']));
  C.append(prose(await content('home')));
  await place(C);
}
async function pageContent(C, name, title, kick, sub, icon) {
  C.append(hero(kick, title, sub));
  const p = prose(await content(name));
  C.append(p);
  await place(C);
}
async function pageRuntime(C, rt) {
  const r = RTI[rt]; if (!r) return notFound(C);
  const flags = REF.flags.filter(f => !f.hidden && f.types.includes(rt));
  const own = flags.filter(f => f.types.length === 1).length;
  C.append(hero('Runtime', rt, r[1], [flags.length + ' flags, ' + own + ' its own', r[2] ? 'benchmarked against ' + r[2] : 'no reference']));
  C.append(el('nav', { class: 'jump' }, ['Overview', 'Flags', 'Benchmarks', 'Manual'].map(t => el('a', { href: '#/rt/' + rt + '/' + t.toLowerCase(), text: t }))));
  const h = await content('rt/' + rt);
  C.append(sec('Overview', rt, 'overview', prose(h || '')));
  C.append(sec('Flags', 'list', 'flags', el('p', { class: 'mut', text: 'Every flag create and edit take for a ' + rt + ', grouped as the dashboard asks for them. Click a row for its whole entry in the manual.' }), el('x-flags', { rt })));
  C.append(sec('Benchmarks', 'bars', 'benchmarks', el('x-bench', { rt })));
  const top = REF.sections.find(s => s.id === rt + '-flags');
  C.append(sec('Manual', 'book', 'manual', el('p', { class: 'mut', text: 'The ' + nice(top.title) + ' section of socketley(1), with every subsection.' }), el('x-man', { s: top.id, fold: '', subs: '' })));
  await place(C);
}
async function pageFlags(C) {
  C.append(hero('Reference', 'All flags', 'Every flag of every runtime type, from the same table the dashboard builds its forms from. The squares say which types take it; a row opens its entry in the manual.'));
  C.append(el('div', { class: 'legend' }, RT.map(([t]) => el('span', {}, el('b', { text: LETTER[t] }), t))));
  C.append(el('x-flags', {}));
  await place(C);
}
async function pageMan(C, sid, eid) {
  if (!sid) {
    C.append(hero('Reference', 'Manual', 'socketley(1), whole: the manual page the code is kept against, here by section. Generated from man/socketley.1 at ' + REF.commit + ' (' + REF.date + ').'));
    const list = el('div', { class: 'cards' });
    for (const s of REF.sections.filter(s => s.level === 1)) {
      const subs = subsOf(s.id);
      list.append(el('a', { class: 'tcard', href: '#/man/' + s.id }, el('b', { text: nice(s.title) }),
        el('p', { text: (s.entries.length ? s.entries.length + ' entries · ' : '') + (subs.length ? subs.length + ' subsections · ' : '') + Math.max(1, Math.round((s.words + subs.reduce((a, c) => a + c.words, 0)) / 220)) + ' min' })));
    }
    C.append(list);
    return;
  }
  const s = SEC.get(sid); if (!s) return notFound(C);
  const parent = s.parent && s.parent !== s.id ? SEC.get(s.parent) : null;
  C.append(hero(parent ? nice(parent.title) : 'Manual', nice(s.title), ''));
  C.append(manBody(sid));
  for (const c of subsOf(sid)) C.append(el('h2', { style: 'margin:30px 0 10px', id: 'sec:' + c.id }, el('a', { href: '#/man/' + c.id, class: 'lnk', text: nice(c.title) })), manBody(c.id));
  if (eid) setTimeout(() => {
    const n = document.getElementById(sid + '/' + eid);
    if (n) { n.classList.add('hl'); n.querySelector('details')?.setAttribute('open', ''); n.scrollIntoView({ block: 'start' }); }
  }, 0);
}
async function pageBench(C, rt) {
  C.append(hero('Performance', 'Benchmarks', 'Each runtime against the server people would otherwise run, on one machine, in one run, the arms interleaved. Every figure carries the CPU it cost and the spread across passes.',
    BENCH?.box ? [BENCH.box.cpu, BENCH.box.vcpus + ' vCPUs', BENCH.box.mem, BENCH.box.os, 'Linux ' + BENCH.box.kernel] : []));
  C.append(prose(await content('bench')));
  const done = [...new Set((BENCH?.sets || []).map(s => s.runtime))];
  C.append(el('nav', { class: 'jump' }, RT.filter(r => done.includes(r[0])).map(([t]) => el('a', { href: '#/bench/' + t, text: t }))));
  for (const [t, , vs] of RT) {
    if (!done.includes(t)) continue;
    C.append(sec(t, t, 'b-' + t, benchFor(t)));
  }
  const left = RT.filter(r => !done.includes(r[0]));
  if (left.length) C.append(sec('Without a comparison', 'clock', 'b-left', el('ul', { class: 'prose' }, left.map(r => el('li', {}, el('b', { text: r[0] }), ': ' + (NOBENCH[r[0]] || 'not measured on the current build yet.'))))));
  await place(C);
  if (rt) setTimeout(() => document.getElementById('b-' + rt)?.scrollIntoView({ block: 'start' }), 0);
}
const REPO = 'https://github.com/HiImSmiley/Socketley/blob/main/';
async function pageExamples(C) {
  C.append(hero('Guide', 'Examples', 'Every script and program in the repository\'s examples/ and sdk/examples/, with what its head comment says it is. Each runs as its first lines describe.', [REF.examples.length + ' files']));
  const groups = new Map();
  for (const e of REF.examples) {
    const dir = e.path.split('/').slice(0, -1).join('/');
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir).push(e);
  }
  const q = el('input', { class: 'inp', placeholder: 'Filter ' + REF.examples.length + ' examples', spellcheck: 'false' });
  C.append(el('div', { class: 'fbar' }, q));
  const blocks = [];
  for (const [dir, es] of groups) {
    const t = el('table', { class: 'ftbl ex' }, el('tbody', {}, es.map(e => el('tr', { 'data-q': (e.path + ' ' + e.title + ' ' + e.summary).toLowerCase() },
      el('td', { class: 'fl' }, el('a', { href: REPO + e.path, target: '_blank', rel: 'noopener', class: 'lnk' }, el('code', { text: e.path.split('/').pop() }))),
      el('td', {}, el('div', { class: 'lb', text: e.title || '' }), e.summary ? el('div', { class: 'hp', text: e.summary }) : null)))));
    const h = el('div', { class: 'fgrp', text: dir });
    blocks.push([h, t]); C.append(h, t);
  }
  q.oninput = () => {
    const s = q.value.trim().toLowerCase();
    for (const [h, t] of blocks) { let n = 0; for (const tr of t.rows) { tr.hidden = !!s && !tr.dataset.q.includes(s); n += !tr.hidden; } h.hidden = t.hidden = !n; }
  };
}
function notFound(C) { C.append(el('div', { class: 'empty' }, ico('search', 'big'), el('h3', { text: 'Nothing here' }), el('p', {}, el('a', { href: '#/', class: 'lnk', text: 'Back to the overview' })))); }

const CONTENT = {
  install: ['Install', 'Start', 'From source, the install script or a Debian package; the daemon then runs as a systemd service.'],
  tour: ['Ten-minute tour', 'Start', 'Make a server, a cache and a proxy, script one of them, and look at all three.'],
  concepts: ['Concepts', 'Start', 'The daemon, its runtimes and the few rules every one of them follows.'],
  lua: ['Lua scripting', 'Guide', 'Callbacks per message, connection and request, the runtime methods a script calls, and what a script may not do.'],
  deploy: ['Deployment', 'Guide', 'Running socketley on a machine that matters: the service, permissions, TLS, state, backups and limits.'],
  cluster: ['Cluster', 'Guide', 'Daemons on several machines that see each other\'s runtimes, and the opt-in Raft mode.'],
  sdk: ['C++ SDK', 'Guide', 'Control a daemon, embed the engine, or attach a process of your own to a daemon.'],
  cli: ['CLI', 'Reference', 'Every command socketley takes, with its options.'],
  env: ['Environment & files', 'Reference', 'The variables the daemon and the CLI read, and where everything lives on disk.'],
};

// ─── routing ───────────────────────────────────────────────────────────────────────────────────────────────────────
async function route() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ''));
  const parts = h.split('/');
  const C = $('#content'); C.textContent = '';
  $('#side').classList.remove('open');
  const key = parts[0] === 'rt' ? 'rt/' + parts[1] : parts[0];
  for (const b of document.querySelectorAll('#side .nav[data-h]')) b.classList.toggle('on', b.dataset.h === key);
  const crumbs = $('#crumbs'); crumbs.textContent = '';
  crumbs.append(el('button', { onclick: () => go('') }, 'socketley'));
  if (key) { crumbs.append(ico('chev')); crumbs.append(el('button', { onclick: () => go(key) }, TITLES[key] || parts[parts.length > 1 ? 1 : 0])); }
  document.title = (TITLES[key] || (parts[0] === 'man' && nice(SEC.get(parts[1])?.title || '')) || 'Documentation') + ' · socketley';
  try {
    if (!key) await pageHome(C);
    else if (parts[0] === 'rt') await pageRuntime(C, parts[1]);
    else if (parts[0] === 'flags') await pageFlags(C);
    else if (parts[0] === 'man') await pageMan(C, parts[1], parts.slice(2).join('/'));
    else if (parts[0] === 'bench') await pageBench(C, parts[1]);
    else if (parts[0] === 'examples') await pageExamples(C);
    else if (CONTENT[parts[0]]) await pageContent(C, parts[0], ...CONTENT[parts[0]]);
    else notFound(C);
  } catch (e) { C.append(el('p', { class: 'bad2', text: String(e) })); }
  // A sub-path names a place on the page: a section, a flag, a subsection of the manual.
  const sub = parts[0] === 'rt' ? parts.slice(2).join('/') : '';
  const S = $('#scroll');
  if (sub.startsWith('flag/')) {
    const tr = document.getElementById('flag:' + parts[1] + ':' + sub.slice(5));
    if (tr) { tr.click(); tr.scrollIntoView({ block: 'center' }); tr.classList.add('sel'); }
  } else if (sub) document.getElementById(sub)?.scrollIntoView({ block: 'start' });
  else if (parts[0] !== 'man' || !parts[2]) S.scrollTop = 0;
}
function go(h) { location.hash = '#/' + h; }

// ─── search ────────────────────────────────────────────────────────────────────────────────────────────────────────
let INDEX = [];
function buildIndex() {
  INDEX = [];
  for (const [h, t] of NAV.flatMap(g => g[1])) INDEX.push({ k: 'page', t, d: CONTENT[h]?.[2] || RTI[t]?.[1] || '', h: '#/' + h });
  for (const f of REF.flags) {
    if (f.hidden) continue;
    const one = f.types.length === 1;
    INDEX.push({ k: 'flag', t: f.flag, a: f.aliases, d: f.label + ' — ' + f.help + ' · ' + (f.types.length > 4 ? f.types.length + ' types' : f.types.join(', ')),
      h: one ? '#/rt/' + f.types[0] + '/flag/' + f.flag : '#/man/' + (Object.values(f.ref).find(Boolean) || '') });
  }
  for (const e of REF.examples || []) INDEX.push({ k: 'example', t: e.path.split('/').pop(), d: e.title, h: REPO + e.path });
  for (const s of REF.sections) {
    INDEX.push({ k: 'manual', t: nice(s.title), d: s.parent && s.parent !== s.id ? nice(SEC.get(s.parent)?.title) : 'socketley(1)', h: '#/man/' + s.id });
    for (const e of s.entries) INDEX.push({ k: s.id.split('.')[0].replace(/-flags$/, '').replace('lua-configuration', 'lua').replace('commands', 'cmd').slice(0, 9), t: e.term, d: e.summary, h: '#/man/' + s.id + '/' + e.id });
  }
}
function search(q) {
  q = q.trim().toLowerCase(); if (!q) return [];
  const out = [];
  for (const it of INDEX) {
    const t = it.t.toLowerCase(); let s = 0;
    if (t === q || it.a?.includes(q)) s = 200;
    else if (t.startsWith(q)) s = 120;
    else if (t.includes(q)) s = 70;
    else if (it.d && it.d.toLowerCase().includes(q)) s = 20;
    if (!s) continue;
    if (it.k === 'page') s += 30; else if (it.k === 'flag') s += 15; else if (it.k === 'manual') s += 10;
    out.push([s - Math.min(it.t.length, 60) / 100, it]);
  }
  return out.sort((a, b) => b[0] - a[0]).slice(0, 40).map(x => x[1]);
}
function setupSearch() {
  const q = $('#q'), box = $('#srch');
  let res = null, cur = 0, hits = [];
  const close = () => { res?.remove(); res = null; };
  const paint = () => {
    close();
    hits = search(q.value);
    if (!q.value.trim()) return;
    res = el('div', { id: 'sres' });
    if (!hits.length) res.append(el('div', { class: 'none', text: 'Nothing matches “' + q.value + '”.' }));
    hits.forEach((it, i) => res.append(el('a', { href: it.h, class: i === cur ? 'cur' : '', onclick: () => { close(); q.blur(); } },
      el('span', { class: 'k', text: it.k }), el('span', { class: 't', text: it.t }), el('span', { class: 'd', text: it.d || '' }))));
    box.append(res);
  };
  q.oninput = () => { cur = 0; paint(); };
  q.onkeydown = e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); cur = Math.max(0, Math.min(hits.length - 1, cur + (e.key === 'ArrowDown' ? 1 : -1))); paint(); res?.querySelector('.cur')?.scrollIntoView({ block: 'nearest' }); }
    else if (e.key === 'Enter' && hits[cur]) { location.hash = hits[cur].h; close(); q.blur(); }
    else if (e.key === 'Escape') { close(); q.blur(); }
  };
  q.onfocus = () => q.value && paint();
  document.addEventListener('click', e => { if (!box.contains(e.target)) close(); });
  document.addEventListener('keydown', e => {
    if ((e.key === '/' || (e.key === 'k' && (e.ctrlKey || e.metaKey))) && document.activeElement !== q) { e.preventDefault(); q.focus(); q.select(); }
  });
}

// ─── start ─────────────────────────────────────────────────────────────────────────────────────────────────────────
function sidebar() {
  const S = $('#side'); S.textContent = '';
  S.append(el('div', { class: 'logo', tabindex: '0', onclick: () => go('') },
    el('div', { class: 'mk' }, (() => { const s = ico('spark'); s.innerHTML = '<path d="M4 12h3.5l2-5 4 10 2-5H20"/>'; return s; })()), 'socketley'));
  for (const [g, items] of NAV) {
    S.append(el('div', { class: 'sh', text: g }));
    for (const [h, t, i] of items) S.append(el('a', { class: 'nav', href: '#/' + h, 'data-h': h, style: 'text-decoration:none' }, ico(i), el('span', { text: t })));
  }
  S.append(el('div', { style: 'flex:1' }), el('div', { class: 'themes', id: 'themes' }));
  paintThemes();
}
async function start() {
  try { const t = localStorage.getItem('skl-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
  sidebar();
  $('#menuB').append(ico('menu')); $('#menuB').onclick = () => $('#side').classList.toggle('open');
  $('#srch').prepend(ico('search'));
  try {
    [REF, BENCH] = await Promise.all([getJSON('data/reference.json'), getJSON('data/bench.json').catch(() => null)]);
  } catch (e) { $('#content').append(el('p', { class: 'bad2', text: 'The reference could not be loaded: ' + e.message })); return; }
  for (const s of REF.sections) { SEC.set(s.id, s); if (s.level === 1) TITLE2SEC.set(s.title, s.id); }
  buildIndex(); setupSearch();
  addEventListener('hashchange', route);
  route();
}
start();
