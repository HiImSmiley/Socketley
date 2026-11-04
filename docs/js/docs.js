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
  flow: '<rect x="3" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="16" width="7" height="5" rx="1.5"/><path d="M6.5 8v4.5a2 2 0 0 0 2 2h9V16"/><path d="m15 12.5 2.5 2 2.5-2"/>',
});

const RT = [
  ['server', 'TCP, UDP, WebSocket and HTTP on one port, answered by Lua or by a built-in path', 'nginx'],
  ['client', 'Dials a server and holds the connection: TCP, UDP or a unix socket, over TLS, reconnecting', ''],
  ['proxy', 'HTTP and TCP reverse proxy: routes by name and path, health checks, retries, mTLS, FastCGI', 'HAProxy, nginx'],
  ['cache', 'In-memory store on the Redis protocol: strings, lists, sets, hashes, sorted sets, streams, pub/sub', 'Redis, Valkey'],
  ['storage', 'S3 object storage over a directory, with versioning, replication, a web drive and git', 'MinIO'],
  ['db', 'JSON documents owned by accounts, over HTTP, with indexes, queries, replicas and backups', 'MongoDB, PocketBase'],
  ['dns', 'Authoritative name server for its zones, over UDP and TCP, with DNSSEC and transfers', 'NSD, Knot'],
  ['idp', 'OpenID Connect provider with its own accounts, second factors, app passwords and SSH certificates', 'Keycloak'],
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
  ['Start', [['', 'Overview', 'home'], ['install', 'Install', 'download'], ['tour', 'Ten-minute tour', 'rocket'], ['concepts', 'Concepts', 'layers'], ['how', 'How it works', 'flow']]],
  ['Runtimes', RT.map(r => ['rt/' + r[0], r[0], r[0]])],
  ['Guides', [['lua', 'Lua scripting', 'code'], ['deploy', 'Deployment', 'shield'], ['operate', 'Operating it', 'eye'], ['cluster', 'Cluster', 'nodes'], ['sdk', 'C++ SDK', 'pkg'], ['examples', 'Examples', 'folder']]],
  ['Reference', [['cli', 'CLI', 'term'], ['flags', 'All flags', 'list'], ['env', 'Environment & files', 'gear'], ['man', 'Manual', 'book']]],
  ['Performance', [['bench', 'Benchmarks', 'bars']]],
];
const TITLES = Object.fromEntries(NAV.flatMap(g => g[1]).map(([h, t]) => [h, t]));

let REF = null, BENCH = null;
const SEC = new Map();      // section id -> section
const FRAG = new Map();     // section id -> parsed DocumentFragment of its html
const PAGE = new Map();     // content path -> html

const KEEP = new Set(['MCP', 'QUIC', 'ACME', 'DNSSEC', 'OIDC', 'JWT', 'SSH', 'SMTP', 'IMAP', 'POP3', 'JMAP', 'MQTT', 'DNS', 'IDP', 'DB', 'MQTT', 'TLS', 'SDK', 'C++', 'IPC', 'JSON', 'HTTP', 'RESP', 'S3', 'CLI', 'API', 'CORS', 'IAM', 'SSE', 'UDP', 'TCP', 'MTLS']);
// The man page's section titles are capitals; on the page they read as a sentence with their acronyms kept.
const acro = w => KEEP.has(w.toUpperCase().replace(/[^A-Z0-9+]/g, '')) || /^[A-Z]+\/\d/.test(w.toUpperCase());
const nice = t => {
  const caps = t === t.toUpperCase();
  return !caps ? t : t.split(' ').map((w, i) => acro(w) ? w : w === 'LUA' ? 'Lua' : i ? w.toLowerCase() : w[0] + w.slice(1).toLowerCase()).join(' ');
};
// A help text's `code` as code, and an example's " - item" runs as lines.
function rich(text) {
  const f = document.createDocumentFragment();
  String(text).split(/(`[^`]+`)/).forEach(part => {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) return f.append(el('code', { text: part.slice(1, -1) }));
    // a flag named in the text is not broken after its hyphens
    part.split(/((?<![\w-])--?[a-z][a-z0-9-]*)/).forEach((x, i) => f.append(i % 2 ? el('span', { class: 'nw2', text: x }) : x));
  });
  return f;
}
// Where a value's placeholder may break: after its commas, bars, brackets and slashes, never inside a word.
const brk = t => t.replace(/([,|\]\/=:])/g, '$1\u200b');
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
  // A fetch that fails (as during a deploy) is tried again once and never remembered as an empty page.
  for (let k = 0; k < 2; k++) {
    try {
      const r = await fetch('content/' + p + '.html', { cache: k ? 'reload' : 'default' });
      if (r.ok) { const h = await r.text(); PAGE.set(p, h); return h; }
      if (r.status === 404) return '';
    } catch (e) {}
    await new Promise(res => setTimeout(res, 400));
  }
  throw new Error('This page could not be loaded; reload to try again.');
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
  for (const c of root.querySelectorAll('code,b')) if (c.textContent.length < 32 && /^-/.test(c.textContent.trim())) c.classList.add('nw');
  // A long path breaks after a slash, not inside a name; <wbr> marks where, and is not copied with the text.
  for (const c of root.querySelectorAll('td code, li code, p code')) {
    if (c.children.length || c.textContent.length < 22 || !c.textContent.includes('/')) continue;
    const parts = c.textContent.split(/(?<=\/)/);
    c.textContent = '';
    parts.forEach((x, i) => { if (i) c.append(document.createElement('wbr')); c.append(x); });
    c.classList.add('pth');
  }
}
function addCopy(p) {
  if (p.querySelector('.cp')) return;
  const b = el('button', { class: 'ib cp', title: 'Copy', 'aria-label': 'Copy', onclick: e => {
    e.stopPropagation();
    navigator.clipboard?.writeText(p.innerText.replace(/\n?$/, '')).then(() => toast('Copied'), fail);
  } }, ico('copy'));
  p.append(b);
}
function manBody(id, full) {
  const d = el('div', { class: 'man' });
  d.append(frag(id).cloneNode(true));
  if (!full) fold1(d, id);
  return linkify(d);
}
// An entry's first sentence, cut at a clause if it runs long: what a row says before it is opened.
function firstLine(t) {
  t = t.replace(/\s+/g, ' ').trim();
  const one = x => (x.match(/^(.+?[.!?])(?=\s+[A-Z(]|$)/) || [, x])[1];
  let s = one(t);
  if (s.length < 30 && t.length > s.length) s += ' ' + one(t.slice(s.length).trim());
  if (s.length > 150) {
    const c = s.slice(0, 150);
    const k = Math.max(c.lastIndexOf('; '), c.lastIndexOf(': '), c.lastIndexOf(' — '), c.lastIndexOf(', '));
    s = (k > 60 ? c.slice(0, k) : c.slice(0, c.lastIndexOf(' '))).replace(/[\s,;:—(]+$/, '') + ' …';
  }
  return s;
}
// What a row names an entry by: its synopsis up to the first optional part, at most a few words.
function shortTerm(t) {
  let s = t.replace(/\s+/g, ' ').split(/ \[| \/ | \| /)[0].replace(/(?<!\.)[.,]$/, '');
  if (s.length > 42) s = s.slice(0, s.lastIndexOf(' ', 40) > 10 ? s.lastIndexOf(' ', 40) : 40).replace(/[,\s]+$/, '') + ' …';
  return s;
}
function openEnt(n) {
  if (!n?.classList.contains('c')) return;
  n.classList.add('open');
  n.querySelectorAll('details').forEach(d => d.open = true);
}
// Each entry of a section becomes one row: name and first sentence; a click opens the whole entry in place.
// Entries the manual calls test hooks or aids go together at the end, folded.
function fold1(d, sid) {
  const meta = new Map((SEC.get(sid)?.entries || []).map(e => [sid + '/' + e.id, e]));
  const tests = [];
  for (const n of d.querySelectorAll('.ent')) {
    const e = meta.get(n.id);
    if (!e) continue;
    const st = shortTerm(e.term);
    const head = el('div', { class: 'er', role: 'button', tabindex: '0', 'aria-expanded': 'false' },
      el('code', { class: 'tm', text: st }), el('span', { class: 'fs', text: firstLine(e.summary) }), ico('chev', 'chev'));
    const flip = () => {
      if (n.classList.contains('open')) n.classList.remove('open'); else openEnt(n);
      head.setAttribute('aria-expanded', n.classList.contains('open'));
    };
    head.onclick = ev => { if (!ev.target.closest('a')) flip(); };
    head.onkeydown = ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); flip(); } };
    n.prepend(head);
    n.classList.add('c');
    if (st === e.term.replace(/\s+/g, ' ').replace(/(?<!\.)[.,]$/, '')) n.classList.add('same');
    if (/^A test (hook|aid)\b/.test(e.summary)) tests.push(n);
  }
  if (tests.length) {
    const box = el('details', { class: 'tests' }, el('summary', {}, ico('chev'), el('span', { text: 'For socketley\'s own tests' }), el('span', { class: 'n', text: tests.length + ' entries' })));
    for (const n of tests) box.append(n);
    d.append(box);
  }
}
// Opens or closes every entry under root; the button says which it will do next.
function expandAll(root) {
  const b = el('button', { class: 'btn sm xa' }, el('span', { text: 'Open all' }));
  b.onclick = () => {
    const open = b.textContent === 'Open all';
    for (const n of root.querySelectorAll('.ent.c')) open ? openEnt(n) : n.classList.remove('open');
    for (const t of root.querySelectorAll('details.tests')) t.open = open;
    b.firstChild.textContent = open ? 'Close all' : 'Open all';
  };
  return b;
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
// One flag a row: the flag with what it takes, then what it is; a click opens its entry in the manual beneath.
function flagRow(f, rt, opts = {}) {
  const ref = rt ? f.ref[rt] : (Object.values(f.ref).find(Boolean) || '');
  // What it takes, as the manual's entry names it (-p port), else the kind of value.
  const [sid, eid] = (ref || '').split('/');
  const term = eid ? (SEC.get(sid)?.entries.find(e => e.id === eid)?.term || '') : '';
  const arg = term.startsWith(f.flag + ' ') ? term.slice(f.flag.length + 1).split(' / ')[0] : '';
  const takes = f.kind === 'switch' ? '' : (arg || f.kind);
  const tr = el('tr', { class: 'f', id: 'flag:' + (rt || 'all') + ':' + f.flag, 'data-q': (f.flag + ' ' + f.aliases.join(' ') + ' ' + f.label + ' ' + f.help + ' ' + f.group).toLowerCase() },
    el('td', { class: 'fl' }, el('code', { text: f.flag }), takes && !f.choices.length ? el('span', { class: 'ph2', text: brk(takes) }) : null,
      f.aliases.length ? el('span', { class: 'al', text: f.aliases.join(', ') }) : null),
    el('td', { class: 'tx' }, ico('chev', 'chev'), el('span', { class: 'lb', text: f.label }), el('span', { class: 'hp' }, ' — ', rich(f.help)),
      f.choices.length ? el('div', { class: 'ch' }, f.choices.map(c => el('span', { text: c }))) : null),
    opts.matrix ? el('td', { class: 'mx' }, el('div', { class: 'tmx' }, RT.map(([t]) => el('i', { class: f.types.includes(t) ? 'on' : '', title: t, text: LETTER[t] })))) : null);
  let x = null;
  tr.onclick = () => {
    if (x) { x.remove(); x = null; tr.classList.remove('open'); return; }
    const n = ref ? entryNode(ref) : null;
    x = el('tr', { class: 'x' }, el('td', { colspan: opts.matrix ? 3 : 2 },
      n || el('p', { class: 'mut', text: 'No entry of its own in the manual.' }),
      ref ? el('p', { class: 'src' }, el('a', { href: '#/man/' + ref, text: 'In the manual: ' + nice(SEC.get(ref.split('/')[0])?.title || '') + ' →' })) : null));
    tr.after(x); tr.classList.add('open');
  };
  return tr;
}
function flagTable(rt, opts = {}) {
  const rows = REF.flags.filter(f => !f.hidden && (!rt || f.types.includes(rt)));
  const box = el('div', {});
  const q = el('input', { class: 'inp', placeholder: 'Filter flags', 'aria-label': 'Filter flags', spellcheck: 'false' });
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
const short = a => a.replace(/ [\d.v-]+$/, '');
function benchSet(s) {
  const arms = s.arms;
  // CPU beside every rate, unless every rate of the set cost the same: then it is said once, above the table.
  const cpus = s.rows.flatMap(r => r.cpu || []).filter(v => v != null);
  const oneCpu = cpus.length && cpus.every(v => v.toFixed(2) === cpus[0].toFixed(2)) ? cpus[0] : null;
  const head = el('tr', {}, el('th', { text: '' }), arms.map(a => el('th', { text: short(a) })),
    arms.slice(1).map(a => el('th', { text: 'vs ' + short(a) })));
  const body = s.rows.map(r => el('tr', {}, el('td', { text: r.name }),
    arms.map((a, k) => el('td', { class: k ? '' : 'us', 'data-l': short(a) }, el('div', { class: 'v', text: fmt(r.v[k], r.unit || s.unit) }),
      r.cpu?.[k] != null && oneCpu == null ? el('div', { class: 'cpu', text: r.cpu[k].toFixed(2) + ' cores' }) : null)),
    arms.slice(1).map((a, k) => {
      const q = r.r?.[k];
      if (!q) return el('td', { text: '–' });
      const cls = q[1] > 1 ? 'up' : q[2] < 1 ? 'dn' : 'eq';
      return el('td', { class: 'rt ' + cls, 'data-l': 'vs ' + short(arms[k + 1]), title: 'From ' + q[1].toFixed(2) + '× to ' + q[2].toFixed(2) + '× across the passes' }, q[0].toFixed(2) + '×', el('span', { class: 'ci', text: q[1].toFixed(2) + '–' + q[2].toFixed(2) }));
    })));
  const meta = [arms.slice(1).join(', '), oneCpu != null ? 'each on ' + (+oneCpu.toFixed(2) === 1 ? 'one core' : oneCpu.toFixed(2) + ' cores') : '', s.passes ? s.passes + ' passes' : '', s.date, s.commit ? 'socketley ' + s.commit : ''].filter(Boolean);
  const notes = el('details', { class: 'bn' }, el('summary', { text: 'How it was measured' }),
    el('p', { text: [s.tool, s.pin].filter(Boolean).join('; ') + '.' }));
  if (s.note) { const p = el('p'); p.innerHTML = s.note; notes.append(p); }
  // The same rows for a narrow card: one line a server, its ratio beside it.
  const comp = el('div', { class: 'bcomp' }, s.rows.map(r => el('div', { class: 'br' }, el('div', { class: 'bn2', text: r.name }),
    el('div', { class: 'bg' }, arms.flatMap((a, k) => {
      const q = k ? r.r?.[k - 1] : null;
      const cls = q ? (q[1] > 1 ? 'up' : q[2] < 1 ? 'dn' : 'eq') : '';
      return [el('span', { class: 'a' + (k ? '' : ' us'), text: short(a) }),
        el('span', { class: 'v' + (k ? '' : ' us'), text: fmt(r.v[k], r.unit || s.unit) }),
        el('span', { class: 'q ' + cls, text: q ? q[0].toFixed(2) + '×' : '' }),
        el('span', { class: 'ci', text: q ? q[1].toFixed(2) + '–' + q[2].toFixed(2) : '' })];
    })))));
  return el('div', { class: 'bset' + (arms.length > 2 ? ' a3' : ''), id: 'bench:' + s.id },
    el('h3', {}, el('span', { text: s.title })),
    el('div', { class: 'meta', text: meta.join(' · ') }),
    el('div', { class: 'mtw' }, el('table', { class: 'btbl' + (arms.length > 2 ? ' a3' : '') }, el('thead', {}, head), el('tbody', {}, body))), comp,
    s.caveat ? el('p', { class: 'cav', text: '⚠ ' + s.caveat[0].toUpperCase() + s.caveat.slice(1) + '.' }) : null,
    notes);
}
function benchLegend(page) {
  return el('div', { class: 'legend' },
    el('div', { class: 'lx' }, el('b', { text: '×' }), ' is how many times better socketley did: more per second, or less time, memory or CPU. Above 1× it is ahead.'),
    el('span', {}, el('i', { class: 'dot', style: 'background:var(--ok)' }), 'ahead in every pass'),
    el('span', {}, el('i', { class: 'dot', style: 'background:var(--mut)' }), 'no clear difference'),
    el('span', {}, el('i', { class: 'dot', style: 'background:var(--bad)' }), 'behind in every pass'),
    page ? el('span', {}, el('b', { class: 'warn2', text: '⚠' }), 'read its note before quoting it') : null);
}
function benchFor(rt, legend = true) {
  const sets = (BENCH?.sets || []).filter(s => !rt || s.runtime === rt);
  const box = el('div', {});
  if (!sets.length) {
    box.append(el('div', { class: 'bnone', text: NOBENCH[rt] || (RTI[rt]?.[2] ? 'Not measured on the current build yet. The comparison planned is against ' + RTI[rt][2] + '.' : 'No comparison is published for this runtime.') }));
    return box;
  }
  if (legend) box.append(benchLegend());
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
    const top = (SEC.get(sid)?.entries || []).filter(e => x.hasAttribute('all') || !/^(-|type$|name$|port$|path$)/.test(e.term));
    const seen = new Set();
    x.replaceWith(el('div', { class: 'chips' }, top.filter(e => { const k = e.term.split(' ')[0].replace(/\(.*$/, '()').replace(/,$/, ''); if (seen.has(k)) return false; seen.add(k); return true; }).map(e => el('a', { href: '#/man/' + sid + '/' + e.id, title: e.summary, onclick: ev => {
      const n = document.getElementById(sid + '/' + e.id);
      if (n) { ev.preventDefault(); openEnt(n); n.scrollIntoView({ block: 'start' }); n.classList.add('hl'); }
    } }, el('span', {}, el('b', { text: e.term.split(' ')[0].replace(/\(.*$/, '()').replace(/,$/, '').slice(0, 40) }))))));
  }
  for (const p of root.querySelectorAll('pre.code')) addCopy(p);
  nowrapFlags(root);
  // A table of three or more columns stacks on a phone: each cell on a line of its own, named by its column.
  for (const t of root.querySelectorAll('table.kv')) {
    const head = [...(t.querySelector('tr')?.children || [])].map(c => c.textContent.trim());
    if (head.length < 3) continue;
    t.classList.add('kv3');
    for (const tr of [...t.querySelectorAll('tr')].slice(1)) [...tr.children].forEach((c, i) => c.dataset.l = head[i] || '');
  }
}
// One row of each runtime's benchmarks, the one its set names as its headline, chosen before the numbers were in.
function glance(caption = true) {
  const tiles = el('div', { class: 'tiles' });
  for (const s of BENCH?.sets || []) {
    if (s.headline == null) continue;
    const r = s.rows[s.headline], q = r?.r?.[0];
    if (!q) continue;
    tiles.append(el('a', { class: 'tile', href: '#/rt/' + s.runtime + '/benchmarks', title: r.name + (s.caveat ? ' — ' + s.caveat : '') },
      el('div', { class: 'k' }, s.runtime, s.caveat ? el('span', { class: 'warn', text: '⚠' }) : null),
      el('div', { class: 'v ' + (q[1] > 1 ? 'ok2' : q[2] < 1 ? 'bad2' : 'eq2') }, q[0].toFixed(1) + '×'),
      el('div', { class: 's', text: 'vs ' + short(s.arms[1]) })));
  }
  if (!tiles.children.length) return el('p', { class: 'mut', text: 'Benchmarks are being measured.' });
  return caption ? el('div', {}, tiles, el('p', { class: 'src', text: '× is how many times better socketley did than the server named; ⚠ marks a result with a caveat in its notes.' })) : tiles;
}
function rtCards() {
  return el('div', { class: 'cards' }, RT.map(([id, d, vs]) => el('a', { class: 'tcard', href: '#/rt/' + id },
    el('b', {}, el('span', { class: 'hb' }, ico(id)), id), el('p', { text: d }), vs ? el('div', { class: 'ref', text: 'vs ' + vs }) : null)));
}
// The head of a page: what part it belongs to, its title, one line on what it holds, and a few facts.
function pageHead(kick, title, lead, chips = [], icon, acts) {
  return el('header', { class: 'ph' }, el('div', { class: 'kick', text: kick }),
    el('h1', {}, icon ? el('span', { class: 'hb' }, ico(icon)) : null, title),
    lead ? el('p', { class: 'lead', text: lead }) : null,
    chips.length ? el('div', { class: 'stats' }, chips.map(c => el('span', { class: 'chip' }, el('span', { text: c })))) : null,
    acts || null);
}
function prose(h) { const d = el('div', { class: 'prose' }); d.innerHTML = h; return d; }
const slug = t => t.toLowerCase().replace(/<[^>]+>/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
// The text of a page beside its contents: every h2 and h3 of it, the one in view marked as the page scrolls.
function article(C, main, opts = {}) {
  const heads = [...main.querySelectorAll(opts.heads || '.prose>h2,.prose>h3,h2.h2')].filter(h => !h.closest('.ftbl,.bset,details'));
  const wrap = el('div', { class: 'page' }, main);
  if (heads.length >= (opts.min || 3)) {
    const toc = el('nav', { class: 'toc' }, el('div', { class: 't', text: 'On this page' }));
    for (const h of heads) {
      if (!h.id) h.id = 'h-' + slug(h.textContent);
      toc.append(el('a', { href: '#', class: h.tagName === 'H3' ? 'l3' : '', 'data-for': h.id, text: h.textContent.trim(),
        onclick: e => { e.preventDefault(); h.scrollIntoView({ block: 'start', behavior: 'smooth' }); } }));
    }
    wrap.classList.add('wtoc'); wrap.append(toc);
    spy(heads, toc);
  }
  C.append(wrap);
  return wrap;
}
let SPY = null;
function spy(heads, toc) {
  const S = $('#scroll');
  if (SPY) S.removeEventListener('scroll', SPY);
  SPY = () => {
    const top = S.getBoundingClientRect().top + 90;
    let cur = heads[0];
    for (const h of heads) if (h.getBoundingClientRect().top <= top) cur = h;
    for (const a of toc.querySelectorAll('a')) a.classList.toggle('on', a.dataset.for === cur.id);
  };
  S.addEventListener('scroll', SPY, { passive: true });
  requestAnimationFrame(SPY);
}

async function pageHome(C) {
  const nflags = REF.flags.filter(f => !f.hidden).length;
  C.append(pageHead('Documentation', 'socketley', 'One Linux daemon and CLI that runs your servers, proxies, caches, storage, databases, DNS, sign-in, MQTT, mail, metrics, tunnels and MCP — each a runtime made with one command.',
    [RT.length + ' runtime types', nflags + ' flags', 'io_uring', 'Lua scripting', 'Linux'], null,
    el('div', { class: 'acts' }, el('a', { class: 'btn pri', href: '#/install' }, el('span', { text: 'Install' })),
      el('a', { class: 'btn', href: '#/tour' }, el('span', { text: 'Ten-minute tour' })),
      el('a', { class: 'btn', href: '#/concepts' }, el('span', { text: 'Concepts' })))));
  const main = el('div', { class: 'main' }, prose(await content('home')));
  await place(main);
  article(C, main, { min: 99 });
}
async function pageContent(C, name, title, kick, sub, icon) {
  C.append(pageHead(kick, title, sub, [], icon));
  const main = el('div', { class: 'main' }, prose(await content(name)));
  await place(main);
  article(C, main);
}
const TABS = [['overview', 'Overview'], ['flags', 'Flags'], ['benchmarks', 'Benchmarks'], ['more', 'In depth']];
async function pageRuntime(C, rt, tab) {
  const r = RTI[rt]; if (!r) return notFound(C);
  const flags = REF.flags.filter(f => !f.hidden && f.types.includes(rt));
  const sets = (BENCH?.sets || []).filter(s => s.runtime === rt);
  const top = REF.sections.find(s => s.id === rt + '-flags');
  const subs = top ? subsOf(top.id) : [];
  // A tab is shown only where it has something: no benchmarks tab for a runtime nothing was measured against.
  const tabs = TABS.filter(([id]) => id === 'overview' || id === 'flags' || (id === 'benchmarks' && sets.length) || (id === 'more' && subs.length));
  if (tab === 'manual') tab = 'more';
  if (!tabs.some(t => t[0] === tab)) tab = 'overview';
  C.append(pageHead('Runtime', rt, '', [], rt));
  C.append(el('nav', { class: 'tabs' }, tabs.map(([id, t]) => el('a', { href: '#/rt/' + rt + (id === 'overview' ? '' : '/' + id), class: id === tab ? 'on' : '' },
    t, id === 'flags' ? el('span', { class: 'n', text: flags.length }) : null))));
  const main = el('div', { class: 'main' });
  const whole = top ? el('p', { class: 'src' }, el('a', { href: '#/man/' + top.id, text: 'The whole ' + nice(top.title) + ' section of the manual →' })) : null;
  if (tab === 'overview') {
    main.append(prose(await content('rt/' + rt) || ''));
    if (!sets.length && NOBENCH[rt]) main.append(el('p', { class: 'src', text: 'No benchmark: ' + NOBENCH[rt][0].toLowerCase() + NOBENCH[rt].slice(1) }));
  } else if (tab === 'flags') {
    main.append(el('p', { class: 'sub', text: 'Every flag a ' + rt + ' takes, grouped as in the dashboard\'s create form. Click one for its full entry in the manual.' }), el('x-flags', { rt }), whole);
  } else if (tab === 'benchmarks') {
    main.append(el('p', { class: 'sub' }, 'Against ' + r[2] + ', on one machine, in one run. ', el('a', { href: '#/bench', text: 'How every benchmark is made →' })), el('x-bench', { rt }));
  } else {
    main.append(el('p', { class: 'sub', text: 'Topics from the manual\'s ' + nice(top.title) + ' section, beyond the flags.' }));
    for (const c of subs) main.append(foldSec(c, false));
    main.append(whole);
  }
  await place(main);
  article(C, main);
}
async function pageFlags(C) {
  C.append(pageHead('Reference', 'All flags', 'Every flag of every runtime type. The letters show which types take it; click a flag for its entry in the manual.'));
  C.append(el('div', { class: 'legend' }, RT.map(([t]) => el('span', {}, el('b', { text: LETTER[t] }), t))));
  C.append(el('x-flags', {}));
  await place(C);
}
async function pageMan(C, sid, eid) {
  if (!sid) {
    C.append(pageHead('Reference', 'Manual', 'socketley(1), the manual page, by section. Generated from man/socketley.1 on ' + REF.date + '.'));
    const lists = [['Runtime flags', s => /-flags$/.test(s.id)], ['Everything else', s => !/-flags$/.test(s.id)]];
    for (const [title, want] of lists) {
    const list = el('div', { class: 'cards' });
    C.append(el('h2', { class: 'h2', text: title }), list);
    for (const s of REF.sections.filter(s => s.level === 1 && want(s))) {
      const subs = subsOf(s.id);
      list.append(el('a', { class: 'tcard', href: '#/man/' + s.id }, el('b', { text: nice(s.title) }),
        el('p', { text: (s.entries.length ? s.entries.length + ' entries · ' : '') + (subs.length ? subs.length + (subs.length === 1 ? ' topic · ' : ' topics · ') : '') + Math.max(1, Math.round((s.words + subs.reduce((a, c) => a + c.words, 0)) / 220)) + ' min read' })));
    }
    }
    return;
  }
  const s = SEC.get(sid); if (!s) return notFound(C);
  const parent = s.parent && s.parent !== s.id ? SEC.get(s.parent) : null;
  C.append(pageHead(parent ? nice(parent.title) : 'Manual', nice(s.title), ''));
  const main = el('div', { class: 'main' });
  main.append(manBody(sid));
  for (const c of subsOf(sid)) main.append(el('h2', { class: 'h2', id: 'sec:' + c.id }, nice(c.title)), manBody(c.id));
  await place(main);
  if (main.querySelector('.ent.c')) main.prepend(el('div', { class: 'xbar' }, expandAll(main)));
  article(C, main, { heads: 'h2.h2', min: 2 });
  if (eid) setTimeout(() => {
    const n = document.getElementById(sid + '/' + eid);
    if (n) { n.classList.add('hl'); n.closest('details.tests')?.setAttribute('open', ''); openEnt(n); n.scrollIntoView({ block: 'start' }); }
  }, 0);
}
async function pageBench(C, rt) {
  if (rt) { location.replace('#/rt/' + rt + '/benchmarks'); return; }
  C.append(pageHead('Performance', 'Benchmarks', 'Each runtime against what people run instead, on one machine, in one run. Every rate carries the CPU it cost.',
    BENCH?.box ? [BENCH.box.cpu, BENCH.box.vcpus + ' vCPUs', BENCH.box.os] : []));
  const main = el('div', { class: 'main' });
  const text = prose(await content('bench'));
  const intro = text.querySelector('p');
  if (intro) main.append(el('div', { class: 'prose' }, intro));
  main.append(el('h2', { class: 'h2', text: 'At a glance' }), glance(false), benchLegend(true));
  const done = [...new Set((BENCH?.sets || []).map(s => s.runtime))];
  for (const [t] of RT) {
    if (!done.includes(t)) continue;
    main.append(el('h2', { class: 'h2', id: 'b-' + t }, el('a', { href: '#/rt/' + t, class: 'hl2', text: t })), benchFor(t, false));
  }
  const left = RT.filter(r => !done.includes(r[0]));
  if (left.length) main.append(el('h2', { class: 'h2', text: 'Without a comparison' }), el('ul', { class: 'prose' }, left.map(r => el('li', {}, el('b', { text: r[0] }), ': ' + (NOBENCH[r[0]] || 'not measured on the current build yet.')))));
  for (const h of text.querySelectorAll('h2')) h.classList.add('h2');
  main.append(text);
  await place(main);
  article(C, main, { heads: 'h2.h2' });
}
const REPO = 'https://github.com/HiImSmiley/Socketley/blob/main/';
async function pageExamples(C) {
  C.append(pageHead('Guide', 'Examples', 'Every script and program in the repository\'s examples/ and sdk/examples/, with what it does. Each runs as its first lines say.', [REF.examples.length + ' files']));
  const groups = new Map();
  for (const e of REF.examples) {
    const dir = e.path.split('/').slice(0, -1).join('/');
    if (!groups.has(dir)) groups.set(dir, []);
    groups.get(dir).push(e);
  }
  const q = el('input', { class: 'inp', placeholder: 'Filter examples', 'aria-label': 'Filter examples', spellcheck: 'false' });
  C.append(el('div', { class: 'fbar' }, q));
  const blocks = [];
  const order = d => ['examples/basic', 'examples/lua', 'examples/cache', 'examples/advanced'].indexOf(d) + 1 || 9;
  for (const [dir, es] of [...groups].sort((a, b) => order(a[0]) - order(b[0]) || a[0].localeCompare(b[0]))) {
    const t = el('table', { class: 'ftbl ex' }, el('tbody', {}, es.map(e => el('tr', { 'data-q': (e.path + ' ' + e.title + ' ' + e.summary).toLowerCase() },
      el('td', { class: 'fl' }, el('a', { href: REPO + e.path, target: '_blank', rel: 'noopener', class: 'ln' }, el('code', { text: e.path.split('/').pop() }))),
      el('td', {}, el('div', { class: 'lb' }, rich(e.title || '')), e.summary ? el('div', { class: 'hp' }, ...e.summary.split(/\s+-\s+(?=[A-Z])/).map((x, i) => i ? el('div', { class: 'li' }, '• ', rich(x)) : rich(x))) : null)))));
    const h = el('div', { class: 'fgrp', text: dir.replace(/^examples\//, '').replace(/^sdk\/examples$/, 'C++ SDK').replace(/^examples$/, 'Other') });
    blocks.push([h, t]); C.append(h, t);
  }
  q.oninput = () => {
    const s = q.value.trim().toLowerCase();
    for (const [h, t] of blocks) { let n = 0; for (const tr of t.rows) { tr.hidden = !!s && !tr.dataset.q.includes(s); n += !tr.hidden; } h.hidden = t.hidden = !n; }
  };
}
function notFound(C) { C.append(el('div', { class: 'empty' }, ico('search', 'big'), el('h3', { text: 'Nothing here' }), el('p', {}, el('a', { href: '#/', class: 'ln', text: 'Back to the overview' })))); }

const CONTENT = {
  install: ['Install', 'Start', 'From source, the install script or a Debian package; the daemon then runs as a systemd service.'],
  tour: ['Ten-minute tour', 'Start', 'Make a server, a cache and a proxy, script one of them, and look at all three.'],
  concepts: ['Concepts', 'Start', 'The daemon, its runtimes and the few rules every one of them follows.'],
  how: ['How it works', 'Start', 'What happens, and where, from the command you type to the answer a client gets.'],
  lua: ['Lua scripting', 'Guide', 'Callbacks per message, connection and request, the runtime methods a script calls, and what a script may not do.'],
  deploy: ['Deployment', 'Guide', 'Running socketley on a machine that matters: the service, permissions, TLS, state, backups and limits.'],
  operate: ['Operating it', 'Guide', 'Is it running, where the log is, why a runtime failed, and what blocks it.'],
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
    else if (parts[0] === 'rt') await pageRuntime(C, parts[1], parts[2] === 'flag' ? 'flags' : parts[2]);
    else if (parts[0] === 'flags') await pageFlags(C);
    else if (parts[0] === 'man') await pageMan(C, parts[1], parts.slice(2).join('/'));
    else if (parts[0] === 'bench') await pageBench(C, parts[1]);
    else if (parts[0] === 'examples') await pageExamples(C);
    else if (CONTENT[parts[0]]) await pageContent(C, parts[0], ...CONTENT[parts[0]]);
    else notFound(C);
  } catch (e) { C.append(el('p', { class: 'bad2', text: String(e) })); }
  // A sub-path names a place on the page: a section, a flag, a subsection of the manual.
  const S = $('#scroll');
  if (parts[0] === 'rt' && parts[2] === 'flag') {
    const tr = document.getElementById('flag:' + parts[1] + ':' + parts.slice(3).join('/'));
    S.scrollTop = 0;
    if (tr) { tr.click(); tr.scrollIntoView({ block: 'center' }); }
  } else if (parts[0] !== 'man' || !parts[2]) S.scrollTop = 0;
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
