// The webmail, whole: markup, its own style and script. The storage interface's stylesheet and helpers go in at
// /*STYLE*/ and /*KIT*/ (mail_web.cpp), so the two look and behave as one.
constexpr std::string_view mail_web_page = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#07080c">
<title>Mail</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x2='1' y2='1'%3E%3Cstop stop-color='%23c084fc'/%3E%3Cstop offset='1' stop-color='%23fb923c'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='24' height='24' rx='6' fill='url(%23g)'/%3E%3Cpath d='M5 8l7 5 7-5M5 7.5h14v9H5z' fill='none' stroke='%23fff' stroke-width='1.8' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
/*STYLE*/
/* ── the webmail's own ── */
#compose{width:100%;justify-content:center;height:44px;margin:0 0 14px;font-size:14.5px}
.nav .cnt{margin-left:auto;font-size:11.5px;font-weight:700;min-width:22px;text-align:center;padding:1px 7px;border-radius:999px;background:rgba(var(--glow),.22);color:var(--fg)}
.nav .cnt.dim{background:none;color:var(--dim);font-weight:500}
.sh.row{display:flex;align-items:center;justify-content:space-between;padding-right:4px}
.nav .fm{display:none;margin-left:4px;width:24px;height:24px;border-radius:7px;align-items:center;justify-content:center;flex:none}
.nav .fm .i{width:16px;height:16px}
.nav:hover .fm,.nav.on .fm{display:inline-flex}
.nav .fm:hover{background:rgba(255,255,255,.1)}
#boxes{overflow:auto;flex:1;min-height:0;margin:0 -4px;padding:0 4px}
.me{display:flex;align-items:center;gap:10px;padding:10px 12px 4px;color:var(--mut);font-size:12.5px;overflow:hidden}
.me b{color:var(--fg);font-weight:600;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.me>div{min-width:0}
#top .grow{flex:1}
#top .search{flex:1;max-width:620px}
#top .search .inp{width:100%}
#panes{flex:1;display:flex;min-height:0}
#listp{width:440px;flex:none;display:flex;flex-direction:column;border-right:1px solid var(--line);min-width:0}
#lhead{display:flex;align-items:center;gap:6px;padding:10px 14px 10px 18px;border-bottom:1px solid var(--line);min-height:56px}
#lhead h2{margin:0;font-size:16px;font-weight:650;letter-spacing:-.01em;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#lhead .n{color:var(--dim);font-size:12.5px;font-weight:500;margin-left:6px}
#lhead .ib{width:32px;height:32px}
#rows{flex:1;overflow:auto}
.row{display:flex;gap:12px;padding:12px 14px 12px 12px;border-bottom:1px solid var(--line);cursor:pointer;position:relative;transition:background .12s}
.row:hover{background:rgba(255,255,255,.035)}
.row.on{background:linear-gradient(90deg,rgba(var(--glow),.16),rgba(var(--glow2),.04));box-shadow:inset 3px 0 0 var(--a1)}
.row.ck{background:rgba(var(--glow),.09)}
.av{width:36px;height:36px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14.5px;color:#fff;text-transform:uppercase;user-select:none}
.row .avw{position:relative;flex:none;width:36px;height:36px;margin-top:2px}
.row .avw .av{margin:0}
.row .tick{position:absolute;inset:0;border-radius:50%;display:none;align-items:center;justify-content:center;background:var(--card2);border:1.5px solid var(--line2);color:var(--fg)}
.row .tick .i{width:18px;height:18px}
.row:hover .tick,.row.ck .tick,#rows.picking .tick{display:flex}
.row.ck .tick{background:var(--grad);border-color:transparent;color:var(--on)}
.row:not(.ck) .tick .i{opacity:0}
.rm{flex:1;min-width:0}
.r1{display:flex;align-items:baseline;gap:8px}
.r1 .who{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--mut)}
.r1 .when{font-size:12px;color:var(--dim);flex:none;font-variant-numeric:tabular-nums}
.r2{display:flex;align-items:center;gap:6px;margin-top:1px}
.r2 .subj{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--mut)}
.r2 .i{width:15px;height:15px;color:var(--dim);flex:none}
.r3{font-size:12.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px}
.row.unread .who,.row.unread .subj{color:var(--fg);font-weight:650}
.row.unread .when{color:var(--a1);font-weight:600}
.row .st{position:absolute;right:10px;bottom:9px;width:26px;height:26px;opacity:0}
.row:hover .st,.row .st.on{opacity:1}
.st.on{color:var(--warn)}
.st.on svg{fill:var(--warn)}
.row .tag{font-size:11px;padding:0 7px;border-radius:999px;background:rgba(255,255,255,.08);color:var(--mut);flex:none}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;gap:10px;color:var(--dim);padding:60px 24px;height:100%}
.empty .i{width:46px;height:46px;opacity:.5}
.empty b{color:var(--mut);font-size:15px;font-weight:600}
.more{padding:14px;text-align:center;color:var(--dim);font-size:12.5px}
#bulk{display:none;align-items:center;gap:4px;flex:1}
#bulk span{font-weight:600;margin-right:6px;font-size:13.5px}
#lhead.picking h2{display:none}
#lhead.picking #bulk{display:flex}
#readp{flex:1;min-width:0;overflow:auto;position:relative}
.rd{max-width:980px;margin:0 auto;padding:18px 28px 80px}
.rbar{display:flex;align-items:center;gap:2px;position:sticky;top:6px;z-index:2;padding:4px 6px;margin:-4px -6px 8px;border-radius:12px;background:rgba(12,11,20,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid var(--line)}
.rbar .grow{flex:1}
.rbar #backB{display:none}
.rd h1{font-size:21px;line-height:1.3;margin:6px 0 16px;font-weight:650;letter-spacing:-.015em;word-break:break-word}
.rd h1 .tag{vertical-align:middle;font-size:11.5px;font-weight:500;margin-left:8px;padding:2px 9px;border-radius:999px;background:rgba(255,255,255,.08);color:var(--mut)}
.hdr{display:flex;gap:12px;align-items:flex-start;margin-bottom:14px}
.hdr .av{width:42px;height:42px;font-size:16px}
.hdr .who{flex:1;min-width:0}
.hdr .who b{font-weight:650}
.hdr .who .addr{color:var(--mut);font-size:13px;margin-left:4px}
.hdr .rcp{color:var(--dim);font-size:12.5px;margin-top:2px;word-break:break-word}
.hdr .when{color:var(--dim);font-size:12.5px;white-space:nowrap;flex:none;margin-top:2px}
.imgbar{display:flex;align-items:center;gap:10px;padding:9px 12px;margin-bottom:12px;border-radius:11px;background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.22);font-size:13px;color:#e9dcb5}
.imgbar .btn{height:30px;font-size:12.5px;margin-left:auto}
.mbody{border-radius:14px;overflow:hidden;background:#fff}
.mbody iframe{display:block;width:100%;border:0;height:120px;background:#fff}
.mtext{white-space:pre-wrap;word-break:break-word;font:14px/1.6 inherit;padding:2px 2px}
.mtext .q{color:var(--dim);border-left:2px solid var(--line2);padding-left:10px;display:block}
.mtext a,.hdr a{color:var(--a1)}
.atts{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
.att{display:flex;align-items:center;gap:10px;padding:8px 12px 8px 8px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid var(--line);max-width:300px;color:var(--fg);text-decoration:none}
.att:hover{background:rgba(255,255,255,.07)}
.att .ti{width:38px;height:38px;border-radius:8px;background:rgba(var(--glow),.14);display:flex;align-items:center;justify-content:center;flex:none;overflow:hidden}
.att .ti img{width:100%;height:100%;object-fit:cover}
.att .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.att .sz{font-size:11.5px;color:var(--dim)}
.att>div{min-width:0}
.blank{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--dim);gap:12px;text-align:center;padding:24px}
.blank .ring{width:92px;height:92px;border-radius:28px;background:linear-gradient(140deg,rgba(var(--glow),.22),rgba(var(--glow2),.06));display:flex;align-items:center;justify-content:center;box-shadow:0 20px 50px -20px rgba(var(--glow),.6)}
.blank .ring .i{width:42px;height:42px;color:var(--fg);opacity:.85}
.blank b{color:var(--mut);font-size:15.5px}
.kbd{font:11.5px var(--mono);padding:1px 6px;border-radius:6px;background:rgba(255,255,255,.08);border:1px solid var(--line);color:var(--mut)}
#cmp{position:fixed;right:24px;bottom:0;width:600px;max-width:calc(100vw - 32px);height:min(640px,calc(100vh - 60px));z-index:50;display:flex;flex-direction:column;background:#11141d;border:1px solid var(--line2);border-bottom:0;border-radius:16px 16px 0 0;box-shadow:0 30px 80px -20px rgba(0,0,0,.9);animation:rise .22s cubic-bezier(.2,.8,.2,1)}
#cmp.min{height:auto}
#cmp.min .cbody,#cmp.min .cfoot{display:none}
#cmp .chead{display:flex;align-items:center;gap:4px;padding:8px 8px 8px 16px;border-bottom:1px solid var(--line);cursor:pointer;border-radius:16px 16px 0 0;background:rgba(255,255,255,.03)}
#cmp .chead b{flex:1;font-weight:600;font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#cmp .chead .ib{width:30px;height:30px}
#cmp .cbody{flex:1;display:flex;flex-direction:column;min-height:0}
#cmp .fl{display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--line);padding:0 14px;min-height:42px}
#cmp .fl label{color:var(--dim);font-size:13px;width:52px;flex:none}
#cmp .fl input{flex:1;background:none;border:0;outline:none;height:40px;min-width:0;font-size:14px}
#cmp .fl .lnk{color:var(--dim);font-size:12.5px;padding:2px 6px;border-radius:6px}
#cmp .fl .lnk:hover{color:var(--fg);background:rgba(255,255,255,.06)}
#cmp textarea{flex:1;background:none;border:0;outline:none;resize:none;padding:14px 16px;font:14px/1.6 inherit;min-height:120px}
#cmp .catts{display:flex;flex-wrap:wrap;gap:6px;padding:0 14px 10px}
#cmp .catts .chip .ib{width:20px;height:20px;margin-right:-6px}
#cmp .cfoot{display:flex;align-items:center;gap:6px;padding:10px 12px;border-top:1px solid var(--line)}
#cmp .cfoot .grow{flex:1}
#cmp .cfoot .note{font-size:12px;color:var(--dim)}
.drop{outline:2px dashed rgba(var(--glow),.7);outline-offset:-6px}
#settings .chk{display:flex;align-items:center;gap:10px;margin:4px 0 12px}
#settings textarea.inp{width:100%;height:auto;min-height:96px;padding:10px 12px;resize:vertical;font:13.5px/1.5 inherit}
#settings .inp{width:100%}
#settings label.l{display:block;font-size:12.5px;color:var(--mut);margin:12px 0 6px}
#settings h4{margin:18px 0 4px;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--dim)}
#fab{display:none;position:fixed;right:18px;bottom:22px;z-index:40;height:54px;padding:0 20px;border-radius:18px;font-size:15px}
#cmp .fl .lnk{align-self:center}
#lidp{width:100%;justify-content:center;height:46px;margin-top:22px;font-size:15px}
@media (max-width:1180px){#listp{width:370px}}
@media (max-width:900px){
  #listp{width:100%;border-right:0}
  #readp{display:none}
  body.reading #listp{display:none}
  body.reading #readp{display:block}
  .rbar #backB{display:inline-flex}
  .rd{padding:12px 16px 80px}
  #cmp{right:0;left:0;width:100%;max-width:none;height:100%;border-radius:0;top:0}
  #top .search{max-width:none;display:block}
  #fab{display:inline-flex}
  body.reading #fab{display:none}
}
</style>
</head>
<body>
<div id="aurora"><i></i><i></i><i></i></div>
<div id="login" hidden>
  <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
  <div class="lcard">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>socketley</div>
    <h1>Mail</h1>
    <p class="mut" id="lsub">Sign in with your account to read and send your mail.</p>
    <div class="err" id="le"></div>
    <a class="btn pri" id="lidp" hidden>Sign in with your account</a>
  </div>
</div>
<div id="app" hidden>
  <aside id="side">
    <div class="logo" id="home"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>Mail</div>
    <button class="btn pri" id="compose"></button>
    <div id="boxes"></div>
    <button class="nav" id="nSet"></button>
    <div class="me" id="me"></div>
    <div class="themes" id="themes"></div>
    <button class="nav" id="nOut"></button>
  </aside>
  <div id="main">
    <div id="top">
      <button class="ib" id="menuB"></button>
      <div class="search" id="srch"><input class="inp" id="q" type="search" placeholder="Search mail" spellcheck="false" autocomplete="off"></div>
      <div class="grow"></div>
      <button class="ib" id="refB"></button>
    </div>
    <div id="panes">
      <section id="listp">
        <div id="lhead"><h2 id="ltitle"></h2><div id="bulk"></div></div>
        <div id="rows"></div>
      </section>
      <section id="readp"></section>
    </div>
  </div>
</div>
<button class="btn pri" id="fab"></button>
<datalist id="addrs"></datalist>
<div id="toasts"></div>
<script>
'use strict';
/*KIT*/
Object.assign(P, {
  inbox: '<path d="M3 13h5l1.5 2.5h5L16 13h5"/><path d="M5.5 5h13L21 13v5.5A1.5 1.5 0 0 1 19.5 20h-15A1.5 1.5 0 0 1 3 18.5V13z"/>',
  star: '<path d="m12 3.5 2.6 5.3 5.8.8-4.2 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.2-4.1 5.8-.8z"/>',
  reply: '<path d="M10 8 5 12.5 10 17"/><path d="M5 12.5h9a5 5 0 0 1 5 5V19"/>',
  replyall: '<path d="M8 8 3 12.5 8 17"/><path d="M13 8 8 12.5 13 17"/><path d="M8 12.5h6a5 5 0 0 1 5 5V19"/>',
  forward: '<path d="m14 8 5 4.5-5 4.5"/><path d="M19 12.5h-9a5 5 0 0 0-5 5V19"/>',
  clip: '<path d="m20 11.5-8.2 8.2a5 5 0 0 1-7.1-7.1l8.6-8.6a3.4 3.4 0 0 1 4.8 4.8l-8.4 8.4a1.7 1.7 0 0 1-2.4-2.4l7.7-7.7"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="m3.5 7 8.5 6 8.5-6"/>',
  mailopen: '<path d="M3 10 12 4l9 6v8.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/><path d="m3.5 10.5 8.5 5.5 8.5-5.5"/>',
  junk: '<circle cx="12" cy="12" r="8.5"/><path d="m6 6 12 12"/>',
  min: '<path d="M6 12h12"/>', pen: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>'
});

// ─── state ──────────────────────────────────────────────────────────────────
const USING = ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'];
const PAGE = 50;
const ROLES = ['inbox', 'starred', 'drafts', 'sent', 'junk', 'trash'];
const ROLE_ICON = { inbox: 'inbox', starred: 'star', drafts: 'pen', sent: 'send', junk: 'junk', trash: 'trash' };
const ROLE_NAME = { inbox: 'Inbox', starred: 'Starred', drafts: 'Drafts', sent: 'Sent', junk: 'Junk', trash: 'Trash' };
const LIST_PROPS = ['id', 'threadId', 'mailboxIds', 'keywords', 'from', 'to', 'subject', 'receivedAt', 'preview', 'hasAttachment', 'size'];
let me = null, acct = '', identity = 'i0', myName = '', signature = '', boxes = [], byRole = {}, byId = {};
// What the list shows: a mailbox by id, the starred, or a search over every mailbox.
let view = { box: '', starred: false, q: '' };
let mails = [], total = 0, loadingMore = false, seq = 0;
let open = null, openMsg = null, picked = new Set(), showImages = new Set();
let es = null, refreshTimer = 0;

// ─── JMAP ───────────────────────────────────────────────────────────────────
async function errText(r) { let t = ''; try { const j = await r.json(); t = j.detail || j.description || j.type || ''; } catch (e) {} return t || r.status + ' ' + r.statusText; }
// One request of method calls, its answers by call id; a method error throws with what it says.
async function jmap(...calls) {
  let r;
  try {
    r = await fetch('/jmap/api', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Socketley-UI': '1' }, body: JSON.stringify({ using: USING, methodCalls: calls }) });
  } catch (e) { throw new Error('The mail server cannot be reached'); }
  if (r.status === 401) { signedOut(r.headers.get('X-Socketley-Idp-Login')); throw new Error('Your session has ended: sign in again'); }
  if (!r.ok) throw new Error(await errText(r));
  const out = {};
  for (const [name, args, id] of (await r.json()).methodResponses) {
    if (name === 'error') throw new Error(args.description || args.type || 'The server refused it');
    (out[id] = out[id] || []).push(args);
  }
  return out;
}
const one = (res, id) => (res[id] || [])[0] || {};
function setErrors(a) {
  const e = Object.values(a.notCreated || {})[0] || Object.values(a.notUpdated || {})[0] || Object.values(a.notDestroyed || {})[0];
  if (e) throw new Error(e.description || e.type);
}
const dl = (blob, name, type) => '/jmap/download/' + encodeURIComponent(acct) + '/' + encodeURIComponent(blob) + '/' + encodeURIComponent(name || 'attachment') + '?type=' + encodeURIComponent(type || 'application/octet-stream');

// ─── text helpers ───────────────────────────────────────────────────────────
const nameOf = a => a ? (a.name || a.email || '') : '';
const who = list => (list || []).map(a => a.name ? a.name + ' <' + a.email + '>' : a.email).join(', ');
const whoShort = list => (list || []).map(a => a.name || a.email).join(', ');
const letter = s => (s || '?').replace(/^["'\s]+/, '').charAt(0) || '?';
function avatar(a, cls) { const s = nameOf(a) || '?'; return el('div', { class: 'av' + (cls ? ' ' + cls : ''), style: 'background:hsl(' + hue((a && a.email) || s) + ' 52% 44%)', text: letter(s) }); }
const LOC = navigator.language || 'en';
function short(d) {
  const t = new Date(d), n = new Date();
  if (t.toDateString() === n.toDateString()) return t.toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit' });
  if (t.getFullYear() === n.getFullYear()) return t.toLocaleDateString(LOC, { day: 'numeric', month: 'short' });
  return t.toLocaleDateString(LOC, { day: '2-digit', month: '2-digit', year: '2-digit' });
}
const full = d => new Date(d).toLocaleString(LOC, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
// "Name <a@b>, c@d" as JMAP addresses, false when one is no address.
function parseAddrs(s) {
  const out = [];
  for (let part of s.split(/[,;]\s*(?=(?:[^"]*"[^"]*")*[^"]*$)/)) {
    part = part.trim(); if (!part) continue;
    const m = part.match(/^(.*?)\s*<([^<>\s]+@[^<>\s]+)>$/);
    const email = m ? m[2] : part, name = m ? m[1].replace(/^"|"$/g, '').trim() : '';
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return false;
    out.push(name ? { name, email } : { email });
  }
  return out;
}
function remember(list) {
  const known = new Set(JSON.parse(store.get('skl-mail-addrs', '[]')));
  let changed = false;
  for (const a of list || []) if (a && a.email && a.email !== me.address) { const v = a.name ? a.name + ' <' + a.email + '>' : a.email; if (!known.has(v)) { known.add(v); changed = true; } }
  if (!changed) return;
  const arr = [...known].slice(-400);
  store.set('skl-mail-addrs', JSON.stringify(arr));
  paintAddrs(arr);
}
function paintAddrs(arr) { const d = $('#addrs'); d.textContent = ''; for (const v of arr || JSON.parse(store.get('skl-mail-addrs', '[]'))) d.append(el('option', { value: v })); }
function linkify(text) {
  const frag = document.createDocumentFragment();
  for (const line of text.split('\n')) {
    const box = /^\s*>/.test(line) ? el('span', { class: 'q' }) : document.createDocumentFragment();
    let last = 0;
    for (const m of line.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/g)) {
      box.append(line.slice(last, m.index));
      box.append(el('a', { href: m[0], target: '_blank', rel: 'noopener noreferrer', text: m[0] }));
      last = m.index + m[0].length;
    }
    box.append(line.slice(last));
    if (box.nodeType === 11) box.append('\n');
    frag.append(box);
  }
  return frag;
}
function textOfHtml(html) { const d = new DOMParser().parseFromString(html, 'text/html'); d.querySelectorAll('style,script,head').forEach(e => e.remove()); for (const b of d.querySelectorAll('br')) b.replaceWith('\n'); for (const p of d.querySelectorAll('p,div,tr,li,h1,h2,h3,h4')) p.append('\n'); return (d.body ? d.body.textContent : '').replace(/\n{3,}/g, '\n\n').trim(); }

// ─── mail's own HTML ────────────────────────────────────────────────────────
// Mail's HTML, cleaned of anything that runs, submits or reaches out, and of remote images until the reader asks for
// them; it is shown in a frame sandboxed without scripts, as the page's CSP has it too.
const FRAME_CSS = 'html,body{margin:0;background:#fff;color:#1f2330;font:14px/1.55 -apple-system,"Segoe UI",Roboto,Inter,Arial,sans-serif;word-wrap:break-word;overflow-wrap:anywhere}body{padding:18px 20px}img{max-width:100%;height:auto}table{max-width:100%}pre{white-space:pre-wrap}blockquote{margin:0 0 0 .8ex;border-left:2px solid #cfd3dc;padding-left:1ex;color:#596070}a{color:#6d28d9}';
function cleanHtml(html, images, cids) {
  const d = new DOMParser().parseFromString(html, 'text/html');
  d.querySelectorAll('script,iframe,frame,frameset,object,embed,applet,form,input,button,select,textarea,meta,link,base,noscript,template,portal,dialog').forEach(e => e.remove());
  let blocked = 0;
  const urlish = /^(href|src|action|formaction|background|poster|srcset|xlink:href|data|lowsrc|dynsrc|cite|longdesc|ping)$/;
  for (const e of d.querySelectorAll('*')) {
    for (const a of [...e.attributes]) {
      const n = a.name.toLowerCase(), v = a.value.replace(/[\u0000- ]/g, '');
      if (n.startsWith('on') || n === 'srcdoc' || n === 'formaction' || n === 'ping') { e.removeAttribute(a.name); continue; }
      if (urlish.test(n) && /^(javascript|vbscript|data:(?!image\/(png|gif|jpe?g|webp);))/i.test(v)) e.removeAttribute(a.name);
    }
    if (e.localName === 'a' && e.hasAttribute('href')) { e.setAttribute('target', '_blank'); e.setAttribute('rel', 'noopener noreferrer'); }
    for (const at of ['src', 'background', 'poster']) {
      const v = (e.getAttribute(at) || '').trim(); if (!v) continue;
      if (/^cid:/i.test(v)) { const u = cids[v.slice(4).replace(/^<|>$/g, '').toLowerCase()]; if (u) e.setAttribute(at, u); else e.removeAttribute(at); }
      else if (/^(https?:)?\/\//i.test(v)) { if (images) e.setAttribute(at, v.replace(/^(http:)?\/\//i, 'https://')); else { e.removeAttribute(at); blocked++; } }
    }
    if (e.hasAttribute('srcset') && !images) { e.removeAttribute('srcset'); blocked++; }
    const st = e.getAttribute('style');
    if (st && /url\s*\(|expression\s*\(/i.test(st)) { if (!images || /expression/i.test(st)) blocked++; e.setAttribute('style', images ? st.replace(/expression\s*\([^)]*\)/gi, '') : st.replace(/url\s*\([^)]*\)|expression\s*\([^)]*\)/gi, 'none')); }
  }
  let css = '';
  for (const s of d.querySelectorAll('style')) {
    let t = s.textContent.replace(/@import[^;]*;?/gi, '').replace(/expression\s*\([^)]*\)/gi, '');
    if (!images && /url\s*\(/i.test(t)) { t = t.replace(/url\s*\([^)]*\)/gi, 'none'); blocked++; }
    css += t + '\n'; s.remove();
  }
  return { doc: '<!doctype html><html><head><meta charset="utf-8"><style>' + FRAME_CSS + '</style><style>' + css.replace(/<\/style/gi, '') + '</style></head><body>' + (d.body ? d.body.innerHTML : '') + '</body></html>', blocked };
}
function frame(docHtml) {
  const f = el('iframe', { sandbox: 'allow-same-origin allow-popups allow-popups-to-escape-sandbox', referrerpolicy: 'no-referrer', title: 'Message' });
  f.srcdoc = docHtml;
  const fit = () => { try { const b = f.contentDocument; if (b && b.documentElement) f.style.height = Math.max(80, b.documentElement.scrollHeight + 2) + 'px'; } catch (e) {} };
  f.addEventListener('load', () => {
    fit();
    try { new ResizeObserver(fit).observe(f.contentDocument.documentElement); for (const i of f.contentDocument.images) i.addEventListener('load', fit); } catch (e) {}
  });
  return f;
}

// ─── signing in ─────────────────────────────────────────────────────────────
function signedOut(login) {
  me = null; if (es) { es.close(); es = null; }
  $('#app').hidden = true; $('#login').hidden = false;
  while (layers.length) layers[layers.length - 1].close();
  closeCompose(true);
  if (login) { $('#lidp').href = login; $('#lidp').hidden = false; $('#le').textContent = ''; }
  else $('#le').textContent = 'This mail server signs in through an idp runtime, which it cannot reach now.';
}
async function signOut() {
  if (me && me.logout) { location.href = me.logout; return; }
  signedOut(null);
}

// ─── mailboxes ──────────────────────────────────────────────────────────────
function boxLabel(b) { return b.role && ROLE_NAME[b.role] ? ROLE_NAME[b.role] : b.name; }
async function loadBoxes() {
  const res = await jmap(['Mailbox/get', { accountId: acct, properties: ['id', 'name', 'role', 'parentId', 'sortOrder', 'totalEmails', 'unreadEmails'] }, 'b']);
  boxes = one(res, 'b').list || [];
  byRole = {}; byId = {};
  for (const b of boxes) { byId[b.id] = b; if (b.role) byRole[b.role] = b; }
  boxes.sort((a, b) => {
    const ra = ROLES.indexOf(a.role), rb = ROLES.indexOf(b.role);
    if (ra !== rb) return (ra < 0 ? 99 : ra) - (rb < 0 ? 99 : rb);
    return (a.sortOrder || 0) - (b.sortOrder || 0) || a.name.localeCompare(b.name);
  });
  if (!view.box && !view.starred && !view.q && byRole.inbox) view.box = byRole.inbox.id;
  paintBoxes();
}
function paintBoxes() {
  const B = $('#boxes'); B.textContent = '';
  const nav = (icon, label, on, fn, cnt, dim) => el('button', { class: 'nav' + (on ? ' on' : ''), onclick: () => { fn(); $('#side').classList.remove('open'); } }, ico(icon), el('span', { text: label }), cnt ? el('span', { class: 'cnt' + (dim ? ' dim' : ''), text: cnt > 999 ? '999+' : String(cnt) }) : null);
  const add = b => {
    const n = nav(b.role && ROLE_ICON[b.role] || 'folder', boxLabel(b), !view.q && !view.starred && view.box === b.id, () => go({ box: b.id }), b.role === 'drafts' ? b.totalEmails : b.role === 'sent' || b.role === 'trash' ? 0 : b.unreadEmails, b.role === 'drafts');
    // A folder of the user's own is renamed or deleted from its menu, on its button or a right click.
    if (!b.role) {
      n.addEventListener('contextmenu', e => { e.preventDefault(); folderMenu({ x: e.clientX, y: e.clientY }, b); });
      n.append(el('span', { class: 'fm', title: 'Folder actions', onclick: e => { e.stopPropagation(); folderMenu(e.currentTarget, b); } }, ico('more')));
    }
    B.append(n);
  };
  for (const b of boxes.filter(b => b.role === 'inbox')) add(b);
  B.append(nav('star', 'Starred', view.starred && !view.q, () => go({ starred: true })));
  for (const b of boxes.filter(b => b.role && b.role !== 'inbox')) add(b);
  const own = boxes.filter(b => !b.role);
  B.append(el('div', { class: 'sh row' }, el('span', { text: 'Folders' }), ibtn('plus', 'New folder', newFolder)));
  for (const b of own) add(b);
  const inbox = byRole.inbox;
  document.title = (inbox && inbox.unreadEmails ? '(' + inbox.unreadEmails + ') ' : '') + title() + ' · Mail';
}
function title() { return view.q ? 'Search' : view.starred ? 'Starred' : byId[view.box] ? boxLabel(byId[view.box]) : 'Mail'; }
async function newFolder() {
  const name = await ask({ title: 'New folder', input: 'Folder name', ok: 'Create' });
  if (!name) return;
  try { const res = await jmap(['Mailbox/set', { accountId: acct, create: { n: { name, parentId: null } } }, 'c']); setErrors(one(res, 'c')); await loadBoxes(); toast('Folder created'); }
  catch (e) { fail(e); }
}
async function folderMenu(at, b) {
  popup(at, [
    { icon: 'edit', label: 'Rename', fn: async () => {
      const name = await ask({ title: 'Rename folder', input: 'Folder name', value: b.name, ok: 'Rename' });
      if (!name || name === b.name) return;
      try { const res = await jmap(['Mailbox/set', { accountId: acct, update: { [b.id]: { name } } }, 'u']); setErrors(one(res, 'u')); await loadBoxes(); } catch (e) { fail(e); }
    } },
    { icon: 'trash', label: 'Delete folder', bad: true, fn: async () => {
      if (!await ask({ title: 'Delete “' + b.name + '”?', text: 'The folder and every message in it are deleted for good.', ok: 'Delete', danger: true })) return;
      try { const res = await jmap(['Mailbox/set', { accountId: acct, destroy: [b.id], onDestroyRemoveEmails: true }, 'd']); setErrors(one(res, 'd')); if (view.box === b.id) view.box = byRole.inbox ? byRole.inbox.id : ''; await loadBoxes(); await loadList(); } catch (e) { fail(e); }
    } }
  ]);
}

// ─── the list ───────────────────────────────────────────────────────────────
function go(v) {
  view = { box: v.box || '', starred: !!v.starred, q: v.q || '' };
  if (!view.q) $('#q').value = '';
  picked.clear(); open = null; openMsg = null; document.body.classList.remove('reading');
  location.hash = view.q ? 'search/' + encodeURIComponent(view.q) : view.starred ? 'starred' : 'box/' + encodeURIComponent(view.box);
  paintBoxes(); paintReader(); loadList();
}
function filter() {
  if (view.q) return { text: view.q };
  if (view.starred) return { hasKeyword: '$flagged' };
  return { inMailbox: view.box };
}
async function loadList(keep) {
  const my = ++seq;
  if (!keep) { mails = []; total = 0; paintList(true); }
  try {
    const res = await jmap(
      ['Email/query', { accountId: acct, filter: filter(), sort: [{ property: 'receivedAt', isAscending: false }], position: 0, limit: Math.max(PAGE, keep ? mails.length : 0), calculateTotal: true }, 'q'],
      ['Email/get', { accountId: acct, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: LIST_PROPS }, 'g']);
    if (my !== seq) return;
    const q = one(res, 'q'), got = one(res, 'g').list || [];
    const by = Object.fromEntries(got.map(m => [m.id, m]));
    mails = (q.ids || []).map(id => by[id]).filter(Boolean);
    total = q.total != null ? q.total : mails.length;
    for (const m of mails.slice(0, 20)) remember(view.box && byId[view.box] && byId[view.box].role === 'sent' ? m.to : m.from);
    paintList();
  } catch (e) { if (my === seq) { paintList(); fail(e); } }
}
async function loadMore() {
  if (loadingMore || mails.length >= total) return;
  loadingMore = true;
  const my = seq;
  try {
    const res = await jmap(
      ['Email/query', { accountId: acct, filter: filter(), sort: [{ property: 'receivedAt', isAscending: false }], position: mails.length, limit: PAGE }, 'q'],
      ['Email/get', { accountId: acct, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: LIST_PROPS }, 'g']);
    if (my !== seq) return;
    const q = one(res, 'q'), by = Object.fromEntries((one(res, 'g').list || []).map(m => [m.id, m]));
    const have = new Set(mails.map(m => m.id));
    for (const id of q.ids || []) if (by[id] && !have.has(id)) mails.push(by[id]);
    paintList();
  } catch (e) { fail(e); }
  finally { loadingMore = false; }
}
function paintList(loading) {
  const H = $('#lhead');
  $('#ltitle').textContent = '';
  $('#ltitle').append(title(), total ? el('span', { class: 'n', text: total.toLocaleString(LOC) }) : null);
  H.classList.toggle('picking', picked.size > 0);
  paintBulk();
  const R = $('#rows'); R.textContent = '';
  R.classList.toggle('picking', picked.size > 0);
  if (loading) { R.append(el('div', { class: 'more', text: 'Loading…' })); return; }
  if (!mails.length) {
    R.append(el('div', { class: 'empty' }, ico(view.q ? 'search' : view.starred ? 'star' : 'inbox'), el('b', { text: view.q ? 'Nothing matches “' + view.q + '”' : 'Nothing here' }), el('span', { text: view.q ? 'Try other words, or a name or address.' : view.starred ? 'Star a message to find it here.' : 'New mail shows up here as it arrives.' })));
    return;
  }
  const sentish = !view.q && !view.starred && byId[view.box] && ['sent', 'drafts'].includes(byId[view.box].role);
  for (const m of mails) R.append(rowOf(m, sentish));
  if (mails.length < total) R.append(el('div', { class: 'more', text: 'Loading more…' }));
}
function rowOf(m, sentish) {
  const k = m.keywords || {}, seen = k.$seen, flagged = k.$flagged;
  const party = sentish ? (m.to && m.to.length ? 'To: ' + whoShort(m.to) : '(no recipient)') : whoShort(m.from) || '(unknown sender)';
  const boxName = view.q || view.starred ? Object.keys(m.mailboxIds || {}).map(id => byId[id]).filter(b => b && b.role !== 'inbox').map(boxLabel)[0] : '';
  const tick = el('div', { class: 'tick', onclick: e => { e.stopPropagation(); togglePick(m.id); } }, ico('check'));
  const r = el('div', { class: 'row' + (seen ? '' : ' unread') + (open === m.id ? ' on' : '') + (picked.has(m.id) ? ' ck' : ''), 'data-id': m.id, onclick: () => openMail(m.id) },
    el('div', { class: 'avw' }, avatar(sentish ? (m.to || [])[0] : (m.from || [])[0]), tick),
    el('div', { class: 'rm' },
      el('div', { class: 'r1' }, el('span', { class: 'who', text: party }), el('span', { class: 'when', text: short(m.receivedAt), title: full(m.receivedAt) })),
      el('div', { class: 'r2' }, el('span', { class: 'subj', text: m.subject || '(no subject)' }), boxName ? el('span', { class: 'tag', text: boxName }) : null, m.hasAttachment ? ico('clip') : null),
      el('div', { class: 'r3', text: m.preview || '' })),
    ibtn('star', flagged ? 'Unstar' : 'Star', e => { e.stopPropagation(); star([m.id], !flagged); }, 'st' + (flagged ? ' on' : '')));
  return r;
}
function paintBulk() {
  const B = $('#bulk'); B.textContent = '';
  if (!picked.size) return;
  const ids = [...picked];
  B.append(ibtn('close', 'Clear the selection', () => { picked.clear(); paintList(); }), el('span', { text: picked.size + ' selected' }),
    ibtn('mailopen', 'Mark as read', () => markSeen(ids, true)), ibtn('mail', 'Mark as unread', () => markSeen(ids, false)),
    ibtn('star', 'Star', () => star(ids, true)), ibtn('folder', 'Move to', e => moveMenu(e.currentTarget, ids)), ibtn('trash', 'Delete', () => remove(ids)));
}
function togglePick(id) { if (picked.has(id)) picked.delete(id); else picked.add(id); paintList(); }
function patchLocal(ids, fn) { for (const m of mails) if (ids.includes(m.id)) fn(m); if (openMsg && ids.includes(openMsg.id)) fn(openMsg); }

// ─── acting on messages ─────────────────────────────────────────────────────
async function update(ids, patch, after) {
  const res = await jmap(['Email/set', { accountId: acct, update: Object.fromEntries(ids.map(id => [id, patch])) }, 'u']);
  setErrors(one(res, 'u'));
  if (after) after();
}
async function markSeen(ids, on) {
  patchLocal(ids, m => { m.keywords = m.keywords || {}; if (on) m.keywords.$seen = true; else delete m.keywords.$seen; });
  paintList(); paintReaderBar();
  try { await update(ids, { 'keywords/$seen': on ? true : null }); await loadBoxes(); } catch (e) { fail(e); loadList(true); }
}
async function star(ids, on) {
  patchLocal(ids, m => { m.keywords = m.keywords || {}; if (on) m.keywords.$flagged = true; else delete m.keywords.$flagged; });
  paintList(); paintReaderBar();
  try { await update(ids, { 'keywords/$flagged': on ? true : null }); if (view.starred && !on) loadList(true); } catch (e) { fail(e); loadList(true); }
}
async function move(ids, to, said) {
  try {
    await update(ids, { mailboxIds: { [to]: true } });
    dropFromList(ids);
    toast(said || 'Moved to ' + boxLabel(byId[to]));
    await loadBoxes();
  } catch (e) { fail(e); loadList(true); }
}
function dropFromList(ids) {
  const at = open && ids.includes(open) ? mails.findIndex(m => m.id === open) : -1;
  mails = mails.filter(m => !ids.includes(m.id)); total = Math.max(0, total - ids.length);
  for (const id of ids) picked.delete(id);
  if (at >= 0) { const next = mails[Math.min(at, mails.length - 1)]; open = null; openMsg = null; if (next && innerWidth > 900) openMail(next.id); else { document.body.classList.remove('reading'); paintReader(); } }
  paintList();
}
async function remove(ids) {
  const trash = byRole.trash;
  const inTrash = mails.filter(m => ids.includes(m.id)).every(m => trash && m.mailboxIds && m.mailboxIds[trash.id]);
  if (!trash || inTrash) {
    if (!await ask({ title: ids.length > 1 ? 'Delete ' + ids.length + ' messages for good?' : 'Delete this message for good?', text: 'It cannot be brought back.', ok: 'Delete', danger: true })) return;
    try { const res = await jmap(['Email/set', { accountId: acct, destroy: ids }, 'd']); setErrors(one(res, 'd')); dropFromList(ids); toast('Deleted'); await loadBoxes(); } catch (e) { fail(e); }
    return;
  }
  await move(ids, trash.id, ids.length > 1 ? ids.length + ' messages moved to Trash' : 'Moved to Trash');
}
function moveMenu(at, ids) {
  const here = mails.find(m => m.id === ids[0]);
  const cur = here ? Object.keys(here.mailboxIds || {})[0] : '';
  popup(at, [{ head: 'Move to' }, ...boxes.filter(b => b.id !== cur && b.role !== 'drafts').map(b => ({ icon: b.role && ROLE_ICON[b.role] || 'folder', label: boxLabel(b), fn: () => move(ids, b.id) }))]);
}

// ─── reading ────────────────────────────────────────────────────────────────
async function openMail(id) {
  open = id; picked.clear();
  for (const r of document.querySelectorAll('.row')) r.classList.toggle('on', r.dataset.id === id);
  document.body.classList.add('reading');
  const listed = mails.find(m => m.id === id);
  if (listed && byId[Object.keys(listed.mailboxIds || {})[0]] && byId[Object.keys(listed.mailboxIds)[0]].role === 'drafts') { editDraft(id); return; }
  $('#readp').textContent = ''; $('#readp').append(el('div', { class: 'blank' }, el('span', { text: 'Opening…' })));
  try {
    const res = await jmap(['Email/get', { accountId: acct, ids: [id], properties: [...LIST_PROPS, 'cc', 'bcc', 'replyTo', 'sentAt', 'messageId', 'inReplyTo', 'references', 'textBody', 'htmlBody', 'attachments', 'bodyValues'],
      bodyProperties: ['partId', 'blobId', 'size', 'name', 'type', 'charset', 'disposition', 'cid'], fetchTextBodyValues: true, fetchHTMLBodyValues: true, maxBodyValueBytes: 4000000 }, 'g']);
    if (open !== id) return;
    openMsg = (one(res, 'g').list || [])[0];
    if (!openMsg) { paintReader(); toast('That message is no longer there', 'bad'); return; }
    paintReader();
    if (!(openMsg.keywords || {}).$seen) markSeen([id], true);
  } catch (e) { fail(e); }
}
function paintReaderBar() {
  const bar = $('#rbar'); if (!bar || !openMsg) return;
  const m = openMsg, flagged = (m.keywords || {}).$flagged, junk = byRole.junk, inJunk = junk && m.mailboxIds && m.mailboxIds[junk.id];
  bar.textContent = '';
  const back = ibtn('left', 'Back to the list', () => { document.body.classList.remove('reading'); open = null; openMsg = null; paintList(); });
  back.id = 'backB';
  bar.append(back);
  bar.append(ibtn('reply', 'Reply  (r)', () => reply(m, false)), ibtn('replyall', 'Reply all  (a)', () => reply(m, true)), ibtn('forward', 'Forward  (f)', () => forward(m)),
    el('div', { class: 'grow' }),
    ibtn('star', flagged ? 'Unstar  (s)' : 'Star  (s)', () => star([m.id], !flagged), 'st' + (flagged ? ' on' : '')),
    ibtn('mail', 'Mark as unread  (u)', () => { markSeen([m.id], false); document.body.classList.remove('reading'); }),
    ibtn('folder', 'Move to', e => moveMenu(e.currentTarget, [m.id])),
    junk && !inJunk ? ibtn('junk', 'Report junk', () => move([m.id], junk.id, 'Moved to Junk')) : null,
    ibtn('trash', 'Delete  (#)', () => remove([m.id])),
    ibtn('more', 'More', e => popup(e.currentTarget, [
      inJunk && byRole.inbox ? { icon: 'inbox', label: 'Not junk', fn: () => move([m.id], byRole.inbox.id, 'Moved to Inbox') } : null,
      { icon: 'download', label: 'Download message (.eml)', fn: () => { location.href = dl(m.id, (m.subject || 'message').replace(/[\\/:*?"<>|]+/g, ' ').slice(0, 80) + '.eml', 'message/rfc822'); } }
    ])));
}
function paintReader() {
  const R = $('#readp'); R.textContent = '';
  const m = openMsg;
  if (!m) {
    R.append(el('div', { class: 'blank' }, el('div', { class: 'ring' }, ico('mail')), el('b', { text: mails.length ? 'Pick a message to read it' : 'Nothing selected' }),
      el('span', {}, 'Press ', el('span', { class: 'kbd', text: 'c' }), ' to write one, ', el('span', { class: 'kbd', text: '/' }), ' to search.')));
    return;
  }
  const from = (m.from || [])[0];
  const rcp = [];
  if (m.to && m.to.length) rcp.push('to ' + who(m.to));
  if (m.cc && m.cc.length) rcp.push('cc ' + who(m.cc));
  if (m.bcc && m.bcc.length) rcp.push('bcc ' + who(m.bcc));
  const box = byId[Object.keys(m.mailboxIds || {})[0]];
  const d = el('div', { class: 'rd' },
    el('div', { class: 'rbar', id: 'rbar' }),
    el('h1', {}, m.subject || '(no subject)', box && box.role !== 'inbox' ? el('span', { class: 'tag', text: boxLabel(box) }) : null),
    el('div', { class: 'hdr' }, avatar(from),
      el('div', { class: 'who' }, el('b', { text: nameOf(from) || '(unknown sender)' }), from && from.name ? el('span', { class: 'addr', text: '<' + from.email + '>' }) : null, el('div', { class: 'rcp', text: rcp.join(' · ') })),
      el('div', { class: 'when', text: full(m.sentAt || m.receivedAt) })));
  const values = m.bodyValues || {};
  const cids = {};
  for (const p of m.attachments || []) if (p.cid) cids[p.cid.replace(/^<|>$/g, '').toLowerCase()] = dl(p.blobId, p.name || 'image', p.type);
  const html = (m.htmlBody || []).filter(p => p.type === 'text/html').map(p => (values[p.partId] || {}).value || '').join('');
  const text = (m.textBody || []).filter(p => p.type !== 'text/html').map(p => (values[p.partId] || {}).value || '').join('\n');
  if (html.trim()) {
    const allow = showImages.has(m.id) || showImages.has('*' + ((from && from.email) || ''));
    const c = cleanHtml(html, allow, cids);
    if (c.blocked && !allow)
      d.append(el('div', { class: 'imgbar' }, ico('image'), el('span', { text: 'Remote images are hidden, so the sender cannot see when you read this.' }),
        btn(null, 'Show images', () => { showImages.add(m.id); paintReader(); }),
        from ? btn(null, 'Always from this sender', () => { showImages.add('*' + from.email); store.set('skl-mail-img', JSON.stringify([...showImages].filter(x => x.startsWith('*')))); paintReader(); }) : null));
    d.append(el('div', { class: 'mbody' }, frame(c.doc)));
  } else d.append(el('div', { class: 'mtext' }, linkify(text || m.preview || '')));
  const atts = (m.attachments || []).filter(p => !(p.cid && html.includes(p.cid.replace(/^<|>$/g, ''))) || p.disposition === 'attachment');
  if (atts.length) {
    const A = el('div', { class: 'atts' });
    for (const p of atts) {
      const url = dl(p.blobId, p.name || 'attachment', p.type);
      const isImg = /^image\/(png|jpe?g|gif|webp)$/i.test(p.type || '');
      A.append(el('a', { class: 'att', href: url, download: p.name || 'attachment', title: p.name || 'attachment' },
        el('div', { class: 'ti' }, isImg ? el('img', { src: url, alt: '' }) : ico(ICON[kind(p.name || '', p.type)] || 'file')),
        el('div', {}, el('div', { class: 'nm', text: p.name || 'attachment' }), el('div', { class: 'sz', text: human(p.size) }))));
    }
    d.append(A);
  }
  R.append(d);
  paintReaderBar();
  R.scrollTop = 0;
}

// ─── writing ────────────────────────────────────────────────────────────────
let cmp = null;
const quoteOf = m => {
  const vals = m.bodyValues || {};
  let t = (m.textBody || []).filter(p => p.type !== 'text/html').map(p => (vals[p.partId] || {}).value || '').join('\n');
  if (!t.trim()) t = textOfHtml((m.htmlBody || []).map(p => (vals[p.partId] || {}).value || '').join(''));
  return t;
};
function reply(m, all) {
  const mine = me.address.toLowerCase();
  const to = (m.replyTo && m.replyTo.length ? m.replyTo : m.from || []).filter(a => a.email.toLowerCase() !== mine);
  const sent = byRole.sent && m.mailboxIds && m.mailboxIds[byRole.sent.id];
  const target = sent ? m.to || [] : to.length ? to : m.from || [];
  const cc = all ? [...(m.to || []), ...(m.cc || [])].filter(a => a.email.toLowerCase() !== mine && !target.some(t => t.email.toLowerCase() === a.email.toLowerCase())) : [];
  const from = (m.from || [])[0];
  const quoted = quoteOf(m).split('\n').map(l => '> ' + l).join('\n');
  compose({
    to: who(target), cc: who(cc), subject: /^re:/i.test(m.subject || '') ? m.subject : 'Re: ' + (m.subject || ''),
    body: '\n\nOn ' + full(m.sentAt || m.receivedAt) + ', ' + (nameOf(from) || 'someone') + ' wrote:\n' + quoted + '\n',
    inReplyTo: m.messageId || null, references: [...(m.references || []), ...(m.messageId || [])], replyTo: m.id
  });
}
function forward(m) {
  const head = '\n\n---------- Forwarded message ----------\nFrom: ' + who(m.from) + '\nDate: ' + full(m.sentAt || m.receivedAt) + '\nSubject: ' + (m.subject || '') + '\nTo: ' + who(m.to) + (m.cc && m.cc.length ? '\nCc: ' + who(m.cc) : '') + '\n\n';
  compose({ subject: /^fwd?:/i.test(m.subject || '') ? m.subject : 'Fwd: ' + (m.subject || ''), body: head + quoteOf(m) + '\n',
    attachments: (m.attachments || []).map(p => ({ blobId: p.blobId, type: p.type, name: p.name || 'attachment', size: p.size })) });
}
async function editDraft(id) {
  try {
    const res = await jmap(['Email/get', { accountId: acct, ids: [id], properties: ['id', 'to', 'cc', 'bcc', 'subject', 'textBody', 'htmlBody', 'attachments', 'bodyValues', 'inReplyTo', 'references'], fetchTextBodyValues: true, fetchHTMLBodyValues: true }, 'g']);
    const m = (one(res, 'g').list || [])[0]; if (!m) return;
    compose({ to: who(m.to), cc: who(m.cc), bcc: who(m.bcc), subject: m.subject || '', body: quoteOf(m), inReplyTo: m.inReplyTo, references: m.references,
      attachments: (m.attachments || []).map(p => ({ blobId: p.blobId, type: p.type, name: p.name || 'attachment', size: p.size })), draft: id });
    document.body.classList.remove('reading'); open = null; paintList();
  } catch (e) { fail(e); }
}
function compose(o = {}) {
  if (cmp) { if (!closeCompose()) return; }
  const field = (lab, val, more) => { const i = el('input', { value: val || '', spellcheck: 'false', autocomplete: 'off', list: lab === 'Subject' ? null : 'addrs' }); return [i, el('div', { class: 'fl' }, el('label', { text: lab }), i, more || null)]; };
  const [to, toRow] = field('To', o.to, el('button', { class: 'lnk', type: 'button', text: 'Cc Bcc', onclick: () => { ccRow.hidden = false; bccRow.hidden = false; toRow.querySelector('.lnk').remove(); cc.focus(); } }));
  const [cc, ccRow] = field('Cc', o.cc), [bcc, bccRow] = field('Bcc', o.bcc), [subj, subjRow] = field('Subject', o.subject);
  ccRow.hidden = !o.cc && !o.bcc; bccRow.hidden = !o.cc && !o.bcc;
  if (o.cc || o.bcc) toRow.querySelector('.lnk').remove();
  const body = el('textarea', { placeholder: 'Write your message', spellcheck: 'true' });
  // A new message, a reply or a forward carries the signature, above what it quotes.
  body.value = o.draft || !signature ? o.body || '' : (o.body ? '\n\n-- \n' + signature + o.body : '\n\n-- \n' + signature);
  const catts = el('div', { class: 'catts' });
  const file = el('input', { type: 'file', multiple: true, hidden: true, onchange: () => { for (const f of file.files) attach(f); file.value = ''; } });
  const head = el('b', { text: o.subject || 'New message' });
  const box = el('div', { id: 'cmp' },
    el('div', { class: 'chead', onclick: e => { if (e.target.closest('.ib')) return; box.classList.toggle('min'); } }, head,
      ibtn('min', 'Minimize', () => box.classList.toggle('min')), ibtn('close', 'Close and keep a draft', () => closeCompose())),
    el('div', { class: 'cbody' }, toRow, ccRow, bccRow, subjRow, body, catts),
    el('div', { class: 'cfoot' }, btn('send', 'Send', () => send(), 'pri'), ibtn('clip', 'Attach files', () => file.click()), file, el('span', { class: 'note', text: '' }), el('div', { class: 'grow' }), ibtn('trash', 'Discard', () => discard())));
  subj.addEventListener('input', () => { head.textContent = subj.value || 'New message'; });
  cmp = { box, to, cc, bcc, subj, body, atts: (o.attachments || []).slice(), uploading: 0, inReplyTo: o.inReplyTo || null, references: o.references || null, draft: o.draft || null, start: JSON.stringify([to.value, cc.value, bcc.value, subj.value, body.value]), atts0: (o.attachments || []).length };
  const paintAtts = () => { catts.textContent = ''; for (const a of cmp.atts) catts.append(el('span', { class: 'chip' }, ico('clip'), el('span', { text: a.name + (a.size ? ' · ' + human(a.size) : '') }), ibtn('close', 'Remove', () => { cmp.atts = cmp.atts.filter(x => x !== a); paintAtts(); }))); };
  cmp.paintAtts = paintAtts; paintAtts();
  async function attach(f) {
    const c = cmp; c.uploading++; const note = box.querySelector('.note'); note.textContent = 'Uploading ' + f.name + '…';
    try {
      const r = await fetch('/jmap/upload/' + encodeURIComponent(acct) + '/', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': f.type || 'application/octet-stream', 'X-Socketley-UI': '1' }, body: f });
      if (r.status === 401) { signedOut(r.headers.get('X-Socketley-Idp-Login')); return; }
      if (!r.ok) throw new Error(f.name + ': ' + await errText(r));
      const j = await r.json();
      if (cmp === c) { c.atts.push({ blobId: j.blobId, type: j.type || f.type || 'application/octet-stream', name: f.name, size: j.size }); paintAtts(); }
    } catch (e) { fail(e); }
    finally { c.uploading--; if (!c.uploading) note.textContent = ''; }
  }
  box.addEventListener('dragover', e => { if ([...e.dataTransfer.types].includes('Files')) { e.preventDefault(); box.classList.add('drop'); } });
  box.addEventListener('dragleave', e => { if (!box.contains(e.relatedTarget)) box.classList.remove('drop'); });
  box.addEventListener('drop', e => { e.preventDefault(); box.classList.remove('drop'); for (const f of e.dataTransfer.files) attach(f); });
  box.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); send(); } if (e.key === 'Escape') { e.stopPropagation(); closeCompose(); } });
  document.body.append(box);
  (o.to ? body : to).focus();
  if (o.to) { body.setSelectionRange(0, 0); body.scrollTop = 0; }
}
function emailOf(c) {
  const to = parseAddrs(c.to.value), cc = parseAddrs(c.cc.value), bcc = parseAddrs(c.bcc.value);
  if (to === false || cc === false || bcc === false) throw new Error('One of the recipients is no address');
  const e = { mailboxIds: { [byRole.drafts.id]: true }, keywords: { $draft: true, $seen: true }, from: [myName ? { name: myName, email: me.address } : { email: me.address }], subject: c.subj.value,
    textBody: [{ partId: 't', type: 'text/plain' }], bodyValues: { t: { value: c.body.value } },
    attachments: c.atts.map(a => ({ blobId: a.blobId, type: a.type, name: a.name, disposition: 'attachment' })) };
  if (to.length) e.to = to; if (cc.length) e.cc = cc; if (bcc.length) e.bcc = bcc;
  if (c.inReplyTo) e.inReplyTo = c.inReplyTo;
  if (c.references && c.references.length) e.references = c.references;
  return { e, rcpts: [...to, ...cc, ...bcc] };
}
const changed = c => c.atts.length !== c.atts0 || JSON.stringify([c.to.value, c.cc.value, c.bcc.value, c.subj.value, c.body.value]) !== c.start;
async function send() {
  const c = cmp; if (!c || c.sending) return;
  if (c.uploading) { toast('Wait until the attachments are uploaded', 'spark'); return; }
  let built;
  try { built = emailOf(c); } catch (e) { fail(e); return; }
  if (!built.rcpts.length) { toast('Add at least one recipient', 'bad'); c.to.focus(); return; }
  if (!c.subj.value.trim() && !await ask({ title: 'Send without a subject?', ok: 'Send' })) return;
  c.sending = true; c.box.querySelector('.cfoot .btn').disabled = true;
  const sent = byRole.sent;
  try {
    const res = await jmap(
      ['Email/set', { accountId: acct, create: { d: built.e } }, 'd'],
      ['EmailSubmission/set', { accountId: acct, create: { s: { identityId: identity, emailId: '#d' } },
        onSuccessUpdateEmail: { '#s': Object.assign(sent ? { mailboxIds: { [sent.id]: true } } : {}, { 'keywords/$draft': null }) } }, 's']);
    setErrors(one(res, 'd')); setErrors(one(res, 's'));
    remember(built.rcpts);
    if (c.draft) jmap(['Email/set', { accountId: acct, destroy: [c.draft] }, 'x']).catch(() => {});
    closeCompose(true);
    toast('Sent');
    await loadBoxes(); loadList(true);
  } catch (e) { fail(e); c.sending = false; c.box.querySelector('.cfoot .btn').disabled = false; }
}
async function saveDraft(c) {
  try {
    const built = emailOf(c);
    const res = await jmap(['Email/set', { accountId: acct, create: { d: built.e }, destroy: c.draft ? [c.draft] : [] }, 'd']);
    setErrors(one(res, 'd'));
    toast('Draft saved'); await loadBoxes();
    if (byId[view.box] && byId[view.box].role === 'drafts') loadList(true);
  } catch (e) { fail(e); }
}
// The window closed: a message written in it is kept as a draft unless it was sent or thrown away.
function closeCompose(force) {
  const c = cmp; if (!c) return true;
  if (!force && c.uploading) { toast('Wait until the attachments are uploaded', 'spark'); return false; }
  cmp = null; c.box.remove();
  if (!force && changed(c) && byRole.drafts) saveDraft(c);
  return true;
}
async function discard() {
  const c = cmp; if (!c) return;
  if (changed(c) && !await ask({ title: 'Discard this message?', ok: 'Discard', danger: true })) return;
  closeCompose(true);
  if (c.draft) { try { await jmap(['Email/set', { accountId: acct, destroy: [c.draft] }, 'x']); await loadBoxes(); if (byId[view.box] && byId[view.box].role === 'drafts') loadList(true); } catch (e) { fail(e); } }
}

// ─── settings ───────────────────────────────────────────────────────────────
async function settings() {
  let vac = { isEnabled: false, subject: '', textBody: '' };
  try { const r = await jmap(['VacationResponse/get', { accountId: acct }, 'v']); vac = (one(r, 'v').list || [])[0] || vac; } catch (e) {}
  const name = el('input', { class: 'inp', value: myName, placeholder: me.user, maxlength: 200 });
  const sig = el('textarea', { class: 'inp', placeholder: 'Sent below every message you write' }); sig.value = signature;
  const on = el('input', { type: 'checkbox' }); on.checked = !!vac.isEnabled;
  const vs = el('input', { class: 'inp', value: vac.subject || '', placeholder: 'Out of office' });
  const vb = el('textarea', { class: 'inp', placeholder: 'I am away until … and will answer when I am back.' }); vb.value = vac.textBody || '';
  const body = el('div', { id: 'settings' },
    el('label', { class: 'l', text: 'Your name, as people see it' }), name,
    el('label', { class: 'l', text: 'Signature' }), sig,
    el('h4', { text: 'Out of office' }),
    el('label', { class: 'chk' }, on, el('span', { text: 'Answer everyone who writes, once a week each' })),
    el('label', { class: 'l', text: 'Subject' }), vs,
    el('label', { class: 'l', text: 'Message' }), vb);
  const save = async () => {
    try {
      const r = await jmap(['Identity/set', { accountId: acct, update: { [identity]: { name: name.value.trim(), textSignature: sig.value.replace(/\s+$/, '') } } }, 'i'],
        ['VacationResponse/set', { accountId: acct, update: { singleton: { isEnabled: on.checked, subject: vs.value.trim() || null, textBody: vb.value.trim() || null } } }, 'v']);
      setErrors(one(r, 'i')); setErrors(one(r, 'v'));
      myName = name.value.trim(); signature = sig.value.replace(/\s+$/, '');
      L.close(); toast('Settings saved');
    } catch (e) { fail(e); }
  };
  const L = modal('Settings', body, [btn(null, 'Cancel', () => L.close()), btn(null, 'Save', save, 'pri')]);
  name.focus();
}

// ─── live ───────────────────────────────────────────────────────────────────
// New mail and changes from other clients come as state changes; the list and the counts are read again.
function live() {
  if (es) es.close();
  es = new EventSource('/jmap/eventsource?types=*&closeafter=no&ping=60', { withCredentials: true });
  es.addEventListener('state', () => { clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 300); });
  es.onerror = () => { if (es && es.readyState === 2) { es = null; setTimeout(() => { if (me) live(); }, 15000); } };
}
async function refresh() {
  if (!me) return;
  const unread = byRole.inbox ? byRole.inbox.unreadEmails : 0;
  try { await loadBoxes(); } catch (e) { return; }
  if (!picked.size) loadList(true);
  if (byRole.inbox && byRole.inbox.unreadEmails > unread && document.hidden) document.title = '(' + byRole.inbox.unreadEmails + ') New mail · Mail';
}

// ─── keys ───────────────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (!me) return;
  if (e.key === 'Escape') { if (openPop) { closePop(); return; } if (layers.length) { layers[layers.length - 1].esc(); return; } if (picked.size) { picked.clear(); paintList(); return; } if (document.body.classList.contains('reading') && innerWidth <= 900) { document.body.classList.remove('reading'); open = null; openMsg = null; paintList(); } return; }
  if (e.target.closest('input,textarea,select,[contenteditable]') || e.ctrlKey || e.metaKey || e.altKey || layers.length) return;
  const at = mails.findIndex(m => m.id === open);
  const k = e.key;
  if (k === 'c') { e.preventDefault(); compose(); }
  else if (k === '/') { e.preventDefault(); $('#q').focus(); $('#q').select(); }
  else if (k === 'j' || k === 'ArrowDown') { const m = mails[at + 1]; if (m) { e.preventDefault(); openMail(m.id); document.querySelector('.row[data-id="' + CSS.escape(m.id) + '"]')?.scrollIntoView({ block: 'nearest' }); } }
  else if (k === 'k' || k === 'ArrowUp') { const m = mails[at - 1]; if (m) { e.preventDefault(); openMail(m.id); document.querySelector('.row[data-id="' + CSS.escape(m.id) + '"]')?.scrollIntoView({ block: 'nearest' }); } }
  else if (openMsg && k === 'r') { e.preventDefault(); reply(openMsg, false); }
  else if (openMsg && k === 'a') { e.preventDefault(); reply(openMsg, true); }
  else if (openMsg && k === 'f') { e.preventDefault(); forward(openMsg); }
  else if (openMsg && k === 's') { star([openMsg.id], !(openMsg.keywords || {}).$flagged); }
  else if (openMsg && k === 'u') { markSeen([openMsg.id], false); }
  else if (openMsg && (k === '#' || k === 'Delete')) { remove([openMsg.id]); }
});

// ─── start ──────────────────────────────────────────────────────────────────
function wire() {
  $('#compose').append(ico('pen'), el('span', { text: 'Compose' }));
  $('#compose').addEventListener('click', () => compose());
  $('#fab').append(ico('pen'), el('span', { text: 'Compose' }));
  $('#fab').addEventListener('click', () => compose());
  $('#menuB').append(ico('menu')); $('#menuB').title = 'Folders';
  $('#menuB').addEventListener('click', () => $('#side').classList.toggle('open'));
  $('#refB').append(ico('sync')); $('#refB').title = 'Check for mail';
  $('#refB').addEventListener('click', async () => { await refresh(); toast('Up to date'); });
  $('#home').addEventListener('click', () => byRole.inbox && go({ box: byRole.inbox.id }));
  $('#nSet').append(ico('gear'), el('span', { text: 'Settings' }));
  $('#nSet').addEventListener('click', () => { settings(); $('#side').classList.remove('open'); });
  $('#nOut').append(ico('out'), el('span', { text: 'Sign out' }));
  $('#nOut').addEventListener('click', signOut);
  let t = 0;
  $('#q').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { const q = $('#q').value.trim(); if (q) go({ q }); else if (view.q) go({ box: byRole.inbox ? byRole.inbox.id : '' }); $('#q').focus(); }, 350); });
  $('#q').addEventListener('keydown', e => { if (e.key === 'Escape') { $('#q').value = ''; $('#q').blur(); if (view.q) go({ box: byRole.inbox ? byRole.inbox.id : '' }); } });
  $('#rows').addEventListener('scroll', () => { const r = $('#rows'); if (r.scrollTop + r.clientHeight > r.scrollHeight - 400) loadMore(); });
  window.addEventListener('beforeunload', e => { if (cmp && changed(cmp)) { e.preventDefault(); e.returnValue = ''; } });
  paintThemes();
}
function fromHash() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ''));
  if (h.startsWith('search/')) return { q: h.slice(7) };
  if (h === 'starred') return { starred: true };
  if (h.startsWith('box/') && byId[h.slice(4)]) return { box: h.slice(4) };
  return { box: byRole.inbox ? byRole.inbox.id : '' };
}
async function start() {
  $('#login').hidden = true; $('#app').hidden = false;
  $('#me').textContent = '';
  $('#me').append(avatar({ name: me.user, email: me.address }), el('div', {}, el('b', { text: me.user }), el('span', { text: me.address })));
  try { for (const x of JSON.parse(store.get('skl-mail-img', '[]'))) showImages.add(x); } catch (e) {}
  paintAddrs();
  try {
    const res = await jmap(['Identity/get', { accountId: acct }, 'i']);
    const ids = one(res, 'i').list || [];
    if (ids.length) { identity = ids[0].id; myName = ids[0].name || ''; signature = ids[0].textSignature || ''; }
  } catch (e) {}
  try { await loadBoxes(); } catch (e) { fail(e); return; }
  const v = fromHash(); view = { box: v.box || '', starred: !!v.starred, q: v.q || '' };
  if (view.q) $('#q').value = view.q;
  paintBoxes(); paintReader(); loadList();
  live();
}
wire();
(async () => {
  let r;
  try { r = await fetch('/~mail/session', { credentials: 'same-origin', headers: { 'X-Socketley-UI': '1' } }); }
  catch (e) { $('#login').hidden = false; $('#le').textContent = 'The mail server cannot be reached.'; return; }
  if (r.status === 401) { signedOut(r.headers.get('X-Socketley-Idp-Login')); return; }
  if (!r.ok) { $('#login').hidden = false; $('#le').textContent = await errText(r); return; }
  me = await r.json(); acct = me.account;
  start();
})();
</script>
</body>
</html>)HTML";
