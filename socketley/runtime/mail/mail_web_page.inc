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
.hdr .who b{font-weight:650;white-space:nowrap}
.hdr .who{overflow:hidden}
.hdr .who .line{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hdr .who .addr{color:var(--mut);font-size:13px;margin-left:4px}
.hdr .rcp{color:var(--dim);font-size:12.5px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hdr .when{color:var(--dim);font-size:12.5px;white-space:nowrap;flex:none;margin-top:2px}
.imgbar{display:flex;align-items:center;gap:10px;padding:9px 12px;margin-bottom:12px;border-radius:11px;background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.22);font-size:13px;color:#e9dcb5}
.imgbar .btn{height:30px;font-size:12.5px;margin-left:auto}
.mbody{border-radius:14px;overflow:hidden;background:#fff}
.mbody iframe{display:block;width:100%;border:0;height:120px;background:#fff}
.mtext{white-space:pre-wrap;word-break:break-word;font:14px/1.6 inherit;padding:2px 2px}
.mtext .q{color:var(--dim);border-left:2px solid var(--line2);padding-left:10px;display:block}
.mtext a,.hdr a{color:var(--a1)}
.atts{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px}
.att{display:flex;align-items:center;gap:10px;padding:8px 12px 8px 8px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid var(--line);max-width:300px;color:var(--fg);text-decoration:none}
.att:hover{background:rgba(255,255,255,.07)}
.att .ti{width:38px;height:38px;border-radius:8px;background:rgba(var(--glow),.14);display:flex;align-items:center;justify-content:center;flex:none;overflow:hidden}
.att .ti img{width:100%;height:100%;object-fit:cover}
.att .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.att .sz{font-size:11.5px;color:var(--dim)}
.att>div{min-width:0}
.r1 .who .tn{display:inline-block;margin-left:6px;font-size:11.5px;font-weight:600;color:var(--dim);vertical-align:1px}
.row.unread .who .tn{color:var(--mut)}
.msg{border:1px solid var(--line);border-radius:16px;padding:14px 16px 16px;margin-bottom:10px;background:rgba(255,255,255,.02)}
.msg .hdr{cursor:default;margin-bottom:12px}
.msg .hdr .ib{width:32px;height:32px;flex:none;margin-top:-4px}
.msg.shut{display:flex;align-items:center;gap:12px;padding:10px 16px;cursor:pointer;background:rgba(255,255,255,.015)}
.msg.shut:hover{background:rgba(255,255,255,.045)}
.msg.shut .av{width:30px;height:30px;font-size:13px}
.msg.shut b{font-weight:600;flex:none;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg.shut .pv{flex:1;min-width:0;color:var(--dim);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg.shut .when{color:var(--dim);font-size:12px;flex:none}
.qt{display:inline-flex;align-items:center;justify-content:center;height:20px;width:34px;margin-top:10px;border-radius:7px;background:rgba(255,255,255,.08);color:var(--mut)}
.qt .i{width:16px;height:16px}
.qt:hover,.qt.on{background:rgba(var(--glow),.22);color:var(--fg)}
.mtext.quoted{margin-top:8px;color:var(--mut)}
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
#settings .approw{font-size:13px;color:var(--dim);margin:2px 0 6px}
.holdbar .lnk{margin-left:12px;font-weight:600}
#cmp .ed{flex:1;min-height:160px;overflow:auto;padding:10px 12px;outline:none;font:14px/1.55 inherit}
#cmp .ed blockquote{margin:6px 0;padding-left:10px;border-left:3px solid var(--line);color:var(--dim)}
#cmp .tools{display:flex;gap:2px;padding:4px 8px;border-bottom:1px solid var(--line)}
#cmp .fromsel{flex:1;background:transparent;border:0;color:inherit;font:inherit;outline:none}
.rules .rule{display:grid;grid-template-columns:110px 1fr 120px 1fr 34px;gap:6px;align-items:center;margin:6px 0}
.rules .rule .inp{height:34px}
pre.hdrs{max-height:60vh;overflow:auto;font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap;word-break:break-all}
@media print{#side,#listp,#rbar,#top,#fab,#cmp,#toasts,#aurora{display:none!important}#readp{position:static!important;display:block!important;width:auto!important}body{background:#fff!important}}
#settings a.btn{display:inline-flex;margin-top:6px;text-decoration:none}
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
// ─── words ──────────────────────────────────────────────────────────────────
if (/^de\b/i.test(navigator.language || '')) { document.documentElement.lang = 'de'; Object.assign(SAY, {
  "Add a rule": "Regel hinzufügen",
  "Add at least one recipient": "Mindestens einen Empfänger angeben",
  "Always from this sender": "Immer von diesem Absender",
  "Answer everyone who writes, once a week each": "Allen antworten, die schreiben, jedem einmal pro Woche",
  "Archive  (e)": "Archivieren  (e)",
  "Archive": "Archiv",
  "Archived": "Archiviert",
  "Attach files": "Dateien anhängen",
  "Back to the list": "Zurück zur Liste",
  "Bold": "Fett",
  "Bulleted list": "Aufzählung",
  "Bcc": "Bcc",
  "Cc": "Cc",
  "Cancel": "Abbrechen",
  "Check for mail": "Nach neuen Mails sehen",
  "Clear the selection": "Auswahl aufheben",
  "Close and keep a draft": "Schließen und als Entwurf behalten",
  "Close": "Schließen",
  "Create": "Erstellen",
  "Delete  (#)": "Löschen  (#)",
  "Delete folder": "Ordner löschen",
  "Delete this for good?": "Endgültig löschen?",
  "Delete": "Löschen",
  "Deleted": "Gelöscht",
  "Discard this message?": "Diese Nachricht verwerfen?",
  "Discard": "Verwerfen",
  "Download message (.eml)": "Nachricht herunterladen (.eml)",
  "Draft saved": "Entwurf gespeichert",
  "Drafts": "Entwürfe",
  "Empty": "Leeren",
  "Every message in it is deleted for good.": "Jede Nachricht darin wird endgültig gelöscht.",
  "Filters saved": "Filter gespeichert",
  "Filters": "Filter",
  "Folder actions": "Ordneraktionen",
  "Folder created": "Ordner erstellt",
  "Folder name": "Ordnername",
  "Folders": "Ordner",
  "Formatting": "Formatierung",
  "Forward  (f)": "Weiterleiten  (f)",
  "Forward to": "Weiterleiten an",
  "Forward": "Weiterleiten",
  "From": "Von",
  "Headers": "Kopfzeilen",
  "I am away until … and will answer when I am back.": "Ich bin bis … nicht erreichbar und antworte, sobald ich zurück bin.",
  "Inbox": "Posteingang",
  "It cannot be brought back.": "Das lässt sich nicht rückgängig machen.",
  "Italic": "Kursiv",
  "Junk": "Spam",
  "Link to": "Link auf",
  "Loading more…": "Lade weitere …",
  "Loading…": "Lade …",
  "Mail apps": "Mail-Apps",
  "Mark as read": "Als gelesen markieren",
  "Mark as unread  (u)": "Als ungelesen markieren  (u)",
  "Mark as unread": "Als ungelesen markieren",
  "Mark this one unread": "Diese als ungelesen markieren",
  "Message": "Nachricht",
  "Minimize": "Minimieren",
  "More": "Mehr",
  "Move to": "Verschieben nach",
  "Moved to Inbox": "In den Posteingang verschoben",
  "Moved to Junk": "In den Spam verschoben",
  "Moved to Trash": "In den Papierkorb verschoben",
  "New folder": "Neuer Ordner",
  "New mail shows up here as it arrives.": "Neue Mails erscheinen hier, sobald sie ankommen.",
  "New mail": "Neue Mail",
  "New message": "Neue Nachricht",
  "New": "Neu",
  "Not junk": "Kein Spam",
  "Nothing here": "Hier ist nichts",
  "Nothing selected": "Nichts ausgewählt",
  "Notifications": "Benachrichtigungen",
  "Numbered list": "Nummerierte Liste",
  "One of the recipients is no address": "Einer der Empfänger ist keine Adresse",
  "Opening…": "Öffne …",
  "Out of office": "Abwesenheitsnotiz",
  "Pick a conversation to read it": "Wähle eine Unterhaltung, um sie zu lesen",
  "Pick a time to come": "Wähle einen Zeitpunkt in der Zukunft",
  "Pick a time…": "Zeitpunkt wählen …",
  "Plain text again": "Wieder reiner Text",
  "Print": "Drucken",
  "Profile for iPhone, iPad and Mac": "Profil für iPhone, iPad und Mac",
  "Quote": "Zitat",
  "Remote images are hidden, so the sender cannot see when you read this.": "Externe Bilder sind ausgeblendet, damit der Absender nicht sieht, wann du das liest.",
  "Remove the rule": "Regel entfernen",
  "Remove": "Entfernen",
  "Rename folder": "Ordner umbenennen",
  "Rename": "Umbenennen",
  "Reply  (r)": "Antworten  (r)",
  "Reply all  (a)": "Allen antworten  (a)",
  "Reply all": "Allen antworten",
  "Reply": "Antworten",
  "Report junk": "Als Spam melden",
  "Rules for arriving mail…": "Regeln für eingehende Mails …",
  "Save": "Speichern",
  "Schedule": "Planen",
  "Search": "Suche",
  "Search mail": "Mails durchsuchen",
  "Send at": "Senden am",
  "Send later": "Später senden",
  "Send without a subject?": "Ohne Betreff senden?",
  "Send": "Senden",
  "Sending (SMTP)": "Versand (SMTP)",
  "Sending…": "Sende …",
  "Sent below every message you write": "Steht unter jeder Nachricht, die du schreibst",
  "Sent": "Gesendet",
  "Settings saved": "Einstellungen gespeichert",
  "Settings": "Einstellungen",
  "Show images": "Bilder anzeigen",
  "Show the headers": "Kopfzeilen anzeigen",
  "Show the quoted text": "Zitierten Text anzeigen",
  "Sign in with your account": "Mit deinem Konto anmelden",
  "Sign in with your account to read and send your mail.": "Melde dich mit deinem Konto an, um deine Mails zu lesen und zu senden.",
  "Sign out": "Abmelden",
  "Signature": "Signatur",
  "Star  (s)": "Markieren  (s)",
  "Star a message to find it here.": "Markiere eine Nachricht mit einem Stern, um sie hier wiederzufinden.",
  "Star": "Markieren",
  "Starred": "Markiert",
  "Subject": "Betreff",
  "Tell me of new mail while this tab is in the background": "Neue Mails melden, während dieser Tab im Hintergrund ist",
  "That conversation is no longer there": "Diese Unterhaltung gibt es nicht mehr",
  "The filters were not saved": "Die Filter wurden nicht gespeichert",
  "The folder and every message in it are deleted for good.": "Der Ordner und jede Nachricht darin werden endgültig gelöscht.",
  "The mail server cannot be reached": "Der Mailserver ist nicht erreichbar",
  "The mail server cannot be reached.": "Der Mailserver ist nicht erreichbar.",
  "The server refused it": "Der Server hat es abgelehnt",
  "This mail server signs in through an idp runtime, which it cannot reach now.": "Dieser Mailserver meldet über eine idp-Runtime an, die er gerade nicht erreicht.",
  "Thunderbird and Outlook find these by themselves from your address.": "Thunderbird und Outlook finden diese Angaben anhand deiner Adresse selbst.",
  "To or Cc": "An oder Cc",
  "To": "An",
  "Trash": "Papierkorb",
  "Try other words, or a name or address.": "Versuche andere Wörter, einen Namen oder eine Adresse.",
  "Underline": "Unterstrichen",
  "Undo": "Rückgängig",
  "Unstar  (s)": "Stern entfernen  (s)",
  "Unstar": "Stern entfernen",
  "Until": "Bis",
  "Up to date": "Auf dem neuesten Stand",
  "Wait until the attachments are uploaded": "Warte, bis die Anhänge hochgeladen sind",
  "Write your message": "Schreibe deine Nachricht",
  "Your name, as people see it": "Dein Name, wie andere ihn sehen",
  "Your session has ended: sign in again": "Deine Sitzung ist abgelaufen: bitte melde dich erneut an",
  "(no subject)": "(kein Betreff)",
  "(no recipient)": "(kein Empfänger)",
  "(unknown sender)": "(unbekannter Absender)",
  "Empty “%”?": "„%“ leeren?",
  "Empty %": "% leeren",
  "Delete “%”?": "„%“ löschen?",
  "Nothing matches “%”": "Nichts passt zu „%“",
  "To: %": "An: %",
  "Select all %": "Alle % auswählen",
  "Moved to %": "Nach % verschoben",
  "Delete % conversations for good?": "% Unterhaltungen endgültig löschen?",
  "Uploading %…": "Lade % hoch …",
  "It goes %": "Wird gesendet: %",
  "Saving replaces the filter “%” a mail app put in place.": "Speichern ersetzt den Filter „%“, den eine Mail-App angelegt hat.",
  "Sign in with % and your password.": "Melde dich mit % und deinem Passwort an.",
  "%: %, port %, %": "%: %, Port %, %",
  "Calendars and contacts: %": "Kalender und Kontakte: %",
  "% is empty": "% ist leer",
  "% selected": "% ausgewählt",
  "% messages": "% Nachrichten",
  "Press % to write one, % to search.": "Drücke % zum Schreiben, % zum Suchen.",
  "On %, % wrote:": "Am % schrieb %:",
  "someone": "jemand"
});
  for (const [q, k] of [['#lsub', 'textContent'], ['#lidp', 'textContent'], ['#q', 'placeholder']]) $(q)[k] = say($(q)[k]);
}
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
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  format: '<path d="M5 19h14M8 15l4-10 4 10M9.5 11.5h5"/>', bold: '<path d="M7 5h6a3.5 3.5 0 0 1 0 7H7zM7 12h7a3.5 3.5 0 0 1 0 7H7z"/>',
  italic: '<path d="M11 5h6M7 19h6M14 5l-4 14"/>', underline: '<path d="M7 5v6a5 5 0 0 0 10 0V5M6 20h12"/>',
  list: '<path d="M9 7h11M9 12h11M9 17h11M4.5 7h.01M4.5 12h.01M4.5 17h.01"/>', olist: '<path d="M10 7h10M10 12h10M10 17h10M4 6h1v4M4 14h2l-2 3h2"/>',
  quote: '<path d="M7 7h4v4c0 2-1 4-4 5M14 7h4v4c0 2-1 4-4 5"/>', link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7L12 6.3M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  clear: '<path d="M6 6l12 12M18 6 6 18"/>',
  min: '<path d="M6 12h12"/>', pen: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>'
});

// ─── state ──────────────────────────────────────────────────────────────────
const USING = ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'];
const PAGE = 50;
const ROLES = ['inbox', 'starred', 'drafts', 'sent', 'archive', 'junk', 'trash'];
const ROLE_ICON = { inbox: 'inbox', starred: 'star', drafts: 'pen', sent: 'send', archive: 'folder', junk: 'junk', trash: 'trash' };
const ROLE_NAME = { inbox: say('Inbox'), starred: say('Starred'), drafts: say('Drafts'), sent: say('Sent'), archive: say('Archive'), junk: say('Junk'), trash: say('Trash') };
const LIST_PROPS = ['id', 'threadId', 'mailboxIds', 'keywords', 'from', 'to', 'subject', 'receivedAt', 'preview', 'hasAttachment', 'size'];
let me = null, acct = '', identity = 'i0', identities = [], myName = '', signature = '', boxes = [], byRole = {}, byId = {};
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
  } catch (e) { throw new Error(say('The mail server cannot be reached')); }
  if (r.status === 401) { signedOut(r.headers.get('X-Socketley-Idp-Login')); throw new Error(say('Your session has ended: sign in again')); }
  if (!r.ok) throw new Error(await errText(r));
  const out = {};
  for (const [name, args, id] of (await r.json()).methodResponses) {
    if (name === 'error') throw new Error(args.description || args.type || say('The server refused it'));
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
// The quotes of what a reply answers, as Gmail, Outlook, Apple Mail and Thunderbird mark them.
const QUOTES = 'blockquote[type=cite],.gmail_quote,.gmail_extra,#divRplyFwdMsg,#divRplyFwdMsg~*,#appendonsend~*,.moz-cite-prefix,.yahoo_quoted,#mail-editor-reference-message-container';
function frame(docHtml, quotes) {
  const f = el('iframe', { sandbox: 'allow-same-origin allow-popups allow-popups-to-escape-sandbox', referrerpolicy: 'no-referrer', title: say('Message') });
  f.srcdoc = docHtml;
  const fit = () => { try { const b = f.contentDocument; if (b && b.documentElement) f.style.height = Math.max(80, b.documentElement.scrollHeight + 2) + 'px'; } catch (e) {} };
  // What a reply quotes is folded away behind a button, as a conversation shows each message above it already.
  f.quoteToggle = quotes ? el('button', { class: 'qt', title: say('Show the quoted text'), hidden: true, onclick: e => {
    const on = !e.currentTarget.classList.contains('on'); e.currentTarget.classList.toggle('on', on);
    try { f.contentDocument.documentElement.classList.toggle('showq', on); } catch (x) {}
    setTimeout(fit, 0);
  } }, ico('more')) : null;
  f.addEventListener('load', () => {
    try {
      const d = f.contentDocument;
      if (quotes && d.querySelector(QUOTES)) {
        d.head.append(Object.assign(d.createElement('style'), { textContent: 'html:not(.showq) :is(' + QUOTES + '){display:none!important}' }));
        f.quoteToggle.hidden = false;
      }
    } catch (e) {}
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
  else $('#le').textContent = say('This mail server signs in through an idp runtime, which it cannot reach now.');
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
      n.append(el('span', { class: 'fm', title: say('Folder actions'), onclick: e => { e.stopPropagation(); folderMenu(e.currentTarget, b); } }, ico('more')));
    }
    B.append(n);
  };
  for (const b of boxes.filter(b => b.role === 'inbox')) add(b);
  B.append(nav('star', say('Starred'), view.starred && !view.q, () => go({ starred: true })));
  for (const b of boxes.filter(b => b.role && b.role !== 'inbox')) add(b);
  const own = boxes.filter(b => !b.role);
  B.append(el('div', { class: 'sh row' }, el('span', { text: say('Folders') }), ibtn('plus', say('New folder'), newFolder)));
  for (const b of own) add(b);
  const inbox = byRole.inbox;
  document.title = (inbox && inbox.unreadEmails ? '(' + inbox.unreadEmails + ') ' : '') + title() + ' · Mail';
}
function title() { return view.q ? say('Search') : view.starred ? say('Starred') : byId[view.box] ? boxLabel(byId[view.box]) : 'Mail'; }
async function newFolder() {
  const name = await ask({ title: say('New folder'), input: say('Folder name'), ok: say('Create') });
  if (!name) return;
  try { const res = await jmap(['Mailbox/set', { accountId: acct, create: { n: { name, parentId: null } } }, 'c']); setErrors(one(res, 'c')); await loadBoxes(); toast(say('Folder created')); }
  catch (e) { fail(e); }
}
// Every message of a folder destroyed, five hundred a call, as emptying Trash or Junk asks.
async function emptyBox(b) {
  if (!await ask({ title: say('Empty “%”?', boxLabel(b)), text: say('Every message in it is deleted for good.'), ok: say('Empty'), danger: true })) return;
  try {
    for (let i = 0; i < 200; i++) {
      const r = await jmap(['Email/query', { accountId: acct, filter: { inMailbox: b.id }, limit: 500 }, 'q']);
      const ids = one(r, 'q').ids || [];
      if (!ids.length) break;
      setErrors(one(await jmap(['Email/set', { accountId: acct, destroy: ids }, 'd']), 'd'));
    }
    toast(say('% is empty', boxLabel(b))); await loadBoxes(); if (view.box === b.id) loadList();
  } catch (e) { fail(e); }
}
async function folderMenu(at, b) {
  if (b.role === 'trash' || b.role === 'junk') { popup(at, [{ icon: 'trash', label: say('Empty %', boxLabel(b)), bad: true, fn: () => emptyBox(b) }]); return; }
  popup(at, [
    { icon: 'edit', label: say('Rename'), fn: async () => {
      const name = await ask({ title: say('Rename folder'), input: say('Folder name'), value: b.name, ok: say('Rename') });
      if (!name || name === b.name) return;
      try { const res = await jmap(['Mailbox/set', { accountId: acct, update: { [b.id]: { name } } }, 'u']); setErrors(one(res, 'u')); await loadBoxes(); } catch (e) { fail(e); }
    } },
    { icon: 'trash', label: say('Delete folder'), bad: true, fn: async () => {
      if (!await ask({ title: say('Delete “%”?', b.name), text: say('The folder and every message in it are deleted for good.'), ok: say('Delete'), danger: true })) return;
      try { const res = await jmap(['Mailbox/set', { accountId: acct, destroy: [b.id], onDestroyRemoveEmails: true }, 'd']); setErrors(one(res, 'd')); if (view.box === b.id) view.box = byRole.inbox ? byRole.inbox.id : ''; await loadBoxes(); await loadList(); } catch (e) { fail(e); }
    } }
  ]);
}

// ─── the list ───────────────────────────────────────────────────────────────
function go(v) {
  view = { box: v.box || '', starred: !!v.starred, q: v.q || '' };
  if (!view.q) $('#q').value = '';
  picked.clear(); open = null; openMsg = null; thread = []; document.body.classList.remove('reading');
  location.hash = view.q ? 'search/' + encodeURIComponent(view.q) : view.starred ? 'starred' : 'box/' + encodeURIComponent(view.box);
  paintBoxes(); paintReader(); loadList();
}
// A search's words, as Gmail's are: from:, to:, subject:, in:, has:attachment, is:unread|read|starred, before: and
// after: a date, the rest the text; each a condition, all of them to hold.
function searchFilter(q) {
  const conds = [], words = [];
  for (const m of q.match(/(\w+:("[^"]*"|\S+))|("[^"]*")|\S+/g) || []) {
    const c = m.indexOf(':'), key = c > 0 ? m.slice(0, c).toLowerCase() : '', val = c > 0 ? m.slice(c + 1).replace(/^"|"$/g, '') : '';
    if (key === 'from' || key === 'to' || key === 'subject') conds.push({ [key]: val });
    else if (key === 'has' && val === 'attachment') conds.push({ hasAttachment: true });
    else if (key === 'is' && val === 'unread') conds.push({ notKeyword: '$seen' });
    else if (key === 'is' && val === 'read') conds.push({ hasKeyword: '$seen' });
    else if (key === 'is' && val === 'starred') conds.push({ hasKeyword: '$flagged' });
    else if ((key === 'before' || key === 'after') && !isNaN(Date.parse(val))) conds.push({ [key]: new Date(val).toISOString().replace(/\.\d+Z$/, 'Z') });
    else if (key === 'in') { const b = Object.values(byId).find(x => boxLabel(x).toLowerCase() === val.toLowerCase() || x.name.toLowerCase() === val.toLowerCase()); if (b) conds.push({ inMailbox: b.id }); else words.push(m); }
    else words.push(m.replace(/^"|"$/g, ''));
  }
  if (words.length) conds.push({ text: words.join(' ') });
  return conds.length === 1 ? conds[0] : { operator: 'AND', conditions: conds };
}
function filter() {
  if (view.q) return searchFilter(view.q);
  if (view.starred) return { hasKeyword: '$flagged' };
  return { inMailbox: view.box };
}
const inDrafts = () => !view.q && !view.starred && byId[view.box] && byId[view.box].role === 'drafts';
const sentView = () => !view.q && !view.starred && byId[view.box] && ['sent', 'drafts'].includes(byId[view.box].role);
// Drafts are listed one by one; any other view a conversation a row, by its newest message there, with every message of
// it in any mailbox beside.
const MEMBER_PROPS = ['id', 'threadId', 'from', 'to', 'keywords', 'mailboxIds', 'receivedAt'];
function listCalls(position, limit) {
  const calls = [['Email/query', { accountId: acct, filter: filter(), sort: [{ property: 'receivedAt', isAscending: false }], collapseThreads: !inDrafts(), position, limit, calculateTotal: position === 0 }, 'q'],
    ['Email/get', { accountId: acct, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: LIST_PROPS }, 'g']];
  if (!inDrafts())
    calls.push(['Thread/get', { accountId: acct, '#ids': { resultOf: 'g', name: 'Email/get', path: '/list/*/threadId' } }, 't'],
      ['Email/get', { accountId: acct, '#ids': { resultOf: 't', name: 'Thread/get', path: '/list/*/emailIds' }, properties: MEMBER_PROPS }, 'e']);
  return calls;
}
function rowsOf(res) {
  const q = one(res, 'q'), by = Object.fromEntries((one(res, 'g').list || []).map(m => [m.id, m]));
  const threads = Object.fromEntries((one(res, 't').list || []).map(t => [t.id, t.emailIds]));
  const members = Object.fromEntries((one(res, 'e').list || []).map(m => [m.id, m]));
  const rows = (q.ids || []).map(id => by[id]).filter(Boolean).map(m => {
    m.members = (threads[m.threadId] || [m.id]).map(id => members[id] || (id === m.id ? m : null)).filter(Boolean);
    if (!m.members.length) m.members = [m];
    return m;
  });
  return { q, rows };
}
async function loadList(keep) {
  const my = ++seq;
  if (!keep) { mails = []; total = 0; paintList(true); }
  try {
    const res = await jmap(...listCalls(0, Math.max(PAGE, keep ? mails.length : 0)));
    if (my !== seq) return;
    const { q, rows } = rowsOf(res);
    mails = rows;
    total = q.total != null ? q.total : mails.length;
    for (const m of mails.slice(0, 20)) remember(sentView() ? m.to : m.from);
    paintList();
    // A conversation being read that grew, a reply come in, is read again.
    if (open && thread.length) {
      const r = mails.find(x => x.threadId === thread[0].threadId);
      if (r && r.members.length !== thread.length) openMail(r.id, true);
    }
  } catch (e) { if (my === seq) { paintList(); fail(e); } }
}
async function loadMore() {
  if (loadingMore || mails.length >= total) return;
  loadingMore = true;
  const my = seq;
  try {
    const res = await jmap(...listCalls(mails.length, PAGE));
    if (my !== seq) return;
    const have = new Set(mails.map(m => m.id));
    for (const r of rowsOf(res).rows) if (!have.has(r.id)) mails.push(r);
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
  if (loading) { R.append(el('div', { class: 'more', text: say('Loading…') })); return; }
  if (!mails.length) {
    R.append(el('div', { class: 'empty' }, ico(view.q ? 'search' : view.starred ? 'star' : 'inbox'), el('b', { text: view.q ? say('Nothing matches “%”', view.q) : say('Nothing here') }), el('span', { text: view.q ? say('Try other words, or a name or address.') : view.starred ? say('Star a message to find it here.') : say('New mail shows up here as it arrives.') })));
    return;
  }
  const sentish = sentView();
  for (const m of mails) R.append(rowOf(m, sentish));
  if (mails.length < total) R.append(el('div', { class: 'more', text: say('Loading more…') }));
}
// Who a conversation is between: one sender by name, several by their first names, the user as "me".
function people(ms) {
  const mine = me.address.toLowerCase(), seen = new Map();
  for (const x of ms) for (const a of (x.from || []).slice(0, 1)) {
    const k = a.email.toLowerCase();
    if (!seen.has(k)) seen.set(k, k === mine ? 'me' : a.name || a.email);
  }
  const names = [...seen.values()];
  if (names.length < 2) return names[0] || say('(unknown sender)');
  const short = names.map(n => n === 'me' ? n : n.includes('@') ? n.split('@')[0] : n.split(/\s+/)[0]);
  return short.length > 3 ? short.slice(0, 2).join(', ') + ' … ' + short[short.length - 1] : short.join(', ');
}
function rowOf(m, sentish) {
  const ms = m.members && m.members.length ? m.members : [m];
  const unread = ms.some(x => !(x.keywords || {}).$seen), flagged = ms.some(x => (x.keywords || {}).$flagged);
  const party = sentish ? (m.to && m.to.length ? say('To: %', whoShort(m.to)) : say('(no recipient)')) : people(ms);
  const boxName = view.q || view.starred ? Object.keys(m.mailboxIds || {}).map(id => byId[id]).filter(b => b && b.role !== 'inbox').map(boxLabel)[0] : '';
  const tick = el('div', { class: 'tick', onclick: e => { e.stopPropagation(); togglePick(m.id); } }, ico('check'));
  return el('div', { class: 'row' + (unread ? ' unread' : '') + (open === m.id ? ' on' : '') + (picked.has(m.id) ? ' ck' : ''), 'data-id': m.id, onclick: () => openMail(m.id) },
    el('div', { class: 'avw' }, avatar(sentish ? (m.to || [])[0] : (m.from || [])[0]), tick),
    el('div', { class: 'rm' },
      el('div', { class: 'r1' }, el('span', { class: 'who' }, party, ms.length > 1 ? el('span', { class: 'tn', text: String(ms.length) }) : null), el('span', { class: 'when', text: short(m.receivedAt), title: full(m.receivedAt) })),
      el('div', { class: 'r2' }, el('span', { class: 'subj', text: m.subject || say('(no subject)') }), boxName ? el('span', { class: 'tag', text: boxName }) : null, m.hasAttachment ? ico('clip') : null),
      el('div', { class: 'r3', text: m.preview || '' })),
    ibtn('star', flagged ? say('Unstar') : say('Star'), e => { e.stopPropagation(); star([m.id], !flagged); }, 'st' + (flagged ? ' on' : '')));
}
function paintBulk() {
  const B = $('#bulk'); B.textContent = '';
  if (!picked.size) return;
  const ids = [...picked];
  const all = mails.length && mails.every(m => picked.has(m.id));
  B.append(ibtn('close', say('Clear the selection'), () => { picked.clear(); paintList(); }), el('span', { text: say('% selected', picked.size) }),
    all ? null : el('button', { class: 'lnk', text: say('Select all %', mails.length), onclick: () => { for (const m of mails) picked.add(m.id); paintList(); } }),
    ibtn('mailopen', say('Mark as read'), () => markSeen(ids, true)), ibtn('mail', say('Mark as unread'), () => markSeen(ids, false)),
    ibtn('star', say('Star'), () => star(ids, true)), ibtn('folder', say('Move to'), e => moveMenu(e.currentTarget, ids)),
    ibtn('folder', say('Archive  (e)'), () => archive(ids)), ibtn('trash', say('Delete'), () => remove(ids)));
}
function togglePick(id) { if (picked.has(id)) picked.delete(id); else picked.add(id); paintList(); }

// ─── acting on conversations ────────────────────────────────────────────────
const rowOfId = id => mails.find(m => m.id === id);
// The messages rows stand for: every one of their conversations, or those in the mailbox shown where `here`.
function memberIds(rowIds, here) {
  const out = new Set();
  for (const id of rowIds) {
    const r = rowOfId(id);
    for (const x of r && r.members ? r.members : [{ id, mailboxIds: {} }])
      if (!here || view.q || view.starred || !view.box || (x.mailboxIds || {})[view.box]) out.add(x.id);
    out.add(id);
  }
  return [...out];
}
function patchLocal(ids, fn) {
  for (const m of mails) { if (ids.includes(m.id)) fn(m); for (const x of m.members || []) if (x !== m && ids.includes(x.id)) fn(x); }
  for (const x of thread) if (ids.includes(x.id)) fn(x);
}
async function update(ids, patch) {
  const res = await jmap(['Email/set', { accountId: acct, update: Object.fromEntries(ids.map(id => [id, patch])) }, 'u']);
  setErrors(one(res, 'u'));
}
async function markSeen(rowIds, on, exact) {
  const ids = exact ? rowIds : memberIds(rowIds, false);
  patchLocal(ids, m => { m.keywords = m.keywords || {}; if (on) m.keywords.$seen = true; else delete m.keywords.$seen; });
  paintList(); paintReaderBar();
  try { await update(ids, { 'keywords/$seen': on ? true : null }); await loadBoxes(); } catch (e) { fail(e); loadList(true); }
}
// A star goes on the conversation's newest message and comes off every one, as a conversation shows starred while any is.
async function star(rowIds, on) {
  const ids = on ? rowIds : memberIds(rowIds, false);
  patchLocal(ids, m => { m.keywords = m.keywords || {}; if (on) m.keywords.$flagged = true; else delete m.keywords.$flagged; });
  paintList(); paintReaderBar();
  try { await update(ids, { 'keywords/$flagged': on ? true : null }); if (view.starred && !on) loadList(true); } catch (e) { fail(e); loadList(true); }
}
// Out of the INBOX into Archive, which is made the first time it is wanted.
async function archive(rowIds) {
  try {
    if (!byRole.archive) {
      const r = await jmap(['Mailbox/set', { accountId: acct, create: { a: { name: 'Archive', parentId: null } } }, 'c']);
      setErrors(one(r, 'c')); await loadBoxes();
    }
    if (byRole.archive) await move(rowIds, byRole.archive.id, say('Archived'));
  } catch (e) { fail(e); }
}
// A message's header as it came, every field of it, in a window of its own.
async function showHeaders(m) {
  if (!m) return;
  try {
    const r = await jmap(['Email/get', { accountId: acct, ids: [m.id], properties: ['headers'] }, 'h']);
    const hs = ((one(r, 'h').list || [])[0] || {}).headers || [];
    const pre = el('pre', { class: 'hdrs', text: hs.map(h => h.name + ':' + h.value).join('\n') });
    const L = modal(say('Headers'), pre, [btn(null, say('Close'), () => L.close())]);
  } catch (e) { fail(e); }
}
async function move(rowIds, to, said) {
  try {
    await update(memberIds(rowIds, true), { mailboxIds: { [to]: true } });
    dropFromList(rowIds);
    toast(said || say('Moved to %', boxLabel(byId[to])));
    await loadBoxes();
  } catch (e) { fail(e); loadList(true); }
}
function dropFromList(rowIds) {
  const at = open && rowIds.includes(open) ? mails.findIndex(m => m.id === open) : -1;
  mails = mails.filter(m => !rowIds.includes(m.id)); total = Math.max(0, total - rowIds.length);
  for (const id of rowIds) picked.delete(id);
  if (at >= 0) { const next = mails[Math.min(at, mails.length - 1)]; open = null; openMsg = null; thread = []; if (next && innerWidth > 900) openMail(next.id); else { document.body.classList.remove('reading'); paintReader(); } }
  paintList();
}
async function remove(rowIds) {
  const trash = byRole.trash;
  const inTrash = rowIds.every(id => { const r = rowOfId(id); return trash && r && r.mailboxIds && r.mailboxIds[trash.id]; });
  if (!trash || inTrash) {
    if (!await ask({ title: rowIds.length > 1 ? say('Delete % conversations for good?', rowIds.length) : say('Delete this for good?'), text: say('It cannot be brought back.'), ok: say('Delete'), danger: true })) return;
    try { const res = await jmap(['Email/set', { accountId: acct, destroy: memberIds(rowIds, true) }, 'd']); setErrors(one(res, 'd')); dropFromList(rowIds); toast(say('Deleted')); await loadBoxes(); } catch (e) { fail(e); }
    return;
  }
  await move(rowIds, trash.id, rowIds.length > 1 ? rowIds.length + ' conversations moved to Trash' : say('Moved to Trash'));
}
function moveMenu(at, rowIds) {
  const here = rowOfId(rowIds[0]);
  const cur = here ? Object.keys(here.mailboxIds || {})[0] : '';
  popup(at, [{ head: say('Move to') }, ...boxes.filter(b => b.id !== cur && b.role !== 'drafts').map(b => ({ icon: b.role && ROLE_ICON[b.role] || 'folder', label: boxLabel(b), fn: () => move(rowIds, b.id) }))]);
}

// ─── reading ────────────────────────────────────────────────────────────────
const FULL_PROPS = [...LIST_PROPS, 'cc', 'bcc', 'replyTo', 'sentAt', 'messageId', 'inReplyTo', 'references', 'textBody', 'htmlBody', 'attachments', 'bodyValues'];
// The conversation's messages, oldest first, and which of them are open: the unread ones and the newest.
let thread = [], expanded = new Set();
async function openMail(id, quiet) {
  open = id; picked.clear();
  for (const r of document.querySelectorAll('.row')) r.classList.toggle('on', r.dataset.id === id);
  document.body.classList.add('reading');
  const row = rowOfId(id);
  if (inDrafts()) { editDraft(id); return; }
  if (!quiet) { $('#readp').textContent = ''; $('#readp').append(el('div', { class: 'blank' }, el('span', { text: say('Opening…') }))); }
  const ids = row && row.members && row.members.length ? row.members.map(x => x.id) : [id];
  try {
    const res = await jmap(['Email/get', { accountId: acct, ids, properties: FULL_PROPS,
      bodyProperties: ['partId', 'blobId', 'size', 'name', 'type', 'charset', 'disposition', 'cid'], fetchTextBodyValues: true, fetchHTMLBodyValues: true, maxBodyValueBytes: 4000000 }, 'g']);
    if (open !== id) return;
    const drafts = byRole.drafts;
    thread = (one(res, 'g').list || []).filter(m => !(drafts && m.mailboxIds && m.mailboxIds[drafts.id]) || ids.length === 1).sort((a, b) => new Date(a.sentAt || a.receivedAt) - new Date(b.sentAt || b.receivedAt));
    if (!thread.length) { openMsg = null; paintReader(); toast(say('That conversation is no longer there'), 'bad'); return; }
    openMsg = thread[thread.length - 1];
    const keep = quiet ? expanded : new Set();
    expanded = new Set([...keep].filter(x => thread.some(m => m.id === x)));
    for (const m of thread) if (!(m.keywords || {}).$seen) expanded.add(m.id);
    expanded.add(openMsg.id);
    paintReader();
    const unseen = thread.filter(m => !(m.keywords || {}).$seen).map(m => m.id);
    if (unseen.length) markSeen(unseen, true, true);
  } catch (e) { fail(e); }
}
function paintReaderBar() {
  const bar = $('#rbar'); if (!bar || !openMsg) return;
  const flagged = thread.some(m => (m.keywords || {}).$flagged), junk = byRole.junk, row = open;
  const inJunk = junk && openMsg.mailboxIds && openMsg.mailboxIds[junk.id];
  bar.textContent = '';
  const back = ibtn('left', say('Back to the list'), () => { document.body.classList.remove('reading'); open = null; openMsg = null; thread = []; paintList(); });
  back.id = 'backB';
  bar.append(...[back, ibtn('reply', say('Reply  (r)'), () => reply(openMsg, false)), ibtn('replyall', say('Reply all  (a)'), () => reply(openMsg, true)), ibtn('forward', say('Forward  (f)'), () => forward(openMsg)),
    el('div', { class: 'grow' }),
    ibtn('star', flagged ? say('Unstar  (s)') : say('Star  (s)'), () => star([row], !flagged), 'st' + (flagged ? ' on' : '')),
    ibtn('mail', say('Mark as unread  (u)'), () => { markSeen([row], false); document.body.classList.remove('reading'); }),
    ibtn('folder', say('Move to'), e => moveMenu(e.currentTarget, [row])),
    ibtn('folder', say('Archive  (e)'), () => archive([row])),
    ibtn('more', say('More'), e => popup(e.currentTarget, [
      { icon: 'info', label: say('Show the headers'), fn: () => showHeaders(openMsg) },
      { icon: 'file', label: say('Print'), fn: () => window.print() }])),
    junk && !inJunk ? ibtn('junk', say('Report junk'), () => move([row], junk.id, say('Moved to Junk'))) : null,
    ibtn('trash', say('Delete  (#)'), () => remove([row])),
    inJunk && byRole.inbox ? ibtn('inbox', say('Not junk'), () => move([row], byRole.inbox.id, say('Moved to Inbox'))) : null].filter(Boolean));
}
function paintReader() {
  const R = $('#readp'); R.textContent = '';
  if (!openMsg) {
    R.append(el('div', { class: 'blank' }, el('div', { class: 'ring' }, ico('mail')), el('b', { text: mails.length ? say('Pick a conversation to read it') : say('Nothing selected') }),
      el('span', {}, ...say('Press % to write one, % to search.').split('%').flatMap((part, i) => i ? [el('span', { class: 'kbd', text: 'c/'[i - 1] }), part] : [part]))));
    return;
  }
  const first = thread[0];
  const box = byId[Object.keys(openMsg.mailboxIds || {})[0]];
  const d = el('div', { class: 'rd' }, el('div', { class: 'rbar', id: 'rbar' }),
    el('h1', {}, first.subject || openMsg.subject || say('(no subject)'), thread.length > 1 ? el('span', { class: 'tag', text: say('% messages', thread.length) }) : null, box && box.role !== 'inbox' ? el('span', { class: 'tag', text: boxLabel(box) }) : null));
  for (const m of thread) d.append(expanded.has(m.id) ? openCard(m) : shutCard(m));
  R.append(d);
  paintReaderBar();
  if (thread.length > 1) { const last = d.querySelector('.msg:last-child'); if (last) setTimeout(() => last.scrollIntoView({ block: 'start' }), 0); } else R.scrollTop = 0;
}
function shutCard(m) {
  const from = (m.from || [])[0];
  return el('div', { class: 'msg shut', onclick: () => { expanded.add(m.id); paintReader(); } },
    avatar(from), el('b', { text: nameOf(from) || say('(unknown sender)') }), el('span', { class: 'pv', text: m.preview || '' }), el('span', { class: 'when', text: short(m.receivedAt), title: full(m.receivedAt) }));
}
function openCard(m) {
  const from = (m.from || [])[0];
  const rcp = [];
  if (m.to && m.to.length) rcp.push('to ' + who(m.to));
  if (m.cc && m.cc.length) rcp.push('cc ' + who(m.cc));
  if (m.bcc && m.bcc.length) rcp.push('bcc ' + who(m.bcc));
  const card = el('div', { class: 'msg' });
  const head = el('div', { class: 'hdr', onclick: e => { if (thread.length > 1 && !e.target.closest('button,a')) { expanded.delete(m.id); paintReader(); } } }, avatar(from),
    el('div', { class: 'who' }, el('div', { class: 'line' }, el('b', { text: nameOf(from) || say('(unknown sender)') }), from && from.name ? el('span', { class: 'addr', text: '<' + from.email + '>' }) : null), el('div', { class: 'rcp', text: rcp.join(' · ') })),
    el('div', { class: 'when', text: full(m.sentAt || m.receivedAt) }),
    ibtn('reply', say('Reply'), () => reply(m, false)),
    ibtn('more', say('More'), e => popup(e.currentTarget, [
      { icon: 'replyall', label: say('Reply all'), fn: () => reply(m, true) },
      { icon: 'forward', label: say('Forward'), fn: () => forward(m) },
      '-',
      { icon: 'mail', label: say('Mark this one unread'), fn: () => markSeen([m.id], false, true) },
      { icon: 'download', label: say('Download message (.eml)'), fn: () => { location.href = dl(m.id, (m.subject || 'message').replace(/[\\/:*?"<>|]+/g, ' ').slice(0, 80) + '.eml', 'message/rfc822'); } }
    ])));
  card.append(head);
  const values = m.bodyValues || {};
  const cids = {};
  for (const p of m.attachments || []) if (p.cid) cids[p.cid.replace(/^<|>$/g, '').toLowerCase()] = dl(p.blobId, p.name || 'image', p.type);
  const html = (m.htmlBody || []).filter(p => p.type === 'text/html').map(p => (values[p.partId] || {}).value || '').join('');
  const text = (m.textBody || []).filter(p => p.type !== 'text/html').map(p => (values[p.partId] || {}).value || '').join('\n');
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
    card.append(A);
  }
  if (html.trim()) {
    const allow = showImages.has(m.id) || showImages.has('*' + ((from && from.email) || ''));
    const c = cleanHtml(html, allow, cids);
    if (c.blocked && !allow)
      card.append(el('div', { class: 'imgbar' }, ico('image'), el('span', { text: say('Remote images are hidden, so the sender cannot see when you read this.') }),
        btn(null, say('Show images'), () => { showImages.add(m.id); paintReader(); }),
        from ? btn(null, say('Always from this sender'), () => { showImages.add('*' + from.email); store.set('skl-mail-img', JSON.stringify([...showImages].filter(x => x.startsWith('*')))); paintReader(); }) : null));
    const f = frame(c.doc, true);
    card.append(el('div', { class: 'mbody' }, f), f.quoteToggle);
  } else {
    const [mine, quoted] = splitQuote(text || m.preview || '');
    const box = el('div', { class: 'mtext' }, linkify(mine));
    card.append(box);
    if (quoted) {
      const q = el('div', { class: 'mtext quoted', hidden: true }, linkify(quoted));
      card.append(el('button', { class: 'qt', title: say('Show the quoted text'), onclick: e => { q.hidden = !q.hidden; e.currentTarget.classList.toggle('on', !q.hidden); } }, ico('more')), q);
    }
  }
  return card;
}
// What a reply wrote, and what it quotes below it: from "On … wrote:", a forwarded or original message's marker, or
// the run of "> " lines it ends with.
function splitQuote(t) {
  const lines = t.split('\n');
  let at = lines.findIndex(l => /^\s*(On\s.{0,300}\swrote:|Am\s.{0,300}\sschrieb.{0,60}:|-{2,}\s*(Original|Forwarded) Message\s*-{2,}|From:\s.+\s<?\S+@\S+>?)\s*$/i.test(l));
  if (at < 0) {
    let i = lines.length;
    while (i > 0 && (/^\s*>/.test(lines[i - 1]) || !lines[i - 1].trim())) i--;
    if (i < lines.length && lines.slice(i).some(l => /^\s*>/.test(l))) at = i;
  }
  if (at <= 0) return [t, ''];
  return [lines.slice(0, at).join('\n').replace(/\s+$/, ''), lines.slice(at).join('\n')];
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
  const own = new Set([me.address, ...identities.map(i => i.email)].map(a => a.toLowerCase()));
  const isMine = a => own.has((a.email || '').toLowerCase());
  const to = (m.replyTo && m.replyTo.length ? m.replyTo : m.from || []).filter(a => !isMine(a));
  const sent = byRole.sent && m.mailboxIds && m.mailboxIds[byRole.sent.id];
  const target = sent ? m.to || [] : to.length ? to : m.from || [];
  const cc = all ? [...(m.to || []), ...(m.cc || [])].filter(a => !isMine(a) && !target.some(t => t.email.toLowerCase() === a.email.toLowerCase())) : [];
  // The reply goes out from the address the message was sent to, where that is one of the user's own.
  const addressed = [...(m.to || []), ...(m.cc || [])].map(a => (a.email || '').toLowerCase());
  const as = identities.find(i => addressed.includes(i.email.toLowerCase()));
  const from = (m.from || [])[0];
  const quoted = quoteOf(m).replace(/\s+$/, '').split('\n').map(l => '> ' + l).join('\n');
  compose({
    to: who(target), cc: who(cc), subject: /^re:/i.test(m.subject || '') ? m.subject : 'Re: ' + (m.subject || ''),
    body: '\n\n' + say('On %, % wrote:', full(m.sentAt || m.receivedAt), nameOf(from) || say('someone')) + '\n' + quoted + '\n',
    inReplyTo: m.messageId || null, references: [...(m.references || []), ...(m.messageId || [])], replyTo: m.id, identity: as && as.id
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
  const field = (lab, val, more) => { const i = el('input', { value: val || '', spellcheck: 'false', autocomplete: 'off', list: lab === 'Subject' ? null : 'addrs' }); return [i, el('div', { class: 'fl' }, el('label', { text: say(lab) }), i, more || null)]; };
  const [to, toRow] = field('To', o.to, el('button', { class: 'lnk', type: 'button', text: 'Cc Bcc', onclick: () => { ccRow.hidden = false; bccRow.hidden = false; toRow.querySelector('.lnk').remove(); cc.focus(); } }));
  const [cc, ccRow] = field('Cc', o.cc), [bcc, bccRow] = field('Bcc', o.bcc), [subj, subjRow] = field('Subject', o.subject);
  ccRow.hidden = !o.cc && !o.bcc; bccRow.hidden = !o.cc && !o.bcc;
  // Which of their addresses it goes from, where they have more than one.
  const fromSel = el('select', { class: 'fromsel' }, ...identities.map(i => el('option', { value: i.id, text: i.email, selected: i.id === (o.identity || identity) })));
  const fromRow = el('div', { class: 'fl', hidden: identities.length < 2 }, el('label', { text: say('From') }), fromSel);
  if (o.cc || o.bcc) toRow.querySelector('.lnk').remove();
  const body = el('textarea', { placeholder: say('Write your message'), spellcheck: 'true' });
  // A new message, a reply or a forward carries the signature, above what it quotes.
  body.value = o.draft || !signature ? o.body || '' : (o.body ? '\n\n-- \n' + signature + o.body : '\n\n-- \n' + signature);
  // Formatting, off unless asked for: an editor beside the text, its HTML sent with the text it reads as.
  const ed = el('div', { class: 'ed', contenteditable: 'true', hidden: true });
  const cmd = (c, v) => () => { ed.focus(); document.execCommand(c, false, v); };
  const tools = el('div', { class: 'tools', hidden: true },
    ibtn('bold', say('Bold'), cmd('bold')), ibtn('italic', say('Italic'), cmd('italic')), ibtn('underline', say('Underline'), cmd('underline')),
    ibtn('list', say('Bulleted list'), cmd('insertUnorderedList')), ibtn('olist', say('Numbered list'), cmd('insertOrderedList')),
    ibtn('quote', say('Quote'), cmd('formatBlock', 'blockquote')),
    ibtn('link', 'Link', async () => { const u = await ask({ title: say('Link to'), input: 'https://…', ok: 'Link' }); if (u && /^(https?:|mailto:)/i.test(u)) cmd('createLink', u)(); }),
    ibtn('clear', say('Plain text again'), cmd('removeFormat')));
  const catts = el('div', { class: 'catts' });
  const file = el('input', { type: 'file', multiple: true, hidden: true, onchange: () => { for (const f of file.files) attach(f); file.value = ''; } });
  const head = el('b', { text: o.subject || say('New message') });
  const box = el('div', { id: 'cmp' },
    el('div', { class: 'chead', onclick: e => { if (e.target.closest('.ib')) return; box.classList.toggle('min'); } }, head,
      ibtn('min', say('Minimize'), () => box.classList.toggle('min')), ibtn('close', say('Close and keep a draft'), () => closeCompose())),
    el('div', { class: 'cbody' }, fromRow, toRow, ccRow, bccRow, subjRow, tools, body, ed, catts),
    el('div', { class: 'cfoot' }, btn('send', say('Send'), () => send(), 'pri'), ibtn('clock', say('Send later'), e => sendLater(e.currentTarget)), ibtn('clip', say('Attach files'), () => file.click()),
      ibtn('format', say('Formatting'), () => richMode(cmp, !cmp.rich)), file, el('span', { class: 'note', text: '' }), el('div', { class: 'grow' }), ibtn('trash', say('Discard'), () => discard())));
  subj.addEventListener('input', () => { head.textContent = subj.value || say('New message'); });
  cmp = { box, to, cc, bcc, subj, body, ed, tools, fromSel, rich: false, atts: (o.attachments || []).slice(), uploading: 0, inReplyTo: o.inReplyTo || null, references: o.references || null, draft: o.draft || null, start: JSON.stringify([to.value, cc.value, bcc.value, subj.value, body.value]), atts0: (o.attachments || []).length };
  const paintAtts = () => { catts.textContent = ''; for (const a of cmp.atts) catts.append(el('span', { class: 'chip' }, ico('clip'), el('span', { text: a.name + (a.size ? ' · ' + human(a.size) : '') }), ibtn('close', say('Remove'), () => { cmp.atts = cmp.atts.filter(x => x !== a); paintAtts(); }))); };
  cmp.paintAtts = paintAtts; paintAtts();
  // Kept as a draft every half minute it has changed, so a closed tab or a crash loses little.
  const mine = cmp;
  mine.autosave = setInterval(() => {
    if (cmp !== mine) { clearInterval(mine.autosave); return; }
    const now = JSON.stringify([mine.to.value, mine.cc.value, mine.bcc.value, mine.subj.value, bodyText(mine), mine.atts.length]);
    if (!mine.sending && !mine.uploading && changed(mine) && now !== mine.saved && byRole.drafts) saveDraft(mine, true);
  }, 30000);
  async function attach(f) {
    const c = cmp; c.uploading++; const note = box.querySelector('.note'); note.textContent = say('Uploading %…', f.name);
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
// Between the text and the editor: what is written carried over, a line a paragraph.
function richMode(c, on) {
  if (!c || c.rich === on) return;
  if (on) {
    c.ed.textContent = '';
    for (const line of c.body.value.split('\n')) c.ed.append(el('div', {}, line ? document.createTextNode(line) : el('br')));
  } else c.body.value = textOfHtml(c.ed.innerHTML);
  c.rich = on; c.ed.hidden = !on; c.tools.hidden = !on; c.body.hidden = on;
  (on ? c.ed : c.body).focus();
}
// The editor's HTML as it is sent: its tags those of text, its links http, https or mailto, nothing else kept.
function editorHtml(ed) {
  const keep = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'A', 'UL', 'OL', 'LI', 'P', 'DIV', 'BR', 'BLOCKQUOTE', 'SPAN']);
  const walk = n => {
    for (const c of [...n.childNodes]) {
      if (c.nodeType === 3) continue;
      if (c.nodeType !== 1 || !keep.has(c.tagName)) { c.replaceWith(...(c.nodeType === 1 && !['SCRIPT', 'STYLE'].includes(c.tagName) ? [...c.childNodes] : [])); continue; }
      for (const a of [...c.attributes]) if (!(c.tagName === 'A' && a.name === 'href' && /^(https?:|mailto:)/i.test(a.value))) c.removeAttribute(a.name);
      walk(c);
    }
  };
  const copy = ed.cloneNode(true); walk(copy);
  return '<!doctype html><html><body style="font-family:Arial,sans-serif">' + copy.innerHTML + '</body></html>';
}
const bodyText = c => c.rich ? textOfHtml(c.ed.innerHTML) : c.body.value;
function emailOf(c) {
  const to = parseAddrs(c.to.value), cc = parseAddrs(c.cc.value), bcc = parseAddrs(c.bcc.value);
  if (to === false || cc === false || bcc === false) throw new Error(say('One of the recipients is no address'));
  const sender = (identities.find(i => i.id === c.fromSel.value) || {}).email || me.address;
  const e = { mailboxIds: { [byRole.drafts.id]: true }, keywords: { $draft: true, $seen: true }, from: [myName ? { name: myName, email: sender } : { email: sender }], subject: c.subj.value,
    textBody: [{ partId: 't', type: 'text/plain' }], bodyValues: Object.assign({ t: { value: bodyText(c) } }, c.rich ? { h: { value: editorHtml(c.ed) } } : {}),
    attachments: c.atts.map(a => ({ blobId: a.blobId, type: a.type, name: a.name, disposition: 'attachment' })) };
  if (c.rich) e.htmlBody = [{ partId: 'h', type: 'text/html' }];
  if (to.length) e.to = to; if (cc.length) e.cc = cc; if (bcc.length) e.bcc = bcc;
  if (c.inReplyTo) e.inReplyTo = c.inReplyTo;
  if (c.references && c.references.length) e.references = c.references;
  return { e, rcpts: [...to, ...cc, ...bcc] };
}
const changed = c => c.atts.length !== c.atts0 || JSON.stringify([c.to.value, c.cc.value, c.bcc.value, c.subj.value, bodyText(c)]) !== c.start;
async function send() {
  const c = cmp; if (!c || c.sending) return;
  if (c.uploading) { toast(say('Wait until the attachments are uploaded'), 'spark'); return; }
  let built;
  try { built = emailOf(c); } catch (e) { fail(e); return; }
  if (!built.rcpts.length) { toast(say('Add at least one recipient'), 'bad'); c.to.focus(); return; }
  if (!c.subj.value.trim() && !await ask({ title: say('Send without a subject?'), ok: say('Send') })) return;
  c.sending = true; c.box.querySelector('.cfoot .btn').disabled = true;
  // Held ten seconds, the window hidden, so a message sent too soon can be taken back.
  c.box.hidden = true;
  if (!await held(c)) { c.box.hidden = false; c.sending = false; c.box.querySelector('.cfoot .btn').disabled = false; return; }
  const sent = byRole.sent;
  try {
    const res = await jmap(
      ['Email/set', { accountId: acct, create: { d: built.e } }, 'd'],
      ['EmailSubmission/set', { accountId: acct, create: { s: Object.assign({ identityId: c.fromSel.value || identity, emailId: '#d' },
        c.holdUntil ? { envelope: { mailFrom: { email: built.e.from[0].email, parameters: { holduntil: c.holdUntil.toISOString().replace(/\.\d+Z$/, 'Z') } }, rcptTo: built.rcpts.map(a => ({ email: a.email })) } } : {}) },
        onSuccessUpdateEmail: { '#s': Object.assign(sent ? { mailboxIds: { [sent.id]: true } } : {}, { 'keywords/$draft': null }) } }, 's']);
    setErrors(one(res, 'd')); setErrors(one(res, 's'));
    remember(built.rcpts);
    if (c.draft) jmap(['Email/set', { accountId: acct, destroy: [c.draft] }, 'x']).catch(() => {});
    closeCompose(true);
    toast(c.holdUntil ? say('It goes %', c.holdUntil.toLocaleString(LOC, { weekday: 'short', hour: '2-digit', minute: '2-digit' })) : say('Sent'));
    await loadBoxes(); loadList(true);
  } catch (e) { fail(e); c.sending = false; c.box.querySelector('.cfoot .btn').disabled = false; }
}
// When a message goes: tomorrow at eight, next Monday at eight, or a time asked for.
function sendLater(at) {
  const at8 = (days) => { const d = new Date(); d.setDate(d.getDate() + days); d.setHours(8, 0, 0, 0); return d; };
  const monday = (8 - new Date().getDay()) % 7 || 7;
  const go = d => { if (!cmp) return; cmp.holdUntil = d; send(); };
  popup(at, [
    { icon: 'clock', label: 'Tomorrow, 8:00', fn: () => go(at8(1)) },
    { icon: 'clock', label: 'Monday, 8:00', fn: () => go(at8(monday)) },
    { icon: 'clock', label: say('Pick a time…'), fn: () => {
      const inp = el('input', { class: 'inp', type: 'datetime-local', value: new Date(Date.now() + 3600000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) });
      const L = modal(say('Send at'), inp, [btn(null, say('Cancel'), () => L.close()), btn(null, say('Schedule'), () => {
        if (inp.value && Date.parse(inp.value) > Date.now()) { L.close(); go(new Date(inp.value)); } else toast(say('Pick a time to come'), 'bad');
      }, 'pri')]);
    } }]);
}
let holding = null;
function held(c) {
  return new Promise(done => {
    const bar = el('div', { class: 'toast ok holdbar' }, el('span', { text: say('Sending…') }),
      el('button', { class: 'lnk', text: say('Undo'), onclick: () => { clearTimeout(holding.t); bar.remove(); holding = null; done(false); } }));
    host().append($('#toasts')); $('#toasts').append(bar);
    holding = { c, done, t: setTimeout(() => { bar.remove(); holding = null; done(true); }, 10000) };
  });
}
async function saveDraft(c, quiet) {
  try {
    const built = emailOf(c);
    const res = await jmap(['Email/set', { accountId: acct, create: { d: built.e }, destroy: c.draft ? [c.draft] : [] }, 'd']);
    setErrors(one(res, 'd'));
    // The window still open, the draft it now has is the one a later save replaces.
    const made = (one(res, 'd').created || {}).d;
    if (made && cmp === c) { c.draft = made.id; c.saved = JSON.stringify([c.to.value, c.cc.value, c.bcc.value, c.subj.value, bodyText(c), c.atts.length]); }
    if (!quiet) toast(say('Draft saved'));
    await loadBoxes();
    if (byId[view.box] && byId[view.box].role === 'drafts') loadList(true);
  } catch (e) { fail(e); }
}
// The window closed: a message written in it is kept as a draft unless it was sent or thrown away.
function closeCompose(force) {
  const c = cmp; if (!c) return true;
  if (!force && c.uploading) { toast(say('Wait until the attachments are uploaded'), 'spark'); return false; }
  cmp = null; c.box.remove(); clearInterval(c.autosave);
  if (!force && changed(c) && byRole.drafts) saveDraft(c);
  return true;
}
async function discard() {
  const c = cmp; if (!c) return;
  if (changed(c) && !await ask({ title: say('Discard this message?'), ok: say('Discard'), danger: true })) return;
  closeCompose(true);
  if (c.draft) { try { await jmap(['Email/set', { accountId: acct, destroy: [c.draft] }, 'x']); await loadBoxes(); if (byId[view.box] && byId[view.box].role === 'drafts') loadList(true); } catch (e) { fail(e); } }
}

// ─── settings ───────────────────────────────────────────────────────────────
// ─── filters ────────────────────────────────────────────────────────────────
// Rules the server runs on mail as it arrives, kept as the Sieve script "webmail": its first line holds the rules as
// JSON, so the page reads back what it wrote.
const FIELDS = { from: say('From'), to: say('To or Cc'), subject: say('Subject') };
const ACTIONS = { move: say('Move to'), read: say('Mark as read'), star: say('Star'), delete: say('Delete'), forward: say('Forward to') };
const sieveStr = s => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
function boxPath(b) { let n = b.name, p = b.parentId && byId[b.parentId]; while (p) { n = p.name + '/' + n; p = p.parentId && byId[p.parentId]; } return byRole.inbox && b.id === byRole.inbox.id ? 'INBOX' : n; }
function sieveOf(rules) {
  const body = rules.filter(r => r.value && (r.action === 'read' || r.action === 'star' || r.action === 'delete' || r.target)).map(r => {
    const test = r.field === 'to' ? 'address :contains ["to", "cc"] ' + sieveStr(r.value) : 'header :contains ' + sieveStr(r.field) + ' ' + sieveStr(r.value);
    const act = r.action === 'move' ? 'fileinto ' + sieveStr(r.target) + '; stop;' : r.action === 'read' ? 'addflag "\\\\Seen";'
      : r.action === 'star' ? 'addflag "\\\\Flagged";' : r.action === 'delete' ? 'discard; stop;' : 'redirect :copy ' + sieveStr(r.target) + ';';
    return 'if ' + test + ' { ' + act + ' }';
  });
  return '# webmail rules: ' + JSON.stringify(rules) + '\nrequire ["fileinto", "imap4flags", "copy"];\n' + body.join('\n') + '\n';
}
async function filtersEditor() {
  let got = { script: '', active: '' };
  try { const r = await fetch('/~mail/filters', { credentials: 'same-origin', headers: { 'X-Socketley-UI': '1' } }); if (r.ok) got = await r.json(); } catch (e) {}
  let rules = [];
  try { const first = (got.script || '').split('\n')[0]; if (first.startsWith('# webmail rules: ')) rules = JSON.parse(first.slice(17)); } catch (e) {}
  const list = el('div', { class: 'rules' });
  const folders = Object.values(byId).filter(b => b.role !== 'drafts' && b.role !== 'sent');
  const paint = () => {
    list.textContent = '';
    rules.forEach((r, i) => {
      const f = el('select', { class: 'inp' }, ...Object.entries(FIELDS).map(([k, v]) => el('option', { value: k, text: v, selected: r.field === k })));
      const v = el('input', { class: 'inp', value: r.value || '', placeholder: 'contains' });
      const a = el('select', { class: 'inp' }, ...Object.entries(ACTIONS).map(([k, t]) => el('option', { value: k, text: t, selected: r.action === k })));
      const t = r.action === 'move' ? el('select', { class: 'inp' }, ...folders.map(b => el('option', { value: boxPath(b), text: boxLabel(b), selected: r.target === boxPath(b) })))
        : r.action === 'forward' ? el('input', { class: 'inp', value: r.target || '', placeholder: 'address' }) : null;
      f.onchange = () => { r.field = f.value; }; v.oninput = () => { r.value = v.value; };
      a.onchange = () => { r.action = a.value; r.target = a.value === 'move' && folders[0] ? boxPath(folders[0]) : ''; paint(); };
      if (t) { t.onchange = t.oninput = () => { r.target = t.value; }; if (r.action === 'move' && !r.target && folders[0]) r.target = boxPath(folders[0]); }
      list.append(el('div', { class: 'rule' }, f, v, a, t, ibtn('trash', say('Remove the rule'), () => { rules.splice(i, 1); paint(); })));
    });
  };
  paint();
  const body = el('div', { id: 'settings' },
    got.active && got.active !== 'webmail' ? el('p', { class: 'approw', text: say('Saving replaces the filter “%” a mail app put in place.', got.active) }) : null,
    list, el('button', { class: 'lnk', text: say('Add a rule'), onclick: () => { rules.push({ field: 'from', value: '', action: 'move', target: '' }); paint(); } }));
  const save = async () => {
    try {
      const r = await fetch('/~mail/filters', { method: 'PUT', credentials: 'same-origin', headers: { 'X-Socketley-UI': '1', 'Content-Type': 'application/sieve' }, body: sieveOf(rules) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || say('The filters were not saved'));
      L.close(); toast(say('Filters saved'));
    } catch (e) { fail(e); }
  };
  const L = modal(say('Filters'), body, [btn(null, say('Cancel'), () => L.close()), btn(null, say('Save'), save, 'pri')]);
}

// What a mail app is set up with, and the profile that sets up an iPhone, an iPad or a Mac at once.
function mailApps() {
  const st = me && me.setup;
  if (!st) return [];
  const row = (what, port, tls) => port ? el('div', { class: 'approw', text: say('%: %, port %, %', what, st.host, port, tls ? 'SSL/TLS' : 'STARTTLS') }) : null;
  return [el('h4', { text: say('Mail apps') }),
    el('div', { class: 'approw', text: say('Sign in with % and your password.', me.address) }),
    row('IMAP', st.imaps || st.imap, !!st.imaps), row('POP3', st.pop3s || st.pop3, !!st.pop3s),
    row(say('Sending (SMTP)'), st.submissions || st.submission, !!st.submissions),
    st.dav ? el('div', { class: 'approw', text: say('Calendars and contacts: %', st.dav) }) : null,
    el('div', { class: 'approw', text: say('Thunderbird and Outlook find these by themselves from your address.') }),
    el('a', { class: 'btn', href: '/~mail/mobileconfig', download: 'mail.mobileconfig', text: say('Profile for iPhone, iPad and Mac') })].filter(Boolean);
}

async function settings() {
  let vac = { isEnabled: false, subject: '', textBody: '' };
  try { const r = await jmap(['VacationResponse/get', { accountId: acct }, 'v']); vac = (one(r, 'v').list || [])[0] || vac; } catch (e) {}
  const name = el('input', { class: 'inp', value: myName, placeholder: me.user, maxlength: 200 });
  const sig = el('textarea', { class: 'inp', placeholder: say('Sent below every message you write') }); sig.value = signature;
  const on = el('input', { type: 'checkbox' }); on.checked = !!vac.isEnabled;
  const vs = el('input', { class: 'inp', value: vac.subject || '', placeholder: say('Out of office') });
  const vb = el('textarea', { class: 'inp', placeholder: say('I am away until … and will answer when I am back.') }); vb.value = vac.textBody || '';
  const local = d => d ? new Date(new Date(d).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '';
  const vf = el('input', { class: 'inp', type: 'datetime-local', value: local(vac.fromDate) });
  const vt = el('input', { class: 'inp', type: 'datetime-local', value: local(vac.toDate) });
  const nt = el('input', { type: 'checkbox' }); nt.checked = store.get('skl-mail-notify') === '1';
  const body = el('div', { id: 'settings' },
    el('label', { class: 'l', text: say('Your name, as people see it') }), name,
    el('label', { class: 'l', text: say('Signature') }), sig,
    el('h4', { text: say('Out of office') }),
    el('label', { class: 'chk' }, on, el('span', { text: say('Answer everyone who writes, once a week each') })),
    el('label', { class: 'l', text: say('From') }), vf, el('label', { class: 'l', text: say('Until') }), vt,
    el('label', { class: 'l', text: say('Subject') }), vs,
    el('label', { class: 'l', text: say('Message') }), vb,
    el('h4', { text: say('Filters') }),
    el('button', { class: 'lnk', text: say('Rules for arriving mail…'), onclick: () => { L.close(); filtersEditor(); } }),
    el('h4', { text: say('Notifications') }),
    el('label', { class: 'chk' }, nt, el('span', { text: say('Tell me of new mail while this tab is in the background') })),
    ...mailApps());
  const save = async () => {
    try {
      const r = await jmap(['Identity/set', { accountId: acct, update: { [identity]: { name: name.value.trim(), textSignature: sig.value.replace(/\s+$/, '') } } }, 'i'],
        ['VacationResponse/set', { accountId: acct, update: { singleton: { isEnabled: on.checked, subject: vs.value.trim() || null, textBody: vb.value.trim() || null,
          fromDate: vf.value ? new Date(vf.value).toISOString().replace(/\.\d+Z$/, 'Z') : null, toDate: vt.value ? new Date(vt.value).toISOString().replace(/\.\d+Z$/, 'Z') : null } } }, 'v']);
      setErrors(one(r, 'i')); setErrors(one(r, 'v'));
      myName = name.value.trim(); signature = sig.value.replace(/\s+$/, '');
      if (nt.checked && 'Notification' in window && Notification.permission !== 'granted') await Notification.requestPermission();
      store.set('skl-mail-notify', nt.checked ? '1' : '0');
      L.close(); toast(say('Settings saved'));
    } catch (e) { fail(e); }
  };
  const L = modal(say('Settings'), body, [btn(null, say('Cancel'), () => L.close()), btn(null, say('Save'), save, 'pri')]);
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
  // New mail while the tab is not looked at, told by the browser where the user allowed it.
  if (byRole.inbox && byRole.inbox.unreadEmails > unread && document.hidden && store.get('skl-mail-notify') === '1' &&
      'Notification' in window && Notification.permission === 'granted') {
    try {
      const r = await jmap(['Email/query', { accountId: acct, filter: { inMailbox: byRole.inbox.id }, sort: [{ property: 'receivedAt', isAscending: false }], limit: 1 }, 'q'],
        ['Email/get', { accountId: acct, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: ['from', 'subject'] }, 'g']);
      const m = (one(r, 'g').list || [])[0];
      if (m) { const n = new Notification(nameOf((m.from || [])[0]) || say('New mail'), { body: m.subject || '', tag: 'skl-mail' }); n.onclick = () => { window.focus(); openMail(m.id); }; }
    } catch (e) {}
  }
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
  else if (openMsg && open && k === 's') { star([open], !thread.some(m => (m.keywords || {}).$flagged)); }
  else if (openMsg && open && k === 'u') { markSeen([open], false); }
  else if (openMsg && open && (k === '#' || k === 'Delete')) { remove([open]); }
  else if (k === 'e' && (open || picked.size)) { archive(picked.size ? [...picked] : [open]); }
  else if (k === '*') { for (const m of mails) picked.add(m.id); paintList(); }
});

// ─── start ──────────────────────────────────────────────────────────────────
function wire() {
  $('#compose').append(ico('pen'), el('span', { text: say('New') }));
  $('#compose').addEventListener('click', () => compose());
  $('#fab').append(ico('pen'), el('span', { text: say('New') }));
  $('#fab').addEventListener('click', () => compose());
  $('#menuB').append(ico('menu')); $('#menuB').title = say('Folders');
  $('#menuB').addEventListener('click', () => $('#side').classList.toggle('open'));
  $('#refB').append(ico('sync')); $('#refB').title = say('Check for mail');
  $('#refB').addEventListener('click', async () => { await refresh(); toast(say('Up to date')); });
  $('#home').addEventListener('click', () => byRole.inbox && go({ box: byRole.inbox.id }));
  $('#nSet').append(ico('gear'), el('span', { text: say('Settings') }));
  $('#nSet').addEventListener('click', () => { settings(); $('#side').classList.remove('open'); });
  $('#nOut').append(ico('out'), el('span', { text: say('Sign out') }));
  $('#nOut').addEventListener('click', signOut);
  let t = 0;
  $('#q').addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { const q = $('#q').value.trim(); if (q) go({ q }); else if (view.q) go({ box: byRole.inbox ? byRole.inbox.id : '' }); $('#q').focus(); }, 350); });
  $('#q').addEventListener('keydown', e => { if (e.key === 'Escape') { $('#q').value = ''; $('#q').blur(); if (view.q) go({ box: byRole.inbox ? byRole.inbox.id : '' }); } });
  $('#rows').addEventListener('scroll', () => { const r = $('#rows'); if (r.scrollTop + r.clientHeight > r.scrollHeight - 400) loadMore(); });
  window.addEventListener('beforeunload', e => {
    // A message held to be taken back goes now, as the tab that held it goes.
    if (holding) { clearTimeout(holding.t); holding.done(true); holding = null; }
    if (cmp && changed(cmp)) { e.preventDefault(); e.returnValue = ''; }
  });
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
    identities = ids;
  } catch (e) {}
  try { await loadBoxes(); } catch (e) { fail(e); return; }
  const v = fromHash(); view = { box: v.box || '', starred: !!v.starred, q: v.q || '' };
  if (view.q) $('#q').value = view.q;
  paintBoxes(); paintReader(); loadList();
  live();
  correspondents();
}
// Whom the user wrote to lately, from their Sent folder, so the addresses they type are offered on any device.
async function correspondents() {
  if (!byRole.sent) return;
  try {
    const r = await jmap(['Email/query', { accountId: acct, filter: { inMailbox: byRole.sent.id }, sort: [{ property: 'receivedAt', isAscending: false }], limit: 300 }, 'q'],
      ['Email/get', { accountId: acct, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: ['to', 'cc', 'bcc'] }, 'g']);
    const seen = [];
    for (const m of one(r, 'g').list || []) seen.push(...(m.to || []), ...(m.cc || []), ...(m.bcc || []));
    remember(seen.reverse());
  } catch (e) {}
}
wire();
(async () => {
  let r;
  try { r = await fetch('/~mail/session', { credentials: 'same-origin', headers: { 'X-Socketley-UI': '1' } }); }
  catch (e) { $('#login').hidden = false; $('#le').textContent = say('The mail server cannot be reached.'); return; }
  if (r.status === 401) { signedOut(r.headers.get('X-Socketley-Idp-Login')); return; }
  if (!r.ok) { $('#login').hidden = false; $('#le').textContent = await errText(r); return; }
  me = await r.json(); acct = me.account;
  start();
})();
</script>
</body>
</html>)HTML";
