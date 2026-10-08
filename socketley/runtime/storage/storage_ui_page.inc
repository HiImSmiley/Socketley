// The page of the web interface, whole: markup, style and script, with nothing fetched from elsewhere.
constexpr std::string_view ui_page = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#07080c">
<title>socketley</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x2='1' y2='1'%3E%3Cstop stop-color='%238b5cf6'/%3E%3Cstop offset='1' stop-color='%2306b6d4'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='24' height='24' rx='6' fill='url(%23g)'/%3E%3Cpath d='M9 7v10l8-5z' fill='white'/%3E%3C/svg%3E">
<style>
:root{
  --bg:#07080c;--bg2:#0c0e15;--panel:rgba(18,21,31,.78);--card:#121520;--card2:#191d2b;--hov:#20253a;
  --line:rgba(255,255,255,.07);--line2:rgba(255,255,255,.13);--fg:#eef0f7;--mut:#9aa2b8;--dim:#626a80;
  --a1:#c084fc;--a2:#f472b6;--a3:#fb923c;--glow:192,132,252;--glow2:244,114,182;--on:#fff;
  --b1:#7c3aed;--b2:#db2777;--b3:#0284c7;--grad:linear-gradient(120deg,var(--a1),var(--a2) 55%,var(--a3));
  --bad:#fb5876;--ok:#34d399;--warn:#fbbf24;--r:14px;--sh:0 18px 50px -18px rgba(0,0,0,.8);
  --mono:ui-monospace,SFMono-Regular,"JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font:14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);
  -webkit-font-smoothing:antialiased;overflow:hidden}
:root[data-theme=ocean]{--a1:#67e8f9;--a2:#60a5fa;--a3:#818cf8;--glow:103,232,249;--glow2:96,165,250;--b1:#0e7490;--b2:#1d4ed8;--b3:#6d28d9}
:root[data-theme=neon]{--a1:#bef264;--a2:#22d3ee;--a3:#f0abfc;--glow:190,242,100;--glow2:34,211,238;--on:#0a0a0a;--b1:#4d7c0f;--b2:#0e7490;--b3:#a21caf}
:root[data-theme=ember]{--a1:#fb7185;--a2:#fb923c;--a3:#fde047;--glow:251,113,133;--glow2:251,146,60;--b1:#be123c;--b2:#c2410c;--b3:#7c2d12}
:root[data-theme=mono]{--a1:#fafafa;--a2:#d4d4d8;--a3:#a1a1aa;--glow:255,255,255;--glow2:212,212,216;--on:#09090b;--b1:#3f3f46;--b2:#27272a;--b3:#52525b}
#aurora{position:fixed;inset:0;z-index:-1;overflow:hidden;background:var(--bg);pointer-events:none}
#aurora i{position:absolute;border-radius:50%;filter:blur(100px);opacity:.42;animation:drift 28s ease-in-out infinite alternate;will-change:transform}
#aurora i:nth-child(1){width:62vw;height:62vw;left:-18vw;top:-30vw;background:var(--b1)}
#aurora i:nth-child(2){width:48vw;height:48vw;right:-16vw;top:6vh;background:var(--b2);animation-duration:34s;animation-delay:-9s}
#aurora i:nth-child(3){width:56vw;height:44vw;left:18vw;bottom:-32vw;background:var(--b3);animation-duration:40s;animation-delay:-17s}
@keyframes drift{50%{transform:translate(9vw,7vh) scale(1.15)}to{transform:translate(-7vw,11vh) scale(.92)}}
#aurora::after{content:"";position:absolute;inset:0;opacity:.09;mix-blend-mode:overlay;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
/* Text trimmed to its capitals, so it sits in the middle of a control beside its icon, whatever the font's metrics. */
.btn>span,.chip>span,.nav>span,.crumbs button,.pop button>span,.sec h2>span,.hero .kick,.qlab,.tagq,.badge{text-box:trim-both cap alphabetic}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer;border:0;background:none;padding:0}
a{color:inherit}
[hidden]{display:none!important}
.i{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.btn{display:inline-flex;align-items:center;gap:.5rem;height:38px;padding:0 14px;border-radius:10px;background:rgba(255,255,255,.06);
  border:1px solid var(--line);font-weight:500;transition:background .15s,border-color .15s,transform .1s;white-space:nowrap}
.btn:hover{background:rgba(255,255,255,.11);border-color:var(--line2)}
.btn:active{transform:scale(.97)}
.btn.pri{background:var(--grad);background-size:160% 100%;background-position:0 0;border-color:transparent;color:var(--on);font-weight:650;box-shadow:0 10px 30px -10px rgba(var(--glow),.75);transition:background-position .4s,box-shadow .3s,transform .1s}
.btn.pri:hover{background-position:100% 0;box-shadow:0 14px 36px -10px rgba(var(--glow2),.85)}
.btn.bad{color:var(--bad)}
.btn.badf{background:var(--bad);color:#fff;border-color:transparent}
.btn.sm{height:30px;padding:0 10px;font-size:13px;border-radius:8px}
.ib{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;color:var(--mut);transition:background .15s,color .15s}
.ib:hover{background:rgba(255,255,255,.08);color:var(--fg)}
.ib.on{color:var(--fg);background:rgba(255,255,255,.1)}
.inp{height:38px;padding:0 12px;border-radius:10px;background:rgba(255,255,255,.05);border:1px solid var(--line);outline:none;transition:border-color .15s,background .15s}
.inp:focus{border-color:rgba(var(--glow),.7);background:rgba(255,255,255,.07)}
.mut{color:var(--mut)}.dim{color:var(--dim)}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:10px;border:2px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background-color:rgba(255,255,255,.22)}::-webkit-scrollbar-corner{background:transparent}

/* sign in */
#login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:16px;overflow:hidden}
#login .orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:.55;animation:float 18s ease-in-out infinite alternate}
#login .o1{width:520px;height:520px;background:var(--b1);left:-120px;top:-140px}
#login .o2{width:460px;height:460px;background:var(--b2);right:-120px;bottom:-160px;animation-delay:-6s}
#login .o3{width:300px;height:300px;background:var(--b3);left:55%;top:20%;animation-delay:-11s;opacity:.35}
@keyframes float{to{transform:translate(60px,40px) scale(1.15)}}
.lcard{position:relative;width:100%;max-width:400px;padding:36px 32px 30px;border-radius:22px;background:rgba(14,16,24,.72);
  border:1px solid var(--line2);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);box-shadow:var(--sh)}
.lcard h1{margin:18px 0 4px;font-size:26px;letter-spacing:-.02em}
.lcard p{margin:0 0 22px}
.lcard label{display:block;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:14px 0 6px}
.lcard .inp{width:100%;height:44px}
.lcard .btn.pri{width:100%;justify-content:center;height:46px;margin-top:22px;font-size:15px}
.chk{display:flex!important;align-items:center;gap:.5rem;text-transform:none!important;letter-spacing:0!important;font-weight:400!important;cursor:pointer}
.err{color:var(--bad);min-height:1.3em;margin-top:10px;font-size:13px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;letter-spacing:-.01em}
.logo .mk{width:34px;height:34px;border-radius:10px;background:var(--grad);display:flex;align-items:center;justify-content:center;box-shadow:0 6px 20px -6px rgba(var(--glow),.9)}
.logo .mk svg{width:20px;height:20px;stroke:var(--on);fill:none;stroke-width:2.2}

/* shell */
#app{display:flex;height:100%}
#side{width:248px;flex:none;display:flex;flex-direction:column;padding:18px 12px;background:rgba(9,8,16,.5);border-right:1px solid var(--line);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);z-index:15}
#side .logo{padding:2px 8px 18px}
#side>*:not(#libs){flex-shrink:0}
.nav{display:flex;align-items:center;gap:12px;width:100%;padding:9px 12px;border-radius:10px;color:var(--mut);font-weight:500;text-align:left;transition:background .15s,color .15s}
.nav:hover{background:rgba(255,255,255,.05);color:var(--fg)}
.nav.on{background:linear-gradient(90deg,rgba(var(--glow),.24),rgba(var(--glow2),.05));color:#fff;box-shadow:inset 3px 0 0 var(--a1),0 8px 24px -14px rgba(var(--glow),.8)}
.nav.on .i{color:var(--a1)}
.nav .dot{width:10px;height:10px;border-radius:3px;flex:none}
.nav span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-bottom:.3em;margin-bottom:-.3em}
.sh{font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--dim);padding:18px 12px 6px}
#libs{overflow:auto;flex:1;min-height:0}
#main{flex:1;min-width:0;display:flex;flex-direction:column;position:relative}
#top{display:flex;align-items:center;gap:10px;padding:12px 24px;border-bottom:1px solid var(--line);background:rgba(8,7,14,.38);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);z-index:10;min-height:64px}
#menuB{display:none}
.crumbs{display:flex;align-items:center;gap:2px;min-width:0;flex:1;overflow:hidden;white-space:nowrap}
.crumbs button{padding:6px 8px;border-radius:8px;color:var(--mut);font-weight:500;overflow:hidden;text-overflow:ellipsis;max-width:220px}
.crumbs button:hover{background:rgba(255,255,255,.06);color:var(--fg)}
.crumbs button:last-child{color:var(--fg);font-weight:600}
.crumbs .i{width:15px;height:15px;color:var(--dim)}
.search{position:relative}
.search .i{position:absolute;left:11px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:var(--dim);pointer-events:none}
.search .inp{padding-left:36px;width:220px}
#scroll{flex:1;overflow:auto;position:relative}
#content{padding:0 24px 120px}
.seg{display:flex;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:10px;padding:2px}
.seg .ib{width:34px;height:32px;border-radius:8px}
select.inp{padding-right:34px;appearance:none;-webkit-appearance:none;cursor:pointer;line-height:36px;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%239aa2b8' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m7 10 5 5 5-5'/%3E%3C/svg%3E");
  background-position:right 10px center;background-size:16px 16px;background-repeat:no-repeat}
select.inp option{background:#151821}

/* hero */
.hero{position:relative;margin:0 -24px 8px;padding:56px 24px 30px;overflow:hidden;min-height:210px;display:flex;flex-direction:column;justify-content:flex-end}
.hero .bd{position:absolute;inset:-40px;background-size:cover;background-position:center;filter:blur(38px) saturate(1.3);opacity:0;transform:scale(1.1);transition:opacity 1s}
.hero .bd.on{opacity:.6}
.hero::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(7,8,12,.1) 0%,rgba(7,8,12,.4) 55%,transparent 100%);pointer-events:none}
.hero .bd{-webkit-mask-image:linear-gradient(#000 30%,transparent 76%);mask-image:linear-gradient(#000 30%,transparent 76%)}
.hero>*:not(.bd){position:relative;z-index:1}
.hero .kick{font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--mut)}
.hero h1{margin:8px 0 12px;font-size:clamp(32px,5vw,60px);line-height:1.02;letter-spacing:-.04em;font-weight:900;word-break:break-word}
.grad-t{background:linear-gradient(100deg,var(--a1),var(--a2),var(--a3),var(--a1));background-size:300% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:flow 8s linear infinite}
@keyframes flow{to{background-position:300% 0}}
.hero .kick{color:var(--a1);opacity:.9}
.hero .stats{display:flex;gap:8px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;background:rgba(255,255,255,.08);border:1px solid var(--line);font-size:12.5px;color:#d5d9e6}
.chip .i{width:14px;height:14px}
.hero .acts{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}

/* sections and cards */
.sec{margin-top:26px}
.sec h2{display:flex;align-items:center;gap:12px;font-size:21px;font-weight:800;letter-spacing:-.02em;margin:0 0 16px}
.sec h2 .hb{width:34px;height:34px;border-radius:11px;display:flex;align-items:center;justify-content:center;background:var(--grad);color:var(--on);box-shadow:0 8px 22px -10px rgba(var(--glow),.9)}
.sec h2 .hb .i{width:18px;height:18px;stroke-width:2.1}
.sec h2 .n{font-size:12px;font-weight:600;color:var(--mut);background:rgba(255,255,255,.07);padding:2px 8px;border-radius:999px}
.grid{display:grid;gap:18px 16px;grid-template-columns:repeat(auto-fill,minmax(var(--w,180px),1fr))}
.grid.vid{--w:260px}.grid.pic{--w:170px}.grid.fold{--w:200px}.grid.aud{--w:170px}.grid.doc{--w:160px}.grid.lib{--w:280px}
.card{position:relative;cursor:pointer;border-radius:var(--r);outline:none;min-width:0}
.card .cv{position:relative;border-radius:var(--r);overflow:hidden;background:var(--card2);aspect-ratio:1;display:flex;align-items:center;justify-content:center;
  border:1px solid var(--line);transition:transform .25s cubic-bezier(.2,.8,.2,1),box-shadow .25s,border-color .25s}
.vid .card .cv{aspect-ratio:16/9}.doc .card .cv{aspect-ratio:4/5}.lib .card .cv{aspect-ratio:16/8}
.card:hover .cv,.card:focus-visible .cv{transform:perspective(900px) rotateX(var(--rx,0deg)) rotateY(var(--ry,0deg)) translateY(-6px) scale(1.03);
  box-shadow:0 30px 50px -22px rgba(0,0,0,.95),0 18px 50px -20px rgba(var(--glow),.55);border-color:transparent}
.cv .ring{position:absolute;inset:0;border-radius:inherit;padding:2px;background:var(--grad);z-index:5;pointer-events:none;opacity:0;transition:opacity .25s;
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0)}
.cv .shine{position:absolute;inset:0;z-index:3;pointer-events:none;opacity:0;transition:opacity .25s;background:radial-gradient(420px circle at var(--mx,50%) var(--my,50%),rgba(255,255,255,.2),transparent 45%)}
.card:hover .ring,.card:focus-visible .ring,.card:hover .shine{opacity:1}
.cv img.cov{z-index:0}
.lib .card .cv.covered .big{opacity:0}
.lib .card .cv.covered::after{background:linear-gradient(180deg,rgba(0,0,0,.05) 20%,rgba(0,0,0,.75))}
.fold .card .cv.covered img.cov{opacity:.38;filter:saturate(1.2)}
.fold .card .cv.covered::after{display:block;background:linear-gradient(90deg,rgba(10,10,18,.85) 25%,rgba(10,10,18,.2))}
.fold .card .cv .fi,.fold .card .cv .fn{position:relative;z-index:2}
.dropin .cv,.dropin td,button.dropin{outline:2px dashed var(--a1);outline-offset:3px;background:rgba(var(--glow),.12)}
.card.sel .cv{box-shadow:0 0 0 3px var(--a1),0 18px 50px -20px rgba(var(--glow),.6);border-color:transparent}
.cv img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .4s}
.cv img.on{opacity:1}
.cv .ph{width:42%;height:42%;color:rgba(255,255,255,.5);stroke-width:1.3}
.cv::after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 55%,rgba(0,0,0,.55));opacity:.8;pointer-events:none}
.card .ct{margin-top:9px;font-weight:600;font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card .cs{font-size:12px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{position:absolute;right:8px;bottom:8px;z-index:2;font-size:11.5px;font-weight:600;padding:2px 7px;border-radius:6px;background:rgba(0,0,0,.65);backdrop-filter:blur(6px)}
.tagq{position:absolute;left:8px;bottom:8px;z-index:2;font-size:10.5px;font-weight:800;letter-spacing:.04em;padding:2px 6px;border-radius:5px;background:rgba(255,255,255,.88);color:#000}
.tagq.hdr{left:auto;right:auto;margin-left:38px;background:linear-gradient(90deg,#f59e0b,#ef4444);color:#fff}
.pbar{position:absolute;left:0;right:0;bottom:0;height:4px;background:rgba(255,255,255,.15);z-index:3}
.pbar i{display:block;height:100%;background:var(--grad)}
.playo{position:absolute;z-index:2;width:56px;height:56px;border-radius:50%;background:rgba(255,255,255,.18);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  display:flex;align-items:center;justify-content:center;opacity:0;transform:scale(.8);transition:opacity .2s,transform .2s;border:1px solid rgba(255,255,255,.3)}
.playo .i{width:24px;height:24px;margin-left:3px;fill:#fff;stroke:none}
.card:hover .playo{opacity:1;transform:scale(1)}
.cb,.cm{position:absolute;top:8px;z-index:4;width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;
  background:rgba(10,12,18,.7);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.18);opacity:0;transition:opacity .15s,background .15s;color:#fff}
.cb{left:8px}.cm{right:8px}
.cb .i,.cm .i{width:16px;height:16px}
.cb .i{opacity:0}
.card:hover .cb,.card:hover .cm,.selecting .cb,.card.sel .cb{opacity:1}
.card.sel .cb{background:var(--a1);border-color:transparent}.card.sel .cb .i{opacity:1}
.fold .card .cv{aspect-ratio:auto;height:72px;justify-content:flex-start;padding:0 16px;gap:14px;background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(255,255,255,.02))}
.fold .card .cv::after{display:none}
.fold .card .fi{width:40px;height:40px;border-radius:11px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,rgba(var(--glow),.35),rgba(var(--glow2),.25));flex:none}
.fold .card .fi .i{width:22px;height:22px;color:#fff}
.fold .card .fn{min-width:0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:26px}
.fold .card .cb{top:22px;left:auto;right:42px}.fold .card .cm{top:22px}
.lib .card .cv{justify-content:flex-start;align-items:flex-end;padding:18px}
.lib .card .cv::after{background:linear-gradient(180deg,transparent 30%,rgba(0,0,0,.55))}
.lib .card .ln{position:relative;z-index:2;font-size:26px;font-weight:900;letter-spacing:-.03em;text-shadow:0 2px 14px rgba(0,0,0,.5)}
.lib .card .cv{background-size:200% 200%!important;animation:flow2 12s ease-in-out infinite alternate}
@keyframes flow2{to{background-position:100% 100%}}
.lib .card .big{position:absolute;right:-18px;top:-18px;width:150px;height:150px;opacity:.18;stroke-width:1.1;color:#fff}
.ext{position:absolute;z-index:2;top:50%;left:50%;transform:translate(-50%,24px);font-size:11px;font-weight:800;letter-spacing:.08em;color:rgba(255,255,255,.65)}
.empty{text-align:center;padding:70px 20px;color:var(--mut)}
.empty .big{width:72px;height:72px;color:var(--dim);stroke-width:1.2}
.empty h3{color:var(--fg);margin:14px 0 6px;font-size:18px}

/* themes and sending */
.themes{display:flex;gap:8px;padding:10px 12px 4px}
.themes button{width:22px;height:22px;border-radius:50%;border:2px solid transparent;box-shadow:0 0 0 1px rgba(255,255,255,.15);transition:transform .15s}
.themes button:hover{transform:scale(1.15)}
.themes button.on{border-color:#fff}
.dz{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:30px 16px;border-radius:18px;cursor:pointer;text-align:center;
  border:2px dashed rgba(var(--glow),.45);background:radial-gradient(400px 160px at 50% 0%,rgba(var(--glow),.16),transparent),rgba(255,255,255,.03);transition:border-color .2s,background .2s}
.dz:hover,.dz.over{border-color:var(--a1);background:radial-gradient(400px 160px at 50% 0%,rgba(var(--glow),.28),transparent),rgba(255,255,255,.05)}
.dz .bub{width:62px;height:62px;border-radius:20px;display:flex;align-items:center;justify-content:center;background:var(--grad);color:var(--on);box-shadow:0 14px 36px -12px rgba(var(--glow),.9)}
.dz .bub .i{width:30px;height:30px}
.dz b{font-size:16px}
.sfl{display:flex;flex-direction:column;gap:6px;margin-top:12px;max-height:150px;overflow:auto}
.sfl div{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.05);font-size:13px}
.sfl div span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pills{display:flex;flex-wrap:wrap;gap:6px}
.pills button{height:32px;padding:0 12px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid var(--line);font-size:13px;font-weight:600;color:var(--mut)}
.pills button:hover{color:var(--fg);border-color:var(--line2)}
.pills button.on{background:var(--grad);color:var(--on);border-color:transparent;box-shadow:0 6px 18px -8px rgba(var(--glow),.9)}
.sres{text-align:center;padding:6px 0 4px}
.sres .bub{width:70px;height:70px;margin:4px auto 14px;border-radius:22px;display:flex;align-items:center;justify-content:center;background:var(--grad);color:var(--on);box-shadow:0 14px 40px -12px rgba(var(--glow),.9);animation:pop .35s}
.sres .bub .i{width:34px;height:34px}
.sres h4{margin:0 0 4px;font-size:19px}
.sbar{height:8px;border-radius:8px;background:rgba(255,255,255,.08);overflow:hidden;margin:14px 0 6px}
.sbar i{display:block;height:100%;width:0;background:var(--grad);transition:width .3s}
.fire{color:var(--a3)}

/* list */
.tbl{width:100%;border-collapse:separate;border-spacing:0;margin-top:18px}
.more-mark{grid-column:1/-1;height:1px}
.tbl th{font-size:11.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--dim);text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);position:sticky;top:0;background:linear-gradient(rgba(var(--glow),.07),rgba(var(--glow2),.04)),rgba(12,14,21,.6);backdrop-filter:blur(16px) saturate(1.4);-webkit-backdrop-filter:blur(16px) saturate(1.4);z-index:2}
.tbl thead th:first-child{border-top-left-radius:10px}.tbl thead th:last-child{border-top-right-radius:10px}
.tbl td{padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap;color:var(--mut)}
.tbl tr.r{cursor:pointer;transition:background .12s}
.tbl tr.r:hover td{background:rgba(255,255,255,.035)}
.tbl tr.sel td{background:rgba(var(--glow),.14)!important}
.tbl td.nm{width:100%;max-width:0;color:var(--fg);font-weight:500}
.tbl .nmw{display:flex;align-items:center;gap:12px;min-width:0}
.tbl .nmw span{overflow:hidden;text-overflow:ellipsis}
.tbl .th{position:relative;width:44px;height:44px;border-radius:9px;overflow:hidden;flex:none;display:flex;align-items:center;justify-content:center;background:var(--card2)}
.tbl .th img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .3s}.tbl .th img.on{opacity:1}
.tbl .th .i{width:20px;height:20px;color:var(--mut)}
.tbl td.ac{text-align:right;padding-right:6px}
.tbl td.ac .ib{width:32px;height:32px;opacity:0}
.tbl tr:hover td.ac .ib{opacity:1}

/* menus, dialogs, toasts */
.pop{position:fixed;z-index:80;min-width:210px;padding:6px;border-radius:12px;background:rgba(22,25,36,.96);border:1px solid var(--line2);box-shadow:var(--sh);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);animation:pop .14s ease-out}
@keyframes pop{from{opacity:0;transform:translateY(-4px) scale(.98)}}
.pop button{display:flex;align-items:center;gap:11px;width:100%;padding:8px 10px;border-radius:8px;text-align:left;color:#dfe3ee}
.pop button:hover{background:rgba(255,255,255,.08)}
.pop button.bad{color:var(--bad)}
.pop button .i{width:17px;height:17px;color:var(--mut)}
.pop button.bad .i{color:var(--bad)}
.pop button .k{margin-left:auto;font-size:11.5px;color:var(--dim)}
.pop hr{border:0;border-top:1px solid var(--line);margin:5px 4px}
.pop .hd{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);padding:6px 10px 4px}
.scrim{position:fixed;inset:0;z-index:60;background:rgba(3,4,8,.62);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:16px;animation:fade .18s}
@keyframes fade{from{opacity:0}}
.dlg{width:100%;max-width:520px;max-height:90vh;overflow:auto;border-radius:18px;background:#11141d;border:1px solid var(--line2);box-shadow:var(--sh);animation:rise .22s cubic-bezier(.2,.8,.2,1)}
.dlg.wide{max-width:860px}
@keyframes rise{from{opacity:0;transform:translateY(14px) scale(.98)}}
.dlg .dh{display:flex;align-items:center;gap:12px;padding:18px 20px 6px}
.dlg .dh h3{margin:0;font-size:18px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dlg .db{padding:8px 20px 6px}
.dlg .df{display:flex;justify-content:flex-end;gap:10px;padding:16px 20px 20px}
.dlg .db p{margin:4px 0 12px;color:var(--mut)}
.fld{display:flex;align-items:center;gap:12px;margin:10px 0}
.fld>label{width:140px;flex:none;color:var(--mut)}
.fld .inp{flex:1;min-width:0}
.lnk{display:flex;gap:8px;margin-top:12px}
.lnk .inp{flex:1;min-width:0;font-family:var(--mono);font-size:12.5px}
.mtbl{width:100%;border-collapse:collapse}
.mtbl td,.mtbl th{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
.mtbl th{color:var(--dim);font-size:11px;letter-spacing:.07em;text-transform:uppercase}
.mtbl td.w{width:100%;word-break:break-all}
.mtbl td.r{text-align:right;white-space:nowrap}
#toasts{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);z-index:95;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:11px 16px;border-radius:12px;background:rgba(24,28,40,.97);border:1px solid var(--line2);box-shadow:var(--sh);animation:rise .2s;max-width:min(560px,90vw);pointer-events:auto}
.toast .i{width:18px;height:18px}
.toast.ok .i{color:var(--ok)}.toast.bad .i{color:var(--bad)}
#selbar{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:40;display:flex;align-items:center;gap:6px;padding:8px 8px 8px 18px;border-radius:16px;
  background:rgba(22,25,36,.94);border:1px solid var(--line2);box-shadow:var(--sh);backdrop-filter:blur(20px);animation:rise .2s}
#selbar b{margin-right:10px;white-space:nowrap}
#drop{position:fixed;inset:12px;z-index:70;border-radius:24px;border:2px dashed rgba(var(--glow),.8);background:rgba(20,16,40,.72);backdrop-filter:blur(8px);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;font-size:22px;font-weight:700;pointer-events:none}
#drop .i{width:64px;height:64px;color:var(--a1);stroke-width:1.4}

/* uploads */
#ups{position:fixed;right:20px;bottom:20px;z-index:45;width:400px;max-width:calc(100vw - 32px);border-radius:16px;background:rgba(17,20,30,.96);border:1px solid var(--line2);
  box-shadow:var(--sh);backdrop-filter:blur(20px);overflow:hidden;animation:rise .2s}
#ups .uh{display:flex;align-items:center;gap:10px;padding:12px 10px 12px 16px;cursor:pointer}
#ups .uh .t{flex:1;min-width:0}
#ups .uh b{display:block;font-size:14px}
#ups .uh small{display:block;color:var(--mut);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#ups .ub{max-height:340px;overflow:auto;border-top:1px solid var(--line)}
#ups.min .ub{display:none}
#ups .tot{height:3px;background:rgba(255,255,255,.06)}#ups .tot i{display:block;height:100%;background:var(--grad);transition:width .3s}
.uj{padding:10px 14px 11px 16px;border-bottom:1px solid var(--line);display:grid;grid-template-columns:1fr auto auto;gap:2px 4px;align-items:center}
.uj:last-child{border-bottom:0}
.uj .n{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.uj .s{font-size:11.5px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;grid-column:1}
.uj .p{grid-column:1/-1;height:5px;border-radius:5px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:6px}
.uj .p i{display:block;height:100%;width:0;background:var(--grad);border-radius:5px;transition:width .25s}
.uj.done .p i{background:var(--ok)}.uj.err .p i{background:var(--bad)}
.uj .x{grid-row:1/3;grid-column:3;width:30px;height:30px}.uj .pz{grid-row:1/3;grid-column:2;width:30px;height:30px}
#ups .uh .btn{height:30px;padding:0 10px;font-size:12.5px}
.uj .pc{font-variant-numeric:tabular-nums}

/* overlays: theater, viewer, editor */
.ov{position:fixed;inset:0;z-index:50;background:#000;display:flex;flex-direction:column;animation:fade .2s}
.ovbar{position:absolute;left:0;right:0;top:0;z-index:5;display:flex;align-items:center;gap:12px;padding:16px 20px 40px;background:linear-gradient(180deg,rgba(0,0,0,.75),transparent);transition:opacity .3s}
.ovbar .tt{flex:1;min-width:0}
.ovbar .tt b{display:block;font-size:17px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-shadow:0 1px 8px rgba(0,0,0,.6)}
.ovbar .tt .chips{display:flex;gap:6px;margin-top:4px;flex-wrap:wrap}
.ovbar .ib{color:#fff}
.theater video{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;background:#000}
.theater video::cue{color:#fff;background:rgba(0,0,0,.55);font-family:Inter,system-ui,sans-serif;line-height:1.35;text-shadow:0 1px 3px rgba(0,0,0,.8)}
.theater.idle{cursor:none}
.theater.idle .ovbar,.theater.idle .ctl{opacity:0;pointer-events:none}
.ctl{position:absolute;left:0;right:0;bottom:0;z-index:5;padding:60px 22px 16px;background:linear-gradient(0deg,rgba(0,0,0,.85),rgba(0,0,0,.4) 60%,transparent);transition:opacity .3s}
.seek{position:relative;height:18px;cursor:pointer;display:flex;align-items:center;touch-action:none}
.seek .tr{position:relative;width:100%;height:4px;border-radius:4px;background:rgba(255,255,255,.2);transition:height .15s}
.seek:hover .tr,.seek.drag .tr{height:6px}
.seek .bf,.seek .pl{position:absolute;left:0;top:0;bottom:0;border-radius:4px}
.seek .bf{background:rgba(255,255,255,.3)}
.seek .pl{background:var(--grad)}
.seek .kn{position:absolute;top:50%;width:14px;height:14px;margin:-7px 0 0 -7px;border-radius:50%;background:#fff;box-shadow:0 0 0 4px rgba(var(--glow),.35);transform:scale(0);transition:transform .15s}
.seek:hover .kn,.seek.drag .kn{transform:scale(1)}
.seek .tip{position:absolute;bottom:22px;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;gap:5px;padding:3px 8px;border-radius:8px;background:rgba(0,0,0,.85);font-size:12px;font-weight:600;font-variant-numeric:tabular-nums;opacity:0;pointer-events:none;white-space:nowrap}
.seek .tip:has(.pv:not([hidden])){padding:5px 5px 6px}
.seek .tip .pv{border-radius:5px;background-repeat:no-repeat;background-color:#000}
.seek .tip small{font-weight:500;color:var(--mut);max-width:170px;overflow:hidden;text-overflow:ellipsis}
.seek .cm{position:absolute;top:0;bottom:0;width:3px;margin-left:-1.5px;background:rgba(0,0,0,.7)}
.skipb{position:absolute;right:28px;bottom:118px;z-index:6;padding:11px 20px;border-radius:12px;background:rgba(15,15,22,.82);border:1px solid var(--line2);color:#fff;font-weight:650;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);box-shadow:var(--sh);transition:background .15s}
.skipb:hover{background:rgba(var(--glow),.3)}
.seek:hover .tip,.seek.drag .tip{opacity:1}
.row2{display:flex;align-items:center;gap:4px;margin-top:8px}
.row2 .ib{color:#fff;width:42px;height:42px}
.row2 .ib .i{width:22px;height:22px}
.row2 .ib.pp .i{width:26px;height:26px;fill:#fff;stroke:none}
.row2 .tm{font-size:13.5px;font-variant-numeric:tabular-nums;margin-left:8px;color:#e5e7ef;white-space:nowrap}
.row2 .sp{flex:1}
.qlab{font-size:11px;font-weight:800;padding:2px 6px;border-radius:5px;background:rgba(255,255,255,.9);color:#000;margin-left:-6px;margin-right:4px;letter-spacing:.02em;pointer-events:none}
.vol{display:flex;align-items:center}
.vol input{width:0;opacity:0;transition:width .2s,opacity .2s;accent-color:var(--a1)}
.vol:hover input,.vol input:focus{width:90px;opacity:1}
.pmenu{position:absolute;right:20px;bottom:86px;z-index:8;min-width:250px;max-height:60vh;overflow:auto;padding:6px;border-radius:14px;background:rgba(18,20,28,.94);border:1px solid var(--line2);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:var(--sh);animation:pop .14s}
.pmenu .hd{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);padding:8px 10px 4px}
.pmenu button{display:flex;align-items:center;gap:10px;width:100%;padding:8px 10px;border-radius:8px;text-align:left}
.pmenu button:hover{background:rgba(255,255,255,.08)}
.pmenu button .ck{width:16px;height:16px;color:var(--a1);visibility:hidden}
.pmenu button.on .ck{visibility:visible}
.pmenu button small{margin-left:auto;color:var(--mut);font-size:12px}
.pmenu hr{border:0;border-top:1px solid var(--line);margin:5px 4px}
.spin{position:absolute;left:50%;top:50%;width:54px;height:54px;margin:-27px 0 0 -27px;border-radius:50%;border:3px solid rgba(255,255,255,.15);border-top-color:var(--a1);animation:rot .8s linear infinite;z-index:3;pointer-events:none}
@keyframes rot{to{transform:rotate(360deg)}}
.flash{position:absolute;left:50%;top:50%;width:84px;height:84px;margin:-42px 0 0 -42px;border-radius:50%;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:4;pointer-events:none;animation:flash .6s forwards}
.flash .i{width:38px;height:38px;fill:#fff;stroke:#fff}
@keyframes flash{from{opacity:1;transform:scale(.8)}to{opacity:0;transform:scale(1.3)}}
.osd{position:absolute;left:50%;top:18%;transform:translateX(-50%);z-index:6;padding:8px 16px;border-radius:10px;background:rgba(0,0,0,.7);font-weight:600;pointer-events:none;transition:opacity .3s}
.upnext{position:absolute;right:24px;bottom:110px;z-index:7;width:320px;padding:14px;border-radius:14px;background:rgba(18,20,28,.95);border:1px solid var(--line2);box-shadow:var(--sh);animation:rise .25s}
.upnext small{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.upnext b{display:block;margin:4px 0 12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.apb{display:flex;align-items:center;gap:8px;height:34px;padding:0 10px;border-radius:9px;color:var(--mut);font-size:12.5px;font-weight:600}
.apb:hover{background:rgba(255,255,255,.08);color:#fff}
.apb .sw{position:relative;width:28px;height:16px;border-radius:9px;background:rgba(255,255,255,.22);transition:background .15s}
.apb .sw::after{content:'';position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:#fff;transition:transform .15s}
.apb.on{color:#fff}.apb.on .sw{background:var(--grad)}.apb.on .sw::after{transform:translateX(12px)}
.theater ::cue{background:rgba(0,0,0,.6);font-size:1.15em}
.viewer .stage{flex:1;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative}
.viewer .stage img{max-width:100%;max-height:100%;object-fit:contain;transition:transform .2s;user-select:none}
.viewer .stage iframe{width:100%;height:100%;border:0;background:#fff}
.viewer .nav2{position:absolute;top:50%;z-index:4;width:52px;height:52px;margin-top:-26px;border-radius:50%;background:rgba(0,0,0,.45);color:#fff;display:flex;align-items:center;justify-content:center}
.viewer .nav2:hover{background:rgba(0,0,0,.7)}
.viewer .nav2.l{left:18px}.viewer .nav2.r{right:18px}
.viewer .stage .spin{position:absolute}
.viewer .info{position:absolute;left:50%;bottom:18px;transform:translateX(-50%);padding:6px 14px;border-radius:999px;background:rgba(0,0,0,.55);font-size:12.5px;color:#ddd;white-space:nowrap}
.fileinfo{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:20px;text-align:center}
.fileinfo .big{width:110px;height:110px;color:var(--dim);stroke-width:1.1}
.fileinfo h2{margin:6px 0 0;word-break:break-all}
.fileinfo .acts{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;justify-content:center}

/* editor */
.editor{background:#0b0d13}
.edh{display:flex;align-items:center;gap:8px;padding:10px 12px 10px 16px;border-bottom:1px solid var(--line);background:#0e1018}
.edh .nm{display:flex;align-items:center;gap:10px;flex:1;min-width:0;font-weight:600}
.edh .nm span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.edh .nm .dirty{width:9px;height:9px;border-radius:50%;background:var(--warn);flex:none}
.edb{flex:1;display:flex;min-height:0;position:relative}
.edpane{flex:1;display:flex;min-width:0;position:relative;overflow:hidden}
.gut{flex:none;min-width:56px;padding:14px 12px 14px 8px;text-align:right;color:#4a5168;font:13px/1.65 var(--mono);user-select:none;overflow:hidden;border-right:1px solid var(--line);background:#0b0d13}
.gut div{white-space:pre}
.codew{position:relative;flex:1;min-width:0}
.codew pre,.codew textarea{position:absolute;inset:0;margin:0;padding:14px 18px;border:0;font:13px/1.65 var(--mono);tab-size:4;-moz-tab-size:4;white-space:pre;overflow:auto;letter-spacing:0}
.codew pre{pointer-events:none;color:#d7dbe8;overflow:hidden}
.codew textarea{background:transparent;color:transparent;caret-color:var(--a1);resize:none;outline:none;-webkit-text-fill-color:transparent}
.codew textarea::selection{background:rgba(var(--glow),.35)}
.codew.wrap pre,.codew.wrap textarea{white-space:pre-wrap;overflow-wrap:anywhere;overflow-y:scroll}
.mdv{flex:1;min-width:0;overflow:auto;padding:20px 32px;border-left:1px solid var(--line);background:#0d0f16;line-height:1.7}
.mdv h1,.mdv h2,.mdv h3{letter-spacing:-.01em;line-height:1.25}
.mdv code{font-family:var(--mono);font-size:.9em;background:rgba(255,255,255,.07);padding:1px 5px;border-radius:5px}
.mdv pre{background:rgba(255,255,255,.05);padding:12px 14px;border-radius:10px;overflow:auto}
.mdv pre code{background:none;padding:0}
.mdv blockquote{margin:0;padding:2px 14px;border-left:3px solid var(--a1);color:var(--mut)}
.mdv a{color:var(--a1)}
.mdv img{max-width:100%}
.mdv hr{border:0;border-top:1px solid var(--line2)}
.edf{display:flex;align-items:center;gap:18px;padding:5px 16px;border-top:1px solid var(--line);background:#0e1018;font-size:12px;color:var(--mut)}
.edf .sp{flex:1}
.find{position:absolute;right:22px;top:10px;z-index:5;display:flex;gap:6px;align-items:center;padding:6px;border-radius:12px;background:#171a26;border:1px solid var(--line2);box-shadow:var(--sh)}
.find .inp{height:32px;width:200px;font-size:13px}
.find .c{font-size:12px;color:var(--mut);min-width:54px;text-align:center}
.t-kw{color:#c792ea}.t-str{color:#c3e88d}.t-num{color:#f78c6c}.t-com{color:#5f6a85;font-style:italic}.t-fn{color:#82aaff}.t-tag{color:#f07178}
.t-attr{color:#ffcb6b}.t-prop{color:#89ddff}.t-head{color:#82aaff;font-weight:700}.t-pre{color:#89ddff}.t-bold{font-weight:700;color:#fff}.t-link{color:#7fdbca}

/* audio bar */
#audio{position:fixed;left:0;right:0;bottom:0;z-index:42;display:flex;align-items:center;gap:16px;padding:10px 20px;background:rgba(12,14,22,.94);border-top:1px solid var(--line2);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);animation:rise .25s}
#audio .art{width:52px;height:52px;border-radius:10px;background:var(--grad);display:flex;align-items:center;justify-content:center;flex:none;box-shadow:0 8px 20px -8px rgba(var(--glow),.8)}
#audio .art .i{color:#fff;width:24px;height:24px}
#audio .art{position:relative;overflow:hidden}#audio .art img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.album{display:grid;grid-template-columns:200px 1fr;gap:28px;margin:34px 0;align-items:start}
.album .art{position:relative;aspect-ratio:1;border-radius:14px;overflow:hidden;background:linear-gradient(135deg,rgba(var(--glow),.28),rgba(var(--glow2),.12));display:flex;align-items:center;justify-content:center;box-shadow:var(--sh)}
.album .art img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.album .art .i{width:56px;height:56px;color:rgba(255,255,255,.6)}
.album .kick{font-size:11.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--a1)}
.album h2{margin:4px 0 2px;font-size:28px;line-height:1.15;font-weight:800;letter-spacing:-.01em}
.album .by{color:var(--mut);margin-bottom:14px}
.album .acts{display:flex;gap:8px;margin-bottom:12px}
.album .trk{display:flex;flex-direction:column}
.album .trow{display:grid;grid-template-columns:30px 1fr auto;align-items:center;gap:12px;padding:8px 10px;border-radius:10px;text-align:left;color:var(--fg);transition:background .12s}
.album .trow:hover{background:rgba(255,255,255,.05)}
.album .trow.on{background:rgba(var(--glow),.14)}.album .trow.on .n{color:var(--a1)}
.album .trow .n{color:var(--dim);font-variant-numeric:tabular-nums;text-align:right}
.album .trow .ti{display:flex;flex-direction:column;min-width:0}
.album .trow b{font-weight:550;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.album .trow small{color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.album .trow .du{color:var(--mut);font-variant-numeric:tabular-nums;font-size:13px}
@media (max-width:700px){.album{grid-template-columns:1fr;gap:16px}.album .art{max-width:200px}}
#audio .meta{width:220px;min-width:0}
#audio .meta b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#audio .meta small{color:var(--mut);font-size:12px}
#audio .mid{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;min-width:0}
#audio .btns{display:flex;align-items:center;gap:4px}
#audio .btns .ib.pp{width:42px;height:42px;background:#fff;color:#000;border-radius:50%}
#audio .btns .ib.pp .i{fill:#000;stroke:none}
#audio .sk{display:flex;align-items:center;gap:10px;width:100%;max-width:640px;font-size:12px;color:var(--mut);font-variant-numeric:tabular-nums}
#audio .sk .seek{flex:1}
body.audio #content{padding-bottom:200px}
body.audio #ups,body.audio #selbar{bottom:96px}

@media (max-width:900px){
  #side{position:fixed;left:0;top:0;bottom:0;transform:translateX(-100%);transition:transform .25s;box-shadow:var(--sh)}
  #side.open{transform:none}
  #menuB{display:inline-flex}
  #top{padding:10px 16px;flex-wrap:wrap}
  #top .crumbs{order:9;flex-basis:100%}
  #top #sort{margin-left:auto}
  .search .inp{width:150px}
  #content{padding:0 16px 120px}
  .hero{margin:0 -16px 8px;padding:40px 16px 22px}
  .grid.vid{--w:200px}.grid.pic,.grid.aud,.grid.doc{--w:130px}.grid.fold{--w:160px}.grid.lib{--w:220px}
  .tbl .hide{display:none}
  #audio .meta{width:auto;flex:1}#audio .mid .sk{display:none}
  .fld{flex-direction:column;align-items:stretch;gap:4px}.fld>label{width:auto}
}
@media (max-width:560px){
  .search{display:none}
  #top .btn span{display:none}
  .row2 .vol input{display:none}
}
</style>
</head>
<body>
<div id="aurora"><i></i><i></i><i></i></div>
<div id="login" hidden>
  <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
  <form class="lcard" id="lf">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>socketley</div>
    <h1>Welcome back</h1>
    <p class="mut">Sign in to your library.</p>
    <label for="lk">Access key</label><input class="inp" id="lk" autocomplete="username" required spellcheck="false">
    <label for="ls">Secret</label><input class="inp" id="ls" type="password" autocomplete="current-password" required>
    <label class="chk"><input type="checkbox" id="lr"> Stay signed in on this device</label>
    <div class="err" id="le"></div>
    <button class="btn pri">Sign in</button>
  </form>
</div>
<div id="app" hidden>
  <aside id="side">
    <div class="logo"><div class="mk"><svg viewBox="0 0 24 24"><path d="M7 5.5v13l11-6.5z"/></svg></div>socketley</div>
    <button class="nav" id="nHome"></button>
    <button class="nav" id="nLinks"></button>
    <div class="sh">Libraries</div>
    <div id="libs"></div>
    <button class="nav" id="nGit"></button>
    <button class="nav" id="nSend"></button>
    <button class="nav" id="nUse"></button>
    <div class="themes" id="themes"></div>
    <button class="nav" id="nOut"></button>
    <button class="nav" id="nAll"></button>
  </aside>
  <div id="main">
    <div id="top">
      <button class="ib" id="menuB"></button>
      <nav class="crumbs" id="crumbs"></nav>
      <div class="search" id="srch"><input class="inp" id="q" placeholder="Search" spellcheck="false"></div>
      <select class="inp" id="sort" title="Sort"><option value="name">Name</option><option value="date">Newest</option><option value="size">Largest</option></select>
      <div class="seg" id="vsw"></div>
      <button class="btn" id="bNew"></button>
      <button class="btn pri" id="bUp"></button>
    </div>
    <div id="scroll"><div id="content"></div></div>
  </div>
</div>
<input type="file" id="fi" multiple hidden>
<input type="file" id="fd" webkitdirectory multiple hidden>
<div id="toasts"></div>
<script>
'use strict';
// ─── helpers ────────────────────────────────────────────────────────────────
const $ = (s, r = document) => r.querySelector(s);
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
  wrap: '<path d="M4 6h16M4 12h13a3 3 0 0 1 0 6h-4m2-2-2 2 2 2M4 18h5"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>', clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  spark: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>', speed: '<path d="M12 13l4-4"/><path d="M4.5 18a9 9 0 1 1 15 0"/>',
  replace: '<path d="M4 7h11l-3-3M20 17H9l3 3"/>',
  send: '<path d="M21 3 10.5 13.5M21 3l-6.5 18-4-7.5L3 9.5z"/>',
  git: '<circle cx="6" cy="5.5" r="2.2"/><circle cx="6" cy="18.5" r="2.2"/><circle cx="18" cy="8.5" r="2.2"/><path d="M6 7.7v8.6M18 10.7c0 4-6 3.3-11 6.2"/>',
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

// ─── state ──────────────────────────────────────────────────────────────────
// Who is signed in, as /~ui/session says; the session itself is an HttpOnly cookie the page never sees.
let me = null;
let auth = false;
let path = [], items = [], buckets = [], shown = [], bucketsAt = 0;
let view = store.get('skl-view', 'grid'), sortBy = store.get('skl-sort', 'name'), query = '';
const sel = new Set(); let anchor = -1;

async function api(method, url, opt = {}) {
  const h = Object.assign({ 'X-Socketley-UI': '1' }, opt.headers || {});
  const r = await fetch(url, { method, headers: h, body: opt.body, signal: opt.signal, credentials: 'same-origin' });
  if (r.status === 401) { signedOut(); throw new Error('Your session ended: sign in again'); }
  return r;
}
async function must(r) { if (!r.ok) { let t = ''; try { t = (await r.text()).trim(); } catch (e) {} const m = /<Message>([^<]*)/.exec(t); throw new Error(m ? m[1] : t.slice(0, 200) || r.status + ' ' + r.statusText); } return r; }

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
const layers = [];
function modal(title, body, foot, wide) {
  const box = el('div', { class: 'dlg' + (wide ? ' wide' : ''), role: 'dialog' });
  const s = el('div', { class: 'scrim' }, box);
  const close = () => { s.remove(); const i = layers.indexOf(L); if (i >= 0) layers.splice(i, 1); if (L.onclose) L.onclose(); };
  const L = { close, esc: close, box };
  box.append(el('div', { class: 'dh' }, el('h3', { text: title }), ibtn('close', 'Close', close)), el('div', { class: 'db' }, body));
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
    const L = modal(title, [text ? el('p', { text }) : null, inp], [btn(null, 'Cancel', () => finish(null)), btn(null, ok, go, danger ? 'badf' : 'pri')]);
    L.onclose = () => { if (!done) { done = true; res(null); } };
    L.box.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
    if (inp) { inp.focus(); const dot = (value || '').lastIndexOf('.'); inp.setSelectionRange(0, dot > 0 ? dot : (value || '').length); }
    else setTimeout(() => L.box.querySelector('.df .btn:last-child').focus(), 0);
  });
}

// ─── signing in ─────────────────────────────────────────────────────────────
function signedOut() {
  auth = false; me = null;
  $('#app').hidden = true; $('#login').hidden = false;
  closeAudio();
  while (layers.length) layers[layers.length - 1].close();
}
async function signOut() {
  try { await fetch('/~ui/session', { method: 'DELETE', headers: { 'X-Socketley-UI': '1' } }); } catch (e) {}
  signedOut();
}
async function signOutAll() {
  if (!await ask({ title: 'Sign out everywhere?', text: 'Every browser and device signed in as you, this one too, has to sign in again. Drives and apps with your key go on.', ok: 'Sign out everywhere', danger: true })) return;
  let r;
  try { r = await api('POST', '/~ui/session?everywhere'); } catch (e) { fail(e); return; }
  if (r.status !== 204) { toast('Signing out everywhere failed: ' + r.status, 'bad'); return; }
  signedOut();
}
$('#lf').addEventListener('submit', async ev => {
  ev.preventDefault();
  // The credentials go to the server once, which answers with the session cookie; the page keeps neither.
  const basic = 'Basic ' + btoa(unescape(encodeURIComponent($('#lk').value.trim() + ':' + $('#ls').value)));
  let r;
  try { r = await fetch('/~ui/session' + ($('#lr').checked ? '?remember' : ''), { method: 'POST', headers: { 'Authorization': basic, 'X-Socketley-UI': '1' } }); }
  catch (e) { $('#le').textContent = 'The server cannot be reached.'; return; }
  if (r.status === 401) { $('#le').textContent = 'Those credentials are not known.'; return; }
  if (r.status === 429) { $('#le').textContent = 'Too many failed sign-ins from here; try again in ' + Math.ceil((+r.headers.get('Retry-After') || 900) / 60) + ' min.'; return; }
  if (!r.ok) { $('#le').textContent = 'Signing in failed: ' + r.status; return; }
  me = await r.json();
  $('#ls').value = '';
  $('#le').textContent = '';
  start();
});

// ─── navigation ─────────────────────────────────────────────────────────────
function go(p) { location.hash = '#/' + enc(p) + (p.length ? '/' : ''); }
function fromHash() { path = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(s => { try { return decodeURIComponent(s); } catch (e) { return s; } }); }
// A new place closes what was open over the old one, as the browser's back button is expected to.
window.addEventListener('hashchange', () => { if (!auth) return; while (layers.length) layers[layers.length - 1].close(); fromHash(); sel.clear(); query = ''; $('#q').value = ''; load(); $('#side').classList.remove('open'); });

// A folder's listing as the drive's compact JSON (?list), asked again with its ETag so a look that finds nothing new
// is a 304 and costs no body; the root of libraries is a PROPFIND.
const LISTED = new Map();
async function propfind(p) {
  if (p.length) {
    const url = dav(p, true) + '?list', was = LISTED.get(url);
    const r = await api('GET', url, { headers: was ? { 'If-None-Match': was.tag } : {} });
    if (r.status === 304 && was) return was.items;
    const j = await (await must(r)).json();
    const items = [];
    for (const n of j.d) items.push({ name: n, segs: [...p, n], dir: true, size: 0, type: '', mod: 0, kind: 'dir' });
    for (const [n, size, mod, type] of j.f) items.push({ name: n, segs: [...p, n], dir: false, size, type, mod, kind: kind(n, type) });
    const tag = r.headers.get('ETag');
    if (tag) { LISTED.set(url, { tag, items }); if (LISTED.size > 64) LISTED.delete(LISTED.keys().next().value); }
    return items;
  }
  const r = await must(await api('PROPFIND', dav(p, true), { headers: { Depth: '1' } }));
  const doc = new DOMParser().parseFromString(await r.text(), 'application/xml');
  const D = 'DAV:', out = [];
  const rs = doc.getElementsByTagNameNS(D, 'response');
  for (let i = 1; i < rs.length; i++) {
    const x = rs[i];
    const g = n => { const e = x.getElementsByTagNameNS(D, n)[0]; return e ? e.textContent : ''; };
    const href = g('href');
    const dir = x.getElementsByTagNameNS(D, 'collection').length > 0;
    const segs = href.replace(/^.*?\/~dav\//, '').split('/').filter(Boolean).map(s => { try { return decodeURIComponent(s); } catch (e) { return s; } });
    const it = { name: g('displayname') || segs[segs.length - 1], segs, dir, size: +g('getcontentlength') || 0, type: g('getcontenttype'), mod: g('getlastmodified') };
    it.kind = dir ? (segs.length === 1 ? 'bucket' : 'dir') : kind(it.name, it.type);
    out.push(it);
  }
  return out;
}
function sorted(list) {
  const by = { name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }), date: (a, b) => (new Date(b.mod) - new Date(a.mod)) || by.name(a, b), size: (a, b) => (b.size - a.size) || by.name(a, b) };
  return list.slice().sort((a, b) => (b.dir - a.dir) || by[sortBy](a, b));
}

function side() {
  const nav = (b, icon, label, on, fn) => { b.textContent = ''; b.append(ico(icon), el('span', { text: label })); b.classList.toggle('on', on); b.onclick = fn; };
  nav($('#nHome'), 'home', 'Home', !path.length, () => go([]));
  nav($('#nLinks'), 'link', 'Shared links', false, linksDlg);
  nav($('#nOut'), 'out', me && me.user ? 'Sign out · ' + (me.name || me.user) : 'Sign out', false, signOut);
  nav($('#nAll'), 'out', 'Sign out everywhere', false, signOutAll);
  $('#nAll').hidden = !(me && me.user);
  nav($('#nSend'), 'send', 'Send a file', false, () => sendDlg());
  nav($('#nUse'), 'bucket', 'Storage', false, usageDlg);
  nav($('#nGit'), 'git', 'Git', false, gitDlg);
  $('#nGit').hidden = !(me && me.user);
  paintThemes();
  const L = $('#libs'); L.textContent = '';
  for (const b of buckets) {
    const h = hue(b.name);
    L.append(el('button', { class: 'nav' + (path[0] === b.name ? ' on' : ''), onclick: () => go([b.name]) },
      el('span', { class: 'dot', style: 'background:linear-gradient(135deg,hsl(' + h + ' 75% 60%),hsl(' + (h + 50) + ' 75% 45%))' }), el('span', { text: b.name === tmpName() ? 'Temporary files' : b.name, title: b.name })));
  }
  if (!buckets.length) L.append(el('div', { class: 'dim', style: 'padding:6px 12px;font-size:13px', text: 'No libraries yet' }));
}
function crumbs() {
  const c = $('#crumbs'); c.textContent = '';
  c.append(el('button', { text: 'Home', onclick: () => go([]) }));
  path.forEach((s, i) => c.append(ico('chev'), el('button', { text: s, title: s, onclick: () => go(path.slice(0, i + 1)) })));
  // A breadcrumb above the folder open takes what is dropped on it, as a folder does.
  [...c.querySelectorAll('button')].forEach((b, i) => { if (i > 0 && i < path.length) dropTarget(b, path.slice(0, i)); });
  const nw = $('#bNew'); nw.textContent = ''; nw.append(ico('plus'), el('span', { text: 'New' }));
  const up = $('#bUp'); up.textContent = ''; up.append(ico('upload'), el('span', { text: 'Upload' }));
  up.hidden = !path.length;
  const v = $('#vsw'); v.textContent = '';
  v.append(ibtn('grid', 'Library view', () => setView('grid'), view === 'grid' ? 'on' : ''), ibtn('list', 'List view', () => setView('list'), view === 'list' ? 'on' : ''));
  $('#sort').value = sortBy;
}
function setView(v) { view = v; store.set('skl-view', v); crumbs(); render(); }
$('#sort').onchange = () => { sortBy = $('#sort').value; store.set('skl-sort', sortBy); render(); };
// The box filters the folder open at once, and from two characters on also asks every library, a moment after the
// last key.
let searchT = 0, found = null, foundFor = '';
$('#q').oninput = () => {
  query = $('#q').value.trim().toLowerCase();
  clearTimeout(searchT);
  if (query.length < 2) { found = null; render(); return; }
  render();
  const q = query;
  searchT = setTimeout(async () => {
    try {
      const r = await api('GET', '/~ui/search?q=' + encodeURIComponent(q));
      if (!r.ok || q !== query) return;
      found = await r.json(); foundFor = q;
      render();
    } catch (e) {}
  }, 300);
};
function searchSection() {
  if (!found || foundFor !== query || !query) return null;
  const here = path.join('/') + (path.length ? '/' : '');
  const list = found.results.filter(x => !(x.bucket + '/' + x.key).startsWith(here) || (x.bucket + '/' + x.key).slice(here.length).includes('/'));
  const T = el('table', { class: 'tbl' });
  const B = el('tbody');
  for (const x of list) {
    const segs = [x.bucket, ...x.key.split('/').filter(Boolean)];
    const it = { name: segs[segs.length - 1], segs, dir: !!x.dir, size: x.size || 0, type: x.type || '', mod: x.modified ? new Date(x.modified).toUTCString() : '' };
    it.kind = it.dir ? 'dir' : kind(it.name, it.type);
    const th = el('span', { class: 'th' }, ico(ICON[it.kind]));
    lazyThumb(th, it, 64);
    const tr = el('tr', { class: 'r' }, el('td', { class: 'nm' }, el('div', { class: 'nmw' }, th, el('span', { text: it.name + (it.dir ? '/' : '') }))),
      el('td', { class: 'hide', text: segs.slice(0, -1).join(' / ') }), el('td', { text: it.dir ? '' : human(it.size) }));
    tr.onclick = () => { if (it.dir) { go(it.segs); return; } const sibs = list.filter(y => !y.dir).map(y => { const sg = [y.bucket, ...y.key.split('/')]; return { name: sg[sg.length - 1], segs: sg, size: y.size, type: y.type, dir: false, kind: kind(sg[sg.length - 1], y.type) }; }); open(Object.assign(it, { _list: sibs })); };
    B.append(tr);
  }
  if (!list.length) B.append(el('tr', {}, el('td', { class: 'mut', text: 'Nothing elsewhere is called like that.' })));
  T.append(B);
  return el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico('search')), el('span', { text: 'In all libraries' }), el('span', { class: 'n', text: String(list.length) + (found.more ? '+' : '') })), T);
}
$('#menuB').append(ico('menu')); $('#menuB').onclick = () => $('#side').classList.toggle('open');
$('#srch').prepend(ico('search'));

let loadSeq = 0;
async function load(keepScroll) {
  const seq = ++loadSeq;
  crumbs();
  const C = $('#content');
  const top = $('#scroll').scrollTop;
  try {
    // The libraries are read again inside one as well, at most every half minute, so one another device made shows up.
    const stale = !buckets.length || Date.now() - bucketsAt > 30000;
    const [list, roots] = await Promise.all([propfind(path), path.length && !stale ? null : propfind([])]);
    if (path.length && stale) bucketsAt = Date.now();
    if (seq !== loadSeq) return;
    if (roots) buckets = roots.filter(b => b.dir);
    items = list;
    if (!path.length) buckets = list.filter(b => b.dir);
  } catch (e) {
    if (seq !== loadSeq) return;
    C.textContent = '';
    C.append(el('div', { class: 'empty' }, ico('info', 'big'), el('h3', { text: 'This place cannot be opened' }), el('div', { text: e.message })));
    side(); return;
  }
  for (const k of [...sel]) if (!items.some(it => keyOf(it) === k)) sel.delete(k);
  liveAt = Date.now();
  side(); render();
  if (keepScroll) fillTo(top);
  $('#scroll').scrollTop = keepScroll ? top : 0;
}
let reloadT = 0;
function reloadSoon() { clearTimeout(reloadT); reloadT = setTimeout(() => load(true), 400); }
// What another device or client changes in the folder open shows here within seconds: the folder is asked again
// every 5 s while the page is seen (30 s past 2000 entries, none while a viewer or dialog is open or items are
// dragged), and drawn anew only when what it holds changed.
const sig = list => list.map(it => it.name + '\u0001' + it.size + '\u0001' + it.mod + '\u0001' + it.dir).join('\u0002');
let liveT = 0, liveAt = 0, dragging = false;
document.addEventListener('dragstart', () => dragging = true); document.addEventListener('dragend', () => dragging = false);
async function liveCheck() {
  if (!auth || document.hidden || layers.length || dragging || openPop) return;
  if (Date.now() - liveAt < (items.length > 2000 ? 30000 : 5000)) return;
  liveAt = Date.now();
  const at = path.join('/');
  try {
    if (path.length && Date.now() - bucketsAt > 30000) {
      bucketsAt = Date.now();
      const roots = (await propfind([])).filter(b => b.dir);
      if (sig(roots) !== sig(buckets)) { buckets = roots; side(); }
    }
    const now = await propfind(path);
    if (path.join('/') !== at || sig(now) === sig(items)) return;
    items = now;
    if (!path.length) buckets = now.filter(b => b.dir);
    for (const k of [...sel]) if (!items.some(it => keyOf(it) === k)) sel.delete(k);
    const top = $('#scroll').scrollTop;
    side(); render(); fillTo(top);
    $('#scroll').scrollTop = top;
  } catch (e) {}
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) { liveAt = 0; liveCheck(); } });

// ─── thumbnails, media facts and watch progress ─────────────────────────────
const thumbQ = []; let thumbBusy = 0;
const io = 'IntersectionObserver' in window ? new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting) { io.unobserve(e.target); thumbQ.push(e.target); pump(); } }, { rootMargin: '300px' }) : null;
function pump() {
  while (thumbBusy < 4 && thumbQ.length) {
    const w = thumbQ.shift();
    if (!w.isConnected) continue;
    thumbBusy++;
    // Read with the session's cookie, and kept by the browser's cache under the ETag the server gives.
    const img = el('img', { alt: '', src: w.dataset.src, draggable: 'false', decoding: 'async' });
    const settle = ok => { if (ok) img.classList.add('on'); else img.remove(); thumbBusy--; pump(); };
    img.onload = () => settle(true); img.onerror = () => settle(false);
    w.append(img);
    if (w.dataset.info) facts(w);
  }
}
function lazyThumb(w, it, size) {
  if (it.kind !== 'image' && it.kind !== 'video') return w;
  w.dataset.src = '/~media/thumb-' + size + '/' + enc(it.segs);
  if (it.kind === 'video' && size >= 320) w.dataset.info = '/~media/info/' + enc(it.segs);
  io ? io.observe(w) : (thumbQ.push(w), pump());
  return w;
}
const infos = new Map();
function getInfo(url) {
  if (!infos.has(url)) infos.set(url, api('GET', url).then(r => r.ok ? r.json() : null).catch(() => null));
  return infos.get(url);
}
async function facts(w) {
  const m = await getInfo(w.dataset.info);
  if (!m || !w.isConnected) return;
  if (m.duration) w.append(el('span', { class: 'badge', text: clock(m.duration) }));
  const h = Math.min(m.width || 0, m.height || 0) ? Math.max(m.height, m.width * 9 / 16) : 0;
  const q = h >= 2000 ? '4K' : h >= 1400 ? '1440p' : h >= 1000 ? 'HD' : '';
  if (q) w.append(el('span', { class: 'tagq', text: q }));
  if (m.hdr) w.append(el('span', { class: 'tagq hdr', text: 'HDR' }));
}
// Where each film was left, the signed-in user's own, kept by the server so every device picks up where another
// stopped; read once at the start and after a film is closed, and kept as it plays.
const PROG = new Map();
async function loadProgress() {
  try {
    const r = await api('GET', '/~ui/progress');
    if (!r.ok) return;
    PROG.clear();
    for (const p of await r.json()) PROG.set(p.bucket + '/' + p.key, p);
  } catch (e) {}
}
// Positions an earlier version of the page kept in this browser go to the server once.
async function migratePositions() {
  const old = [];
  try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k.startsWith('skl-pos:')) old.push(k); } } catch (e) { return; }
  for (const k of old) {
    try {
      const v = JSON.parse(localStorage.getItem(k)), segs = k.slice(8).split('/');
      await api('POST', '/~ui/progress', { body: JSON.stringify({ bucket: segs[0], key: segs.slice(1).join('/'), t: v.t, d: v.d }) });
    } catch (e) {}
    store.del(k);
  }
}
function position(it) { return PROG.get(it.segs.join('/')) || null; }
let lastSaved = '';
function savePosition(it, t, d, force) {
  if (!d || !isFinite(d)) return;
  const k = it.segs.join('/');
  const gone = t < 10 || t > d - Math.min(20, d * 0.05);
  const was = PROG.get(k);
  if (gone) { if (!was) return; PROG.delete(k); }
  else PROG.set(k, { bucket: it.segs[0], key: it.segs.slice(1).join('/'), t, d, at: Date.now(), size: it.size, type: it.type || '' });
  // A position a few seconds from the last one kept is not sent again, unless the film is paused or closed.
  const sig = k + ':' + (gone ? -1 : Math.round(t / 10));
  if (!force && sig === lastSaved) return;
  lastSaved = sig;
  api('POST', '/~ui/progress', { body: JSON.stringify({ bucket: it.segs[0], key: it.segs.slice(1).join('/'), t: gone ? -1 : t, d }) }).catch(() => {});
}
function watching() {
  return [...PROG.values()].sort((a, b) => b.at - a.at).slice(0, 12).map(p => {
    const segs = [p.bucket, ...p.key.split('/')];
    return { name: segs[segs.length - 1], segs, size: p.size || 0, type: p.type, dir: false, kind: 'video', mod: '' };
  });
}

// ─── rendering ──────────────────────────────────────────────────────────────
function render() {
  const C = $('#content'); C.textContent = '';
  MORE.clear();
  closePop();
  const list = sorted(items.filter(it => !query || it.name.toLowerCase().includes(query)));
  shown = list;
  C.append(hero(list));
  if (!items.length) {
    C.append(el('div', { class: 'empty' }, ico(path.length ? 'upload' : 'bucket', 'big'),
      el('h3', { text: path.length ? 'Nothing here yet' : 'No libraries yet' }),
      el('div', { text: path.length ? 'Drop files or folders anywhere on this page, or use Upload.' : 'A library is a bucket: make one with New.' })));
  } else if (!list.length) C.append(el('div', { class: 'empty', style: 'padding:30px 20px' }, el('h3', { text: 'Nothing here is called like that' }), el('div', { text: query.length >= 2 ? 'Results from every library are below.' : 'Type another letter to search every library.' })));
  else if (view === 'list') C.append(table(list));
  if (query.length >= 2) { const f = searchSection(); if (f) C.append(f); }
  // The list holds the folder already; only what is not in it, the films being watched, is added below it.
  else if (view === 'list') {
    const cw = !path.length ? watching() : [];
    if (cw.length) C.append(section('Continue watching', 'vid', cw, it => videoCard(it, cw)));
  }
  else {
    if (!path.length) {
      const cw = watching();
      if (cw.length && !query) C.append(section('Continue watching', 'vid', cw, it => videoCard(it, cw)));
      C.append(section('Libraries', 'lib', list, libCard) || '');
    } else {
      const by = k => list.filter(it => it.kind === k);
      const vids = by('video'), pics = by('image'), auds = by('audio');
      const docs = list.filter(it => ['text', 'pdf'].includes(it.kind)), other = list.filter(it => ['archive', 'file'].includes(it.kind));
      C.append(...[section('Folders', 'fold', by('dir'), folderCard), ...videoSections(vids),
        ...pictureSections(pics), auds.length ? musicSections(auds) : null,
        section('Documents', 'doc', docs, it => fileCard(it)), section('Other files', 'doc', other, it => fileCard(it))].filter(Boolean));
    }
  }
  selbar();
}
function hero(list) {
  const h = el('div', { class: 'hero' });
  const bd = el('div', { class: 'bd' });
  h.append(bd);
  const count = k => items.filter(it => it.kind === k).length;
  if (!path.length) {
    const hr = new Date().getHours();
    h.append(el('div', { class: 'kick', text: 'socketley' }), el('h1', {}, el('span', { text: (hr < 5 ? 'Good night' : hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening') + ', ' }), el('span', { class: 'grad-t', text: 'welcome back' })),
      el('div', { class: 'stats' }, el('span', { class: 'chip' }, ico('bucket'), el('span', { text: buckets.length + (buckets.length === 1 ? ' library' : ' libraries') }))));
    h.append(el('div', { class: 'acts' }, btn('send', 'Send a file', () => sendDlg(), 'pri'), btn('plus', 'New library', newBucket), btn('link', 'Shared links', linksDlg)));
  } else {
    const total = items.reduce((s, it) => s + it.size, 0);
    const stats = el('div', { class: 'stats' });
    for (const [k, i, one, many] of [['dir', 'folder', 'folder', 'folders'], ['video', 'video', 'video', 'videos'], ['image', 'image', 'picture', 'pictures'], ['audio', 'music', 'track', 'tracks'], ['text', 'text', 'document', 'documents']]) {
      const n = count(k); if (n) stats.append(el('span', { class: 'chip' }, ico(i), el('span', { text: n + ' ' + (n === 1 ? one : many) })));
    }
    if (total) stats.append(el('span', { class: 'chip' }, el('span', { text: human(total) })));
    h.append(el('div', { class: 'kick', text: path.length === 1 ? 'Library' : path.slice(0, -1).join(' / ') }), el('h1', { text: path[path.length - 1] }), stats);
    const vids = sorted(items.filter(it => it.kind === 'video')), auds = sorted(items.filter(it => it.kind === 'audio'));
    const acts = el('div', { class: 'acts' });
    if (vids.length) acts.append(btn('play', 'Play', () => playVideo(vids[0], vids), 'pri'));
    if (auds.length) acts.append(btn('music', 'Play music', () => playAudio(auds[0], auds), vids.length ? '' : 'pri'));
    acts.append(btn('upload', 'Upload', upFiles, vids.length || auds.length ? '' : 'pri'), btn('send', 'Send', () => sendDlg()), btn('newfile', 'New text file', newText));
    if (items.length) acts.append(btn('archive', 'Download all', () => downloadZip([])));
    if (path.length) acts.append(btn('restore', 'Trash', trashDlg));
    // Sharing the library with other users, for whoever may change its policy.
    if (path.length === 1 && me && !me.anonymous) {
      const lib = path[0];
      api('GET', '/~ui/access?bucket=' + encodeURIComponent(lib)).then(r => { if (r.ok && acts.isConnected && path[0] === lib) acts.append(btn('users', 'Share library', () => accessDlg(lib))); }).catch(() => {});
    }
    h.append(acts);
    const cover = items.find(it => it.kind === 'video') || items.find(it => it.kind === 'image');
    if (cover) {
      const src = '/~media/thumb-1280/' + enc(cover.segs);
      const pre = new Image();
      pre.onload = () => { bd.style.backgroundImage = 'url("' + src + '")'; bd.classList.add('on'); };
      pre.src = src;
    }
  }
  return h;
}
const SECI = { vid: 'video', pic: 'image', aud: 'music', doc: 'text', fold: 'folder', lib: 'bucket' };
// ─── large folders ──────────────────────────────────────────────────────────
// A long list is drawn a few hundred at a time, the next part once the end of the last comes near the screen.
const MORE = new Set();
// Watched against the scrolling pane itself, so the margin reaches below what it shows.
let moreIo = null;
function moreWatch() { if (!moreIo && 'IntersectionObserver' in window) moreIo = new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting && e.target._more) e.target._more(); }, { root: $('#scroll'), rootMargin: '0px 0px 1500px 0px' }); return moreIo; }
function chunked(box, list, make, marker) {
  let at = 0;
  const mark = marker();
  const step = () => {
    const end = Math.min(list.length, at + (at ? 300 : 150));
    const frag = document.createDocumentFragment();
    for (; at < end; at++) frag.append(make(list[at]));
    mark.before(frag);
    if (at < list.length) return true;
    MORE.delete(step); if (moreIo) moreIo.unobserve(mark); mark.remove();
    return false;
  };
  box.append(mark);
  mark._more = step; MORE.add(step);
  if (step()) { if (moreWatch()) moreIo.observe(mark); else while (step()); }
}
// Enough drawn to scroll back to where the folder was, after it is drawn anew.
function fillTo(top) { const S = $('#scroll'); for (const f of MORE) while (S.scrollHeight < top + S.clientHeight * 2 && f()); }

function section(title, cls, list, make) {
  if (!list.length) return null;
  const g = el('div', { class: 'grid ' + cls });
  chunked(g, list, make, () => el('div', { class: 'more-mark' }));
  return el('section', { class: 'sec' }, el('h2', {}, el('span', { class: 'hb' }, ico(title === 'Continue watching' ? 'clock' : title === 'Other files' ? 'file' : SECI[cls])), el('span', { text: title }), el('span', { class: 'n', text: String(list.length) })), g);
}
function cardShell(it, cover, extra) {
  const k = keyOf(it);
  const c = el('div', { class: 'card' + (sel.has(k) ? ' sel' : ''), tabindex: '0', 'data-k': k }, cover, ...(extra || []));
  cover.append(el('span', { class: 'shine' }), el('span', { class: 'ring' }));
  // A tilt toward the pointer, and a light where it is.
  cover.addEventListener('pointermove', e => {
    if (e.pointerType !== 'mouse') return;
    const r = cover.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
    cover.style.setProperty('--ry', ((x - .5) * 9).toFixed(2) + 'deg'); cover.style.setProperty('--rx', ((.5 - y) * 9).toFixed(2) + 'deg');
    cover.style.setProperty('--mx', (x * 100).toFixed(1) + '%'); cover.style.setProperty('--my', (y * 100).toFixed(1) + '%');
  });
  cover.addEventListener('pointerleave', () => { cover.style.setProperty('--rx', '0deg'); cover.style.setProperty('--ry', '0deg'); });
  cover.append(el('button', { class: 'cb', title: 'Select', onclick: e => { e.stopPropagation(); toggleSel(it, e); } }, ico('check')),
    el('button', { class: 'cm', title: 'More', onclick: e => { e.stopPropagation(); if (!sel.has(k)) { sel.clear(); sel.add(k); paintSel(); } popup(e.currentTarget, actions()); } }, ico('more')));
  c.addEventListener('click', e => clickItem(it, e));
  c.addEventListener('keydown', e => { if (e.key === 'Enter') open(it); });
  c.addEventListener('contextmenu', e => ctxMenu(it, e));
  movable(c, it);
  return c;
}
// Items dragged onto a folder, a breadcrumb or a library move there, the selection with them when they are part of it.
const DRAG = 'application/x-socketley-items';
function movable(node, it) {
  if (it.kind === 'bucket') { dropTarget(node, it.segs); return; }
  node.draggable = true;
  node.addEventListener('dragstart', e => {
    const list = sel.has(keyOf(it)) ? selected() : [it];
    e.dataTransfer.setData(DRAG, JSON.stringify(list.map(x => ({ segs: x.segs, dir: x.dir, name: x.name }))));
    e.dataTransfer.effectAllowed = 'move';
  });
  if (it.dir) dropTarget(node, it.segs);
}
function dropTarget(node, segs) {
  node.addEventListener('dragover', e => { if (e.dataTransfer.types.includes(DRAG)) { e.preventDefault(); e.stopPropagation(); node.classList.add('dropin'); } });
  node.addEventListener('dragleave', () => node.classList.remove('dropin'));
  node.addEventListener('drop', e => {
    if (!e.dataTransfer.types.includes(DRAG)) return;
    e.preventDefault(); e.stopPropagation(); node.classList.remove('dropin');
    moveTo(JSON.parse(e.dataTransfer.getData(DRAG)), segs);
  });
}
async function moveTo(list, dest) {
  const go2 = list.filter(x => x.segs.slice(0, -1).join('/') !== dest.join('/') && !(x.dir && (dest.join('/') + '/').startsWith(x.segs.join('/') + '/')));
  if (!go2.length) return;
  let moved = 0; const errs = [];
  for (const x of go2) {
    try {
      await must(await api('MOVE', dav(x.segs, x.dir), { headers: { Destination: location.origin + dav([...dest, x.name], x.dir), Overwrite: 'F' } }));
      moved++;
    } catch (e) { errs.push(x.name + ': ' + e.message); }
  }
  sel.clear();
  if (moved) toast('Moved ' + (moved === 1 ? go2[0].name : moved + ' items') + ' to ' + (dest[dest.length - 1] || 'Home'));
  if (errs.length) toast(errs[0], 'bad', 7000);
  load(true);
}
// Episodes named S01E02 or 1x02: a season each, in their order, the rest of the films after them.
const EP = /(?:^|[^a-z0-9])s(\d{1,2})[ ._-]?e(\d{1,3})|(?:^|[^0-9])(\d{1,2})x(\d{2,3})(?:[^0-9]|$)/i;
function episodeOf(name) {
  const m = EP.exec(name);
  if (!m) return null;
  const season = +(m[1] || m[3]), ep = +(m[2] || m[4]);
  let title = name.replace(/\.[^.]+$/, '').slice(m.index + m[0].length).replace(/^[\s._-]+/, '').replace(/[._]/g, ' ').trim();
  title = title.replace(/\b(1080p|720p|2160p|480p|x264|x265|h264|h265|hevc|web[- ]?dl|webrip|bluray|hdr|10bit|aac|dts|ddp?5 1)\b.*$/i, '').trim();
  return { season, ep, title };
}
function videoSections(vids) {
  const eps = vids.map(it => [it, episodeOf(it.name)]).filter(([, e]) => e);
  if (eps.length < 2) return [section('Videos', 'vid', vids, it => videoCard(it, vids))];
  const seasons = new Map();
  for (const [it, e] of eps) { if (!seasons.has(e.season)) seasons.set(e.season, []); seasons.get(e.season).push([it, e]); }
  const order = [...seasons.keys()].sort((a, b) => a - b);
  // A film plays on into the next episode, across seasons.
  const all = order.flatMap(sn => seasons.get(sn).sort((a, b) => a[1].ep - b[1].ep).map(([it]) => it));
  for (const it of all) it._list = all;
  const out = order.map(sn => {
    const list = seasons.get(sn).map(([it]) => it);
    return section('Season ' + sn, 'vid', list, it => { const e = episodeOf(it.name); const c = videoCard(it, all); const t = c.querySelector('.ct'); t.textContent = 'E' + String(e.ep).padStart(2, '0') + (e.title ? ' · ' + e.title : ''); return c; });
  });
  const rest = vids.filter(it => !episodeOf(it.name));
  if (rest.length) out.push(section('Videos', 'vid', rest, it => videoCard(it, rest)));
  return out;
}
// Pictures in months of their dates, newest first, once there are many of them; a slideshow from the first.
// ─── music by album ─────────────────────────────────────────────────────────
// A song's tags come with its info, asked four at a time and kept for the page's life.
const TAGS = new Map(), tagQ = [];
let tagRun = 0;
function infoOf(it) {
  const k = keyOf(it) + '|' + it.mod;
  if (!TAGS.has(k)) TAGS.set(k, new Promise(res => {
    tagQ.push(async () => { try { const r = await api('GET', '/~media/info/' + enc(it.segs)); res(r.ok ? await r.json() : null); } catch (e) { res(null); } });
    pumpTags();
  }));
  return TAGS.get(k);
}
function pumpTags() { while (tagRun < 4 && tagQ.length) { const f = tagQ.shift(); tagRun++; f().finally(() => { tagRun--; pumpTags(); }); } }
// Songs as albums, an artist's in the order they came out, once their tags are read; those without an album after.
function musicSections(auds) {
  const wrap = el('div', { class: 'music' });
  wrap.append(section('Music', 'aud', auds, it => fileCard(it)));
  if (auds.length < 2) return wrap;
  Promise.all(auds.map(infoOf)).then(infos => {
    if (!wrap.isConnected) return;
    const albums = new Map(), loose = [];
    auds.forEach((it, i) => {
      const inf = infos[i], t = inf && inf.tags;
      it._tags = t || null; it._dur = inf ? inf.duration : 0;
      if (!t || !t.album) { loose.push(it); return; }
      const who = t.album_artist || t.artist || '', k = who.toLowerCase() + '\n' + t.album.toLowerCase();
      if (!albums.has(k)) albums.set(k, { album: t.album, artist: who, year: (t.date || '').slice(0, 4), list: [] });
      albums.get(k).list.push(it);
    });
    if (!albums.size) return;
    wrap.textContent = '';
    const cmp = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
    for (const a of [...albums.values()].sort((a, b) => cmp(a.artist, b.artist) || cmp(a.year, b.year) || cmp(a.album, b.album))) wrap.append(albumBlock(a));
    if (loose.length) wrap.append(section(albums.size ? 'Other music' : 'Music', 'aud', loose, it => fileCard(it)));
    paintPlaying();
  });
  return wrap;
}
function albumBlock(a) {
  const num = (x, k) => (x._tags && x._tags[k]) || 0;
  a.list.sort((x, y) => (num(x, 'disc') - num(y, 'disc')) || (num(x, 'track') - num(y, 'track')) || x.name.localeCompare(y.name, undefined, { numeric: true }));
  for (const it of a.list) it._list = a.list;
  const art = el('div', { class: 'art' }, ico('music'));
  const img = el('img', { alt: '', src: '/~media/thumb-320/' + enc(a.list[0].segs), draggable: 'false' });
  img.onerror = () => img.remove(); art.prepend(img);
  const rows = el('div', { class: 'trk' });
  a.list.forEach((it, i) => {
    const t = it._tags;
    const r = el('button', { class: 'trow', 'data-k': keyOf(it), onclick: () => playAudio(it, a.list) },
      el('span', { class: 'n', text: String(t.track || i + 1) }),
      el('span', { class: 'ti' }, el('b', { text: t.title || it.name.replace(/\.[^.]+$/, '') }), t.artist && t.artist !== a.artist ? el('small', { text: t.artist }) : null),
      el('span', { class: 'du', text: it._dur ? clock(it._dur) : '' }));
    r.addEventListener('contextmenu', e => ctxMenu(it, e));
    rows.append(r);
  });
  const total = a.list.reduce((s, x) => s + (x._dur || 0), 0);
  return el('section', { class: 'album' }, art, el('div', { class: 'ab' },
    el('div', { class: 'kick', text: 'Album' + (a.year ? ' · ' + a.year : '') }), el('h2', { text: a.album }),
    el('div', { class: 'by', text: [a.artist || 'Unknown artist', a.list.length + (a.list.length === 1 ? ' song' : ' songs'), total ? Math.round(total / 60) + ' min' : ''].filter(Boolean).join(' · ') }),
    el('div', { class: 'acts' }, btn('play', 'Play', () => playAudio(a.list[0], a.list), 'pri sm'),
      btn('shuffle', 'Shuffle', () => { const l = a.list.slice().sort(() => Math.random() - 0.5); playAudio(l[0], l); }, 'sm')),
    rows));
}
// The song playing marked in its album.
function paintPlaying() {
  const k = AU && AU.list[AU.i] ? keyOf(AU.list[AU.i]) : '';
  document.querySelectorAll('.album .trow').forEach(r => r.classList.toggle('on', r.dataset.k === k));
}

// When and where the photos of a folder were taken, from their EXIF, asked once a folder and its pictures.
const TAKEN = new Map();
function takenIn(segs, pics) {
  const k = segs.join('/') + '|' + pics.length + '|' + pics.reduce((m, x) => x.mod > m ? x.mod : m, '');
  if (!TAKEN.has(k)) TAKEN.set(k, api('GET', '/~ui/taken?bucket=' + encodeURIComponent(segs[0]) + '&prefix=' + encodeURIComponent(segs.slice(1).map(x => x + '/').join('')))
    .then(r => r.ok ? r.json() : { photos: [] }).then(j => new Map(j.photos.map(p => [p.key, p]))).catch(() => new Map()));
  return TAKEN.get(k);
}
// A picture's date: when it was taken, as the camera's clock said, else when it was stored.
const shotAt = it => it._exif && it._exif.taken ? new Date(it._exif.taken.slice(0, 19)) : it.mod ? new Date(it.mod) : null;
function pictureSections(pics) {
  const wrap = el('div', { class: 'pics' });
  const draw = () => { wrap.textContent = ''; wrap.append(...picturesByMonth(pics).filter(Boolean)); };
  draw();
  if (path.length && /\.(jpe?g|tiff?|dng|heic|heif|hif)$/im.test(pics.map(x => x.name).join('\n'))) takenIn(path, pics).then(m => {
    let any = false;
    for (const it of pics) { const e = m.get(it.segs.slice(1).join('/')) || null; any = any || !!e; it._exif = e; }
    if (any && wrap.isConnected) draw();
  });
  return [wrap];
}
function picturesByMonth(pics) {
  if (pics.length < 13 || sortBy !== 'date' && sortBy !== 'name') return [section('Pictures', 'pic', pics, it => fileCard(it))];
  const months = new Map();
  const ordered = pics.slice().sort((a, b) => ((shotAt(b) || 0) - (shotAt(a) || 0)) || a.name.localeCompare(b.name, undefined, { numeric: true }));
  // The viewer steps through them as they are shown.
  for (const it of ordered) it._list = ordered;
  for (const it of ordered) {
    const d = shotAt(it), k = d ? d.getFullYear() * 12 + d.getMonth() : -1;
    if (!months.has(k)) months.set(k, { label: d ? d.toLocaleDateString(undefined, { month: 'long', year: 'numeric' }) : 'Undated', list: [] });
    months.get(k).list.push(it);
  }
  return [...months.values()].map(m => section(m.label, 'pic', m.list, it => fileCard(it)));
}
// A folder's or a library's cover: a picture called folder, cover or poster in it, else its first picture or film,
// found by one listing when its card comes into view.
const covers = new Map();
const coverIo = 'IntersectionObserver' in window ? new IntersectionObserver(es => { for (const e of es) if (e.isIntersecting) { coverIo.unobserve(e.target); coverFor(e.target); } }, { rootMargin: '200px' }) : null;
function lazyCover(cv, it) { cv._it = it; coverIo ? coverIo.observe(cv) : coverFor(cv); }
async function coverFor(cv) {
  const it = cv._it, k = keyOf(it);
  if (!covers.has(k)) covers.set(k, propfind(it.segs).then(list => {
    const files = list.filter(x => !x.dir);
    const named = files.find(x => x.kind === 'image' && /^(folder|cover|poster)\.(jpe?g|png|webp)$/i.test(x.name));
    return named || files.find(x => x.kind === 'video') || files.find(x => x.kind === 'image') || null;
  }).catch(() => null));
  const c = await covers.get(k);
  if (!c || !cv.isConnected) return;
  const img = el('img', { alt: '', src: '/~media/thumb-' + (it.kind === 'bucket' ? 960 : 480) + '/' + enc(c.segs), draggable: 'false', class: 'cov' });
  img.onload = () => { img.classList.add('on'); cv.classList.add('covered'); };
  cv.prepend(img);
}
function libCard(it) {
  const h = hue(it.name);
  const cv = el('div', { class: 'cv', style: 'background:linear-gradient(135deg,hsl(' + h + ' 70% 42%),hsl(' + (h + 45) + ' 75% 24%) 70%)' }, ico('bucket', 'big'), el('span', { class: 'ln', text: it.name }));
  lazyCover(cv, it);
  return cardShell(it, cv);
}
function folderCard(it) {
  const cv = el('div', { class: 'cv' }, el('span', { class: 'fi' }, ico('folder')), el('span', { class: 'fn', text: it.name }));
  lazyCover(cv, it);
  return cardShell(it, cv);
}
function videoCard(it, list) {
  const cv = el('div', { class: 'cv' }, ico('video', 'ph'), el('span', { class: 'playo' }, ico('play')));
  lazyThumb(cv, it, 480);
  const p = position(it);
  if (p) cv.append(el('div', { class: 'pbar' }, el('i', { style: 'width:' + Math.round(100 * p.t / p.d) + '%' })));
  const c = cardShell(it, cv, [el('div', { class: 'ct', text: it.name.replace(/\.[^.]+$/, ''), title: it.name }),
    el('div', { class: 'cs', text: [p ? clock(p.d - p.t) + ' left' : '', it.size ? human(it.size) : '', when(it.mod)].filter(Boolean).join(' · ') })]);
  c._list = list;
  return c;
}
function fileCard(it) {
  const cv = el('div', { class: 'cv' }, ico(ICON[it.kind], 'ph'));
  if (it.kind === 'image') lazyThumb(cv, it, 320);
  else if (ext(it.name)) cv.append(el('span', { class: 'ext', text: ext(it.name).toUpperCase() }));
  if (it.kind === 'audio') cv.style.background = 'linear-gradient(135deg,hsl(' + hue(it.name) + ' 60% 32%),#151826)';
  return cardShell(it, cv, [el('div', { class: 'ct', text: it.name, title: it.name }), el('div', { class: 'cs', text: [human(it.size), when(it.mod)].filter(Boolean).join(' · ') })]);
}
function table(list) {
  const T = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', { text: 'Name' }), el('th', { class: 'hide', text: 'Kind' }), el('th', { text: 'Size' }), el('th', { class: 'hide', text: 'Modified' }), el('th'))));
  const B = el('tbody');
  chunked(B, list, listRow, () => el('tr', { class: 'more-mark' }));
  T.append(B);
  return T;
}
// A row of the list.
function listRow(it) {
  const k = keyOf(it);
  const th = el('span', { class: 'th' }, ico(ICON[it.kind]));
  lazyThumb(th, it, 64);
  const tr = el('tr', { class: 'r' + (sel.has(k) ? ' sel' : ''), 'data-k': k },
    el('td', { class: 'nm' }, el('div', { class: 'nmw' }, th, el('span', { text: it.name + (it.dir ? '/' : ''), title: it.name }))),
    el('td', { class: 'hide', text: it.kind === 'dir' ? 'Folder' : it.kind === 'bucket' ? 'Library' : (ext(it.name).toUpperCase() || it.kind) }),
    el('td', { text: it.dir ? '' : human(it.size) }),
    el('td', { class: 'hide', text: it.mod ? new Date(it.mod).toLocaleString() : '' }),
    el('td', { class: 'ac' }, ibtn('more', 'More', e => { e.stopPropagation(); if (!sel.has(k)) { sel.clear(); sel.add(k); paintSel(); } popup(e.currentTarget, actions()); })));
  tr.addEventListener('click', e => clickItem(it, e));
  tr.addEventListener('dblclick', () => open(it));
  tr.addEventListener('contextmenu', e => ctxMenu(it, e));
  movable(tr, it);
  return tr;
}

// ─── selection and actions ──────────────────────────────────────────────────
function paintSel() {
  document.querySelectorAll('[data-k]').forEach(n => n.classList.toggle('sel', sel.has(n.dataset.k)));
  $('#content').classList.toggle('selecting', sel.size > 0);
  selbar();
}
function toggleSel(it, e) {
  const k = keyOf(it), i = shown.indexOf(it);
  if (e && e.shiftKey && anchor >= 0) { const [a, b] = [Math.min(anchor, i), Math.max(anchor, i)]; for (let j = a; j <= b; j++) sel.add(keyOf(shown[j])); }
  else { sel.has(k) ? sel.delete(k) : sel.add(k); anchor = i; }
  paintSel();
}
function clickItem(it, e) {
  if (e.ctrlKey || e.metaKey || e.shiftKey || (sel.size && view === 'grid')) { toggleSel(it, e); return; }
  if (view === 'list' && !(e.target.closest && e.target.closest('.nmw'))) { sel.clear(); sel.add(keyOf(it)); anchor = shown.indexOf(it); paintSel(); return; }
  open(it);
}
function ctxMenu(it, e) {
  e.preventDefault();
  if (!sel.has(keyOf(it))) { sel.clear(); sel.add(keyOf(it)); anchor = shown.indexOf(it); paintSel(); }
  popup({ x: e.clientX, y: e.clientY }, actions());
}
const selected = () => shown.filter(it => sel.has(keyOf(it)));
function actions() {
  const s = selected(); if (!s.length) return [];
  const one = s.length === 1 ? s[0] : null, files = s.filter(it => !it.dir);
  return [
    one ? { icon: one.dir ? 'folder' : one.kind === 'video' || one.kind === 'audio' ? 'play' : 'eye', label: one.dir ? 'Open' : one.kind === 'video' || one.kind === 'audio' ? 'Play' : 'Open', fn: () => open(one) } : null,
    one && !one.dir && (one.kind === 'text' || one.kind === 'file') && one.size < 8e6 ? { icon: 'code', label: 'Edit as text', fn: () => editText(one) } : null,
    one && !one.dir ? { icon: 'download', label: 'Download', fn: () => download(files) } : null,
    !one || one.dir ? { icon: 'archive', label: one ? 'Download as ZIP' : 'Download ' + s.length + ' items as ZIP', fn: () => downloadZip(s) } : null,
    one && !one.dir && ext(one.name) === 'zip' ? { icon: 'archive', label: 'Unzip here', fn: () => unzip(one) } : null,
    one ? { icon: 'share', label: 'Share link…', fn: () => shareDlg(one) } : null,
    one && one.kind !== 'bucket' ? { icon: 'edit', label: 'Rename…', key: 'F2', fn: () => rename(one) } : null,
    s.every(x => x.kind !== 'bucket') ? { icon: 'copy', label: s.length > 1 ? 'Copy ' + s.length + ' items' : 'Copy', key: 'Ctrl+D', fn: () => duplicate(s) } : null,
    '-',
    { icon: 'trash', label: s.length > 1 ? 'Delete ' + s.length + ' items' : 'Delete', key: 'Del', bad: true, fn: () => remove(s) }
  ];
}
function selbar() {
  let b = $('#selbar');
  const s = selected();
  if (!s.length) { if (b) b.remove(); return; }
  if (!b) { b = el('div', { id: 'selbar' }); document.body.append(b); }
  b.textContent = '';
  const files = s.filter(it => !it.dir);
  b.append(el('b', { text: s.length + ' selected' }));
  if (s.length === 1 && !s[0].dir) b.append(btn('download', 'Download', () => download(files), 'sm'));
  else b.append(btn('archive', 'Download ZIP', () => downloadZip(s), 'sm'));
  if (s.length === 1) b.append(btn('share', 'Share', () => shareDlg(s[0]), 'sm'));
  b.append(btn('trash', 'Delete', () => remove(s), 'sm bad'), ibtn('close', 'Clear selection', () => { sel.clear(); paintSel(); }));
}
function open(it) {
  if (it.dir) return go(it.segs);
  const sibs = k => (it._list || shown).filter(x => x.kind === k);
  if (it.kind === 'video') return playVideo(it, sibs('video'));
  if (it.kind === 'audio') return playAudio(it, sibs('audio'));
  if (it.kind === 'image') return viewImage(it, sibs('image'));
  if (it.kind === 'text') return editText(it);
  if (it.kind === 'pdf') return viewPdf(it);
  fileInfo(it);
}
async function newBucket() {
  const n = await ask({ title: 'New library', text: 'A library is a bucket: lowercase letters, digits, dots and dashes, 3 to 63 of them.', input: 'my-films', ok: 'Create' });
  if (!n) return;
  try { await must(await api('MKCOL', dav([n], true))); buckets = []; go([n]); toast('Library ' + n + ' created'); } catch (e) { fail(e); }
}
async function newFolder() {
  if (!path.length) return newBucket();
  const n = await ask({ title: 'New folder', input: 'Folder name', ok: 'Create' });
  if (!n) return;
  try { await must(await api('MKCOL', dav([...path, n], true))); load(true); } catch (e) { fail(e); }
}
async function newText() {
  if (!path.length) return toast('Open a library first', 'bad');
  const n = await ask({ title: 'New text file', input: 'notes.md', value: 'untitled.md', ok: 'Create' });
  if (!n) return;
  if (items.some(it => it.name === n && !it.dir)) return toast(n + ' is already there', 'bad');
  editText({ name: n, segs: [...path, n], size: 0, dir: false, kind: 'text', fresh: true });
}
$('#bNew').onclick = e => popup(e.currentTarget, path.length ? [
  { icon: 'newfolder', label: 'Folder', fn: newFolder }, { icon: 'newfile', label: 'Text file', fn: newText }, '-',
  { icon: 'upload', label: 'Upload files', fn: upFiles }, { icon: 'folder', label: 'Upload a folder', fn: upFolder }
] : [{ icon: 'bucket', label: 'Library', fn: newBucket }]);
async function remove(list) {
  if (!list.length) return;
  const dirs = list.filter(it => it.dir).length;
  const what = list.length === 1 ? '“' + list[0].name + '”' + (list[0].dir ? ' and everything in it' : '') : list.length + ' items' + (dirs ? ', ' + dirs + ' of them folders with everything in them' : '');
  const ok = await ask({ title: 'Delete ' + (list.length === 1 ? list[0].name : list.length + ' items') + '?', text: 'This deletes ' + what + '. A library that keeps versions keeps deleted files in its Trash; any other deletion is final.', ok: 'Delete', danger: true });
  if (!ok) return;
  let done = 0; const errs = [];
  const t = list.length > 3 ? toast('Deleting…', 'info', 60000) : null;
  for (const it of list) {
    try { await must(await api('DELETE', dav(it.segs, it.dir))); done++; if (t) t.lastChild.textContent = 'Deleting… ' + done + ' / ' + list.length; }
    catch (e) { errs.push(it.name + ': ' + e.message); }
  }
  if (t) t.remove();
  sel.clear();
  if (done) toast(done === 1 ? 'Deleted ' + (list.length === 1 ? list[0].name : '1 item') : 'Deleted ' + done + ' items');
  if (errs.length) toast(errs[0] + (errs.length > 1 ? ' (and ' + (errs.length - 1) + ' more)' : ''), 'bad', 7000);
  if (!path.length) buckets = [];
  load(true);
}
// A copy beside the original, named as a file manager names one: “photo (1).jpg”, then “photo (2).jpg”.
function copyName(name, dir, n) {
  const dot = dir ? -1 : name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name, tail = dot > 0 ? name.slice(dot) : '';
  return stem.replace(/ \(\d+\)$/, '') + ' (' + n + ')' + tail;
}
async function duplicate(list) {
  if (!list.length) return;
  const t = list.length > 1 ? toast('Copying…', 'info', 600000) : null;
  let done = 0, last = ''; const errs = [];
  for (const it of list) {
    try {
      // The drive refuses to copy over a name that is taken, so the next number is tried until one is free.
      for (let n = 1; ; n++) {
        const name = copyName(it.name, it.dir, n);
        const r = await api('COPY', dav(it.segs, it.dir), { headers: { Destination: location.origin + dav([...it.segs.slice(0, -1), name], it.dir), Overwrite: 'F', Depth: 'infinity' } });
        if (r.status === 412 && n < 100) continue;
        await must(r); last = name; done++;
        break;
      }
      if (t) t.lastChild.textContent = 'Copying… ' + done + ' / ' + list.length;
    } catch (e) { errs.push(it.name + ': ' + e.message); }
  }
  if (t) t.remove();
  if (done) toast(done === 1 ? 'Copied as ' + last : 'Copied ' + done + ' items');
  if (errs.length) toast(errs[0] + (errs.length > 1 ? ' (and ' + (errs.length - 1) + ' more)' : ''), 'bad', 7000);
  sel.clear(); load(true);
}
// A ZIP is unpacked by the drive itself, into a folder beside it of its name, so none of it comes down and goes back up.
async function unzip(it) {
  const t = toast('Unzipping ' + it.name + '…', 'info', 3600000);
  try {
    const r = await api('POST', dav(it.segs) + '?unzip');
    // The answer tells what was made, and what was not, whether or not all of it went well.
    let j = null; try { j = await r.clone().json(); } catch (e) {}
    if (!j) await must(r);
    const folder = j.folder.replace(/\/$/, '').split('/').pop();
    if (j.files || !j.failed) toast('Unzipped ' + j.files + (j.files === 1 ? ' file' : ' files') + ' into ' + folder);
    const few = (n, names) => names.slice(0, 3).join(', ') + (n > 3 ? ', …' : '');
    if (j.failed) toast(j.failed + ' of its files could not be unpacked (' + few(j.failed, j.failed_names) + ')', 'bad', 8000);
    if (j.skipped) toast(j.skipped + ' not unpacked: encrypted, packed another way or named outside the folder (' + few(j.skipped, j.skipped_names) + ')', 'bad', 8000);
  } catch (e) { fail(e); } finally { t.remove(); }
  sel.clear(); load(true);
}
async function rename(it) {
  const n = await ask({ title: 'Rename', input: 'New name', value: it.name, ok: 'Rename' });
  if (!n || n === it.name) return;
  const dst = location.origin + dav([...it.segs.slice(0, -1), n], it.dir);
  try { await must(await api('MOVE', dav(it.segs, it.dir), { headers: { Destination: dst, Overwrite: 'F' } })); sel.clear(); load(true); toast('Renamed to ' + n); } catch (e) { fail(e); }
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { if (openPop) { closePop(); return; } if (layers.length) { layers[layers.length - 1].esc(); return; } if (sel.size) { sel.clear(); paintSel(); } return; }
  if (layers.length || !auth || $('#app').hidden || /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) return;
  if (e.key === 'Delete' && sel.size) { e.preventDefault(); remove(selected()); }
  else if (e.key === 'F2' && sel.size === 1) { e.preventDefault(); rename(selected()[0]); }
  else if ((e.ctrlKey || e.metaKey) && e.key === 'd' && sel.size) { e.preventDefault(); const s = selected(); if (s.every(x => x.kind !== 'bucket')) duplicate(s); }
  else if ((e.ctrlKey || e.metaKey) && e.key === 'a') { e.preventDefault(); shown.forEach(it => sel.add(keyOf(it))); paintSel(); }
  else if (e.key === '/') { e.preventDefault(); $('#q').focus(); }
  else if (e.key === 'Backspace' && path.length) { e.preventDefault(); go(path.slice(0, -1)); }
});
$('#scroll').addEventListener('click', e => { if (sel.size && (e.target.id === 'content' || e.target.classList.contains('grid') || e.target.classList.contains('hero'))) { sel.clear(); paintSel(); } });

// ─── links and downloads ────────────────────────────────────────────────────
// A download is the drive's GET with ?download, which the session's cookie signs and the server answers with the file
// under its name; a browser resuming it later sends the cookie again.
async function download(list) {
  for (const it of list) {
    const a = el('a', { href: '/~dav/' + enc(it.segs) + '?download', download: it.name, style: 'display:none' });
    document.body.append(a); a.click(); a.remove();
    await sleep(350);
  }
  if (list.length > 1) toast('Downloading ' + list.length + ' files');
}
// Several items, or a folder, as one ZIP the server streams; an empty list is the whole folder open.
function downloadZip(list) {
  const url = dav(path, true) + '?zip' + list.map(it => '&n=' + encodeURIComponent(it.name)).join('');
  const a = el('a', { href: list.length === 1 && list[0].dir ? dav(list[0].segs, true) + '?zip' : url, download: '', style: 'display:none' });
  document.body.append(a); a.click(); a.remove();
  toast('Preparing the ZIP: the download starts in a moment');
}
// A webhook a link tells of its downloads: Discord, Slack or ntfy, remembered in this browser for the next link.
function notifyField() {
  const n = el('input', { class: 'inp', type: 'url', placeholder: 'Optional: Discord, Slack or ntfy webhook', spellcheck: 'false', value: store.get('skl-notify', '') });
  const f = el('div', { class: 'fld' }, el('label', { text: 'Tell me on download' }), n);
  return { el: f, value: () => { const v = n.value.trim(); store.set('skl-notify', v); return v; } };
}
function shareDlg(it) {
  const exp = el('select', { class: 'inp' }, ...[['3600', '1 hour'], ['86400', '1 day'], ['604800', '7 days'], ['2592000', '30 days'], ['0', 'Never']].map(([v, t]) => el('option', { value: v, text: t })));
  exp.value = '604800';
  const pw = el('input', { class: 'inp', type: 'password', placeholder: 'None', autocomplete: 'new-password' });
  const max = el('input', { class: 'inp', type: 'number', min: '0', placeholder: 'Unlimited' });
  const up = el('input', { type: 'checkbox' });
  const out = el('div');
  let nf;
  const body = [el('p', { text: 'Anyone with the link can ' + (it.dir ? 'browse this folder' : 'download this file') + ' without signing in.' }),
    el('div', { class: 'fld' }, el('label', { text: 'Expires' }), exp), el('div', { class: 'fld' }, el('label', { text: 'Password' }), pw), (nf = notifyField()).el,
    it.dir ? el('div', { class: 'fld' }, el('label', { text: 'Others may upload' }), up) : el('div', { class: 'fld' }, el('label', { text: 'Download limit' }), max), out];
  const make = async () => {
    const key = it.segs.slice(1).join('/') + (it.dir && it.segs.length > 1 ? '/' : '');
    try {
      const r = await must(await api('POST', '/~share', { body: JSON.stringify({ bucket: it.segs[0], key, expires_in: +exp.value, password: pw.value, max_downloads: +max.value || 0, upload: up.checked, notify: nf.value() || undefined }) }));
      const url = location.origin + (await r.json()).url;
      const inp = el('input', { class: 'inp', value: url, readonly: '' });
      out.textContent = '';
      out.append(el('div', { class: 'lnk' }, inp, btn('link', 'Copy', () => copy(url, inp), 'pri')));
      copy(url, inp);
    } catch (e) { fail(e); }
  };
  modal('Share ' + it.name, body, [btn('link', 'Create link', make, 'pri')]);
}
function copy(text, inp) {
  const ok = () => toast('Link copied');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(ok, () => {});
  else if (inp) { inp.select(); try { document.execCommand('copy'); ok(); } catch (e) {} }
}
function linksDlg() {
  const T = el('table', { class: 'mtbl' });
  const L = modal('Shared links', T, null, true);
  const fill = async () => {
    T.textContent = '';
    T.append(el('tr', {}, el('th', { text: 'What' }), el('th', { text: 'Expires' }), el('th', { text: 'Reads' }), el('th')));
    let ls;
    try { ls = await (await must(await api('GET', '/~share'))).json(); } catch (e) { T.append(el('tr', {}, el('td', { text: e.message }))); return; }
    ls = ls.filter(s => s.note !== 'player');
    if (!ls.length) T.append(el('tr', {}, el('td', { class: 'mut', colspan: '4', text: 'No links yet. Share a file or a folder from its menu.' })));
    for (const s of ls) {
      const url = location.origin + s.url;
      T.append(el('tr', {},
        el('td', { class: 'w' }, el('a', { href: url, target: '_blank', rel: 'noopener', text: s.bucket + '/' + s.key }), el('span', { class: 'mut', text: (s.password ? ' · password' : '') + (s.upload ? ' · upload' : '') }), s.burn ? el('span', { class: 'fire', text: ' · deleted when it ends' }) : null, s.notify ? el('span', { class: 'mut', text: ' · tells a webhook' }) : null),
        el('td', { class: 'mut', text: s.expires ? new Date(s.expires).toLocaleString() : 'Never' }),
        el('td', { class: 'mut', text: s.downloads + (s.max_downloads ? ' / ' + s.max_downloads : '') }),
        el('td', { class: 'r' }, btn(null, 'Copy', () => copy(url), 'sm'), ' ', btn(null, 'Revoke', async () => { try { await must(await api('DELETE', '/~share/' + s.id)); fill(); } catch (e) { fail(e); } }, 'sm bad'))));
    }
  };
  fill();
  return L;
}
// Git repositories kept in a library: fetched every day, their branch's files under <name>/ and a bundle of their
// history under _backups/<name>/ whenever anything moved.
function gitDlg() {
  const box = el('div');
  const L = modal('Git', box, null, true);
  let timer = 0;
  L.onclose = () => clearTimeout(timer);
  const field = (label, input) => el('label', { style: 'display:flex;flex-direction:column;gap:4px;font-size:12.5px;flex:1;min-width:140px' }, el('span', { class: 'mut', text: label }), input);
  const url = el('input', { class: 'inp', placeholder: 'https://github.com/you/repo', spellcheck: 'false', autocomplete: 'off' });
  const branch = el('input', { class: 'inp', value: 'main', spellcheck: 'false', title: 'A branch, or * for every branch' });
  const lib = el('input', { class: 'inp', value: 'git', spellcheck: 'false' });
  const name = el('input', { class: 'inp', placeholder: 'from the URL', spellcheck: 'false' });
  const hour = el('select', { class: 'inp' }, ...Array.from({ length: 24 }, (_, h) => el('option', { value: String(h), text: String(h).padStart(2, '0') + ':00' })));
  hour.value = '3';
  const priv = el('input', { type: 'checkbox' });
  const add = async () => {
    const u = url.value.trim();
    if (!u) { url.focus(); return; }
    try {
      const r = await (await must(await api('POST', '/~ui/git', { body: JSON.stringify({ action: 'add', url: u, branch: branch.value.trim() || 'main', bucket: lib.value.trim() || 'git', name: name.value.trim(), private: priv.checked, hour: +hour.value }) }))).json();
      url.value = ''; name.value = '';
      toast(r.started ? 'Added; the first copy is being made' : 'Added, but not run: ' + r.why, r.started ? 'ok' : 'bad');
      fill();
    } catch (e) { fail(e); }
  };
  url.addEventListener('keydown', e => { if (e.key === 'Enter') add(); });
  const tok = el('input', { class: 'inp', type: 'password', placeholder: 'GitHub token (read access to contents)', autocomplete: 'off', style: 'flex:1' });
  const tokState = el('span', { class: 'mut', style: 'font-size:12.5px' });
  const setTok = async v => { try { await must(await api('POST', '/~ui/git', { body: JSON.stringify({ action: 'token', token: v }) })); tok.value = ''; toast(v ? 'Token kept' : 'Token removed'); fill(); } catch (e) { fail(e); } };
  const T = el('table', { class: 'mtbl' });
  const form = el('div', {},
    el('div', { style: 'display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end' }, field('Repository URL', url), field('Branch', branch), field('Library', lib), field('Folder', name), field('Daily at', hour)),
    el('div', { style: 'display:flex;gap:10px;align-items:center;margin:10px 0 18px' }, el('label', { class: 'chk' }, priv, ' Private (uses your GitHub token)'), el('span', { style: 'flex:1' }), btn('plus', 'Add repository', add, 'pri')));
  const acct = el('div', { style: 'margin-top:20px' }, el('h4', { text: 'Your GitHub token', style: 'margin:0 0 6px' }),
    el('p', { class: 'mut', style: 'font-size:12.5px;margin:0 0 8px', text: 'Only needed for private repositories. A fine-grained token with read access to their contents is enough. It is kept sealed with your own key and never shown again.' }),
    el('div', { style: 'display:flex;gap:8px;align-items:center' }, tok, btn(null, 'Save', () => tok.value.trim() && setTok(tok.value.trim()), 'sm'), btn(null, 'Remove', () => setTok(''), 'sm bad')), tokState);
  async function fill() {
    clearTimeout(timer);
    let g;
    try { g = await (await must(await api('GET', '/~ui/git'))).json(); } catch (e) { box.textContent = ''; box.append(el('p', { text: e.message })); return; }
    box.textContent = '';
    if (!g.available) { box.append(el('p', { text: 'Git is not available on this runtime: ' + g.why })); return; }
    tokState.textContent = g.token ? 'A token is set.' : 'No token set.';
    T.textContent = '';
    T.append(el('tr', {}, el('th', { text: 'Repository' }), el('th', { text: 'Branch' }), el('th', { text: 'Last run' }), el('th')));
    if (!g.repos.length) T.append(el('tr', {}, el('td', { class: 'mut', colspan: '4', text: 'No repositories yet. Add one above; it is copied now and then every day.' })));
    let busy = false;
    for (const r of g.repos) {
      busy = busy || r.running;
      const st = r.state;
      const last = r.running ? el('span', { text: 'running…' })
        : !st ? el('span', { class: 'mut', text: 'not yet' })
        : st.ok ? el('span', { title: st.commit || '', text: new Date(st.at * 1000).toLocaleString() + (st.commit ? ' · ' + st.commit.slice(0, 7) : '') + (st.changed ? ' · ' + st.files + ' file' + (st.files === 1 ? '' : 's') + ' written' : ' · unchanged') })
        : el('span', { class: 'fire', title: st.error || '', text: 'failed ' + new Date(st.at * 1000).toLocaleString() + ': ' + (st.error || 'see the log') });
      T.append(el('tr', {},
        el('td', { class: 'w' }, el('a', { href: '#', text: r.bucket + '/' + r.name, onclick: e => { e.preventDefault(); L.close(); go([r.bucket, r.name]); } }),
          el('div', { class: 'mut', style: 'font-size:12px;word-break:break-all', text: r.url + (r.private ? ' · private' : '') + (g.repos.some(x => x.owner !== r.owner) ? ' · ' + r.owner : '') + ' · daily at ' + String(r.hour).padStart(2, '0') + ':00' })),
        el('td', { class: 'mut', text: r.branch === '*' ? 'all' : r.branch }),
        el('td', { style: 'font-size:12.5px' }, last),
        el('td', { class: 'r', style: 'white-space:nowrap' },
          btn(null, 'Sync now', async () => { try { await must(await api('POST', '/~ui/git', { body: JSON.stringify({ action: 'sync', id: r.id }) })); toast('Running'); setTimeout(fill, 600); } catch (e) { fail(e); } }, 'sm'), ' ',
          btn(null, 'Backups', () => { L.close(); go([r.bucket, '_backups', r.name]); }, 'sm'), ' ',
          btn(null, 'Remove', async () => {
            if (!await ask({ title: 'Remove ' + r.name + '?', text: 'It is no longer fetched. Its files and backups stay in ' + r.bucket + ' until you delete them.', ok: 'Remove', danger: true })) return;
            try { await must(await api('POST', '/~ui/git', { body: JSON.stringify({ action: 'remove', id: r.id }) })); fill(); } catch (e) { fail(e); }
          }, 'sm bad'))));
    }
    box.append(form, T, acct);
    if (busy) timer = setTimeout(fill, 3000);
  }
  fill();
  return L;
}
// Who else may read or write a library, each a statement of its bucket's policy the server writes.
function accessDlg(lib) {
  const T = el('table', { class: 'mtbl' });
  const who = el('input', { class: 'inp', placeholder: 'User id, as in the credentials', spellcheck: 'false', autocomplete: 'off' });
  const lvl = el('select', { class: 'inp', style: 'flex:none;width:auto' }, el('option', { value: 'read', text: 'Can view' }), el('option', { value: 'write', text: 'Can edit' }));
  const set = async (user, access) => {
    try { await must(await api('POST', '/~ui/access', { body: JSON.stringify({ bucket: lib, user, access }) })); fill(); toast(access === 'none' ? user + ' no longer has access' : 'Shared with ' + user); }
    catch (e) { fail(e); }
  };
  const add = () => { const u = who.value.trim(); if (u) { set(u, lvl.value); who.value = ''; } };
  who.addEventListener('keydown', e => { if (e.key === 'Enter') add(); });
  const body = [el('p', { text: 'People who sign in to this runtime with their own key see “' + lib + '” among their libraries. Viewers can browse, play and download; editors can also upload, rename and delete.' }),
    el('div', { class: 'lnk', style: 'margin:4px 0 14px' }, who, lvl, btn('plus', 'Add', add, 'pri')), T];
  modal('Share “' + lib + '”', body, null, true);
  async function fill() {
    T.textContent = '';
    let a;
    try { a = await (await must(await api('GET', '/~ui/access?bucket=' + encodeURIComponent(lib)))).json(); } catch (e) { T.append(el('tr', {}, el('td', { text: e.message }))); return; }
    T.append(el('tr', {}, el('td', { class: 'w' }, el('b', { text: a.owner || 'you' })), el('td', { class: 'mut', text: 'Owner' }), el('td')));
    if (!a.grants.length) T.append(el('tr', {}, el('td', { class: 'mut', colspan: '3', text: 'Nobody else has access yet.' })));
    for (const g of a.grants) {
      const sel = el('select', { class: 'inp', style: 'height:32px' }, el('option', { value: 'read', text: 'Can view' }), el('option', { value: 'write', text: 'Can edit' }));
      sel.value = g.access; sel.onchange = () => set(g.user, sel.value);
      T.append(el('tr', {}, el('td', { class: 'w', text: g.user }), el('td', {}, sel), el('td', { class: 'r' }, btn(null, 'Remove', () => set(g.user, 'none'), 'sm bad'))));
    }
  }
  fill();
}
// How full each library is; an admin sets a library's quota here.
function usageDlg() {
  const box = el('div');
  const L = modal('Storage', box, null, true);
  const fill = async () => {
    box.textContent = '';
    let u;
    try { u = await (await must(await api('GET', '/~ui/usage'))).json(); } catch (e) { box.append(el('p', { text: e.message })); return; }
    const own = u.libraries.filter(l => !l.shared), mine = own.reduce((a, l) => a + l.bytes, 0);
    box.append(el('div', { class: 'stats', style: 'display:flex;gap:8px;flex-wrap:wrap;margin:2px 0 16px' },
      el('span', { class: 'chip' }, el('span', { text: human(mine) + ' in ' + own.length + (own.length === 1 ? ' library' : ' libraries') })),
      u.user_max_bytes ? el('span', { class: 'chip' }, el('span', { text: 'your quota ' + human(u.user_max_bytes) + ' · ' + Math.round(100 * mine / u.user_max_bytes) + '% used' })) : null,
      u.admin ? el('span', { class: 'chip' }, el('span', { text: 'admin: every library' })) : null));
    const top = Math.max(1, ...u.libraries.map(l => l.max_bytes || l.bytes));
    for (const l of u.libraries.sort((a, b) => b.bytes - a.bytes)) {
      const cap = l.max_bytes || 0, pct = cap ? Math.min(100, 100 * l.bytes / cap) : 100 * l.bytes / top;
      const bar = el('div', { class: 'sbar' }, el('i', { style: 'width:' + pct.toFixed(1) + '%' + (cap && pct > 90 ? ';background:var(--bad)' : '') }));
      const head = el('div', { style: 'display:flex;align-items:baseline;gap:10px;margin-top:14px' },
        el('b', { text: l.bucket }), el('span', { class: 'mut', style: 'font-size:12.5px', text: u.admin ? 'owner ' + l.owner : l.shared ? 'shared with you by ' + l.owner : '' }),
        el('span', { style: 'margin-left:auto;font-variant-numeric:tabular-nums', text: (l.partial ? 'at least ' : '') + human(l.bytes) + (cap ? ' of ' + human(cap) : '') + ' · ' + l.objects + (l.objects === 1 ? ' file' : ' files') }));
      box.append(head, bar);
      if (u.admin) {
        const q = el('input', { class: 'inp', type: 'number', min: '0', step: '0.1', placeholder: 'No quota', value: cap ? String(+(cap / 1e9).toFixed(2)) : '', style: 'width:120px;height:32px' });
        box.append(el('div', { style: 'display:flex;align-items:center;gap:8px;margin-top:6px' }, el('span', { class: 'mut', style: 'font-size:12.5px', text: 'Quota in GB' }), q,
          btn(null, 'Set', async () => { try { await must(await api('POST', '/~ui/usage', { body: JSON.stringify({ bucket: l.bucket, max_bytes: Math.round((+q.value || 0) * 1e9), max_objects: l.max_objects || 0 }) })); toast(+q.value ? 'Quota of ' + l.bucket + ' set to ' + q.value + ' GB' : 'Quota of ' + l.bucket + ' removed'); fill(); } catch (e) { fail(e); } }, 'sm')));
      }
    }
    if (!u.libraries.length) box.append(el('p', { class: 'mut', text: 'No libraries yet.' }));
    box.append(el('p', { class: 'mut', style: 'font-size:12.5px;margin-top:18px', text: 'Sizes are summed from each library’s listing and kept for a minute.' }));
  };
  fill();
  return L;
}
function trashDlg() {
  const T = el('table', { class: 'mtbl' });
  modal('Trash · ' + path.join('/'), [el('p', { text: 'Files deleted from a library that keeps versions. Restoring brings back the last version before the deletion.' }), T], null, true);
  const fill = async () => {
    T.textContent = '';
    let ls;
    try { ls = await (await must(await api('GET', dav(path, true) + '?trash'))).json(); } catch (e) { T.append(el('tr', {}, el('td', { text: e.message }))); return; }
    if (!ls.length) T.append(el('tr', {}, el('td', { class: 'mut', text: 'Nothing here. A library keeps deleted files only with versioning on.' })));
    for (const f of ls)
      T.append(el('tr', {}, el('td', { class: 'w', text: f.key }), el('td', { class: 'mut', text: human(f.size) }), el('td', { class: 'mut', text: new Date(f.deleted).toLocaleString() }),
        el('td', { class: 'r' }, btn('restore', 'Restore', async () => { try { await must(await api('POST', dav([path[0], ...f.key.split('/')]) + '?restore')); fill(); load(true); toast('Restored ' + f.key); } catch (e) { fail(e); } }, 'sm'))));
  };
  fill();
}

// ─── viewers ────────────────────────────────────────────────────────────────
function overlay(cls) {
  const o = el('div', { class: 'ov ' + cls });
  document.body.append(o);
  const L = { o, close() { o.remove(); const i = layers.indexOf(L); if (i >= 0) layers.splice(i, 1); if (L.onclose) L.onclose(); }, esc() { L.close(); } };
  layers.push(L);
  return L;
}
function topbar(L, it, extra) {
  return el('div', { class: 'ovbar' }, ibtn('left', 'Back', () => L.close()), el('div', { class: 'tt' }, el('b', { text: it.name }), extra || null),
    !it.fresh && !it.dir ? ibtn('download', 'Download', () => download([it])) : null, !it.fresh ? ibtn('share', 'Share', () => shareDlg(it)) : null,
    !it.fresh ? ibtn('trash', 'Delete', async () => { await remove([it]); if (!items.some(x => keyOf(x) === keyOf(it))) L.close(); }) : null);
}
function viewImage(it, list) {
  const L = overlay('viewer');
  let i = Math.max(0, list.findIndex(x => keyOf(x) === keyOf(it)));
  const stage = el('div', { class: 'stage' }), info = el('div', { class: 'info' });
  let bar = null, zoom = 1;
  const show = async () => {
    const cur = list[i];
    if (bar) bar.remove();
    bar = topbar(L, cur); L.o.prepend(bar);
    stage.querySelectorAll('img,.spin').forEach(n => n.remove());
    const sp = el('div', { class: 'spin' }); stage.append(sp);
    const x = cur._exif;
    info.textContent = '';
    info.append(el('span', { text: (i + 1) + ' / ' + list.length + ' · ' + human(cur.size) + (x && x.taken ? ' · taken ' + shotAt(cur).toLocaleString() : cur.mod ? ' · ' + new Date(cur.mod).toLocaleString() : '') }));
    // Where it was taken, as a link to the map, which the page itself never loads.
    if (x && x.lat != null) info.append(' · ', el('a', { href: 'https://www.openstreetmap.org/?mlat=' + x.lat + '&mlon=' + x.lon + '#map=15/' + x.lat + '/' + x.lon, target: '_blank', rel: 'noopener noreferrer', style: 'color:var(--a1)', text: 'Show on map' }));
    zoom = 1;
    // A HEIF no browser but Safari shows is shown as the server's large still of it.
    const heif = /\.(heic|heif|hif)$/i.test(cur.name);
    const img = el('img', { src: heif ? '/~media/thumb-1920/' + enc(cur.segs) : '/~dav/' + enc(cur.segs), alt: cur.name, draggable: 'false' });
    img.onload = () => sp.remove();
    img.onerror = () => { sp.remove(); img.remove(); stage.append(el('div', { class: 'mut', text: 'This picture cannot be shown.' })); };
    img.ondblclick = () => { zoom = zoom > 1 ? 1 : 2.2; img.style.transform = 'scale(' + zoom + ')'; };
    stage.append(img);
    // The neighbours, so the next step shows at once.
    for (const j of [i + 1, i - 1]) if (list[j]) new Image().src = (/\.(heic|heif|hif)$/i.test(list[j].name) ? '/~media/thumb-1920/' : '/~dav/') + enc(list[j].segs);
  };
  const step = d => { if (list.length < 2) return; i = (i + d + list.length) % list.length; show(); };
  if (list.length > 1) stage.append(el('button', { class: 'nav2 l', title: 'Previous', onclick: () => { stopShow(); step(-1); } }, ico('left')), el('button', { class: 'nav2 r', title: 'Next', onclick: () => { stopShow(); step(1); } }, ico('chev')));
  // A slideshow: the next picture every four seconds until it is stopped, by S, a click on it or a step by hand.
  let showT = 0;
  const ssB = list.length > 1 ? el('button', { class: 'btn sm', style: 'position:absolute;right:18px;bottom:16px;z-index:5', onclick: () => showT ? stopShow() : startShow() }, ico('play'), el('span', { text: 'Slideshow' })) : null;
  function startShow() { showT = setInterval(() => step(1), 4000); if (ssB) { ssB.firstChild.innerHTML = P.pause; ssB.lastChild.textContent = 'Stop'; } }
  function stopShow() { clearInterval(showT); showT = 0; if (ssB) { ssB.firstChild.innerHTML = P.play; ssB.lastChild.textContent = 'Slideshow'; } }
  L.o.append(stage, info);
  if (ssB) L.o.append(ssB);
  const key = e => { if (layers[layers.length - 1] !== L) return; if (e.key === 'ArrowRight') { stopShow(); step(1); } else if (e.key === 'ArrowLeft') { stopShow(); step(-1); } else if (e.key.toLowerCase() === 's') showT ? stopShow() : startShow(); };
  document.addEventListener('keydown', key);
  L.onclose = () => { stopShow(); document.removeEventListener('keydown', key); };
  show();
}
async function viewPdf(it) {
  const L = overlay('viewer');
  L.o.append(topbar(L, it));
  const stage = el('div', { class: 'stage', style: 'padding-top:64px' });
  L.o.append(stage);
  stage.append(el('iframe', { src: '/~dav/' + enc(it.segs), title: it.name }));
}
function fileInfo(it) {
  const L = overlay('viewer');
  L.o.style.background = 'radial-gradient(800px 500px at 50% 30%,rgba(var(--glow),.15),transparent),#07080c';
  L.o.append(topbar(L, it), el('div', { class: 'fileinfo' }, ico(ICON[it.kind], 'big'), el('h2', { text: it.name }),
    el('div', { class: 'mut', text: [human(it.size), it.type, it.mod ? new Date(it.mod).toLocaleString() : ''].filter(Boolean).join(' · ') }),
    el('div', { class: 'acts' }, btn('download', 'Download', () => download([it]), 'pri'), btn('share', 'Share', () => shareDlg(it)),
      it.size < 8e6 ? btn('code', 'Open as text', () => { L.close(); editText(it); }) : null)));
}

// ─── the player ─────────────────────────────────────────────────────────────
// The master's streams through Media Source Extensions: the stream the bandwidth carries chosen at every segment,
// positions kept in seconds so that the copied stream and the renditions, whose segments begin at different times,
// follow one another, a seek begun where it lands, and a change of quality made in place: what is buffered past the
// next six seconds is dropped and the new stream appended from there, on the same media source, so the
// picture plays on while the server makes the new stream's first segment.
class MsePlayer {
  constructor(video, master, choice) {
    this.v = video; this.master = master; this.choice = choice; this.alive = true; this.lists = {};
    this.inited = -1; this.playing = -1; this.flush = false; this.ended = false; this.onlevel = () => {};
  }
  static source() { return window.ManagedMediaSource || window.MediaSource; }
  stop() {
    this.alive = false; if (this.ctl) this.ctl.abort(); clearInterval(this.tick);
    this.v.removeEventListener('seeking', this.onseek);
    this.v.removeAttribute('src'); this.v.load();
    if (this.url) URL.revokeObjectURL(this.url);
  }
  pick(c) {
    const L = this.levels, f = p => L.findIndex(p);
    if (c === 'copy') return Math.max(0, f(l => l.copy));
    if (c !== 'auto') { const i = f(l => !l.copy && l.rung === +c); return i >= 0 ? i : 0; }
    // The copied picture where the browser takes it and the line plausibly carries it, which costs the server
    // almost nothing; else 720p or the largest rendition below about 4.5 Mbit/s.
    return f(l => l.copy && l.bw <= 12e6) >= 0 ? f(l => l.copy) : L.reduce((best, l, i) => !l.copy && l.bw <= 4.5e6 ? i : best, 0);
  }
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
      const url = new URL(lines[i + 1].trim(), new URL(this.master, location.href)).href;
      const copy = url.includes('/hls-copy/');
      const rung = +(/\/hls-(\d+)\//.exec(url) || [0, 0])[1];
      if (MS.isTypeSupported('video/mp4; codecs="' + codecs + '"')) this.levels.push({ bw, codecs, h, rung, copy, url });
    }
    if (!this.levels.length || !this.alive) return false;
    this.levels.sort((a, b) => a.bw - b.bw);
    this.level = this.pick(this.choice);
    this.fixed = this.choice !== 'auto';
    let first = await this.list(this.level);
    // The film's length is a rendition's, written whole up front; a copied stream's playlist is only as long as the
    // remux has come.
    const whole = this.levels.findIndex(l => !l.copy);
    if (!first.ended && whole >= 0) first = await this.list(whole);
    if (!this.alive) return false;
    this.ms = new MS();
    if (window.ManagedMediaSource) this.v.disableRemotePlayback = true;
    this.url = URL.createObjectURL(this.ms);
    this.v.src = this.url;
    await new Promise(r => this.ms.addEventListener('sourceopen', r, { once: true }));
    this.ms.duration = first.total;
    this.sb = this.ms.addSourceBuffer('video/mp4; codecs="' + this.levels[this.level].codecs + '"');
    this.onseek = () => { if (this.ctl) this.ctl.abort(); };
    this.v.addEventListener('seeking', this.onseek);
    // A hole where two of the server's jobs meet, or one a change of quality left, is stepped over rather than
    // stalled in.
    this.tick = setInterval(() => {
      try {
        const v = this.v;
        if (v.paused || v.seeking || v.readyState >= 3) return;
        const b = this.sb.buffered, t = v.currentTime;
        for (let i = 0; i < b.length; i++) if (b.start(i) > t && b.start(i) - t < 1.5) { v.currentTime = b.start(i) + 0.02; break; }
      } catch (e) {}
    }, 400);
    if (at) this.v.currentTime = at;
    this.pump();
    return true;
  }
  setChoice(c) {
    this.choice = c; this.fixed = c !== 'auto';
    const l = this.pick(c);
    if (l === this.level) return;
    this.level = l; this.flush = true;
    if (this.ctl) this.ctl.abort();
  }
  current() { return this.levels[this.playing >= 0 ? this.playing : this.level]; }
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
    const out = { segs, init, total: ended ? t : Math.max(t, this.ms ? this.ms.duration : 0), ended };
    this.lists[level] = out;
    return out;
  }
  bufferedEnd() { const b = this.sb.buffered, t = this.v.currentTime; for (let i = 0; i < b.length; i++) if (b.start(i) <= t + 0.3 && b.end(i) > t) return b.end(i); return t; }
  updated() { return new Promise(r => this.sb.addEventListener('updateend', r, { once: true })); }
  async append(data) {
    for (let tries = 0; ; tries++) {
      try { this.sb.appendBuffer(data); break; }
      catch (e) {
        // A full buffer gives up what lies well behind the playhead, and takes the segment after.
        if (e.name !== 'QuotaExceededError' || tries > 2) throw e;
        const keep = Math.max(0, this.v.currentTime - 10);
        if (keep <= 0) throw e;
        this.sb.remove(0, keep);
        await this.updated();
      }
    }
    await this.updated();
  }
  async pump() {
    while (this.alive && this.v.isConnected) {
      try {
        if (this.sb.updating) { await sleep(100); continue; }
        if (this.flush) {
          this.flush = false;
          // What was buffered in the old quality goes, behind the playhead as well as ahead of it, so a seek back
          // shows the new one; only the segment playing stays, cut where segments begin with a keyframe.
          const t = this.v.currentTime, lst = this.lists[this.playing >= 0 ? this.playing : this.level];
          const cur = lst && lst.segs.find(x => x.start <= t && x.start + x.dur > t);
          const keepFrom = cur ? cur.start : t, keepTo = cur ? cur.start + cur.dur : t + 1;
          if (keepFrom > 0.1 && this.sb.buffered.length && this.sb.buffered.start(0) < keepFrom) { this.sb.remove(0, keepFrom); await this.updated(); }
          if (this.bufferedEnd() > keepTo) { this.sb.remove(keepTo, Infinity); await this.updated(); }
          this.ended = false;
        }
        const end = this.bufferedEnd();
        if (end - this.v.currentTime > 30) { await sleep(300); continue; }
        let level = this.level;
        this.ctl = new AbortController();
        let list = await this.list(level);
        // The copied stream is remuxed from the start; a place it has not reached yet is played from a rendition,
        // which the server begins anywhere at once, and the copy is taken up again once it has caught up.
        if (this.levels[level].copy && !list.ended && end + 1 > list.total) {
          const fb = this.levels.reduce((best, l, i) => !l.copy && l.bw <= 4.5e6 ? i : best, -1);
          const any = this.levels.findIndex(l => !l.copy);
          if (fb >= 0 || any >= 0) { level = fb >= 0 ? fb : any; list = await this.list(level); }
        }
        const lvl = this.levels[level];
        let si = list.segs.findIndex(s => s.start + s.dur > end + 0.05);
        // A segment whose media ends a little short of its playlist length, as a copied stream's does at its last audio
        // frame, leaves the buffer where it left it; the next one is asked for, not the same one again.
        const last = this.last;
        if (si >= 0 && last && last.level === level && si <= last.i && Math.abs(end - last.end) < 0.01) si = last.i + 1;
        const seg = si >= 0 ? list.segs[si] : undefined;
        if (!seg) {
          if (list.ended || end >= list.total - 0.1) {
            // The end is marked once; a seek back after it is still fed, as appending opens the source again.
            if (!this.ended && this.ms.readyState === 'open' && end >= this.ms.duration - 0.5) { this.ms.endOfStream(); this.ended = true; }
            await sleep(500); continue;
          }
          // A copied stream not yet made this far is read again in a moment.
          await sleep(1000); delete this.lists[level]; continue;
        }
        // The init of a stream just switched to is fetched beside its first segment, not before it.
        const t0 = performance.now();
        const want = [fetch(seg.url, { signal: this.ctl.signal, priority: 'high' })];
        if (this.inited !== level) want.push(fetch(list.init, { signal: this.ctl.signal, priority: 'high' }));
        const [res, ires] = await Promise.all(want);
        if (!res.ok) throw new Error('segment ' + res.status);
        const t1 = performance.now();
        const data = await res.arrayBuffer();
        const bps = data.byteLength * 8 / Math.max(0.05, (performance.now() - t1) / 1000);
        if (!this.alive) return;
        // A change of quality made while this segment came in drops it, so the old stream is not appended after the flush.
        if (this.flush) continue;
        this.ended = false;
        if (ires) {
          if (this.sb.changeType) this.sb.changeType('video/mp4; codecs="' + lvl.codecs + '"');
          await this.append(await ires.arrayBuffer());
          this.inited = level;
        }
        await this.append(data);
        this.last = { level, i: si, end: this.bufferedEnd() };
        if (this.playing !== level) { this.playing = level; this.onlevel(); }
        // Up when the next stream fits the measured rate twice over and answers at once; down when this one does not
        // fit it, or the server takes more than half a segment to answer, as it does when it cannot keep up.
        if (!this.fixed && level === this.level) {
          const ttfb = (t1 - t0) / 1000;
          const up = this.levels[level + 1];
          if (up && bps > up.bw * 2 && ttfb < seg.dur / 4) this.level = level + 1;
          else if (level > 0 && (bps < lvl.bw * 1.1 || ttfb > seg.dur / 2)) this.level = level - 1;
        }
        const t = this.v.currentTime;
        if (t > 90 && !this.sb.updating) { this.sb.remove(0, t - 60); await this.updated(); }
      } catch (e) {
        if (!this.alive) return;
        if (e.name !== 'AbortError') await sleep(1000);
      }
    }
  }
}

function seekBar(onseek) {
  const tr = el('div', { class: 'tr' }), bf = el('div', { class: 'bf' }), pl = el('div', { class: 'pl' }), kn = el('div', { class: 'kn' });
  const pv = el('div', { class: 'pv', hidden: '' }), tt = el('span'), ch = el('small', { hidden: '' });
  const tip = el('div', { class: 'tip' }, pv, tt, ch);
  tr.append(bf, pl, kn);
  const s = el('div', { class: 'seek' }, tr, tip);
  let dur = 0, drag = false, trick = null, chapters = [];
  const frac = e => { const r = tr.getBoundingClientRect(); return Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)); };
  // The film's still nearest the time, from its sprite, once that is loaded; asked again a while after a failure.
  function sprite() {
    if (!trick || trick.ready || trick.loading || Date.now() - trick.failed < 15000) return;
    trick.loading = true;
    const img = new Image();
    img.onload = () => { trick.loading = false; trick.ready = true; pv.style.backgroundImage = 'url("' + trick.url + '")'; pv.style.width = trick.width + 'px'; pv.style.height = trick.height + 'px'; };
    img.onerror = () => { trick.loading = false; trick.failed = Date.now(); };
    img.src = trick.url;
  }
  function marks() { tr.querySelectorAll('.cm').forEach(n => n.remove()); if (dur) for (const c of chapters) if (c.start > 0.5 && c.start < dur) tr.append(el('div', { class: 'cm', style: 'left:' + (c.start / dur * 100) + '%' })); }
  s.addEventListener('pointerenter', sprite);
  s.addEventListener('pointermove', e => {
    const f = frac(e), t = f * dur;
    tt.textContent = clock(t);
    const c = chapters.find(x => t >= x.start && t < x.end);
    ch.textContent = c ? c.title : ''; ch.hidden = !ch.textContent;
    if (trick && trick.ready) {
      const i = Math.min(trick.count - 1, Math.floor(t / trick.every));
      pv.style.backgroundPosition = -(i % trick.columns) * trick.width + 'px ' + -Math.floor(i / trick.columns) * trick.height + 'px';
      pv.hidden = false;
    }
    // Kept inside the bar, so a still near either end is seen whole.
    const w = tr.getBoundingClientRect().width, half = tip.offsetWidth / 2;
    tip.style.left = Math.max(half, Math.min(w - half, f * w)) + 'px';
    if (drag) set(t, null);
  });
  s.addEventListener('pointerdown', e => { drag = true; s.classList.add('drag'); s.setPointerCapture(e.pointerId); set(frac(e) * dur, null); });
  s.addEventListener('pointerup', e => { if (!drag) return; drag = false; s.classList.remove('drag'); onseek(frac(e) * dur); });
  function set(t, b) { const f = dur ? Math.min(1, t / dur) : 0; pl.style.width = f * 100 + '%'; kn.style.left = f * 100 + '%'; if (b != null) bf.style.width = (dur ? Math.min(1, b / dur) : 0) * 100 + '%'; }
  return {
    el: s,
    update(t, d, b) { if ((d || 0) !== dur) { dur = d || 0; marks(); } if (!drag) set(t, b); },
    preview(url, t) { trick = Object.assign({ url, failed: 0 }, t); },
    chapters(list) { chapters = list || []; marks(); },
    get dragging() { return drag; }
  };
}
function bufferedAt(m) { const b = m.buffered, t = m.currentTime; for (let i = 0; i < b.length; i++) if (b.start(i) <= t + 0.5 && b.end(i) >= t) return b.end(i); return t; }

// ─── subtitle files beside a film ───────────────────────────────────────────
// Film.srt, Film.de.srt, Film.forced.en.vtt or Film.ass beside Film.mkv, as WebVTT the video element shows.
const subLangs = { de: 'Deutsch', ger: 'Deutsch', deu: 'Deutsch', en: 'English', eng: 'English', fr: 'Français', fre: 'Français', fra: 'Français', es: 'Español', spa: 'Español', it: 'Italiano', ita: 'Italiano', nl: 'Nederlands', pl: 'Polski', pt: 'Português', ru: 'Русский', tr: 'Türkçe', ja: '日本語', jpn: '日本語' };
function sidecars(film, siblings) {
  const stem = film.name.replace(/\.[^.]+$/, '').toLowerCase();
  return siblings.filter(x => !x.dir && /\.(srt|vtt|ass|ssa)$/i.test(x.name) && x.name.toLowerCase().startsWith(stem + '.'))
    .map(x => {
      const tags = x.name.slice(stem.length).replace(/\.[^.]+$/, '').split('.').filter(Boolean).map(t => t.toLowerCase());
      const lang = tags.find(t => /^[a-z]{2,3}$/.test(t) && t !== 'sdh') || '';
      const label = [subLangs[lang] || (lang ? lang.toUpperCase() : 'Subtitles'), tags.includes('forced') ? 'forced' : '', tags.includes('sdh') || tags.includes('cc') ? 'SDH' : ''].filter(Boolean).join(' · ');
      return { it: x, lang, label };
    });
}
// Bytes as text: UTF-8 where they are, else Windows-1252, as older German and French files are.
function subText(buf) { try { return new TextDecoder('utf-8', { fatal: true }).decode(buf).replace(/^\uFEFF/, ''); } catch (e) { return new TextDecoder('windows-1252').decode(buf); } }
function toVtt(text, ext) {
  text = text.replace(/\r\n?/g, '\n');
  if (ext === 'vtt') return text;
  if (ext === 'srt') return 'WEBVTT\n\n' + text.replace(/(\d\d:\d\d:\d\d),(\d{3})/g, '$1.$2').replace(/^\d+\n(?=\d\d:)/gm, '');
  // ASS and SSA: each Dialogue line's start, end and text, its override tags left out.
  let out = 'WEBVTT\n\n', fmt = null;
  const ts = t => { const m = /(\d+):(\d\d):(\d\d)[.:](\d\d)/.exec(t); return m ? String(m[1]).padStart(2, '0') + ':' + m[2] + ':' + m[3] + '.' + m[4] + '0' : null; };
  for (const line of text.split('\n')) {
    if (/^Format:/i.test(line) && !fmt) { const f = line.slice(7).split(',').map(x => x.trim().toLowerCase()); if (f.includes('text')) fmt = f; continue; }
    if (!/^Dialogue:/i.test(line) || !fmt) continue;
    const parts = line.slice(9).split(','), text2 = parts.slice(fmt.length - 1).join(',');
    const a = ts(parts[fmt.indexOf('start')] || ''), b = ts(parts[fmt.indexOf('end')] || '');
    if (!a || !b) continue;
    const body = text2.replace(/\{[^}]*\}/g, '').replace(/\\N/gi, '\n').replace(/\\h/g, ' ').trim();
    if (body) out += a + ' --> ' + b + '\n' + body + '\n\n';
  }
  return out;
}
async function addSidecars(v, film) {
  let sibs = [];
  try { sibs = await propfind(film.segs.slice(0, -1)); } catch (e) { return 0; }
  let n = 0;
  for (const sc of sidecars(film, sibs)) {
    try {
      const r = await api('GET', '/~dav/' + enc(sc.it.segs));
      if (!r.ok) continue;
      const vtt = toVtt(subText(await r.arrayBuffer()), ext(sc.it.name));
      const url = URL.createObjectURL(new Blob([vtt], { type: 'text/vtt' }));
      v.append(el('track', { kind: 'subtitles', src: url, srclang: sc.lang || 'und', label: sc.label }));
      n++;
    } catch (e) {}
  }
  return n;
}

async function playVideo(it, list) {
  closeAudio();
  const L = overlay('theater');
  const O = L.o;
  watchingStart();
  const v = el('video', { playsinline: '', preload: 'auto' });
  const spin = el('div', { class: 'spin' });
  const chips = el('div', { class: 'chips' });
  O.append(v, spin, topbar(L, it, chips));
  let player = null, meta = null, base = '', master = '', choice = 'orig', direct = false, copyOK = false, streams = false, native = false, audio = 0;
  const MS = MsePlayer.source();
  const vol = +store.get('skl-vol', '1'); v.volume = isFinite(vol) ? vol : 1; v.muted = store.get('skl-muted', '0') === '1';
  // Controls
  const sk = seekBar(t => { v.currentTime = t; });
  const ppB = ibtn('play', 'Play (k)', () => toggle(), 'pp');
  const volB = ibtn('vol', 'Mute (m)', () => { v.muted = !v.muted; });
  const volR = el('input', { type: 'range', min: '0', max: '1', step: '0.02', value: String(v.volume), 'aria-label': 'Volume' });
  volR.oninput = () => { v.volume = +volR.value; v.muted = v.volume === 0; };
  const tm = el('span', { class: 'tm', text: '0:00 / 0:00' });
  const idx = list.findIndex(x => keyOf(x) === keyOf(it));
  const nextIt = idx >= 0 && idx < list.length - 1 ? list[idx + 1] : null;
  // Whether the next film starts by itself at the end, kept in the browser; on unless turned off.
  let autoplay = store.get('skl-autoplay', '1') === '1';
  const apB = nextIt ? el('button', { class: 'apb' + (autoplay ? ' on' : ''), title: 'Play the next one by itself (a)', onclick: e => { e.stopPropagation(); setAutoplay(!autoplay); } }, el('span', { text: 'Autoplay' }), el('span', { class: 'sw' })) : null;
  function setAutoplay(on) { autoplay = on; store.set('skl-autoplay', on ? '1' : '0'); if (apB) apB.classList.toggle('on', on); if (!on) cancelNext(); osd('Autoplay ' + (on ? 'on' : 'off')); }
  const ccB = ibtn('cc', 'Subtitles (c)', e => menu('cc', e)); ccB.hidden = true;
  const chB = ibtn('list', 'Chapters', e => menu('ch', e)); chB.hidden = true;
  const skipB = el('button', { class: 'skipb', hidden: '', onclick: e => { e.stopPropagation(); const c = intro(); if (c) { v.currentTime = c.end; osd('Skipped ' + c.title); } } });
  const qlab = el('span', { class: 'qlab' }); qlab.hidden = true;
  const gearB = ibtn('gear', 'Quality and speed', e => menu('q', e));
  const fsB = ibtn('fs', 'Full screen (f)', () => fullscreen());
  const pipB = document.pictureInPictureEnabled ? ibtn('pip', 'Picture in picture', () => { (document.pictureInPictureElement ? document.exitPictureInPicture() : v.requestPictureInPicture()).catch(() => {}); }) : null;
  const ctl = el('div', { class: 'ctl' }, sk.el, el('div', { class: 'row2' }, ppB, ibtn('back10', 'Back 10 s (j)', () => { v.currentTime = Math.max(0, v.currentTime - 10); }),
    ibtn('fwd10', 'Forward 10 s (l)', () => { v.currentTime = Math.min(v.duration || 1e9, v.currentTime + 10); }), nextIt ? ibtn('next', 'Next: ' + nextIt.name, () => playNext()) : null,
    el('div', { class: 'vol' }, volB, volR), tm, el('span', { class: 'sp' }), apB, chB, ccB, gearB, qlab, pipB, fsB));
  O.append(ctl, skipB);
  // A chapter named as an opening, a recap or the credits is offered to be skipped while it plays.
  const skippable = /^(intro|opening|opener|vorspann|recap|previously|rückblick|credits|abspann|outro)\b/i;
  function intro() { const t = v.currentTime; return ((meta && meta.chapters) || []).find(c => skippable.test(c.title.trim()) && t >= c.start && t < c.end - 1) || null; }
  let pm = null;
  const closeMenu = () => { if (pm) { pm.remove(); pm = null; } };
  function qualityName(c) {
    if (c === 'orig') return 'Original';
    if (c === 'auto') { const l = player && player.current && player.current(); return 'Auto' + (l ? ' · ' + (l.copy ? 'Original' : l.rung + 'p') : ''); }
    return c + 'p';
  }
  function menu(which, e) {
    e.stopPropagation();
    if (pm && pm.dataset.w === which) return closeMenu();
    closeMenu();
    pm = el('div', { class: 'pmenu', 'data-w': which });
    const item = (label, on, fn, sub) => pm.append(el('button', { class: on ? 'on' : '', onclick: ev => { ev.stopPropagation(); fn(); closeMenu(); } }, ico('check', 'ck'), el('span', { text: label }), sub ? el('small', { text: sub }) : null));
    if (which === 'q') {
      pm.append(el('div', { class: 'hd', text: 'Quality' }));
      const src = meta && meta.height ? meta.height + 'p' + (meta.video ? ' · ' + meta.video.toUpperCase() : '') + (meta.hdr ? ' HDR' : '') : '';
      if (direct || copyOK) item('Original', choice === 'orig', () => setChoice('orig'), [src, direct ? 'the file' : 'stream'].filter(Boolean).join(' · '));
      if (streams) {
        item('Auto', choice === 'auto', () => setChoice('auto'), choice === 'auto' ? qualityName('auto').replace(/^Auto · /, '') : 'adapts to the line');
        for (const h of (meta.renditions || []).slice().sort((a, b) => b - a)) item(h + 'p', choice === String(h), () => setChoice(String(h)), h >= 2160 ? '4K' : h >= 1080 ? 'HD' : '');
      }
      if (!streams && !direct && !copyOK) pm.append(el('div', { class: 'hd', style: 'text-transform:none;letter-spacing:0', text: 'Only the file itself is offered.' }));
      const tracks = (meta && meta.tracks) || [];
      if (tracks.length > 1 && (streams || copyOK)) {
        pm.append(el('hr'), el('div', { class: 'hd', text: 'Audio' }));
        tracks.forEach((t, i) => item(trackName(t, i), audio === i, () => setAudio(i), [t.codec.toUpperCase(), t.channels > 2 ? (t.channels === 6 ? '5.1' : t.channels === 8 ? '7.1' : t.channels + ' ch') : t.channels === 1 ? 'mono' : 'stereo'].join(' · ')));
      }
      pm.append(el('hr'), el('div', { class: 'hd', text: 'Speed' }));
      for (const r of [0.5, 0.75, 1, 1.25, 1.5, 2]) item(r === 1 ? 'Normal' : r + '×', v.playbackRate === r, () => { v.playbackRate = r; osd(r === 1 ? 'Normal speed' : r + '× speed'); });
    } else if (which === 'ch') {
      pm.append(el('div', { class: 'hd', text: 'Chapters' }));
      const t = v.currentTime;
      meta.chapters.forEach((c, i) => item(c.title || 'Chapter ' + (i + 1), t >= c.start && t < c.end, () => { v.currentTime = c.start; osd(c.title || 'Chapter ' + (i + 1)); }, clock(c.start)));
    } else {
      pm.append(el('div', { class: 'hd', text: 'Subtitles' }));
      const tracks = [...v.textTracks];
      item('Off', tracks.every(t => t.mode !== 'showing'), () => tracks.forEach(t => t.mode = 'disabled'));
      tracks.forEach((t, i) => item(t.label || t.language || 'Track ' + (i + 1), t.mode === 'showing', () => tracks.forEach((x, j) => x.mode = j === i ? 'showing' : 'disabled'), t.language));
    }
    O.append(pm);
  }
  O.addEventListener('click', e => { if (pm && !pm.contains(e.target)) closeMenu(); });
  const osdEl = el('div', { class: 'osd' }); osdEl.style.opacity = 0; O.append(osdEl);
  let osdT = 0;
  function osd(text) { osdEl.textContent = text; osdEl.style.opacity = 1; clearTimeout(osdT); osdT = setTimeout(() => osdEl.style.opacity = 0, 1300); }
  function flash(n) { const f = el('div', { class: 'flash' }, ico(n)); O.append(f); setTimeout(() => f.remove(), 650); }
  function toggle() { if (v.paused) { v.play().catch(() => {}); flash('play'); } else { v.pause(); flash('pause'); } }
  function fullscreen() { if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); else (O.requestFullscreen ? O.requestFullscreen() : Promise.reject()).catch(() => {}); }
  // Idle hiding of the controls.
  let idleT = 0;
  const wake = () => { O.classList.remove('idle'); clearTimeout(idleT); idleT = setTimeout(() => { if (!v.paused && !pm && !sk.dragging) O.classList.add('idle'); }, 2600); };
  O.addEventListener('mousemove', wake); O.addEventListener('touchstart', wake, { passive: true });
  v.addEventListener('click', () => { if (pm) return closeMenu(); toggle(); });
  v.addEventListener('dblclick', fullscreen);
  // State painting.
  const paint = () => {
    sk.update(v.currentTime, v.duration, bufferedAt(v));
    tm.textContent = clock(v.currentTime) + ' / ' + clock(v.duration);
  };
  v.addEventListener('timeupdate', paint); v.addEventListener('progress', paint); v.addEventListener('durationchange', paint);
  // Cues end at 84% of the picture's height, clear of the controls, unless a file places them itself.
  v.textTracks.addEventListener('addtrack', e => e.track.addEventListener('cuechange', () => { for (const c of e.track.activeCues || []) if (c.line === 'auto') { c.snapToLines = false; c.line = 84; c.lineAlign = 'end'; } }));
  v.addEventListener('timeupdate', () => { const c = intro(); skipB.hidden = !c; if (c) skipB.textContent = 'Skip ' + c.title.trim().toLowerCase(); });
  v.addEventListener('play', () => { ppB.firstChild.innerHTML = P.pause; wake(); });
  v.addEventListener('pause', () => { ppB.firstChild.innerHTML = P.play; O.classList.remove('idle'); savePosition(it, v.currentTime, v.duration, true); });
  v.addEventListener('waiting', () => spin.hidden = false);
  for (const ev of ['playing', 'canplay', 'seeked', 'pause']) v.addEventListener(ev, () => { if (ev !== 'pause' || v.readyState >= 3) spin.hidden = true; });
  v.addEventListener('volumechange', () => { volB.firstChild.innerHTML = v.muted || !v.volume ? P.mute : P.vol; volR.value = String(v.muted ? 0 : v.volume); store.set('skl-vol', String(v.volume)); store.set('skl-muted', v.muted ? '1' : '0'); });
  v.dispatchEvent(new Event('volumechange'));
  document.addEventListener('fullscreenchange', onfs);
  function onfs() { fsB.firstChild.innerHTML = document.fullscreenElement ? P.fsx : P.fs; }
  let saveT = setInterval(() => { if (!v.paused) savePosition(it, v.currentTime, v.duration); }, 5000);
  v.addEventListener('ended', () => { savePosition(it, v.duration, v.duration, true); if (nextIt && autoplay) upNext(); });
  // Going back into the film, or playing it again, is staying with it: the next one is not started.
  v.addEventListener('seeking', () => { if (v.currentTime < (v.duration || 0) - 0.5) cancelNext(); });
  v.addEventListener('play', cancelNext);
  v.addEventListener('error', () => { if (choice === 'orig' && direct && streams && !player) { toast('The browser cannot play this file itself: streaming it instead', 'info'); direct = false; setChoice('auto'); } });
  let upT = 0, upCard = null;
  function cancelNext() { clearInterval(upT); upT = 0; if (upCard) { upCard.remove(); upCard = null; } }
  function upNext() {
    cancelNext();
    const card = upCard = el('div', { class: 'upnext' }, el('small', { text: 'Up next' }), el('b', { text: nextIt.name }));
    let n = 8;
    const b = btn('play', 'Play now (' + n + ')', () => playNext(), 'pri sm');
    card.append(el('div', { style: 'display:flex;gap:8px' }, b, btn(null, 'Cancel', cancelNext, 'sm')));
    O.append(card);
    upT = setInterval(() => { n--; b.lastChild.textContent = 'Play now (' + n + ')'; if (n <= 0) playNext(); }, 1000);
  }
  function playNext() { clearInterval(upT); L.close(); playVideo(nextIt, list); }
  const keys = e => {
    if (layers[layers.length - 1] !== L || /INPUT|TEXTAREA/.test(document.activeElement.tagName) && document.activeElement !== volR) return;
    const k = e.key.toLowerCase();
    if (k === ' ' || k === 'k') { e.preventDefault(); toggle(); }
    else if (k === 'arrowright' || k === 'l') { e.preventDefault(); v.currentTime = Math.min(v.duration || 1e9, v.currentTime + (k === 'l' ? 10 : 5)); osd('+' + (k === 'l' ? 10 : 5) + ' s'); }
    else if (k === 'arrowleft' || k === 'j') { e.preventDefault(); v.currentTime = Math.max(0, v.currentTime - (k === 'j' ? 10 : 5)); osd('−' + (k === 'j' ? 10 : 5) + ' s'); }
    else if (k === 'arrowup') { e.preventDefault(); v.volume = Math.min(1, v.volume + 0.05); v.muted = false; osd('Volume ' + Math.round(v.volume * 100) + '%'); }
    else if (k === 'arrowdown') { e.preventDefault(); v.volume = Math.max(0, v.volume - 0.05); osd('Volume ' + Math.round(v.volume * 100) + '%'); }
    else if (k === 'f') fullscreen();
    else if (k === 'm') v.muted = !v.muted;
    else if (k === 'c' && !ccB.hidden) { const t = [...v.textTracks]; const on = t.findIndex(x => x.mode === 'showing'); t.forEach((x, j) => x.mode = j === (on + 1 === t.length ? -1 : on + 1) ? 'showing' : 'disabled'); const s = t.find(x => x.mode === 'showing'); osd(s ? 'Subtitles: ' + (s.label || s.language) : 'Subtitles off'); }
    else if (k === 'n' && nextIt) playNext();
    else if (k === 'a' && nextIt) setAutoplay(!autoplay);
    // A frame on or back, paused, as editors step.
    else if (k === ',' || k === '.') { e.preventDefault(); v.pause(); const f = 1 / (meta && meta.fps > 0 ? meta.fps : 25); v.currentTime = Math.max(0, Math.min(v.duration || 0, v.currentTime + (k === '.' ? f : -f))); osd(k === '.' ? 'Next frame' : 'Previous frame'); }
    else if (/^[0-9]$/.test(k) && v.duration) v.currentTime = v.duration * (+k) / 10;
    wake();
  };
  document.addEventListener('keydown', keys);
  L.esc = () => { if (pm) closeMenu(); else if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); else L.close(); };
  L.onclose = () => {
    watchingEnd();
    savePosition(it, v.currentTime, v.duration, true);
    clearInterval(saveT); clearInterval(upT); clearTimeout(idleT);
    document.removeEventListener('keydown', keys); document.removeEventListener('fullscreenchange', onfs);
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    if (player) player.stop(); else { v.pause(); v.removeAttribute('src'); v.load(); }
    loadProgress().then(() => { if (auth && !layers.length) render(); });
  };
  // Where it plays from.
  async function setChoice(c, from) {
    const at = from != null ? from : v.currentTime || start;
    const paused = v.paused && v.currentTime > 0;
    choice = c;
    qlab.hidden = c === 'orig' && !player; qlab.textContent = c === 'orig' ? 'ORIG' : c === 'auto' ? 'AUTO' : c + 'p';
    // The file itself plays only its default sound, so another track is always streamed.
    const viaStream = c !== 'orig' || !direct || audio > 0;
    if (viaStream && MS) {
      const want = c === 'orig' ? 'copy' : c;
      if (player) { player.setChoice(want); osd('Quality: ' + qualityName(c)); return; }
      spin.hidden = false;
      player = new MsePlayer(v, master, want);
      player.onlevel = () => { const l = player.current(); if (l) qlab.textContent = choice === 'auto' ? 'AUTO ' + (l.copy ? 'ORIG' : l.rung + 'p') : qlab.textContent; };
      if (!(await player.start(at))) { player.stop(); player = null; choice = 'orig'; v.src = base; v.currentTime = at; }
    } else {
      if (player) { player.stop(); player = null; }
      const obj = '/' + enc(it.segs);
      const a = audio ? '-a' + audio : '';
      v.src = viaStream ? '/~media/' + (c === 'auto' ? 'hls' + a + obj + '/master.m3u8' : (c === 'orig' ? 'hls-copy' : 'hls-' + c) + a + obj + '/index.m3u8') : base;
      if (at) v.currentTime = at;
    }
    if (!paused) v.play().catch(() => {});
    if (c !== 'orig' || player) osd('Quality: ' + qualityName(c));
  }
  function trackName(t, i) { return t.title || (t.lang && t.lang !== 'und' ? t.lang.toUpperCase() : 'Track ' + (i + 1)); }
  // Another sound track is another stream of the same film, begun again where the film is.
  async function setAudio(i) {
    if (i === audio) return;
    audio = i;
    master = '/~media/hls' + (i ? '-a' + i : '') + '/' + enc(it.segs) + '/master.m3u8';
    const t = v.currentTime, paused = v.paused;
    if (player) { player.stop(); player = null; }
    let c = choice;
    if (c === 'orig' && !copyOK) c = 'auto';
    await setChoice(c, t);
    if (paused) v.pause();
    osd('Audio: ' + trackName(meta.tracks[i], i));
  }
  const pos = position(it);
  const start = pos ? pos.t : 0;
  try {
    // Everything is read with the session's cookie: the file through the drive, and the media made of it.
    const obj = '/' + enc(it.segs);
    base = '/~dav' + obj; master = '/~media/hls' + obj + '/master.m3u8';
    try { const r = await api('GET', '/~media/info' + obj); if (r.ok) meta = await r.json(); } catch (e) {}
    if (!O.isConnected) return;
    native = v.canPlayType('application/vnd.apple.mpegurl') !== '';
    streams = !!(meta && meta.video && (MS || native) && (meta.renditions || []).length);
    copyOK = !!(meta && meta.copy && (MS ? MS.isTypeSupported('video/mp4; codecs="' + meta.copy + '"') : native));
    direct = meta ? !!meta.mime && v.canPlayType(meta.mime) !== '' : v.canPlayType(it.type || 'video/mp4') !== '';
    if (meta) {
      const c = (t, cls) => chips.append(el('span', { class: 'chip' + (cls ? ' ' + cls : ''), text: t }));
      if (meta.height) c(meta.height + 'p'); if (meta.video) c(meta.video.toUpperCase()); if (meta.hdr) c('HDR'); if (meta.audio) c(meta.audio.toUpperCase());
      if (meta.duration) c(clock(meta.duration));
      for (const s of meta.subtitles || [])
        v.append(el('track', { kind: 'subtitles', src: '/~media/sub-' + s.index + '/' + enc(it.segs) + '/subs.vtt?v=' + meta.version, srclang: (s.lang || 'und').slice(0, 3), label: s.title || s.lang || 'Track ' + s.index }));
      ccB.hidden = !(meta.subtitles || []).length;
      if (meta.trick) sk.preview('/~media/trick/' + enc(it.segs) + '?v=' + meta.version, meta.trick);
      if ((meta.chapters || []).length > 1) { sk.chapters(meta.chapters); chB.hidden = false; }
      if ((meta.tracks || []).length > 1) c((meta.tracks.length) + ' audio tracks');
    }
    if (it.size) chips.append(el('span', { class: 'chip', text: human(it.size) }));
    addSidecars(v, it).then(n => { if (n) ccB.hidden = false; });
    // The file itself where the browser plays it, which costs the server nothing; a stream where it does not.
    const first = direct || (!streams && !copyOK) ? 'orig' : copyOK ? 'orig' : 'auto';
    if (start) v.addEventListener('loadedmetadata', () => { if (!player && v.currentTime < 1) v.currentTime = start; }, { once: true });
    await setChoice(first);
    if (start) osd('Resuming at ' + clock(start));
    v.play().catch(() => {});
    wake();
  } catch (e) { spin.hidden = true; O.append(el('div', { class: 'osd', text: e.message })); }
}

// ─── music ──────────────────────────────────────────────────────────────────
let AU = null;
function closeAudio() { if (AU) { watchingEnd(); AU.a.pause(); AU.a.removeAttribute('src'); AU.a.load(); AU.bar.remove(); AU = null; document.body.classList.remove('audio'); paintPlaying(); } }
async function playAudio(it, list) {
  if (!AU) {
    const a = el('audio', { preload: 'auto' });
    const title = el('b'), sub = el('small');
    const sk = seekBar(t => { a.currentTime = t; });
    const cur = el('span', { text: '0:00' }), dur = el('span', { text: '0:00' });
    const pp = ibtn('play', 'Play', () => a.paused ? a.play().catch(() => {}) : a.pause(), 'pp');
    const bar = el('div', { id: 'audio' }, el('div', { class: 'art' }, ico('music')), el('div', { class: 'meta' }, title, sub),
      el('div', { class: 'mid' }, el('div', { class: 'btns' }, ibtn('prev', 'Previous', () => skip(-1)), pp, ibtn('next', 'Next', () => skip(1))), el('div', { class: 'sk' }, cur, sk.el, dur)),
      ibtn('close', 'Close', closeAudio), a);
    AU = { a, bar, title, sub, list: [], i: 0 };
    const paint = () => { sk.update(a.currentTime, a.duration, bufferedAt(a)); cur.textContent = clock(a.currentTime); dur.textContent = clock(a.duration); };
    a.addEventListener('timeupdate', paint); a.addEventListener('durationchange', paint); a.addEventListener('progress', paint);
    a.addEventListener('play', () => pp.firstChild.innerHTML = P.pause); a.addEventListener('pause', () => pp.firstChild.innerHTML = P.play);
    a.addEventListener('ended', () => { if (AU.i < AU.list.length - 1) skip(1); });
    a.volume = +store.get('skl-vol', '1') || 1;
    document.body.append(bar); document.body.classList.add('audio');
    watchingStart();
    if ('mediaSession' in navigator) { navigator.mediaSession.setActionHandler('previoustrack', () => skip(-1)); navigator.mediaSession.setActionHandler('nexttrack', () => skip(1)); }
  }
  AU.list = list; AU.i = Math.max(0, list.findIndex(x => keyOf(x) === keyOf(it)));
  const cur = list[AU.i];
  const t = cur._tags;
  AU.title.textContent = (t && t.title) || cur.name.replace(/\.[^.]+$/, '');
  AU.sub.textContent = (t && (t.artist || t.album) ? [t.artist, t.album].filter(Boolean).join(' — ') : cur.segs.slice(0, -1).join(' / ')) + ' · ' + (AU.i + 1) + ' of ' + list.length;
  // The song's own cover where it has one, the note where not.
  const art = AU.bar.querySelector('.art'); art.querySelectorAll('img').forEach(n => n.remove());
  const cover = '/~media/thumb-320/' + enc(cur.segs), img = el('img', { alt: '', src: cover });
  img.onerror = () => img.remove(); art.append(img);
  if ('mediaSession' in navigator && window.MediaMetadata) navigator.mediaSession.metadata = new MediaMetadata({ title: AU.title.textContent, artist: (t && t.artist) || '', album: (t && t.album) || cur.segs.slice(0, -1).join(' / '), artwork: [{ src: cover, sizes: '320x320', type: 'image/jpeg' }] });
  paintPlaying();
  AU.a.src = '/~dav/' + enc(cur.segs); AU.a.play().catch(() => {});
}
function skip(d) { if (!AU) return; const j = AU.i + d; if (j < 0 || j >= AU.list.length) return; playAudio(AU.list[j], AU.list); }

// ─── the text editor ────────────────────────────────────────────────────────
const RX = {
  bc: String.raw`/\*[\s\S]*?(?:\*/|$)`, lc: String.raw`//.*`, hash: String.raw`#.*`, dd: String.raw`--.*`, semi: String.raw`;.*`,
  dq: String.raw`"(?:[^"\\\n]|\\.)*"?`, sq: String.raw`'(?:[^'\\\n]|\\.)*'?`, bt: String.raw`\x60(?:[^\x60\\]|\\.)*\x60?`,
  tq: String.raw`"""[\s\S]*?(?:"""|$)|'''[\s\S]*?(?:'''|$)`,
  num: String.raw`\b(?:0[xX][\da-fA-F]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)\b`, word: String.raw`[A-Za-z_$][\w$]*`,
  pre: String.raw`^[ \t]*#[ \t]*\w+`, key: String.raw`^[ \t-]*["']?[\w.\- ]+["']?(?=[ \t]*[:=](?:\s|$))`, sect: String.raw`^[ \t]*\[[^\]\n]*\]`,
  jkey: String.raw`"(?:[^"\\\n]|\\.)*"(?=\s*:)`, var: String.raw`\$\{?[\w@#?*!-]+\}?`
};
const KW = {
  c: 'if else for while do switch case default break continue return goto try catch finally throw new delete this class struct enum union namespace using template typename public private protected virtual override final static const constexpr consteval volatile extern inline auto void int long short char unsigned signed float double bool true false nullptr NULL sizeof typedef noexcept operator friend explicit mutable thread_local co_await co_return import package interface extends implements super instanceof var val fun func let mut pub use mod impl trait match loop fn self Self crate where move ref dyn defer go chan map range type nil make len append string byte rune uint8 int64 uint64 size_t std abstract sealed when object in is as out readonly async await yield lock foreach get set',
  js: 'var let const function return if else for while do switch case default break continue new delete typeof instanceof in of class extends super this import export from as async await yield try catch finally throw null undefined true false void static get set interface type enum implements private public protected readonly declare namespace keyof',
  py: 'def class return if elif else for while in not and or is None True False import from as with try except finally raise lambda yield pass break continue global nonlocal async await self cls print match case',
  sh: 'if then else elif fi for in do done while until case esac function return local export echo exit set unset source alias cd readonly shift trap eval exec test true false',
  lua: 'and break do else elseif end false for function goto if in local nil not or repeat return then true until while self require',
  sql: 'select from where and or not insert into values update set delete create table drop alter index primary key foreign references join left right inner outer full cross on group by order having limit offset as distinct null is like in between case when then else end union all count sum avg min max default unique check constraint view trigger begin commit rollback exists asc desc',
  css: 'important media import from to and not only screen print keyframes supports font-face root hover focus active before after',
  yaml: 'true false null yes no on off'
};
const LANGS = {};
function lang(name, cls, parts, kw, flags) { const re = new RegExp(parts.map(p => '(' + RX[p] + ')').join('|'), 'g' + (flags || '')); LANGS[name] = { name, re, cls: parts.map(p => cls[p] || p), kw: new Set((kw || '').split(' ')), ci: (flags || '').includes('i') }; }
const CL = { bc: 'com', lc: 'com', hash: 'com', dd: 'com', semi: 'com', dq: 'str', sq: 'str', bt: 'str', tq: 'str', num: 'num', word: 'w', pre: 'pre', key: 'prop', sect: 'kw', jkey: 'prop', var: 'attr' };
lang('C-like', CL, ['bc', 'lc', 'pre', 'dq', 'sq', 'num', 'word'], KW.c, 'm');
lang('JavaScript', CL, ['bc', 'lc', 'dq', 'sq', 'bt', 'num', 'word'], KW.js);
lang('JSON', CL, ['bc', 'lc', 'jkey', 'dq', 'num', 'word'], 'true false null');
lang('Python', CL, ['tq', 'hash', 'dq', 'sq', 'num', 'word'], KW.py);
lang('Shell', CL, ['hash', 'dq', 'sq', 'var', 'num', 'word'], KW.sh);
lang('Lua', Object.assign({}, CL, { lb: 'com' }), ['bc', 'dd', 'dq', 'sq', 'num', 'word'], KW.lua);
lang('SQL', CL, ['bc', 'dd', 'dq', 'sq', 'num', 'word'], KW.sql, 'i');
lang('CSS', Object.assign({}, CL, { key: 'prop' }), ['bc', 'dq', 'sq', 'num', 'word'], KW.css);
lang('YAML', CL, ['hash', 'key', 'dq', 'sq', 'num', 'word'], KW.yaml, 'm');
lang('INI', CL, ['hash', 'semi', 'sect', 'key', 'dq', 'sq', 'num', 'word'], 'true false yes no on off', 'm');
(() => {
  const P2 = [[String.raw`<!--[\s\S]*?(?:-->|$)`, 'com'], [String.raw`<\/?[\w:.-]+`, 'tag'], [String.raw`\/?>`, 'tag'], [String.raw`[\w:.-]+(?==)`, 'attr'], [RX.dq, 'str'], [RX.sq, 'str']];
  LANGS.HTML = { name: 'HTML', re: new RegExp(P2.map(p => '(' + p[0] + ')').join('|'), 'g'), cls: P2.map(p => p[1]), kw: new Set() };
  const M = [[String.raw`^#{1,6} .*`, 'head'], [String.raw`^\x60\x60\x60.*`, 'com'], [String.raw`\x60[^\x60\n]+\x60`, 'str'], [String.raw`\*\*[^*\n]+\*\*|__[^_\n]+__`, 'bold'],
    [String.raw`!?\[[^\]\n]*\]\([^)\n]*\)`, 'link'], [String.raw`^[ \t]*(?:[-*+]|\d+\.)(?= )`, 'kw'], [String.raw`^>.*`, 'com'], [String.raw`^(?:---+|\*\*\*+)$`, 'kw']];
  LANGS.Markdown = { name: 'Markdown', re: new RegExp(M.map(p => '(' + p[0] + ')').join('|'), 'gm'), cls: M.map(p => p[1]), kw: new Set() };
  const S = [[String.raw`\d\d:\d\d:\d\d[,.]\d{3}`, 'num'], [String.raw`-->`, 'kw'], [String.raw`^\d+$`, 'attr']];
  LANGS.Subtitles = { name: 'Subtitles', re: new RegExp(S.map(p => '(' + p[0] + ')').join('|'), 'gm'), cls: S.map(p => p[1]), kw: new Set() };
})();
function langOf(n) {
  const e = ext(n);
  if (/^(makefile|dockerfile)$/i.test(n)) return LANGS.Shell;
  const m = { c: 'C-like', h: 'C-like', cc: 'C-like', cpp: 'C-like', cxx: 'C-like', hpp: 'C-like', hh: 'C-like', java: 'C-like', kt: 'C-like', kts: 'C-like', cs: 'C-like', go: 'C-like', rs: 'C-like', swift: 'C-like', php: 'C-like', gradle: 'C-like',
    js: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript', ts: 'JavaScript', tsx: 'JavaScript', jsx: 'JavaScript', vue: 'HTML', svelte: 'HTML', json: 'JSON', jsonc: 'JSON',
    py: 'Python', rb: 'Python', sh: 'Shell', bash: 'Shell', zsh: 'Shell', fish: 'Shell', env: 'Shell', mk: 'Shell', cmake: 'Shell', ps1: 'Shell', lua: 'Lua', sql: 'SQL',
    css: 'CSS', scss: 'CSS', sass: 'CSS', less: 'CSS', yml: 'YAML', yaml: 'YAML', toml: 'INI', ini: 'INI', conf: 'INI', cfg: 'INI', properties: 'INI', editorconfig: 'INI', gitignore: 'Shell', dockerignore: 'Shell',
    html: 'HTML', htm: 'HTML', xml: 'HTML', svg: 'HTML', md: 'Markdown', markdown: 'Markdown', srt: 'Subtitles', vtt: 'Subtitles' }[e];
  return m ? LANGS[m] : null;
}
const escH = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function highlight(src, L) {
  if (!L || src.length > 400000) return escH(src);
  const re = L.re; re.lastIndex = 0;
  let out = '', last = 0, m;
  while ((m = re.exec(src))) {
    if (!m[0]) { re.lastIndex++; continue; }
    let g = 1; while (m[g] === undefined) g++;
    let c = L.cls[g - 1];
    if (c === 'w') { const w = L.ci ? m[0].toLowerCase() : m[0]; c = L.kw.has(w) ? 'kw' : src[re.lastIndex] === '(' ? 'fn' : ''; }
    out += escH(src.slice(last, m.index)) + (c ? '<span class="t-' + c + '">' + escH(m[0]) + '</span>' : escH(m[0]));
    last = re.lastIndex;
  }
  return out + escH(src.slice(last));
}
// Markdown as HTML for the preview, from text escaped first, so only the tags made here are ever in it.
function markdown(src) {
  const inline = s => escH(s).replace(/\x60([^\x60]+)\x60/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*|__([^_]+)__/g, (m, a, b) => '<strong>' + (a || b) + '</strong>')
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>').replace(/!?\[([^\]]*)\]\(([^)\s]+)[^)]*\)/g, (m, t, u) => /^(https?:\/\/|\/|#|\.{0,2}\/?[\w-])/.test(u) && !/^\s*(javascript|data|vbscript):/i.test(u) ? '<a href="' + u.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener">' + t + '</a>' : t);
  const lines = src.split('\n'); let out = '', i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (/^\x60\x60\x60/.test(l)) { let code = ''; i++; while (i < lines.length && !/^\x60\x60\x60/.test(lines[i])) code += lines[i++] + '\n'; i++; out += '<pre><code>' + escH(code) + '</code></pre>'; continue; }
    let m;
    if ((m = /^(#{1,6})\s+(.*)/.exec(l))) { out += '<h' + m[1].length + '>' + inline(m[2]) + '</h' + m[1].length + '>'; i++; continue; }
    if (/^(?:---+|\*\*\*+)\s*$/.test(l)) { out += '<hr>'; i++; continue; }
    if (/^>\s?/.test(l)) { let q = ''; while (i < lines.length && /^>\s?/.test(lines[i])) q += lines[i++].replace(/^>\s?/, '') + ' '; out += '<blockquote><p>' + inline(q) + '</p></blockquote>'; continue; }
    if (/^\s*(?:[-*+]|\d+\.)\s+/.test(l)) { const ol = /^\s*\d+\./.test(l); out += ol ? '<ol>' : '<ul>'; while (i < lines.length && /^\s*(?:[-*+]|\d+\.)\s+/.test(lines[i])) out += '<li>' + inline(lines[i++].replace(/^\s*(?:[-*+]|\d+\.)\s+/, '').replace(/^\[ \]\s*/, '☐ ').replace(/^\[x\]\s*/i, '☑ ')) + '</li>'; out += ol ? '</ol>' : '</ul>'; continue; }
    if (!l.trim()) { i++; continue; }
    let p = ''; while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|\x60\x60\x60|>|\s*(?:[-*+]|\d+\.)\s)/.test(lines[i])) p += lines[i++] + '\n';
    out += '<p>' + inline(p.trim()).replace(/\n/g, '<br>') + '</p>';
  }
  return out;
}
async function editText(it) {
  const L = overlay('editor');
  const O = L.o;
  const lng = langOf(it.name);
  let saved = '', dirty = false, wrap = store.get('skl-wrap', '0') === '1';
  const dot = el('span', { class: 'dirty' }); dot.hidden = true;
  const nameEl = el('span', { text: it.segs.slice(0, -1).join(' / ') + ' / ' + it.name });
  const ta = el('textarea', { spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', wrap: 'off', 'aria-label': it.name });
  const pre = el('pre', { 'aria-hidden': 'true' }), gutIn = el('div'), gut = el('div', { class: 'gut' }, gutIn);
  const code = el('div', { class: 'codew' + (wrap ? ' wrap' : '') }, pre, ta);
  const pane = el('div', { class: 'edpane' }, gut, code);
  const md = el('div', { class: 'mdv' }); md.hidden = true;
  const st = { pos: el('span'), len: el('span'), lang: el('span', { text: lng ? lng.name : 'Plain text' }) };
  const saveB = btn('save', 'Save', () => save(), 'pri sm');
  const wrapB = ibtn('wrap', 'Wrap lines (Alt+Z)', () => { wrap = !wrap; store.set('skl-wrap', wrap ? '1' : '0'); code.classList.toggle('wrap', wrap); ta.setAttribute('wrap', wrap ? 'soft' : 'off'); gut.hidden = wrap; wrapB.classList.toggle('on', wrap); sync(); });
  wrapB.classList.toggle('on', wrap); gut.hidden = wrap; if (wrap) ta.setAttribute('wrap', 'soft');
  const isMd = lng === LANGS.Markdown;
  const mdB = isMd ? ibtn('eye', 'Preview (Ctrl+Shift+V)', () => { md.hidden = !md.hidden; mdB.classList.toggle('on', !md.hidden); if (!md.hidden) md.innerHTML = markdown(ta.value); }) : null;
  O.append(el('div', { class: 'edh' }, ibtn('left', 'Close', () => L.esc()), el('div', { class: 'nm' }, ico(lng ? 'code' : 'text'), nameEl, dot),
    ibtn('search', 'Find (Ctrl+F)', () => find()), wrapB, mdB, it.fresh ? null : ibtn('download', 'Download', () => download([it])), saveB),
    el('div', { class: 'edb' }, pane, md), el('div', { class: 'edf' }, st.pos, st.len, el('span', { class: 'sp' }), st.lang, el('span', { text: 'UTF-8' }), el('span', { text: 'LF' })));
  let lines = 0, hT = 0;
  function paintCode() {
    const v = ta.value;
    pre.innerHTML = highlight(v, lng) + '\n ';
    const n = v.split('\n').length;
    if (n !== lines) { lines = n; let s = ''; for (let i = 1; i <= n; i++) s += i + '\n'; gutIn.textContent = s; gutIn.style.whiteSpace = 'pre'; }
    if (!md.hidden) md.innerHTML = markdown(v);
    sync();
  }
  function sync() { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; gutIn.style.transform = 'translateY(' + -ta.scrollTop + 'px)'; }
  function status() {
    const v = ta.value, p = ta.selectionStart, before = v.slice(0, p), ln = before.split('\n').length, col = p - before.lastIndexOf('\n');
    st.pos.textContent = 'Ln ' + ln + ', Col ' + col + (ta.selectionEnd > p ? ' (' + (ta.selectionEnd - p) + ' selected)' : '');
    st.len.textContent = lines + ' lines · ' + human(new Blob([v]).size);
  }
  function setDirty(d) { dirty = d; dot.hidden = !d; }
  ta.addEventListener('input', () => { setDirty(ta.value !== saved); clearTimeout(hT); if (ta.value.length < 60000) paintCode(); else hT = setTimeout(paintCode, 120); status(); });
  ta.addEventListener('scroll', sync);
  for (const ev of ['keyup', 'click', 'select']) ta.addEventListener(ev, status);
  function replaceSel(text, selStart, selEnd) {
    // execCommand keeps the browser's undo history; where it is gone the text is set directly.
    ta.focus();
    if (!document.execCommand || !document.execCommand('insertText', false, text)) ta.setRangeText(text, ta.selectionStart, ta.selectionEnd, 'end');
    if (selStart != null) ta.setSelectionRange(selStart, selEnd);
    ta.dispatchEvent(new Event('input'));
  }
  ta.addEventListener('keydown', e => {
    const v = ta.value, s = ta.selectionStart, en = ta.selectionEnd;
    if (e.key === 'Tab') {
      e.preventDefault();
      const ls = v.lastIndexOf('\n', s - 1) + 1;
      if (s === en && !e.shiftKey) { replaceSel('    '); return; }
      const le = v.indexOf('\n', en - (en > s && v[en - 1] === '\n' ? 1 : 0)); const blockEnd = le < 0 ? v.length : le;
      const block = v.slice(ls, blockEnd);
      const out = e.shiftKey ? block.replace(/^(?: {1,4}|\t)/gm, '') : block.replace(/^/gm, '    ');
      ta.setSelectionRange(ls, blockEnd); replaceSel(out, ls, ls + out.length);
    } else if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey) {
      const ls = v.lastIndexOf('\n', s - 1) + 1, ind = /^[ \t]*/.exec(v.slice(ls, s))[0];
      const extra = /[{[(:]\s*$/.test(v.slice(ls, s)) ? '    ' : '';
      e.preventDefault(); replaceSel('\n' + ind + extra);
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); save(); }
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') { e.preventDefault(); find(); }
    else if ((e.ctrlKey || e.metaKey) && e.key === '/' ) {
      e.preventDefault();
      const cm = { Python: '# ', Shell: '# ', YAML: '# ', INI: '# ', Lua: '-- ', SQL: '-- ' }[lng && lng.name] || '// ';
      const ls = v.lastIndexOf('\n', s - 1) + 1, le0 = v.indexOf('\n', Math.max(s, en - 1)), le = le0 < 0 ? v.length : le0;
      const block = v.slice(ls, le), on = block.split('\n').every(x => !x.trim() || x.trimStart().startsWith(cm.trim()));
      const out = on ? block.replace(new RegExp('^(\\s*)' + cm.trim().replace(/[/\\^$*+?.()|[\]{}-]/g, '\\$&') + ' ?', 'gm'), '$1') : block.replace(/^(\s*)(?=\S)/gm, '$1' + cm);
      ta.setSelectionRange(ls, le); replaceSel(out, ls, ls + out.length);
    } else if (e.altKey && e.key.toLowerCase() === 'z') { e.preventDefault(); wrapB.click(); }
    else if (isMd && (e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'v') { e.preventDefault(); mdB.click(); }
  });
  // Find and replace.
  let fb = null;
  function find() {
    if (fb) { fb.querySelector('input').focus(); fb.querySelector('input').select(); return; }
    const q = el('input', { class: 'inp', placeholder: 'Find', spellcheck: 'false' }), r = el('input', { class: 'inp', placeholder: 'Replace', spellcheck: 'false' });
    const cnt = el('span', { class: 'c' });
    const all = () => { const s = q.value.toLowerCase(); if (!s) return []; const v = ta.value.toLowerCase(), out = []; let i = v.indexOf(s); while (i >= 0 && out.length < 100000) { out.push(i); i = v.indexOf(s, i + s.length); } return out; };
    const goTo = d => {
      const hits = all(); if (!hits.length) { cnt.textContent = q.value ? 'no match' : ''; return; }
      const from = d > 0 ? ta.selectionEnd : ta.selectionStart;
      let k = d > 0 ? hits.findIndex(h => h >= from) : hits.length - 1 - hits.slice().reverse().findIndex(h => h < from);
      if (k < 0 || k >= hits.length) k = d > 0 ? 0 : hits.length - 1;
      ta.focus(); ta.setSelectionRange(hits[k], hits[k] + q.value.length);
      const ln = ta.value.slice(0, hits[k]).split('\n').length;
      ta.scrollTop = Math.max(0, (ln - 5) * 21.45); sync(); status();
      cnt.textContent = (k + 1) + ' / ' + hits.length; q.focus();
    };
    q.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); goTo(e.shiftKey ? -1 : 1); } else if (e.key === 'Escape') { e.stopPropagation(); closeFind(); } });
    r.addEventListener('keydown', e => { if (e.key === 'Escape') { e.stopPropagation(); closeFind(); } });
    q.addEventListener('input', () => { const n = all().length; cnt.textContent = q.value ? (n ? n + ' found' : 'no match') : ''; });
    const replOne = () => { if (ta.value.slice(ta.selectionStart, ta.selectionEnd).toLowerCase() === q.value.toLowerCase() && q.value) replaceSel(r.value); goTo(1); };
    const replAll = () => { if (!q.value) return; const re = new RegExp(q.value.replace(/[/\\^$*+?.()|[\]{}-]/g, '\\$&'), 'gi'); const n = all().length; ta.select(); replaceSel(ta.value.replace(re, () => r.value), 0, 0); cnt.textContent = n + ' replaced'; };
    fb = el('div', { class: 'find' }, q, cnt, ibtn('left', 'Previous (Shift+Enter)', () => goTo(-1)), ibtn('chev', 'Next (Enter)', () => goTo(1)), r,
      btn(null, 'Replace', replOne, 'sm'), btn(null, 'All', replAll, 'sm'), ibtn('close', 'Close', () => closeFind()));
    pane.append(fb);
    const s = ta.value.slice(ta.selectionStart, ta.selectionEnd); if (s && !s.includes('\n')) q.value = s;
    q.focus(); q.select();
  }
  function closeFind() { if (fb) { fb.remove(); fb = null; ta.focus(); } }
  async function save() {
    saveB.disabled = true;
    try {
      const body = ta.value;
      await must(await api('PUT', '/~dav/' + enc(it.segs), { body, headers: { 'Content-Type': (MIME[ext(it.name)] || 'text/plain') + '; charset=utf-8' } }));
      saved = body; setDirty(false);
      toast('Saved ' + it.name);
      if (it.fresh) { it.fresh = false; }
      reloadSoon();
    } catch (e) { fail(e); }
    saveB.disabled = false;
  }
  L.esc = async () => {
    if (fb) return closeFind();
    if (dirty && !(await ask({ title: 'Discard your changes?', text: it.name + ' has changes that are not saved.', ok: 'Discard', danger: true }))) return;
    L.close();
  };
  const unload = e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', unload);
  L.onclose = () => window.removeEventListener('beforeunload', unload);
  if (!it.fresh) {
    ta.disabled = true; pre.textContent = 'Loading…';
    try {
      const r = await must(await api('GET', '/~dav/' + enc(it.segs)));
      const buf = await r.arrayBuffer();
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); }
      catch (e) { if (!(await ask({ title: 'Not UTF-8 text', text: it.name + ' does not read as UTF-8 text. Opening it anyway shows replacement characters, and saving would change the file.', ok: 'Open anyway' }))) { L.close(); return; } text = new TextDecoder('utf-8').decode(buf); }
      saved = text.replace(/\r\n/g, '\n'); ta.value = saved;
      if (saved !== text) { setDirty(true); toast('Line endings were turned into LF; saving keeps that'); }
    } catch (e) { pre.textContent = e.message; return; }
    ta.disabled = false;
  } else setDirty(true);
  paintCode(); status();
  if (isMd && saved) mdB.click();
  ta.focus(); ta.setSelectionRange(0, 0);
}

// ─── sending ────────────────────────────────────────────────────────────────
// A file sent as wormhole sends one: uploaded into the library's Sent folder, behind a link that ends after a time or
// a number of downloads, and that takes the file with it when it does.
// Where what is only for a while is kept: a library of the user's own, tmp-<user>, made when it is first needed.
function tmpName() {
  const u = me && me.user ? me.user.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 59) : '';
  return u ? 'tmp-' + u : 'tmp';
}
async function tmpLibrary() {
  const name = tmpName();
  const r = await api('PROPFIND', '/~dav/' + name + '/', { headers: { Depth: '0' } });
  if (r.status === 404) { await must(await api('MKCOL', '/~dav/' + name + '/')); buckets = (await propfind([])).filter(b => b.dir); side(); }
  else await must(r);
  return name;
}
function sendDlg(preset) {
  const files = [...(preset || [])];
  let exp = 86400, lim = 1;
  const fin = el('input', { type: 'file', multiple: true, hidden: true });
  const list = el('div', { class: 'sfl' });
  const dz = el('div', { class: 'dz', onclick: () => fin.click() }, el('span', { class: 'bub' }, ico('send')), el('b', { text: 'Drop files to send' }), el('span', { class: 'mut', text: 'or click to choose them' }));
  const paintList = () => { list.textContent = ''; files.forEach((f, i) => list.append(el('div', {}, ico(ICON[kind(f.name, f.type)]), el('span', { text: f.name }), el('small', { class: 'mut', text: human(f.size) }), ibtn('close', 'Remove', () => { files.splice(i, 1); paintList(); })))); go.disabled = !files.length; };
  fin.onchange = () => { files.push(...fin.files); fin.value = ''; paintList(); };
  dz.addEventListener('dragover', e => { e.preventDefault(); e.stopPropagation(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', e => { e.preventDefault(); e.stopPropagation(); dz.classList.remove('over'); files.push(...e.dataTransfer.files); paintList(); });
  const pills = (opts, get, set) => { const p = el('div', { class: 'pills' }); const paint = () => { p.textContent = ''; for (const [v, t] of opts) p.append(el('button', { class: get() === v ? 'on' : '', text: t, onclick: () => { set(v); paint(); } })); }; paint(); return p; };
  const pw = el('input', { class: 'inp', type: 'password', placeholder: 'None', autocomplete: 'new-password' });
  let snf;
  const body = el('div', {}, dz, fin, list,
    el('div', { class: 'fld' }, el('label', { text: 'Deleted after' }), pills([[3600, '1 hour'], [86400, '1 day'], [604800, '7 days'], [2592000, '30 days']], () => exp, v => exp = v)),
    el('div', { class: 'fld' }, el('label', { text: 'Downloads' }), pills([[1, '1'], [3, '3'], [10, '10'], [100, '100'], [0, 'Unlimited']], () => lim, v => lim = v)),
    el('div', { class: 'fld' }, el('label', { text: 'Password' }), pw),
    (snf = notifyField()).el,
    el('div', { class: 'fld' }, el('label', { text: 'Kept in' }), el('span', { class: 'mut', text: tmpName() + ', your library for temporary files, until the link ends' })));
  const go = btn('send', 'Send', () => send(), 'pri');
  go.disabled = true;
  const L = modal('Send files', body, [go]);
  paintList();
  async function send() {
    let lib;
    try { lib = await tmpLibrary(); } catch (e) { toast('The library for temporary files could not be made: ' + e.message, 'bad', 7000); return; }
    const n = files.length;
    const stamp = new Date().toISOString().slice(0, 10) + '-' + Math.random().toString(36).slice(2, 8);
    const base = [lib, stamp];
    const total = files.reduce((a, f) => a + f.size, 0);
    const bar = el('div', { class: 'sbar' }, el('i')), note = el('div', { class: 'mut', style: 'text-align:center;font-size:13px' });
    body.textContent = ''; L.box.querySelector('.df').remove();
    body.append(el('div', { class: 'sres' }, el('div', { class: 'bub' }, ico('upload')), el('h4', { text: 'Sending ' + (n === 1 ? files[0].name : n + ' files') })), bar, note);
    const jobs = []; let ended = 0, failed = false;
    const tickT = setInterval(() => { const s = jobs.reduce((a, j) => a + sentOf(j), 0); bar.firstChild.style.width = (100 * s / Math.max(1, total)) + '%'; const r = jobs.reduce((a, j) => a + (j.rate || 0), 0); note.textContent = human(s) + ' of ' + human(total) + (r > 0 ? ' · ' + human(r) + '/s · ' + clock((total - s) / r) + ' left' : ''); }, 300);
    await new Promise(res => { for (const f of files) jobs.push(enqueue(f, f.name, base, j => { if (j.state !== 'done') failed = true; if (++ended === n) res(); })); });
    clearInterval(tickT);
    if (failed) { body.textContent = ''; body.append(el('div', { class: 'sres' }, el('h4', { text: 'The upload did not finish' }), el('p', { class: 'mut', text: 'Nothing was sent. What did arrive is in ' + base.join('/') + '.' }))); return; }
    try {
      const key = base.slice(1).join('/') + '/' + (n === 1 ? files[0].name : '');
      const r = await must(await api('POST', '/~share', { body: JSON.stringify({ bucket: lib, key, expires_in: exp, max_downloads: lim * n, password: pw.value, burn: true, note: 'sent', notify: snf.value() || undefined }) }));
      const url = location.origin + (await r.json()).url;
      const inp = el('input', { class: 'inp', value: url, readonly: '' });
      const ends = [exp >= 86400 ? exp / 86400 + (exp === 86400 ? ' day' : ' days') : '1 hour', lim ? lim + (lim === 1 ? ' download' : ' downloads') + (n > 1 ? ' of each file' : '') : ''].filter(Boolean).join(' or ');
      body.textContent = '';
      body.append(el('div', { class: 'sres' }, el('div', { class: 'bub' }, ico('check')), el('h4', { text: 'Ready to share' }),
        el('p', { class: 'mut', text: (n === 1 ? files[0].name : n + ' files') + ' · ' + human(total) + ' · deleted after ' + ends + (pw.value ? ' · with a password' : '') })),
        el('div', { class: 'lnk' }, inp, btn('link', 'Copy', () => copy(url, inp), 'pri')));
      copy(url, inp);
      if (path[0] === lib) reloadSoon();
    } catch (e) { fail(e); }
  }
}

// ─── uploads ────────────────────────────────────────────────────────────────
// Several files at once, and a large file in parts side by side over /~dav/'s multipart, so a line with latency is
// filled by more than one connection. A part is tried again a few times; a file whose connection is lost is paused,
// not given up, and taken up again when the line is back or on a click. Any upload can be paused by hand, one or all.
// Every upload is remembered in IndexedDB until it ends, so a reload or a closed tab leaves it paused rather than gone:
// a small file with its bytes, which go on in any browser with one click; a large one with the handle Chrome and Edge
// hand out for a picked or dropped file, which needs one click too; else its file is chosen again, all of them in one
// dialog or by dropping them, and each is matched to its upload by name, size and time. A large one goes on from the
// parts the server says arrived.
const UP = { jobs: [], busy: 0, slots: 4, ui: null, rate: 0, lastBytes: 0, lastT: 0, ticking: 0, watching: 0, sending: 0 };
// A browser keeps six connections to a server that speaks HTTP/1.1, as this one does, for all its tabs together; while
// a film or a song plays in any tab of it, uploads take one of them, so the player's segments never wait behind them,
// and four again once it is closed. Tabs tell each other on a channel, a player every 5 s while it is open.
const PLAYERS = new Map();
const playCh = 'BroadcastChannel' in window ? new BroadcastChannel('skl-play') : null;
const tabId = Math.random().toString(36).slice(2);
const othersWatching = () => { const now = Date.now(); for (const [k, t] of PLAYERS) if (now - t > 12000) PLAYERS.delete(k); return PLAYERS.size > 0; };
// Over HTTP/2 every request shares one connection and none waits for a free one, so a player and uploads go side by
// side and uploads keep all their places; the limit above is HTTP/1.1's.
const overH2 = (() => { try { return (performance.getEntriesByType('navigation')[0] || {}).nextHopProtocol === 'h2'; } catch (e) { return false; } })();
const upSlots = () => !overH2 && (UP.watching || othersWatching()) ? 1 : UP.slots;
let playBeat = 0;
if (playCh) playCh.onmessage = e => {
  const m = e.data || {};
  if (m.on) { const fresh = !PLAYERS.has(m.id); PLAYERS.set(m.id, Date.now()); if (fresh) giveWay(); }
  else { PLAYERS.delete(m.id); if (UP.jobs.length) schedule(); }
};
// The requests past that one give way at once: each is ended and its part, or its file sent whole, is queued again;
// the one furthest along goes on.
function giveWay() {
  if (overH2) return;
  const data = UP.jobs.flatMap(j => [...j.xhrs].filter(x => x._data)).sort((a, b) => (b._sent || 0) - (a._sent || 0));
  for (const x of data.slice(1)) { x._yield = true; x.abort(); }
}
function watchingStart() {
  UP.watching++;
  giveWay();
  if (playCh && UP.watching === 1) { playCh.postMessage({ id: tabId, on: true }); playBeat = setInterval(() => playCh.postMessage({ id: tabId, on: true }), 5000); }
}
function watchingEnd() {
  UP.watching = Math.max(0, UP.watching - 1);
  if (playCh && !UP.watching) { clearInterval(playBeat); playCh.postMessage({ id: tabId, on: false }); }
  if (UP.jobs.length) schedule();
}
window.addEventListener('pagehide', () => { if (playCh && UP.watching) playCh.postMessage({ id: tabId, on: false }); });
const PART_FROM = 48 << 20;
function partSize(n) { return Math.max(16 << 20, Math.ceil(n / 9000 / (1 << 20)) << 20); }
const KEEP = 'skl-upload:';
function makeParts(size, ps) { const out = []; for (let o = 0, n = 1; o < size; o += ps, n++) out.push({ n, from: o, to: Math.min(size, o + ps), state: 'todo', tries: 0 }); return out; }
// The uploads kept, by a key of their own: one write a moment for all that changed, in one transaction, so a folder of
// thousands is a handful of writes.
const UDB = (() => {
  let opening = null, pending = new Map(), flushT = 0;
  const open = () => opening || (opening = new Promise(res => {
    try {
      const r = indexedDB.open('skl-uploads', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('jobs', { keyPath: 'k' });
      r.onsuccess = () => res(r.result); r.onerror = () => res(null); r.onblocked = () => res(null);
    } catch (e) { res(null); }
  }));
  function flush() {
    flushT = 0;
    const ops = pending; pending = new Map();
    return open().then(d => new Promise(res => {
      if (!d || !ops.size) return res();
      try {
        const t = d.transaction('jobs', 'readwrite'), st = t.objectStore('jobs');
        for (const [k, v] of ops) v ? st.put(v) : st.delete(k);
        t.oncomplete = t.onerror = t.onabort = () => res();
      } catch (e) { res(); }
    }));
  }
  const later = () => { if (!flushT) flushT = setTimeout(flush, 150); };
  return {
    put(rec) { pending.set(rec.k, rec); later(); },
    del(k) { pending.set(k, null); later(); },
    now() { clearTimeout(flushT); return flush(); },
    async all() {
      const d = await open(); if (!d) return [];
      return new Promise(res => { try { const r = d.transaction('jobs').objectStore('jobs').getAll(); r.onsuccess = () => res(r.result || []); r.onerror = () => res([]); } catch (e) { res([]); } });
    }
  };
})();
// A small file's bytes are kept with it, up to this much for all of them together, so it goes on after a reload in any
// browser; a larger one, or past that, is kept by its handle where the browser gives one, else by its name.
const STASH_MAX = 512 << 20;
UP.stashed = 0;
function remember(j) {
  if (j.onend || ['done', 'error', 'canceled'].includes(j.state)) return;
  const f = j.file;
  if (j.stash === undefined) {
    j.stash = !!f && !j.parts && UP.stashed + j.size <= STASH_MAX;
    if (j.stash) UP.stashed += j.size;
  }
  UDB.put({ k: j.k, segs: j.segs, size: j.size, mod: f ? f.lastModified : j.mod, type: f ? f.type : j.type, ps: j.ps, id: j.id || null,
            paused: j.state === 'paused' && j.why === 'user', handle: j.handle || null, root: j.root || null,
            blob: j.stash ? f : null, tab: tabId, at: j.at || (j.at = Date.now()) });
}
function forget(j) {
  if (j.k) UDB.del(j.k);
  if (j.id) store.del(KEEP + j.id);
  if (j.stash) { UP.stashed = Math.max(0, UP.stashed - j.size); j.stash = false; }
}
const newKey = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
function enqueue(file, rel, base, onend, handle, root) {
  const segs = [...(base || path), ...rel.split('/').filter(Boolean)];
  // A file chosen again for an upload a reload paused takes that upload up instead of beginning another.
  if (!onend) { const left = staleFor(file, segs); if (left) { adopt(left, file, handle); return left; } }
  const j = { k: newKey(), file, segs, name: segs[segs.length - 1], dir: segs.slice(0, -1).join('/'), size: file.size, state: 'queued', tries: 0, sent: 0,
              inflight: new Map(), xhrs: new Set(), rate: 0, hist: [], onend, handle: handle || null, root: root || null };
  if (file.size >= PART_FROM) { j.ps = partSize(file.size); j.parts = makeParts(file.size, j.ps); }
  UP.jobs.push(j);
  remember(j);
  paintUploads(); schedule();
  return j;
}
// The parts of upload `j` the server has, pages of them, marked done with their ETags; false when the upload is gone.
async function arrived(j) {
  let marker = '';
  for (;;) {
    const r = await api('GET', url(j) + '?uploadId=' + encodeURIComponent(j.id) + (marker ? '&part-number-marker=' + marker : ''));
    if (!r.ok) return false;
    const doc = new DOMParser().parseFromString(await r.text(), 'application/xml');
    const t = (e, n) => { const x = e.getElementsByTagName(n)[0]; return x ? x.textContent : ''; };
    for (const e of doc.getElementsByTagName('Part')) {
      const p = j.parts[+t(e, 'PartNumber') - 1];
      if (p && +t(e, 'Size') === p.to - p.from && p.state !== 'done') { p.state = 'done'; p.etag = t(e, 'ETag'); j.sent += p.to - p.from; }
    }
    if (t(doc, 'IsTruncated') !== 'true') return true;
    marker = t(doc, 'NextPartNumberMarker');
  }
}
// A tab holds a lock as long as it is open, so the uploads another open tab is sending are not taken up here as well.
if (navigator.locks) navigator.locks.request('skl-up-' + tabId, () => new Promise(() => {})).catch(() => {});
// The uploads a closed or reloaded page left, paused: those whose bytes or handle were kept go on with a click, the
// others once their file is chosen again. A large one keeps the parts the server has.
async function restore() {
  const recs = await UDB.all();
  // Those an older page kept by their multipart upload alone.
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i); if (!key.startsWith(KEEP)) continue;
      const id = key.slice(KEEP.length);
      let v; try { v = JSON.parse(store.get(key, 'null')); } catch (e) {}
      if (v && v.segs && !recs.some(r => r.id === id)) recs.push({ k: newKey(), segs: v.segs, size: v.size, mod: v.mod, ps: v.ps, id, old: true });
    }
  } catch (e) {}
  let held = new Set();
  try { if (navigator.locks) held = new Set(((await navigator.locks.query()).held || []).map(l => l.name)); } catch (e) {}
  recs.sort((a, b) => (a.at || 0) - (b.at || 0));
  for (const v of recs) {
    if (!v.segs || UP.jobs.some(j => j.k === v.k || v.id && j.id === v.id) || v.tab && v.tab !== tabId && held.has('skl-up-' + v.tab)) continue;
    const j = { k: v.k, file: v.blob || null, segs: v.segs, name: v.segs[v.segs.length - 1], dir: v.segs.slice(0, -1).join('/'), size: v.size, mod: v.mod, type: v.type,
                ps: v.ps, id: v.id || null, handle: v.handle || null, root: v.root || null, stash: !!v.blob, at: v.at,
                state: 'paused', why: v.paused ? 'user' : 'page', tries: 0, sent: 0, inflight: new Map(), xhrs: new Set(), rate: 0, hist: [] };
    if (!j.file && !j.handle) j.state = 'stale';
    if (j.stash) UP.stashed += j.size;
    if (j.ps) {
      j.parts = makeParts(j.size, j.ps);
      // The server no longer holds it: it begins again when it goes on.
      if (j.id && !(await arrived(j))) { if (v.old) { store.del(KEEP + j.id); continue; } j.id = null; j.parts = makeParts(j.size, j.ps); j.sent = 0; }
    }
    UP.jobs.push(j);
    remember(j);
    if (v.old) store.del(KEEP + v.id);
  }
  paintUploads();
}
// A paused or left upload `j` whose file was chosen again, or dropped again into its folder, by the same name and size.
function staleFor(file, segs) {
  const at = segs.join('/');
  return UP.jobs.find(j => !j.file && (j.state === 'stale' || j.state === 'paused') && j.segs.join('/') === at && j.size === file.size) || null;
}
// Its file, changed since the upload began, taken up from the beginning.
function restartWith(j, f) {
  if (j.id) { xhr(j, 'DELETE', url(j) + '?uploadId=' + encodeURIComponent(j.id)); store.del(KEEP + j.id); j.id = null; }
  if (j.stash) { UP.stashed = Math.max(0, UP.stashed - j.size); }
  j.stash = undefined;
  j.file = f; j.size = f.size; j.mod = f.lastModified; j.sent = 0; j.tries = 0; j.inflight.clear();
  if (f.size >= PART_FROM) { j.ps = partSize(f.size); j.parts = makeParts(f.size, j.ps); } else { j.ps = undefined; j.parts = undefined; }
}
async function adopt(j, f, handle) {
  if (handle) j.handle = handle;
  if (j.mod && f.lastModified !== j.mod) {
    if (!(await ask({ title: 'A different version', text: f.name + ' was changed since its upload began. It is uploaded again from the beginning.', ok: 'Upload it again' }))) return false;
    restartWith(j, f);
  } else j.file = f;
  if (j.state === 'stale') { j.state = 'paused'; j.why = 'page'; }
  resume(j);
  return true;
}
// The file behind a kept handle, once the browser lets this page read it again; asked of its folder first, which then
// covers every file of it at once.
async function fromHandle(j) {
  try {
    let st = await j.handle.queryPermission({ mode: 'read' });
    if (st !== 'granted' && j.root && await j.root.requestPermission({ mode: 'read' }) === 'granted') st = await j.handle.queryPermission({ mode: 'read' });
    if (st !== 'granted') st = await j.handle.requestPermission({ mode: 'read' });
    if (st !== 'granted') return false;
    const f = await j.handle.getFile();
    if (f.size === j.size && (!j.mod || f.lastModified === j.mod)) { j.file = f; return true; }
    if (!(await ask({ title: 'A different version', text: f.name + ' was changed since its upload began. It is uploaded again from the beginning.', ok: 'Upload it again' }))) return false;
    restartWith(j, f);
    return true;
  } catch (e) { return false; }
}
// Files chosen in the dialog, each with the handle Chrome and Edge give for it, by which it goes on after a reload; null
// when nothing was chosen.
async function chooseFiles() {
  if (window.showOpenFilePicker) {
    try { const hs = await showOpenFilePicker({ multiple: true }); return (await Promise.all(hs.map(h => h.getFile().then(file => ({ file, handle: h }), () => null)))).filter(Boolean); }
    catch (e) { if (e.name === 'AbortError') return null; }
  }
  return new Promise(res => {
    const pick = el('input', { type: 'file', multiple: true });
    pick.onchange = () => res([...pick.files].map(file => ({ file, handle: null })));
    pick.oncancel = () => res(null);
    pick.click();
  });
}
// The files of uploads left without them, all chosen in one dialog and each matched to its upload by name and size.
async function pickFor(list) {
  const got = await chooseFiles(); if (!got) return;
  let n = 0;
  for (const { file, handle } of got) {
    const j = list.find(j => !j.file && (j.state === 'stale' || j.state === 'paused') && j.name === file.name && j.size === file.size);
    if (j && await adopt(j, file, handle)) n++;
  }
  if (n < got.length) toast(got.length - n === 1 ? got[0].file.name + ' is not the file of a paused upload' : (got.length - n) + ' of the chosen files belong to no paused upload', 'bad', 6000);
}
// Upload `j` goes on: at once when its file is at hand, else after the browser lets its handle be read, else once it is
// chosen again.
async function resume(j) {
  if (j.state !== 'paused' && j.state !== 'stale') return;
  if (!j.file && !(j.handle && await fromHandle(j))) return pickFor(UP.jobs.filter(o => !o.file && (o.state === 'stale' || o.state === 'paused')));
  if (j.state !== 'paused' && j.state !== 'stale') return;
  for (const p of j.parts || []) if (p.state === 'sending') p.state = 'todo';
  j.state = j.parts && j.id ? 'running' : 'queued'; j.why = ''; j.err = ''; j.hist = []; j.tries = 0;
  remember(j); schedule(); paintUploads();
}
async function resumeAll() {
  const held = UP.jobs.filter(j => j.state === 'paused' || j.state === 'stale');
  const want = [];
  for (const j of held) { if (j.file || j.handle && await fromHandle(j)) resume(j); else want.push(j); }
  if (want.length) pickFor(want);
}
function pauseAll() { for (const j of UP.jobs) pause(j, 'user'); }
window.addEventListener('online', () => { for (const j of UP.jobs) if (j.state === 'paused' && j.why === 'line') resume(j); });
// A server restarting, or a line lost past the browser, never says it is back: such an upload is tried again every
// 15 s, and pauses again if it is still gone.
setInterval(() => { if (navigator.onLine !== false) for (const j of UP.jobs) if (j.state === 'paused' && j.why === 'line' && Date.now() - j.pausedAt > 15000) resume(j); }, 5000);
function xhr(j, method, url, body, headers, onprog) {
  return new Promise(res => {
    const x = new XMLHttpRequest();
    x.open(method, url);
    x.setRequestHeader('X-Socketley-UI', '1');
    for (const [k, v] of Object.entries(headers || {})) x.setRequestHeader(k, v);
    // A request carrying a file's bytes, and how many it has sent, which the player's turn looks at.
    x._data = method === 'PUT';
    if (x._data) UP.sending++;
    x.upload.onprogress = e => { x._sent = e.loaded; if (onprog) onprog(e.loaded); };
    x.onloadend = () => { if (x._data) UP.sending--; j.xhrs.delete(x); res({ status: x.status, text: x.responseText || '', etag: x.getResponseHeader('ETag'), yielded: !!x._yield }); };
    j.xhrs.add(x);
    x.send(body);
  });
}
// The next step of one file, marked as taken: its whole PUT, its start, a part, or its completion.
function stepOf(j) {
  if (j.state === 'queued' && !j.parts) { j.state = 'running'; return () => putWhole(j); }
  if (!j.parts || ['done', 'error', 'canceled', 'paused', 'stale'].includes(j.state)) return null;
  if (j.state === 'queued') { j.state = 'starting'; return () => begin(j); }
  if (j.state !== 'running') return null;
  const p = j.parts.find(p => p.state === 'todo');
  if (p) { p.state = 'sending'; return () => sendPart(j, p); }
  if (j.parts.every(p => p.state === 'done')) { j.state = 'finishing'; return () => finish(j); }
  return null;
}
// Up to three files go up side by side: a free place goes to the open file with the fewest requests on the way, and a
// queued file opens while fewer than three are open, so a large file's parts never hold every place.
const FILES_MAX = 3;
function nextTask() {
  const open = UP.jobs.filter(j => (j.active || 0) > 0 || ['running', 'starting', 'finishing'].includes(j.state));
  const order = open.slice().sort((a, b) => (a.active || 0) - (b.active || 0));
  if (open.length < FILES_MAX) order.unshift(...UP.jobs.filter(j => j.state === 'queued').slice(0, FILES_MAX - open.length));
  for (const j of order) { const t = stepOf(j); if (t) return [j, t]; }
  return null;
}
function schedule() {
  if (!UP.ticking) UP.ticking = setInterval(tick, 500);
  while (UP.busy < upSlots()) {
    const n = nextTask(); if (!n) break;
    const [j, t] = n;
    UP.busy++; j.active = (j.active || 0) + 1;
    if (!UP.jobs.some(j => j.started)) UP.started = Date.now();
    t().finally(() => { UP.busy--; j.active--; schedule(); paintUploads(); });
  }
  if (!UP.busy && !UP.jobs.some(j => ['queued', 'running', 'starting', 'finishing'].includes(j.state))) { clearInterval(UP.ticking); UP.ticking = 0; paintUploads(); }
}
// Each part's CRC-32, which the server checks against what arrived and refuses with BadDigest when they differ, so a
// part changed on its way, or by the file changing under the upload, is sent again rather than stored.
const CRC_T = (() => {
  const t = new Uint32Array(1024);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  for (let n = 0; n < 256; n++) for (let k = 1; k < 4; k++) t[k * 256 + n] = (t[(k - 1) * 256 + n] >>> 8) ^ t[t[(k - 1) * 256 + n] & 255];
  return t;
})();
function crc32(u8) {
  const t = CRC_T; let c = 0xFFFFFFFF, i = 0;
  // Four bytes a step, as slicing-by-4 does.
  for (const n = u8.length & ~3; i < n; i += 4) {
    c ^= u8[i] | u8[i + 1] << 8 | u8[i + 2] << 16 | u8[i + 3] << 24;
    c = t[768 + (c & 255)] ^ t[512 + (c >>> 8 & 255)] ^ t[256 + (c >>> 16 & 255)] ^ t[c >>> 24];
  }
  for (; i < u8.length; i++) c = t[(c ^ u8[i]) & 255] ^ (c >>> 8);
  c = (c ^ 0xFFFFFFFF) >>> 0;
  return btoa(String.fromCharCode(c >>> 24, c >>> 16 & 255, c >>> 8 & 255, c & 255));
}
// The bytes of a part, read once, and their CRC-32 header.
async function checked(blob) { const u8 = new Uint8Array(await blob.arrayBuffer()); return { body: u8, crc: { 'x-amz-checksum-crc32': crc32(u8) } }; }
const badDigest = r => r.status === 400 && /BadDigest/.test(r.text);
const url = j => '/~dav/' + enc(j.segs);
const typeOf = f => f.type || MIME[ext(f.name)] || '';
// Each pause counts up `gen`, so a step begun before it, still reading or sending when the upload goes on again,
// leaves what the new one does alone.
async function putWhole(j) {
  j.started = j.started || Date.now();
  const gen = j.gen = (j.gen || 0) + 1;
  for (;;) {
    let c;
    try { c = await checked(j.file); } catch (e) { if (gen === j.gen) { failed(j, { status: 0, text: '' }); j.err = 'the file could not be read'; } return; }
    if (gen !== j.gen || j.state !== 'running') return;
    // A player that began while the file was read takes the place it would have sent in.
    if (UP.sending >= upSlots()) { j.state = 'queued'; return; }
    const r = await xhr(j, 'PUT', url(j), c.body, Object.assign(typeOf(j.file) ? { 'Content-Type': typeOf(j.file) } : {}, c.crc), n => { j.inflight.set(0, n); });
    c = null;
    if (gen !== j.gen || j.state !== 'running') return;
    j.inflight.clear();
    if (r.yielded) { j.state = 'queued'; return; }
    if (r.status >= 200 && r.status < 300) { j.sent = j.size; return done(j); }
    if ((r.status === 0 || r.status >= 500 || badDigest(r)) && ++j.tries < 4) { await sleep(1000 * j.tries); if (gen !== j.gen || j.state !== 'running') return; continue; }
    // A lost line pauses it; a refusal ends it.
    if (r.status === 0 || r.status >= 500) return pause(j, 'line');
    return failed(j, r);
  }
}
async function begin(j) {
  j.started = Date.now();
  const r = await xhr(j, 'POST', url(j) + '?uploads', null, typeOf(j.file) ? { 'Content-Type': typeOf(j.file) } : null);
  if (j.state === 'canceled') return;
  const m = /<UploadId>([^<]+)<\/UploadId>/.exec(r.text);
  // Paused while it began, it stays so, with the upload the server opened if it did.
  if (j.state === 'paused') { if (r.status === 200 && m) { j.id = m[1]; remember(j); } return; }
  if (r.status === 0 || r.status >= 500) return pause(j, 'line');
  if (r.status !== 200 || !m) return failed(j, r);
  j.id = m[1]; j.state = 'running';
  remember(j);
}
async function sendPart(j, p) {
  const gen = j.gen || 0;
  for (;;) {
    let c;
    try { c = await checked(j.file.slice(p.from, p.to)); } catch (e) { if (gen === (j.gen || 0)) { failed(j, { status: 0, text: '' }); j.err = 'the file could not be read'; } return; }
    if (gen !== (j.gen || 0) || j.state !== 'running') return;
    if (UP.sending >= upSlots()) { p.state = 'todo'; return; }
    const r = await xhr(j, 'PUT', url(j) + '?partNumber=' + p.n + '&uploadId=' + encodeURIComponent(j.id), c.body, c.crc, n => j.inflight.set(p.n, n));
    c = null;
    // A part the server took counts even when the upload was paused meanwhile.
    if (r.status === 200 && r.etag && p.state !== 'done') { p.etag = r.etag; p.state = 'done'; j.sent += p.to - p.from; }
    if (gen !== (j.gen || 0)) return;
    j.inflight.delete(p.n);
    if (j.state !== 'running') return;
    if (r.yielded) { p.state = 'todo'; return; }
    if (r.status === 200 && r.etag) return;
    if ((r.status === 0 || r.status >= 500 || badDigest(r)) && ++p.tries < 5) { await sleep(800 * p.tries); if (gen !== (j.gen || 0) || j.state !== 'running') return; continue; }
    // A lost line pauses the file with what arrived kept; a refusal ends it.
    if (r.status === 0 || r.status >= 500) { p.state = 'todo'; p.tries = 0; pause(j, 'line'); return; }
    failed(j, r);
    xhr(j, 'DELETE', url(j) + '?uploadId=' + encodeURIComponent(j.id));
    forget(j);
    return;
  }
}
async function finish(j) {
  const body = '<CompleteMultipartUpload>' + j.parts.map(p => '<Part><PartNumber>' + p.n + '</PartNumber><ETag>' + p.etag + '</ETag></Part>').join('') + '</CompleteMultipartUpload>';
  const r = await xhr(j, 'POST', url(j) + '?uploadId=' + encodeURIComponent(j.id), body, { 'Content-Type': 'application/xml' });
  if (j.state === 'canceled') return;
  if (r.status === 200 && !/<Error>/.test(r.text)) return done(j);
  failed(j, r);
}
// Upload `j` paused: by hand ('user'), which only a click ends, or by a lost line ('line'), which ends when the line is
// back. What is on its way is let go, a part to be sent again; what arrived is kept.
function pause(j, why) {
  if (j.state === 'paused' || j.state === 'stale') { if (why === 'user' && j.why !== 'user') { j.why = 'user'; remember(j); paintUploads(); } return; }
  if (!['queued', 'running', 'starting'].includes(j.state)) return;
  j.state = 'paused'; j.why = why; j.gen = (j.gen || 0) + 1; j.pausedAt = Date.now();
  for (const x of [...j.xhrs]) if (x._data) x.abort();
  for (const p of j.parts || []) if (p.state === 'sending') p.state = 'todo';
  j.inflight.clear(); j.rate = 0;
  if (why === 'line' && !j.told) { j.told = true; toast(j.name + ' is paused: it goes on when the server is reachable again', 'bad', 6000); }
  remember(j); paintUploads(); schedule();
}
// A picture's or a film's media are asked for as soon as it is up, so the server makes them while nobody waits: its
// thumbnails and facts, and where this browser would not play the file itself, the start of its stream.
async function warm(j) {
  const k = kind(j.name, j.file && j.file.type), obj = enc(j.segs);
  const quiet = u => fetch(u, { headers: { 'X-Socketley-UI': '1' } }).then(r => r.ok ? r : null).catch(() => null);
  if (k === 'image') { quiet('/~media/thumb-320/' + obj); return; }
  if (k !== 'video') return;
  quiet('/~media/thumb-480/' + obj); quiet('/~media/thumb-1280/' + obj);
  const r = await quiet('/~media/info/' + obj);
  const m = r && await r.json().catch(() => null);
  if (!m || (m.mime && document.createElement('video').canPlayType(m.mime))) return;
  const master = await quiet('/~media/hls/' + obj + '/master.m3u8');
  const first = master && (await master.text()).split('\n').find(l => l && !l.startsWith('#'));
  if (!first) return;
  const url = new URL(first, location.origin + '/~media/hls/' + obj + '/master.m3u8').href;
  const list = await quiet(url); const seg = list && (await list.text()).split('\n').find(l => l && !l.startsWith('#'));
  if (seg) quiet(new URL(seg, url).href);
}
function done(j) { forget(j); warm(j); j.state = 'done'; j.ended = Date.now(); if (j.onend) j.onend(j); if (j.dir === path.join('/') || path.length && j.dir.startsWith(path.join('/') + '/')) reloadSoon(); }
function failed(j, r) {
  if (j.state === 'error') return;
  j.state = 'error'; j.ended = Date.now();
  const m = /<Message>([^<]*)/.exec(r.text);
  j.err = r.status ? r.status + ' ' + (m ? m[1] : (r.text || '').trim().slice(0, 120)) : 'the connection was lost';
  if (j.k) UDB.del(j.k);
  if (j.onend) j.onend(j);
  for (const x of j.xhrs) x.abort();
  toast('Upload of ' + j.name + ' failed: ' + j.err, 'bad', 7000);
}
function cancel(j) {
  if (['done', 'error', 'canceled'].includes(j.state)) { UP.jobs.splice(UP.jobs.indexOf(j), 1); paintUploads(); return; }
  j.state = 'canceled'; j.ended = Date.now();
  for (const x of [...j.xhrs]) x.abort();
  if (j.onend) j.onend(j);
  if (j.id) xhr(j, 'DELETE', url(j) + '?uploadId=' + encodeURIComponent(j.id));
  forget(j);
  paintUploads(); schedule();
}
const sentOf = j => j.state === 'done' ? j.size : j.sent + [...j.inflight.values()].reduce((a, b) => a + b, 0);
function tick() {
  const now = performance.now();
  for (const j of UP.jobs) {
    if (!['running', 'starting', 'finishing'].includes(j.state)) continue;
    j.hist.push([now, sentOf(j)]); while (j.hist.length > 12) j.hist.shift();
    const [t0, b0] = j.hist[0]; j.rate = j.hist.length > 1 ? (sentOf(j) - b0) / ((now - t0) / 1000) : 0;
  }
  // A player in another tab that stopped telling, closed without a word, gives its places back.
  if (UP.busy < upSlots()) schedule();
  paintUploads();
}
function paintUploads() {
  const live = UP.jobs.filter(j => ['queued', 'running', 'starting', 'finishing'].includes(j.state));
  if (!UP.jobs.length) { if (UP.ui) { UP.ui.remove(); UP.ui = null; } return; }
  if (!UP.ui) {
    UP.ui = el('div', { id: 'ups' });
    UP.head = el('div', { class: 'uh', onclick: e => { if (!e.target.closest('button')) UP.ui.classList.toggle('min'); } });
    UP.bar = el('div', { class: 'tot' }, el('i'));
    UP.body = el('div', { class: 'ub' });
    UP.ui.append(UP.head, UP.bar, UP.body); document.body.append(UP.ui);
    UP.rows = new Map();
  }
  const total = UP.jobs.filter(j => j.state !== 'canceled').reduce((a, j) => a + j.size, 0), sent = UP.jobs.filter(j => j.state !== 'canceled').reduce((a, j) => a + sentOf(j), 0);
  const rate = live.reduce((a, j) => a + (j.rate || 0), 0);
  const left = live.reduce((a, j) => a + j.size - sentOf(j), 0);
  UP.head.textContent = '';
  const errs = UP.jobs.filter(j => j.state === 'error').length, held = UP.jobs.filter(j => j.state === 'paused' || j.state === 'stale').length;
  const pausable = UP.jobs.filter(j => ['queued', 'running', 'starting'].includes(j.state)).length;
  UP.head.append(el('div', { class: 't' },
    el('b', { text: live.length ? 'Uploading ' + live.length + (live.length === 1 ? ' file' : ' files') + ' · ' + Math.floor(100 * sent / Math.max(1, total)) + '%' + (held ? ' · ' + held + ' paused' : '') : held ? held + ' upload' + (held > 1 ? 's' : '') + ' paused · ' + Math.floor(100 * sent / Math.max(1, total)) + '%' : errs ? errs + ' upload' + (errs > 1 ? 's' : '') + ' failed' : 'Uploads complete' }),
    el('small', { text: live.length ? human(rate) + '/s · ' + (rate > 0 ? clock(left / rate) + ' left' : 'starting…') + ' · ' + human(sent) + ' of ' + human(total) : held ? human(sent) + ' of ' + human(total) : UP.jobs.filter(j => j.state === 'done').length + ' done · ' + human(total) })),
    held && !pausable ? btn('play', held > 1 ? 'Resume all' : 'Resume', resumeAll, 'pri') : '',
    pausable > 1 ? ibtn('pause', 'Pause all', pauseAll) : '',
    live.length || held ? '' : ibtn('close', 'Clear', () => { UP.jobs = UP.jobs.filter(j => !['done', 'error', 'canceled'].includes(j.state)); paintUploads(); }));
  UP.bar.firstChild.style.width = (100 * sent / Math.max(1, total)) + '%';
  for (const [j, row] of UP.rows) if (!UP.jobs.includes(j)) { row.remove(); UP.rows.delete(j); }
  for (const j of UP.jobs) {
    let r = UP.rows.get(j);
    if (!r) {
      r = el('div', { class: 'uj' }, el('div', { class: 'n', text: j.name, title: j.segs.join('/') }), el('div', { class: 's' }), el('div', { class: 'p' }, el('i')));
      r.append(ibtn('close', 'Cancel', () => cancel(j), 'x'));
      r._pz = ibtn('pause', 'Pause', () => j.state === 'paused' || j.state === 'stale' ? resume(j) : pause(j, 'user'), 'pz');
      r.append(r._pz);
      r._go = btn('upload', 'Choose the file to resume', () => resume(j), 'sm pri');
      r._go.style.gridColumn = '1'; r._go.style.justifySelf = 'start'; r._go.style.marginTop = '6px';
      r.append(r._go);
      UP.rows.set(j, r); UP.body.append(r);
    }
    const held1 = j.state === 'paused' || j.state === 'stale';
    r._go.hidden = j.state !== 'stale';
    r._pz.hidden = !held1 && !['queued', 'running', 'starting'].includes(j.state);
    const pzWant = held1 ? 'play' : 'pause';
    if (r._pz._i !== pzWant) { r._pz._i = pzWant; r._pz.firstChild.innerHTML = P[pzWant]; r._pz.title = held1 ? 'Resume' : 'Pause'; r._pz.setAttribute('aria-label', r._pz.title); }
    const s = sentOf(j), pct = 100 * s / Math.max(1, j.size);
    r.className = 'uj' + (j.state === 'done' ? ' done' : j.state === 'error' ? ' err' : '');
    const started = j.started ? new Date(j.started).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    let text;
    if (j.state === 'queued') text = 'Waiting · ' + human(j.size);
    else if (j.state === 'done') { const secs = Math.max(0.001, (j.ended - j.started) / 1000); text = '✓ ' + human(j.size) + ' in ' + clock(secs) + ' · ' + human(j.size / secs) + '/s · started ' + started; }
    else if (j.state === 'error') text = 'Failed: ' + j.err;
    else if (j.state === 'canceled') text = 'Canceled';
    else if (j.state === 'paused') text = 'Paused at ' + pct.toFixed(0) + '% of ' + human(j.size) + (j.why === 'line' ? ' · the connection was lost' : j.why === 'page' ? ' · the page was closed' + (j.file ? '' : ' · resuming asks to read the file again') : '');
    else if (j.state === 'stale') text = 'Paused at ' + pct.toFixed(0) + '% of ' + human(j.size) + ' when the page was closed · choose the file again · in ' + j.dir;
    else text = pct.toFixed(pct < 10 ? 1 : 0) + '% · ' + human(s) + ' / ' + human(j.size) + ' · ' + (j.rate > 0 ? human(j.rate) + '/s · ' + clock((j.size - s) / j.rate) + ' left' : '…') + ' · started ' + started + (j.parts ? ' · ' + j.parts.length + ' parts' : '');
    r.children[1].textContent = text;
    r.children[2].firstChild.style.width = (j.state === 'canceled' ? 0 : pct) + '%';
    r.children[3].title = ['done', 'error', 'canceled'].includes(j.state) ? 'Remove' : 'Cancel';
  }
}
// Leaving asks first only while an upload is on its way that could not go on after: neither its bytes nor its handle kept.
window.addEventListener('beforeunload', e => {
  UDB.now();
  if (UP.jobs.some(j => ['queued', 'running', 'starting', 'finishing'].includes(j.state) && (j.onend || !j.stash && !j.handle))) { e.preventDefault(); e.returnValue = ''; }
});
window.addEventListener('pagehide', () => UDB.now());
// Files and folders are chosen with the dialogs that give handles where the browser has them, so they go on after a
// reload; elsewhere with the inputs.
async function upFiles() {
  const base = path.slice();
  if (!window.showOpenFilePicker) return $('#fi').click();
  let hs; try { hs = await showOpenFilePicker({ multiple: true }); } catch (e) { if (e.name !== 'AbortError') $('#fi').click(); return; }
  for (const h of hs) { try { const f = await h.getFile(); enqueue(f, f.name, base, null, h); } catch (e) {} }
}
async function upFolder() {
  const base = path.slice();
  if (!window.showDirectoryPicker) return $('#fd').click();
  let d; try { d = await showDirectoryPicker(); } catch (e) { if (e.name !== 'AbortError') $('#fd').click(); return; }
  await walkHandle(d, d.name + '/', base, d);
}
$('#bUp').onclick = upFiles;
$('#fi').onchange = () => { for (const f of $('#fi').files) enqueue(f, f.name); $('#fi').value = ''; };
$('#fd').onchange = () => { for (const f of $('#fd').files) enqueue(f, f.webkitRelativePath || f.name); $('#fd').value = ''; };
async function walkHandle(h, prefix, base, root) {
  try {
    for await (const c of h.values()) {
      if (c.kind === 'file') { try { const f = await c.getFile(); enqueue(f, prefix + c.name, base, null, c, root); } catch (e) {} }
      else await walkHandle(c, prefix + c.name + '/', base, root);
    }
  } catch (e) {}
}
async function walkEntry(entry, prefix, base) {
  if (entry.isFile) { await new Promise(res => entry.file(f => { enqueue(f, prefix + f.name, base); res(); }, res)); return; }
  if (entry.isDirectory) {
    const rd = entry.createReader();
    for (;;) {
      const batch = await new Promise(res => rd.readEntries(res, () => res([])));
      if (!batch.length) break;
      for (const e of batch) await walkEntry(e, prefix + entry.name + '/', base);
    }
  }
}
let dragDepth = 0, dropEl = null;
const dropShow = on => { if (on && !dropEl) { dropEl = el('div', { id: 'drop' }, ico('upload'), el('div', { text: 'Drop to upload into ' + path[path.length - 1] }), el('div', { class: 'mut', style: 'font-size:14px;font-weight:500', text: 'Files and whole folders' })); document.body.append(dropEl); } else if (!on && dropEl) { dropEl.remove(); dropEl = null; } };
window.addEventListener('dragenter', e => { if (auth && path.length && e.dataTransfer.types.includes('Files')) { dragDepth++; dropShow(true); } });
window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; dropShow(false); } });
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', async e => {
  e.preventDefault(); dragDepth = 0; dropShow(false);
  if (!auth || !path.length) return;
  const base = path.slice();
  // Asked of every item before anything is awaited: the browser empties them once this handler gives way.
  const items = [...e.dataTransfer.items].filter(i => i.kind === 'file');
  const hs = items.map(i => i.getAsFileSystemHandle ? i.getAsFileSystemHandle().catch(() => null) : null);
  const ents = items.map(i => i.webkitGetAsEntry && i.webkitGetAsEntry());
  const files = [...e.dataTransfer.files];
  if (!items.length) { for (const f of files) enqueue(f, f.name, base); return; }
  for (let n = 0; n < items.length; n++) {
    const h = await hs[n];
    if (h && h.kind === 'file') { try { const f = await h.getFile(); enqueue(f, f.name, base, null, h); continue; } catch (e) {} }
    if (h && h.kind === 'directory') { await walkHandle(h, h.name + '/', base, h); continue; }
    if (ents[n]) await walkEntry(ents[n], '', base);
  }
});

async function start() {
  auth = true;
  $('#login').hidden = true; $('#app').hidden = false; fromHash(); buckets = [];
  await migratePositions();
  await loadProgress();
  load();
  restore();
  if (!liveT) liveT = setInterval(liveCheck, 1000);
}
// A session the browser still holds signs in at once.
(async () => {
  try {
    const r = await fetch('/~ui/session', { headers: { 'X-Socketley-UI': '1' } });
    if (r.ok) { me = await r.json(); start(); return; }
  } catch (e) {}
  signedOut();
})();
</script>
</body>
</html>
)HTML";
