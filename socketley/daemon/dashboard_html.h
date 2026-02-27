#pragma once

static constexpr const char* DASHBOARD_HTML = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Socketley Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
header{background:#1e293b;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #334155}
header h1{font-size:20px;font-weight:600;color:#38bdf8}
header .meta{font-size:13px;color:#94a3b8}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;padding:24px}
.card{background:#1e293b;border-radius:8px;padding:20px;border:1px solid #334155}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:8px}
.card .value{font-size:28px;font-weight:700;color:#f1f5f9}
.card .sub{font-size:12px;color:#64748b;margin-top:4px}
table{width:100%;border-collapse:collapse;margin:0 24px 24px;max-width:calc(100% - 48px)}
th{text-align:left;padding:10px 16px;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;border-bottom:1px solid #334155}
td{padding:10px 16px;border-bottom:1px solid #1e293b;font-size:14px}
tr:hover td{background:#1e293b}
.state{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
.state-running{background:#065f4620;color:#4ade80;border:1px solid #4ade8040}
.state-created{background:#854d0e20;color:#facc15;border:1px solid #facc1540}
.state-stopped,.state-failed{background:#7f1d1d20;color:#f87171;border:1px solid #f8717140}
.type-badge{font-size:11px;padding:2px 8px;border-radius:4px;background:#334155;color:#94a3b8}
h2{padding:0 24px;font-size:16px;font-weight:600;color:#cbd5e1;margin-bottom:12px}
#error{display:none;padding:8px 24px;color:#f87171;font-size:13px}
</style>
</head>
<body>
<header>
 <h1>Socketley Dashboard</h1>
 <div class="meta"><span id="uptime">-</span> &middot; <span id="version">-</span></div>
</header>
<div id="error"></div>
<div class="cards">
 <div class="card"><div class="label">Runtimes</div><div class="value" id="rt-total">-</div><div class="sub"><span id="rt-running">-</span> running</div></div>
 <div class="card"><div class="label">Connections</div><div class="value" id="conn-active">-</div><div class="sub"><span id="conn-total">-</span> total</div></div>
 <div class="card"><div class="label">Messages</div><div class="value" id="msg-total">-</div><div class="sub" id="msg-rate">-</div></div>
 <div class="card"><div class="label">Throughput</div><div class="value" id="bytes-rate">-</div><div class="sub"><span id="bytes-in">-</span> in / <span id="bytes-out">-</span> out</div></div>
</div>
<h2>Runtimes</h2>
<table>
 <thead><tr><th>Name</th><th>Type</th><th>State</th><th>Port</th><th>Connections</th><th>Messages</th><th>Bytes In</th><th>Bytes Out</th></tr></thead>
 <tbody id="rt-body"></tbody>
</table>
<script>
let prevMsg=0,prevBytes=0,prevTime=0;
function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'G';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function fmtB(n){if(n>=1e9)return(n/1e9).toFixed(2)+' GB';if(n>=1e6)return(n/1e6).toFixed(2)+' MB';if(n>=1e3)return(n/1e3).toFixed(2)+' KB';return n+' B'}
function fmtUp(s){let d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+'d ':'')+(h?h+'h ':'')+(m?m+'m ':'')+Math.floor(s%60)+'s'}

async function refresh(){
 try{
  let[ov,rts]=await Promise.all([fetch('/api/overview').then(r=>r.json()),fetch('/api/runtimes').then(r=>r.json())]);
  document.getElementById('error').style.display='none';
  document.getElementById('uptime').textContent='Uptime: '+fmtUp(ov.uptime_seconds);
  document.getElementById('version').textContent='v'+ov.version;
  document.getElementById('rt-total').textContent=ov.runtimes_total;
  document.getElementById('rt-running').textContent=ov.runtimes_running;
  document.getElementById('conn-active').textContent=fmt(ov.connections_active);
  document.getElementById('conn-total').textContent=fmt(ov.connections_total)+' total';
  document.getElementById('msg-total').textContent=fmt(ov.messages_total);
  let now=Date.now()/1000;
  if(prevTime>0){
   let dt=now-prevTime;
   let mr=(ov.messages_total-prevMsg)/dt;
   let br=((ov.bytes_in+ov.bytes_out)-(prevBytes))/dt;
   document.getElementById('msg-rate').textContent=fmt(Math.round(mr))+'/s';
   document.getElementById('bytes-rate').textContent=fmtB(Math.round(br))+'/s';
  }
  prevMsg=ov.messages_total;prevBytes=ov.bytes_in+ov.bytes_out;prevTime=now;
  document.getElementById('bytes-in').textContent=fmtB(ov.bytes_in);
  document.getElementById('bytes-out').textContent=fmtB(ov.bytes_out);

  let html='';
  for(let r of rts){
   let sc=r.state==='running'?'running':r.state==='created'?'created':'stopped';
   html+='<tr><td><strong>'+r.name+'</strong></td><td><span class="type-badge">'+r.type+'</span></td>'
    +'<td><span class="state state-'+sc+'">'+r.state+'</span></td>'
    +'<td>'+(r.port||'-')+'</td><td>'+fmt(r.connections)+'</td>'
    +'<td>'+fmt(r.messages_total)+'</td><td>'+fmtB(r.bytes_in)+'</td><td>'+fmtB(r.bytes_out)+'</td></tr>';
  }
  document.getElementById('rt-body').innerHTML=html;
 }catch(e){
  document.getElementById('error').style.display='block';
  document.getElementById('error').textContent='Failed to fetch: '+e.message;
 }
}
refresh();setInterval(refresh,2000);
</script>
</body>
</html>)html";
