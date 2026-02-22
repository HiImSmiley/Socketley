#!/usr/bin/env python3
"""
Socketley Benchmark Visualizer
Reads the latest JSON result files and produces a self-contained HTML report.
Usage: python3 visualize.py [results_dir]
"""

import json, os, sys, re, glob
from pathlib import Path
from datetime import datetime

RESULTS_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "results"


def latest(prefix):
    """Return the most-recently-modified JSON file matching a prefix."""
    files = sorted(RESULTS_DIR.glob(f"{prefix}_*.json"), key=os.path.getmtime)
    return files[-1] if files else None


def load(path):
    if not path:
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def find(records, test_name):
    for r in records:
        if r.get("test") == test_name:
            return r
    return {}


def fmt(n, digits=0):
    if n is None:
        return "N/A"
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "N/A"
    if n >= 1_000_000:
        return f"{n/1_000_000:.{digits}f}M"
    if n >= 1_000:
        return f"{n/1_000:.{digits}f}K"
    return f"{n:.{digits}f}"


def v(record, key, default=0):
    """Safely extract a numeric value from a result record."""
    try:
        return float(record.get(key, default) or default)
    except (TypeError, ValueError):
        return default


# ── load results ─────────────────────────────────────────────────────────────
sf  = latest("server")
cf  = latest("cache")
pf  = latest("proxy")
wf  = latest("websocket")

server  = load(sf)
cache   = load(cf)
proxy   = load(pf)
ws      = load(wf)

# Pick the latest timestamp for the title
ts_raw = (sf or cf or pf or wf)
ts_str = datetime.fromtimestamp(os.path.getmtime(ts_raw)).strftime("%Y-%m-%d %H:%M") if ts_raw else "unknown"

# ── server metrics ────────────────────────────────────────────────────────────
s_conn  = find(server, "server_connection_rate")
s_burst = find(server, "server_burst_connections")
s_tp64  = next((r for r in server if r.get("test") == "server_single_client_throughput"
                and r.get("message_size_bytes") == 64), {})
s_tp1k  = next((r for r in server if r.get("test") == "server_single_client_throughput"
                and r.get("message_size_bytes") == 1024), {})
s_conc  = find(server, "server_concurrent_clients")

sv_conn_rate   = v(s_conn,  "connections_per_sec")
sv_burst_rate  = v(s_burst, "connections_per_sec")
sv_conn_lat    = float(s_conn.get("avg_latency_ms", 0) or 0)
sv_tp64_msg    = v(s_tp64,  "messages_per_sec")
sv_tp64_mb     = v(s_tp64,  "throughput_mb_sec")
sv_tp1k_msg    = v(s_tp1k,  "messages_per_sec")
sv_tp1k_mb     = v(s_tp1k,  "throughput_mb_sec")
sv_conc_msg    = v(s_conc,  "messages_per_sec")
sv_max_conn    = v(s_burst, "max_concurrent")

# ── cache metrics ─────────────────────────────────────────────────────────────
c_set   = find(cache, "cache_set_throughput")
c_get   = find(cache, "cache_get_throughput")
c_mix   = find(cache, "cache_mixed_workload")
c_conc  = find(cache, "cache_concurrent_access")
c_pers  = find(cache, "cache_persistence")

cv_set  = v(c_set,  "ops_per_sec")
cv_get  = v(c_get,  "ops_per_sec")
cv_mix  = v(c_mix,  "ops_per_sec")
cv_conc = v(c_conc, "ops_per_sec")
cv_flush= v(c_pers, "flush_time_ms")
cv_load = v(c_pers, "load_time_ms")

# ── proxy metrics ─────────────────────────────────────────────────────────────
p_http1 = find(proxy, "proxy_http_single_backend")
p_httplb= find(proxy, "proxy_http_load_balancing")
p_tcp   = find(proxy, "proxy_tcp_throughput")
p_conc  = find(proxy, "proxy_concurrent_connections")
p_over  = find(proxy, "proxy_overhead")
p_name  = find(proxy, "proxy_runtime_name_backend")

pv_http1  = v(p_http1, "requests_per_sec")
pv_httplb = v(p_httplb,"requests_per_sec")
pv_tcp    = v(p_tcp,   "messages_per_sec")
pv_tcp_mb = v(p_tcp,   "throughput_mb_sec")
pv_conc   = v(p_conc,  "messages_per_sec")
pv_overhead= v(p_over, "overhead_percent")
pv_name   = v(p_name,  "messages_per_sec")

# ── websocket metrics ─────────────────────────────────────────────────────────
w_hs    = find(ws, "ws_handshake_throughput")
w_coex  = find(ws, "ws_tcp_coexistence")
w_conc  = find(ws, "ws_concurrent")

wv_hs   = v(w_hs,   "ops_per_sec")
wv_coex = v(w_coex, "ops_per_sec")
wv_conc = v(w_conc, "ops_per_sec")


def kilo(n):
    return round(n / 1000, 1)


HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Socketley Benchmark Results</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:      #0d1117;
    --panel:   #161b22;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --orange:  #d29922;
    --purple:  #bc8cff;
    --red:     #f85149;
    --teal:    #39d353;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    font-size: 14px;
    line-height: 1.6;
  }}
  header {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 40px 24px;
  }}
  header h1 {{
    font-size: 28px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: -0.5px;
  }}
  header h1 span {{ color: var(--accent); }}
  header p {{ color: var(--muted); margin-top: 6px; font-size: 13px; }}

  .badges {{
    display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap;
  }}
  .badge {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 12px;
    color: var(--muted);
  }}
  .badge b {{ color: var(--text); }}

  main {{ padding: 32px 40px; max-width: 1400px; margin: 0 auto; }}

  /* ── hero KPI row ─────────────────────────────────────────────────────────── */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 40px;
  }}
  .kpi {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    transition: border-color .2s;
  }}
  .kpi:hover {{ border-color: var(--accent); }}
  .kpi .label {{ font-size: 11px; color: var(--muted); text-transform: uppercase;
                 letter-spacing: .6px; margin-bottom: 6px; }}
  .kpi .value {{ font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; }}
  .kpi .unit  {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
  .kpi.blue  .value {{ color: var(--accent); }}
  .kpi.green .value {{ color: var(--green); }}
  .kpi.purple.value {{ color: var(--purple); }}
  .kpi.orange .value {{ color: var(--orange); }}

  /* ── sections ────────────────────────────────────────────────────────────── */
  .section {{ margin-bottom: 48px; }}
  .section-header {{
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
  }}
  .section-icon {{
    width: 32px; height: 32px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
  }}
  .section-icon.server  {{ background: rgba(88,166,255,.15); }}
  .section-icon.cache   {{ background: rgba(63,185,80,.15);  }}
  .section-icon.proxy   {{ background: rgba(188,140,255,.15);}}
  .section-icon.ws      {{ background: rgba(210,153,34,.15); }}
  .section h2 {{ font-size: 18px; font-weight: 600; }}
  .section p.desc {{ font-size: 13px; color: var(--muted); margin-top: 2px; }}

  /* ── chart cards ─────────────────────────────────────────────────────────── */
  .chart-grid {{
    display: grid;
    gap: 16px;
  }}
  .chart-grid.cols-2 {{ grid-template-columns: 1fr 1fr; }}
  .chart-grid.cols-3 {{ grid-template-columns: 1fr 1fr 1fr; }}
  @media (max-width: 900px) {{
    .chart-grid.cols-2,
    .chart-grid.cols-3 {{ grid-template-columns: 1fr; }}
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }}
  .card h3 {{
    font-size: 13px; font-weight: 600; color: var(--muted);
    text-transform: uppercase; letter-spacing: .5px; margin-bottom: 16px;
  }}
  .chart-wrap {{ position: relative; height: 220px; }}
  .chart-wrap.tall {{ height: 280px; }}

  /* ── stat table ──────────────────────────────────────────────────────────── */
  .stat-table {{ width: 100%; border-collapse: collapse; margin-top: 4px; }}
  .stat-table th, .stat-table td {{
    padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border);
    font-size: 13px;
  }}
  .stat-table th {{ color: var(--muted); font-weight: 500; font-size: 12px;
                    text-transform: uppercase; letter-spacing: .4px; }}
  .stat-table tr:last-child td {{ border-bottom: none; }}
  .stat-table .num {{ text-align: right; font-variant-numeric: tabular-nums;
                      font-weight: 600; color: var(--text); }}
  .stat-table .hi  {{ color: var(--green); }}
  .stat-table .lo  {{ color: var(--muted); }}

  footer {{
    border-top: 1px solid var(--border);
    padding: 20px 40px;
    color: var(--muted);
    font-size: 12px;
    text-align: center;
  }}
</style>
</head>
<body>

<header>
  <h1><span>Socketley</span> Benchmark Results</h1>
  <p>io_uring async I/O · single-threaded event loop · Linux</p>
  <div class="badges">
    <span class="badge">🕐 <b>{ts_str}</b></span>
    <span class="badge">🖥️ Intel Core Ultra 5 125H</span>
    <span class="badge">⚙️ 4 cores / 3.8 GiB VM</span>
    <span class="badge">🐧 Kernel 6.8.0-100-generic</span>
    <span class="badge">🔧 Release build · statically linked</span>
  </div>
</header>

<main>

<!-- ── KPI hero ──────────────────────────────────────────────────────────── -->
<div class="kpi-grid">
  <div class="kpi blue">
    <div class="label">Server conn/sec</div>
    <div class="value">{fmt(sv_conn_rate, 1)}</div>
    <div class="unit">connections per second</div>
  </div>
  <div class="kpi blue">
    <div class="label">Burst connections</div>
    <div class="value">{fmt(sv_burst_rate, 1)}</div>
    <div class="unit">5 000-conn burst</div>
  </div>
  <div class="kpi blue">
    <div class="label">Single-client throughput</div>
    <div class="value">{fmt(sv_tp64_msg, 1)}</div>
    <div class="unit">msg/sec @ 64 B</div>
  </div>
  <div class="kpi blue">
    <div class="label">100-client aggregate</div>
    <div class="value">{fmt(sv_conc_msg, 1)}</div>
    <div class="unit">msg/sec concurrent</div>
  </div>
  <div class="kpi green">
    <div class="label">Cache GET</div>
    <div class="value">{fmt(cv_get, 1)}</div>
    <div class="unit">ops/sec</div>
  </div>
  <div class="kpi green">
    <div class="label">Cache SET</div>
    <div class="value">{fmt(cv_set, 1)}</div>
    <div class="unit">ops/sec</div>
  </div>
  <div class="kpi purple">
    <div class="label">HTTP proxy</div>
    <div class="value">{fmt(pv_http1, 1)}</div>
    <div class="unit">req/sec</div>
  </div>
  <div class="kpi purple">
    <div class="label">Proxy overhead</div>
    <div class="value">{pv_overhead:.1f}%</div>
    <div class="unit">vs direct connection</div>
  </div>
  <div class="kpi orange">
    <div class="label">WS handshakes</div>
    <div class="value">{fmt(wv_hs, 1)}</div>
    <div class="unit">handshakes/sec</div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- SERVER                                                                  -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="section">
  <div class="section-header">
    <div class="section-icon server">🖧</div>
    <div>
      <h2>Server Runtime</h2>
      <p class="desc">TCP server — accept rate, message throughput, concurrent clients</p>
    </div>
  </div>

  <div class="chart-grid cols-3">
    <div class="card">
      <h3>Connection Rate (K conn/sec)</h3>
      <div class="chart-wrap">
        <canvas id="sConnChart"></canvas>
      </div>
    </div>
    <div class="card">
      <h3>Single-Client Throughput (K msg/sec)</h3>
      <div class="chart-wrap">
        <canvas id="sTpChart"></canvas>
      </div>
    </div>
    <div class="card">
      <h3>Throughput (MB/sec)</h3>
      <div class="chart-wrap">
        <canvas id="sMbChart"></canvas>
      </div>
    </div>
  </div>

  <div class="chart-grid cols-2" style="margin-top:16px">
    <div class="card">
      <h3>Aggregate — 100 clients × 500 msgs (K msg/sec)</h3>
      <div class="chart-wrap">
        <canvas id="sConcChart"></canvas>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center;">
      <h3>Connection Details</h3>
      <table class="stat-table">
        <thead><tr><th>Test</th><th class="num">Value</th><th class="num">Unit</th></tr></thead>
        <tbody>
          <tr><td>Conn rate (sustained)</td><td class="num hi">{sv_conn_rate:,.0f}</td><td class="num lo">conn/sec</td></tr>
          <tr><td>Conn rate (burst 5K)</td><td class="num hi">{sv_burst_rate:,.0f}</td><td class="num lo">conn/sec</td></tr>
          <tr><td>Avg connect latency</td><td class="num">{sv_conn_lat:.3f}</td><td class="num lo">ms</td></tr>
          <tr><td>Max concurrent</td><td class="num hi">{int(sv_max_conn):,}</td><td class="num lo">connections</td></tr>
          <tr><td>64 B throughput</td><td class="num hi">{sv_tp64_msg:,.0f}</td><td class="num lo">msg/sec</td></tr>
          <tr><td>1 KB throughput</td><td class="num hi">{sv_tp1k_msg:,.0f}</td><td class="num lo">msg/sec</td></tr>
          <tr><td>1 KB bandwidth</td><td class="num hi">{sv_tp1k_mb:.1f}</td><td class="num lo">MB/sec</td></tr>
          <tr><td>100-client aggregate</td><td class="num hi">{sv_conc_msg:,.0f}</td><td class="num lo">msg/sec</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- CACHE                                                                   -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="section">
  <div class="section-header">
    <div class="section-icon cache">⚡</div>
    <div>
      <h2>Cache Runtime</h2>
      <p class="desc">RESP-protocol in-memory cache — SET, GET, mixed workloads</p>
    </div>
  </div>

  <div class="chart-grid cols-2">
    <div class="card">
      <h3>Operation Throughput (K ops/sec)</h3>
      <div class="chart-wrap">
        <canvas id="cOpsChart"></canvas>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center;">
      <h3>Cache Details</h3>
      <table class="stat-table">
        <thead><tr><th>Test</th><th class="num">ops/sec</th><th class="num">ops/sec (K)</th></tr></thead>
        <tbody>
          <tr><td>SET throughput</td><td class="num hi">{cv_set:,.0f}</td><td class="num lo">{cv_set/1000:.1f}K</td></tr>
          <tr><td>GET throughput</td><td class="num hi">{cv_get:,.0f}</td><td class="num lo">{cv_get/1000:.1f}K</td></tr>
          <tr><td>Mixed 80/20 GET/SET</td><td class="num hi">{cv_mix:,.0f}</td><td class="num lo">{cv_mix/1000:.1f}K</td></tr>
          <tr><td>20-client concurrent</td><td class="num hi">{cv_conc:,.0f}</td><td class="num lo">{cv_conc/1000:.1f}K</td></tr>
          {"<tr><td>Flush (persist)</td><td class='num'>" + str(int(cv_flush)) + " ms</td><td class='num lo'>—</td></tr>" if cv_flush else ""}
          {"<tr><td>Load (restore)</td><td class='num'>" + str(int(cv_load)) + " ms</td><td class='num lo'>—</td></tr>" if cv_load else ""}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PROXY                                                                   -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="section">
  <div class="section-header">
    <div class="section-icon proxy">↔️</div>
    <div>
      <h2>Proxy Runtime</h2>
      <p class="desc">TCP &amp; HTTP forwarding — single backend, load balancing, overhead</p>
    </div>
  </div>

  <div class="chart-grid cols-3">
    <div class="card">
      <h3>HTTP Proxy Throughput (req/sec)</h3>
      <div class="chart-wrap">
        <canvas id="pHttpChart"></canvas>
      </div>
    </div>
    <div class="card">
      <h3>TCP Forwarding (K msg/sec)</h3>
      <div class="chart-wrap">
        <canvas id="pTcpChart"></canvas>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center;">
      <h3>Proxy Details</h3>
      <table class="stat-table">
        <thead><tr><th>Test</th><th class="num">Value</th><th class="num">Unit</th></tr></thead>
        <tbody>
          <tr><td>HTTP single backend</td><td class="num hi">{pv_http1:,.0f}</td><td class="num lo">req/sec</td></tr>
          <tr><td>HTTP load balancing</td><td class="num hi">{pv_httplb:,.0f}</td><td class="num lo">req/sec</td></tr>
          <tr><td>TCP throughput</td><td class="num hi">{pv_tcp:,.0f}</td><td class="num lo">msg/sec</td></tr>
          <tr><td>TCP bandwidth</td><td class="num hi">{pv_tcp_mb:.1f}</td><td class="num lo">MB/sec</td></tr>
          <tr><td>20-client concurrent</td><td class="num hi">{pv_conc:,.0f}</td><td class="num lo">msg/sec</td></tr>
          <tr><td>Named backend</td><td class="num hi">{pv_name:,.0f}</td><td class="num lo">msg/sec</td></tr>
          <tr><td>Proxy overhead</td><td class="num">{pv_overhead:.1f}%</td><td class="num lo">vs direct</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- WEBSOCKET                                                               -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="section">
  <div class="section-header">
    <div class="section-icon ws">🌐</div>
    <div>
      <h2>WebSocket Runtime</h2>
      <p class="desc">WS upgrade handshake rate, TCP coexistence, concurrent clients</p>
    </div>
  </div>

  <div class="chart-grid cols-2">
    <div class="card">
      <h3>Handshake Throughput (ops/sec)</h3>
      <div class="chart-wrap">
        <canvas id="wsChart"></canvas>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column;justify-content:center;">
      <h3>WebSocket Details</h3>
      <table class="stat-table">
        <thead><tr><th>Test</th><th class="num">ops/sec</th></tr></thead>
        <tbody>
          <tr><td>Handshake throughput</td><td class="num hi">{wv_hs:,.0f}</td></tr>
          <tr><td>WS + TCP coexistence</td><td class="num hi">{wv_coex:,.0f}</td></tr>
          <tr><td>20-client concurrent</td><td class="num hi">{wv_conc:,.0f}</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

</main>

<footer>
  Socketley Benchmark · {ts_str} · Intel Core Ultra 5 125H · 4c/3.8 GiB VM · Kernel 6.8.0-100-generic
</footer>

<script>
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", monospace';
Chart.defaults.font.size = 12;

function hbar(id, labels, data, colors, xLabel) {{
  const ctx = document.getElementById(id).getContext('2d');
  new Chart(ctx, {{
    type: 'bar',
    data: {{
      labels: labels,
      datasets: [{{ data: data, backgroundColor: colors, borderRadius: 5, borderSkipped: false }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: ctx => ' ' + ctx.parsed.x.toLocaleString(undefined, {{maximumFractionDigits:1}}) + (xLabel ? ' ' + xLabel : '')
          }}
        }}
      }},
      scales: {{
        x: {{
          grid: {{ color: '#21262d' }},
          ticks: {{ callback: v => v >= 1000 ? (v/1000).toFixed(v%1000===0?0:1)+'K' : v }}
        }},
        y: {{ grid: {{ display: false }} }}
      }}
    }}
  }});
}}

function vbar(id, labels, data, colors, yLabel) {{
  const ctx = document.getElementById(id).getContext('2d');
  new Chart(ctx, {{
    type: 'bar',
    data: {{
      labels: labels,
      datasets: [{{ data: data, backgroundColor: colors, borderRadius: 5, borderSkipped: false }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: ctx => ' ' + ctx.parsed.y.toLocaleString(undefined, {{maximumFractionDigits:1}}) + (yLabel ? ' ' + yLabel : '')
          }}
        }}
      }},
      scales: {{
        y: {{
          grid: {{ color: '#21262d' }},
          ticks: {{ callback: v => v >= 1000 ? (v/1000).toFixed(v%1000===0?0:1)+'K' : v }}
        }},
        x: {{ grid: {{ display: false }} }}
      }}
    }}
  }});
}}

// ── Server ────────────────────────────────────────────────────────────────
hbar('sConnChart',
  ['Sustained', 'Burst (5K)'],
  [{kilo(sv_conn_rate)}, {kilo(sv_burst_rate)}],
  ['#58a6ff', '#388bfd'],
  'conn/sec (K)'
);

vbar('sTpChart',
  ['64 B msg', '1 KB msg'],
  [{kilo(sv_tp64_msg)}, {kilo(sv_tp1k_msg)}],
  ['#58a6ff', '#388bfd'],
  'K msg/sec'
);

vbar('sMbChart',
  ['64 B', '1 KB'],
  [{sv_tp64_mb:.1f}, {sv_tp1k_mb:.1f}],
  ['#58a6ff', '#388bfd'],
  'MB/sec'
);

hbar('sConcChart',
  ['100 clients × 500 msgs'],
  [{kilo(sv_conc_msg):.1f}],
  ['#3fb950'],
  'K msg/sec aggregate'
);

// ── Cache ─────────────────────────────────────────────────────────────────
vbar('cOpsChart',
  ['SET', 'GET', 'Mixed 80/20', '20-client conc.'],
  [{kilo(cv_set):.1f}, {kilo(cv_get):.1f}, {kilo(cv_mix):.1f}, {kilo(cv_conc):.1f}],
  ['#3fb950', '#56d364', '#3fb950', '#26a641'],
  'K ops/sec'
);

// ── Proxy ─────────────────────────────────────────────────────────────────
hbar('pHttpChart',
  ['Single backend', 'Load balancing'],
  [{pv_http1:.0f}, {pv_httplb:.0f}],
  ['#bc8cff', '#a371f7'],
  'req/sec'
);

hbar('pTcpChart',
  ['Single', '20-client conc.', 'Named backend'],
  [{kilo(pv_tcp):.1f}, {kilo(pv_conc):.1f}, {kilo(pv_name):.1f}],
  ['#bc8cff', '#a371f7', '#8957e5'],
  'K msg/sec'
);

// ── WebSocket ─────────────────────────────────────────────────────────────
vbar('wsChart',
  ['Handshake', 'WS+TCP coexist', '20-client conc.'],
  [{wv_hs:.0f}, {wv_coex:.0f}, {wv_conc:.0f}],
  ['#d29922', '#e3b341', '#bb8009'],
  'ops/sec'
);

</script>
</body>
</html>
"""

out = RESULTS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
out.write_text(HTML)
print(f"Report written to: {out}")
