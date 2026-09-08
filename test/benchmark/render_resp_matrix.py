#!/usr/bin/env python3
# Renders the RESP matrix HTML from the two arms' run logs.
#
#   render_resp_matrix.py <unsharded.log> <sharded.log> [out.html]
#
# It lived in /tmp for three runs, which meant the committed HTML had no source
# anybody could re-run.  A number in a report that cannot be regenerated is a
# screenshot.
#
# It reads only the per-command table lines, so a log with a cell the harness
# marked unreadable keeps that mark and is excluded from the medians rather
# than quietly averaged in.
import re, statistics, datetime, sys, os

def parse(path):
    """A row per command: rate, redis rate, ratio, spread, client cores, verdict."""
    rows, meta = {}, {}
    for line in open(path, encoding='utf-8', errors='replace'):
        line = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()
        m = re.match(r'\s+([A-Z][A-Z0-9]*)\s+(\d+)\s+(\d+)\s+([\d.]+)x\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(.*)$', line)
        if m:
            rows[m.group(1)] = dict(skl=int(m.group(2)), redis=int(m.group(3)),
                                    ratio=float(m.group(4)), spread=float(m.group(5)),
                                    sc=float(m.group(6)), rc=float(m.group(7)),
                                    verdict=m.group(8).strip())
        if 'passes per cell' in line:
            meta['run'] = line.split(']')[-1].strip()
        if 'keys loaded' in line:
            meta['keys'] = line.split(']')[-1].strip()
    return rows, meta

un, un_meta = parse(sys.argv[1])
sh, sh_meta = parse(sys.argv[2])
if not un or not sh:
    sys.exit(f"leer: unsharded={len(un)} sharded={len(sh)}")

READ = lambda d: [v for v in d.values() if 'not readable' not in v['verdict']
                                       and 'client-bound' not in v['verdict']
                                       and not (v['skl'] == 0 and v['redis'] == 0)]
med  = lambda d: statistics.median(v['ratio'] for v in READ(d)) if READ(d) else 0
worst= lambda d: min((v['ratio'] for v in READ(d)), default=0)

cmds = sorted(set(un) | set(sh), key=lambda c: sh.get(c, un.get(c))['ratio'])

def cls(v):
    if v is None: return ''
    if v < 1.00: return 'bad'
    if v < 1.30: return 'weak'
    if v > 2.50: return 'great'
    return ''
num = lambda v: f'{v:,}'.replace(',', ' ') if v is not None else '—'
def cell(d, key):
    if not d: return '<td class="n">—</td><td class="n">—</td><td class="r">—</td><td class="sp">—</td>'
    # A cell where BOTH arms measured nothing is not a result and must not be
    # drawn like one: "0.00x" beside a 900% spread reads as "infinitely slower"
    # when it means "the client never ran".  Redis is not affected by our code,
    # so two zeroes together are always the instrument.
    if d['skl'] == 0 and d['redis'] == 0:
        return ('<td class="n dim">—</td><td class="n dim">—</td>'
                '<td class="r dim" title="no measurement: both arms returned '
                'nothing, so this is the harness and not the servers">not measured</td>'
                '<td class="sp dim">—</td>')
    unread = 'not readable' in d['verdict'] or 'client-bound' in d['verdict']
    rcls = 'dim' if unread else cls(d['ratio'])
    sp = f"{d['spread']*100:.0f}%"
    spcls = 'sp warn' if d['spread'] > 0.25 else 'sp'
    return (f'<td class="n">{num(d["skl"])}</td><td class="n">{num(d["redis"])}</td>'
            f'<td class="r {rcls}">{d["ratio"]:.2f}x</td><td class="{spcls}">{sp}</td>')

# PING does no work at all, so it is the ceiling of its arm: a row can only be
# as fast relative to Redis as the empty command is.  Without this column the
# table invites the wrong question -- three sharded rows sat "below 1.30x" all
# night and every one of them was within 10% of a command that does nothing,
# while the control itself moved between 1.23x and 1.46x from run to run.
un_ping = un.get('PING', {}).get('ratio') or None
sh_ping = sh.get('PING', {}).get('ratio') or None
def vs_ping(d, base):
    if not d or not base or d['skl'] == 0 or 'not readable' in d['verdict']:
        return '<td class="sp dim">—</td>'
    f = d['ratio'] / base
    cls = 'sp' if f >= 0.85 else 'sp warn'
    return f'<td class="{cls}" title="of the no-work control in this arm">{f:.2f}</td>'

rows = []
for c in cmds:
    u, s = un.get(c), sh.get(c)
    rows.append(f'<tr><td class="cmd">{c}</td>{cell(u,c)}{vs_ping(u, un_ping)}'
                f'{cell(s,c)}{vs_ping(s, sh_ping)}'
                f'<td class="n s">{s["sc"]:.1f} / {s["rc"]:.1f}</td></tr>' if s else
                f'<tr><td class="cmd">{c}</td>{cell(u,c)}{vs_ping(u, un_ping)}'
                f'{cell(None,c)}<td class="sp dim">—</td><td class="n s">—</td></tr>')

stamp = datetime.datetime.now().strftime('%d.%m.%Y %H:%M')
un_unread = sum(1 for v in un.values() if 'not readable' in v['verdict'])
sh_unread = sum(1 for v in sh.values() if 'not readable' in v['verdict'])
sh_low = sorted([(v['ratio'], c) for c, v in sh.items()
                 if v['ratio'] < 1.30 and 'not readable' not in v['verdict']
                 and not (v['skl'] == 0 and v['redis'] == 0)])
un_low = sorted([(v['ratio'], c) for c, v in un.items()
                 if v['ratio'] < 1.30 and 'not readable' not in v['verdict']
                 and not (v['skl'] == 0 and v['redis'] == 0)])

doc = f"""<!doctype html><html lang="de"><meta charset="utf-8">
<title>socketley vs Redis — jedes RESP-Kommando</title>
<style>
:root{{--bg:#0f1115;--fg:#d8dee9;--dim:#6b7280;--line:#242833;--card:#161922}}
*{{box-sizing:border-box}}
body{{margin:0;padding:2.5rem 1.5rem;background:var(--bg);color:var(--fg);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:1320px;margin:0 auto}}
h1{{font-size:1.5rem;margin:0 0 .3rem;font-weight:650;letter-spacing:-.01em}}
.sub{{color:var(--dim);margin:0 0 1.6rem;font-size:.9rem;max-width:78ch}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.75rem;margin-bottom:1.6rem}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.85rem 1rem}}
.card .k{{color:var(--dim);font-size:.71rem;text-transform:uppercase;letter-spacing:.06em}}
.card .v{{font-size:1.5rem;font-weight:650;margin-top:.15rem;font-variant-numeric:tabular-nums}}
.card .n{{color:var(--dim);font-size:.76rem;margin-top:.2rem;line-height:1.4}}
table{{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}}
th,td{{padding:.38rem .5rem;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}}
th{{position:sticky;top:0;background:var(--bg);color:var(--dim);font-weight:600;font-size:.7rem;
 text-transform:uppercase;letter-spacing:.05em;cursor:pointer;user-select:none}}
th:hover{{color:var(--fg)}}
th.grp{{text-align:center;background:var(--card);color:var(--dim);cursor:default}}
td.cmd,th.l{{text-align:left}}
td.cmd{{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:.83rem}}
tbody tr:hover{{background:#1a1e28}}
.r{{font-weight:600}} .n{{color:#aab2c0}} .s{{color:var(--dim);font-size:.77rem}}
.sp{{color:var(--dim);font-size:.76rem}} .sp.warn{{color:#f0c674}}
.dim{{color:var(--dim);font-weight:400}}
.bad{{color:#f2777a}} .weak{{color:#f0c674}} .great{{color:#6cc98f}}
footer{{margin-top:2rem;color:var(--dim);font-size:.84rem;line-height:1.7;max-width:90ch}}
footer h3{{color:var(--fg);font-size:.92rem;margin:1.5rem 0 .4rem}}
footer code{{background:var(--card);padding:.08rem .32rem;border-radius:3px;font-size:.82rem}}
footer b{{color:#c8d0dc}}
</style>
<div class="wrap">
<h1>socketley vs Redis — jedes RESP-Kommando</h1>
<p class="sub">{len(cmds)} Kommandos, beide Arme frisch gemessen, 5 Pässe je Zelle mit alternierender
Reihenfolge, 500&thinsp;000 Operationen je Client-Prozess, 8 Client-Prozesse, Pipeline 16.
Aufsteigend nach der sharded Ratio, schlechteste Zelle oben. Stand {stamp}.</p>

<div class="cards">
<div class="card"><div class="k">1 Shard vs redis-server</div><div class="v">{med(un):.2f}x</div>
  <div class="n">Median der lesbaren Zellen<br>schlechteste {worst(un):.2f}x</div></div>
<div class="card"><div class="k">4 Shards --cluster vs Redis Cluster</div><div class="v" style="color:#6cc98f">{med(sh):.2f}x</div>
  <div class="n">Median der lesbaren Zellen<br>schlechteste {worst(sh):.2f}x</div></div>
<div class="card"><div class="k">unter 1,30x</div><div class="v">{len(un_low)} / {len(sh_low)}</div>
  <div class="n">unsharded / sharded<br>nur lesbare Zellen gezählt</div></div>
<div class="card"><div class="k">nicht lesbar</div><div class="v">{un_unread} / {sh_unread}</div>
  <div class="n">Streuung über 25 %<br>bekommen kein Urteil</div></div>
</div>

<table id="t">
<thead>
<tr><th class="l" rowspan="2">Kommando</th>
    <th class="grp" colspan="5">unsharded — socketley 1 Shard vs redis-server</th>
    <th class="grp" colspan="5">sharded — socketley --shards 4 --cluster vs Redis Cluster 4</th>
    <th class="grp" rowspan="2">Client-Kerne<br>skl / redis</th></tr>
<tr><th>socketley</th><th>Redis</th><th>Ratio</th><th>Streuung</th><th>von PING</th>
    <th>socketley</th><th>Redis Cluster</th><th>Ratio</th><th>Streuung</th><th>von PING</th></tr>
</thead>
<tbody>
{chr(10).join(rows)}
</tbody></table>

<footer>
<h3>Wozu die Tabelle da ist</h3>
Sie ist kein Ranking, sondern ein Ausreißer-Detektor. Ein Kommando, bei dem wir gleichauf liegen, ist
uninteressant; eines, das deutlich unter der Norm sitzt, ist ein Vormittag Arbeit mit bekanntem
Ertrag. So wurden pub/sub, MSET/MGET, die INCR-Familie und ZADD gefunden — jedes Mal erst, als etwas
<b>alle</b> Kommandos druckte statt sechs.

<h3>Die Streuungsspalte ist das Wichtigste hier</h3>
Jede Ratio wird <b>pro Pass</b> gebildet und davon der Median genommen — nicht als Median geteilt durch
Median. Die Streuung ist der Abstand der beiden äußersten Pass-Ratios, gemessen an ihrem eigenen
Median. <b>Über 25 % bekommt eine Zelle kein Urteil</b>, weil sie dann nichts gemessen hat.
<br><br>
Das steht hier, weil die vorige Fassung dieser Seite es nicht hatte: mit der alten Form kamen zwei
Kommandos, die sich <i>einen Codepfad teilen</i>, als 0,91x und 1,53x heraus. Direkt hintereinander
gemessen sind sie gleich schnell. Die alte Form mittelte das Rauschen weg und druckte eine Zahl, die
gesetzt aussah und keine war.

<h3>Warum Ratios und keine absoluten Zahlen</h3>
Diese Box ist ein Gast ohne sichtbare Taktfrequenz — <code>/proc/cpuinfo</code> meldet konstant
2995,200&nbsp;MHz, egal was der Host tut. Absolute Werte aus verschiedenen Läufen sind daher nicht
vergleichbar; zwischen zwei Läufen dieser Nacht stiegen <i>beide</i> Arme um rund 55 %. Jede Ratio ist
dagegen innerhalb eines Passes gegen Redis als Kontrolle gemessen und übersteht das.
<br><br>
Aus demselben Grund fehlen die Spalten „vorher" und „ohne <code>--cluster</code>" der alten Seite: sie
stammten aus Läufen mit dem alten Instrument, und sie neben frische Zahlen zu stellen wäre genau der
Vergleich, den diese Seite verbietet.

<h3>Was der Lastgenerator beiträgt</h3>
Beide Arme fährt dasselbe Binary mit denselben Flags — <code>redis-benchmark</code>, acht Prozesse.
Vier waren zu wenig: acht sind +49 % auf GET, und eine Decke bremst den <i>schnelleren</i> Arm härter,
staucht die Ratio also gegen 1,0. <b><code>PING</code> steht als Kontrolle in der Tabelle</b> — es
fasst keine Daten an, und eine PING-Zelle nahe 1,2x wäre eine Aussage über den Client, nicht über uns.
<br><br>
Der Rest ist der Kernel: bei acht Prozessen ist die Box zu 83 % leer, mehr Parallelität kauft null
Durchsatz bei konstanter CPU, und 72 % der belegten Zeit ist system+softirq. Über AF_UNIX gewinnen
<i>beide</i> Arme rund 50 %. Ein geteilter Engpass staucht Verhältnisse — was hier steht, ist also der
für uns ungünstigste Aufbau.

<h3>Grenzen</h3>
Client-Kerne über etwa 7,6 von 8,0 heißen, dass der Lastgenerator selbst zum Faktor wird; solche
Zellen sind untere Schranken und werden als „client-bound" markiert statt bewertet.
<code>PUBLISH</code> vergleicht zwei verschiedene Dinge: Redis Cluster verteilt jede Veröffentlichung
über den Cluster-Bus an alle Knoten. Der Bus hat kein <code>client-output-buffer-limit</code>, und
unter voller Last hat dieser Benchmark damit zweimal einen Redis-Knoten per OOM-Killer getötet —
5,77&nbsp;GB bei einem Datensatz von 1,4&nbsp;MB. Die Zelle läuft deshalb mit reduzierter Last, und
jede Zelle prüft danach, ob beide Arme noch vollzählig sind.
</footer>
</div>
<script>
document.querySelectorAll('#t thead tr:nth-child(2) th, #t thead tr:first-child th.l').forEach((th)=>{{
  th.onclick=()=>{{
    const tb=document.querySelector('#t tbody');
    const idx=[...th.parentNode.children].indexOf(th)+(th.classList.contains('l')?0:1);
    const asc=th.dataset.asc==='1'; th.dataset.asc=asc?'0':'1';
    const val=(tr)=>{{const t=tr.children[idx].textContent.trim().replace(/[\\u202f,%]/g,'').replace(/x.*$/,'');
      const n=parseFloat(t); return isNaN(n)?t:n;}};
    [...tb.rows].sort((a,b)=>{{const x=val(a),y=val(b);
      return (typeof x==='number'?x-y:String(x).localeCompare(y))*(asc?1:-1);}})
      .forEach(r=>tb.appendChild(r));
  }};
}});
</script>
</html>"""
out = (sys.argv[3] if len(sys.argv) > 3 else
       os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', 'resp_matrix.html'))
open(out, 'w', encoding='utf-8').write(doc)
print(f"{len(cmds)} Zeilen | unsharded {med(un):.2f}x ({un_unread} unlesbar, {len(un_low)} unter 1.30) "
      f"| sharded {med(sh):.2f}x ({sh_unread} unlesbar, {len(sh_low)} unter 1.30)")
if sh_low: print("  sharded unter 1.30:", ", ".join(f"{c} {r:.2f}x" for r, c in sh_low))
if un_low: print("  unsharded unter 1.30:", ", ".join(f"{c} {r:.2f}x" for r, c in un_low))
