#!/usr/bin/env bash
# Integration test: the daemon's dashboard.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   the schema   every flag a create parser in flag_handlers.cpp takes is in
#                the dashboard's schema (or an alias of one), for its type
#   the page     served with the storage interface's style and helpers in it,
#                and a script that parses
#   signing in   an admin's key and secret make a session; another user's, a
#                wrong secret and none do not; five failures bar the address
#   reading      figures and the schema need a session, a local scraper's
#                /metrics does not, a proxy's does
#   commands     need a session and the page's header, take only the
#                dashboard's verbs and no word with a space, and create, show,
#                import, stop, start and remove a runtime as the CLI would
#   the log      a worker's lines come through the daemon named by runtime,
#                its stderr still gets them, and a reader asks for what is new
#   domains      the entrance's routes, a certificate's names and days, a zone
#                read, edited (served at once), refused when it does not parse
#                or is no dns runtime's, and only from the page
#   no creds     without dashboard_credentials it reads and changes nothing
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/../../socketley/daemon/flag_handlers.cpp"
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: ${2:0:300}" ;; esac; }

daemon_isolate dash
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1950))
M=$P
trap 'daemon_stop' EXIT

echo "=== Integration: the daemon's dashboard ==="

ADMIN="AKIADASHTESTADMIN000:dashtestadminsecretdashtestadminsecret00"
BOB="AKIADASHTESTBOB00000:dashtestbobsecretdashtestbobsecretdashte"
printf '[admin]\nadmin = true\n%s\n[bob]\n%s\n' "$ADMIN" "$BOB" > "$T/creds"
cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $M, dashboard_credentials = "$T/creds" }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
daemon_start "$BIN"
U="http://127.0.0.1:$M"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
code() { curl -s -o /dev/null -w '%{http_code}' -m 10 "$@"; }

# ─── the schema ─────────────────────────────────────────────────────────────
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
curl -s -b "$T/jar" "$U/api/schema" > "$T/schema.json"
# Which edits a running runtime takes at once, for the edit form to mark the rest.
expect "the schema names what a running runtime takes at once" \
    "$(python3 -c 'import json,sys; l=json.load(open(sys.argv[1])).get("live",[]); print("max_connections" in l, "port" in l)' "$T/schema.json")" "True False"
missing=$(python3 - "$SRC" "$T/schema.json" <<'PY'
import json, re, sys
src, schema = open(sys.argv[1]).read(), json.load(open(sys.argv[2]))
known = {}
for f in schema["flags"]:
    names = [f["flag"]] + [a for a in f.get("aliases", "").split(",") if a]
    for n in names:
        known.setdefault(n, set()).update(f["types"])
# The create parsers, each one's cases.
parsers = {"parse_common_flags": None, "parse_server_flags": "server", "parse_client_flags": "client",
           "parse_proxy_gate_flag": "proxy", "parse_proxy_flags": "proxy", "parse_cache_flags": "cache",
           "parse_dns_flags": "dns", "parse_storage_flags": "storage", "parse_sync_flags": "sync",
           "parse_idp_flags": "idp", "parse_db_flags": "db"}
out = []
for fn, ty in parsers.items():
    m = re.search(r"\n(?:static )?int " + fn + r"\(.*?\n\}\n", src, re.S)
    if not m:
        out.append("no " + fn); continue
    for flag in set(re.findall(r'case fnv1a\("(-[^"]*)"\)', m.group(0))):
        if flag not in known:
            out.append(flag + " (" + fn + ")")
        elif ty and ty not in known[flag]:
            out.append(flag + " not offered for " + ty)
print(" ".join(sorted(out)) or "none")
PY
)
# "none" is said, never left empty: a schema that did not load fails python, and an empty answer passed for parity.
expect "every flag a create parser takes is in the dashboard's schema, for its type" "$missing" "none"
# The key each row names is one a runtime's state is written under, per type: the page reads and writes by it alone.
keys=$(python3 - "$HERE/../../socketley/shared/persist/state_persistence.cpp" "$T/schema.json" <<'PY'
import json, re, sys
src = open(sys.argv[1]).read()
# The fields written by name, and the arrays written as a quoted key ahead of their bracket.
written = set(re.findall(r'append_[a-z]+_field\("([a-z_]+)"', src)) | set(re.findall(r'\\"([a-z_]+)\\": \[', src))
flags = json.load(open(sys.argv[2]))["flags"]
key = {(f["flag"], t): f.get("key") for f in flags for t in f["types"]}
out = sorted({f["key"] for f in flags if f.get("key") and f["key"] not in written})
print(" ".join(out) or "none", key[("--cache", "server")], key[("--cache", "db")], key[("--replicate", "cache")],
      key[("--replicate", "db")], key[("--mode", "cache")], key[("--mode", "server")], key[("--every", "sync")])
PY
)
expect "every key the schema names is one a runtime's state holds, and each type's own" \
    "$keys" "none cache_name cache replicate_target replicate cache_mode mode every"

# ─── the page ───────────────────────────────────────────────────────────────
curl -s "$U/" > "$T/page.html"
has "the page is served with the storage interface's style" "$(cat "$T/page.html")" "#aurora"
has "and its dialogs" "$(cat "$T/page.html")" "function modal("
# The runtimes table says what each one costs the machine, beside its CPU.
has "the runtimes table has a memory column" "$(cat "$T/page.html")" "'CPU', 'Memory'"
has "filled from what the runtime costs, not its shards' resident memory added up" "$(cat "$T/page.html")" "human(r.memory_bytes"
if command -v node >/dev/null 2>&1; then
    python3 -c "import re,sys; open(sys.argv[2],'w').write(re.search(r'<script>(.*)</script>', open(sys.argv[1]).read(), re.S).group(1))" "$T/page.html" "$T/page.js"
    node --check "$T/page.js" 2>"$T/node.err" && ok "its script parses" || bad "its script parses" "$(head -5 "$T/node.err")"
    # The stats panel's reading of a sharded runtime's text, run as the page has it.
    python3 -c "
import re,sys; s=open(sys.argv[1]).read()
print('\n'.join(re.search(r'^const %s = .*$' % n, s, re.M).group(0) for n in ('COPY', 'PART')))
print(re.search(r'^function readStats\(.*?^}$', s, re.M | re.S).group(0))" "$T/page.js" > "$T/read.js"
    cat >> "$T/read.js" <<'EOF'
const st = readStats('name:s\ntype:storage\nport:1\nconnections:0\nbytes_in:9\ncpus:max\n'
  + '[shard 0]\nshard_connections:0\nshard_bytes_in:4\nshard_index:0\nbuckets:3\nobjects:5\nmax_bytes:0\nerror_NoSuchKey:2\nshard_commits_sent:1\nshard_commits_served:1\nmesh_links:1\n'
  + '[shard 1]\nshard_connections:0\nshard_bytes_in:5\nshard_index:1\nbuckets:3\nobjects:5\nmax_bytes:0\nerror_NoSuchKey:0\nshard_commits_sent:2\nshard_commits_served:0\nmesh_links:1\nshards:2\nshard_pids:7,8\n');
const c = Object.fromEntries(st.counters.map(x => [x.k, x]));
console.log([c.objects.v, c.buckets.v, c.mesh_links.v, c.max_bytes.v, c.shard_commits_sent.v, c.shard_commits_sent.group, c.shard_commits_sent.label,
  c.error_NoSuchKey.bad, 'bytes_in' in c, 'shard_bytes_in' in c, 'shard_index' in c, st.shards.length, st.texts.map(t => t.join('=')).join(' ')].join('|'));
EOF
    expect "the stats panel adds a counter over the shards, takes a whole copy once, folds nothing the tiles show, and groups by part" \
        "$(node "$T/read.js" 2>&1)" "10|3|1|0|3|shard|commits sent|true|false|false|false|2|cpus=max pids=7,8"
    # The names each runtime is opened by, read from an entrance's routes as the page reads them.
    python3 -c "
import re,sys; print(re.search(r'^function hostsOf\(.*?^}$', open(sys.argv[1]).read(), re.M | re.S).group(0))" "$T/page.js" > "$T/hosts.js"
    cat >> "$T/hosts.js" <<'EOF'
const h = hostsOf({ entrances: [{ name: 'ns-proxy', routes: [
  { name: '*.storage.example', to: [{ address: '127.0.0.1:1', runtime: 'ui' }] },
  { name: 'storage.example', to: [{ address: '127.0.0.1:1', runtime: 'ui' }] },
  { name: 'files.example', to: [{ address: '127.0.0.1:1', runtime: 'ui' }] },
  { name: 'gone.example', to: [{ address: '10.0.0.9:80', runtime: '' }] }] }] });
console.log(JSON.stringify(h));
EOF
    expect "a runtime is opened by the names an entrance sends it, never by a wildcard or an address of no runtime" \
        "$(node "$T/hosts.js" 2>&1)" '{"ui":["storage.example","files.example"]}'
fi

# ─── signing in ─────────────────────────────────────────────────────────────
expect "figures need a session" "$(code "$U/api/runtimes")" 401
expect "so does the schema" "$(code "$U/api/schema")" 401
expect "a local scraper's /metrics does not" "$(code "$U/metrics")" 200
expect "a proxy's does" "$(code -H 'Via: 1.1 entrance' "$U/metrics")" 401
expect "an admin signs in" "$(code -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session")" 200
has "as an HttpOnly, SameSite=Strict cookie" "$(grep -c skl_dash "$T/jar") $(curl -s -D - -o /dev/null -X POST -u "$ADMIN" "$U/api/session" | tr -d '\r' | grep -i '^set-cookie')" "HttpOnly; SameSite=Strict"
expect "and reads the figures" "$(code -b "$T/jar" "$U/api/runtimes")" 200
expect "and is named as the credentials file names it, not by the key" \
    "$(curl -s -X POST -u "$ADMIN" "$U/api/session")" '{"user":"admin"}'
expect "another user does not sign in" "$(code -X POST -u "$BOB" "$U/api/session")" 401
expect "nor a wrong secret" "$(code -X POST -u "${ADMIN%%:*}:wrong" "$U/api/session")" 401
for _ in 1 2 3 4 5; do code -X POST -H 'X-Forwarded-For: 10.9.9.9' -H 'Via: 1.1 e' -u "${ADMIN%%:*}:guess" "$U/api/session" >/dev/null; done
expect "an address that keeps failing is barred, the right secret too" \
    "$(code -X POST -H 'X-Forwarded-For: 10.9.9.9' -H 'Via: 1.1 e' -u "$ADMIN" "$U/api/session")" 429
expect "while another is not" "$(code -X POST -H 'X-Forwarded-For: 10.9.9.8' -H 'Via: 1.1 e' -u "$ADMIN" "$U/api/session")" 200
expect "a forged cookie is no session" "$(code -b 'skl_dash=AKIADASHTESTADMIN000.9999999999.00' "$U/api/runtimes")" 401
# A browser sends one cookie of a name per domain it was set for, so a forged one beside the real one must not win.
dash=$(awk '$6 == "skl_dash" {print $7}' "$T/jar")
forged='skl_dash=AKIADASHTESTADMIN000.9999999999.00'
expect "a forged cookie sent after the real one does not shut the session out" \
    "$(code -b "skl_dash=$dash; $forged" "$U/api/runtimes")" 200
expect "nor one sent before it" "$(code -b "$forged; skl_dash=$dash" "$U/api/runtimes")" 200

# ─── commands ───────────────────────────────────────────────────────────────
run() { curl -s -m 30 -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -H 'Content-Type: application/json' -d "$1" "$U/api/run"; }
j() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
expect "a command needs the page's header" "$(code -b "$T/jar" -d '{"args":["ls"]}' "$U/api/run")" 403
expect "and a session" "$(code -H 'X-Socketley-Dashboard: 1' -d '{"args":["ls"]}' "$U/api/run")" 401
expect "a verb that is not the dashboard's is refused" "$(code -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -d '{"args":["daemon-stop"]}' "$U/api/run")" 403
expect "a word with a tab is refused" "$(code -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -d '{"args":["create","server","a\tb"]}' "$U/api/run")" 400
# A space travels inside its word, so the daemon judges the one name and makes neither half of it.
expect "a word with a space arrives as one" \
    "$(run '{"args":["create","server","a b"]}' | j "d['code'] != 0 and 'a b' in d['out']") $("$BIN" ls 2>/dev/null | grep -cE '^ *(a|b) ')" "True 0"
expect "a runtime is made, started" "$(run "{\"args\":[\"create\",\"server\",\"web\",\"-p\",\"$((P+1))\",\"-s\"]}" | j "d['code']")" 0
for _ in $(seq 1 30); do [ "$(curl -s -b "$T/jar" "$U/api/runtimes" | j "[r['state'] for r in d if r['name']=='web'][0]")" = running ] && break; sleep 0.2; done
expect "and runs" "$(curl -s -b "$T/jar" "$U/api/runtimes" | j "[r['state'] for r in d if r['name']=='web'][0]")" running
expect "a refusal comes back with the daemon's words" "$(run '{"args":["create","server","web"]}' | j "d['code'] != 0 and 'already' in d['out']")" True
expect "show gives its configuration" "$(run '{"args":["show","web"]}' | j "json.loads(d['out'])['port']")" "$((P+1))"
expect "import changes it" "$(run '{"args":["import","web","{\"max_connections\": 77}"]}' | j "d['code']") $(run '{"args":["show","web"]}' | j "json.loads(d['out'])['max_connections']")" "0 77"
expect "stop stops it" "$(run '{"args":["stop","web"]}' | j "d['code']") $("$BIN" ls 2>/dev/null | grep -c ' web .*Stopped')" "0 1"
expect "start starts it" "$(run '{"args":["start","web"]}' | j "d['code']")" 0
expect "and remove removes it" "$(run '{"args":["remove","web"]}' | j "d['code']") $("$BIN" ls 2>/dev/null | grep -c ' web ')" "0 0"
# A command is logged without its secrets: the value after a flag that holds one, and an import's document.
run "{\"args\":[\"create\",\"server\",\"pw\",\"-p\",\"$((P+3))\",\"--mode\",\"master\",\"--master-pw\",\"dashtopsecretpw\"]}" >/dev/null
run '{"args":["import","pw","{\"master_pw\": \"dashothersecret\"}"]}' >/dev/null
sleep 0.5
expect "the dashboard's log of a command keeps no password" \
    "$(grep -c 'dashtopsecretpw\|dashothersecret' "$SOCKETLEY_DLOG") $(grep -c 'ran create server pw .*--master-pw \*\*\*' "$SOCKETLEY_DLOG")" "0 1"
run '{"args":["remove","pw"]}' >/dev/null
# ─── the log ────────────────────────────────────────────────────────────────
run "{\"args\":[\"create\",\"storage\",\"loud\",\"-p\",\"$((P+2))\",\"--dir\",\"$T/loud\",\"--anonymous\",\"-s\"]}" >/dev/null
logs() { curl -s -b "$T/jar" "$U/api/logs?$1"; }
got=""
for _ in $(seq 1 30); do got=$(logs "runtime=loud" | j "any(l['rt']=='loud' for l in d['lines'])"); [ "$got" = True ] && break; sleep 0.2; done
expect "a worker's lines reach the daemon's log, named by their runtime" "$got" True
expect "and its stderr still gets them" "$(grep -q "storage 'loud'" "$SOCKETLEY_DLOG" && echo yes)" yes
expect "the daemon's own lines are there too" "$(logs "max=2000" | j "any(l['rt']=='' and 'daemon started' in l['text'] for l in d['lines'])")" True
n=$(logs "max=1" | j "d['next']")
# A command after the mark logs a line, so the filters below are judged on lines rather than on an empty list.
run '{"args":["stop","loud"]}' >/dev/null
expect "a reader asks for what is new" "$(logs "since=$n" | j "len(d['lines']) > 0 and all(l['seq'] > $n for l in d['lines'])")" True
# The refused sign-ins above logged warnings, and the level is a floor.
expect "and filters by level" "$(logs "level=warn&max=2000" | j "len(d['lines']) > 0 and all(l['lv'] in ('warn','error') for l in d['lines'])")" True
expect "the log needs a session" "$(code "$U/api/logs")" 401

# ─── domains ────────────────────────────────────────────────────────────────
command -v openssl >/dev/null 2>&1 && openssl req -x509 -newkey rsa:2048 -nodes -days 20 -subj /CN=example.com \
    -addext "subjectAltName=DNS:*.example.com,DNS:example.com" -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
run "{\"args\":[\"create\",\"proxy\",\"web\",\"-p\",\"$((P+3))\",\"--tls\",\"--cert\",\"$T/e.pem\",\"--key\",\"$T/e.key\",\"-s\"]}" >/dev/null
run "{\"args\":[\"create\",\"dns\",\"ns\",\"-p\",\"$((P+4))\",\"--zone\",\"example.com\",\"--proxy\",\"web\",\"--publish\",\"192.0.2.7\",\"-s\"]}" >/dev/null
run "{\"args\":[\"create\",\"server\",\"site\",\"-p\",\"$((P+5))\",\"--domain\",\"site\",\"--http\",\"$T\",\"-s\"]}" >/dev/null
edge() { curl -s -b "$T/jar" "$U/api/edge"; }
got=""
for _ in $(seq 1 30); do got=$(edge | j "[r['to'][0]['runtime'] for e in d['entrances'] if e['name']=='web' for r in e['routes'] if r['name']=='site.example.com']"); [ "$got" = "['site']" ] && break; sleep 0.2; done
expect "the entrance's routes name the runtime each goes to" "$got" "['site']"
expect "a certificate says its names and how long it has" \
    "$(edge | j "[(sorted(c['names']), 19 <= c['expires_in'] // 86400 <= 20) for c in d['certs'] if c['runtime']=='web']")" "[(['*.example.com', 'example.com'], True)]"
zpath=$(edge | j "[z['path'] for z in d['zones'] if z['runtime']=='ns'][0]")
expect "a zone is listed with its origin" "$(edge | j "[z['origin'] for z in d['zones'] if z['runtime']=='ns'][0]")" "example.com."
zone_text=$(curl -s -b "$T/jar" -G --data-urlencode "runtime=ns" --data-urlencode "path=$zpath" "$U/api/zone")
has "and read whole" "$zone_text" "SOA"
put() { curl -s -o "$T/put.out" -w '%{http_code}' -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -X PUT --data-binary "$1" "$U/api/zone"; }
body=$(python3 -c 'import json,sys; t=sys.argv[3].replace("hostmaster 2026","hostmaster 2027") + "\nhello TXT \"from the dashboard\"\n"; print(json.dumps({"runtime":sys.argv[1],"path":sys.argv[2],"text":t}))' ns "$zpath" "$zone_text")
expect "an edit is written" "$(put "$body")" 204
for _ in $(seq 1 30); do got=$(dig @127.0.0.1 -p $((P+4)) +short hello.example.com TXT 2>/dev/null); [ -n "$got" ] && break; sleep 0.2; done
expect "and served" "$got" '"from the dashboard"'
bad=$(python3 -c 'import json,sys; print(json.dumps({"runtime":"ns","path":sys.argv[1],"text":sys.argv[2]+"\nbroken A 999.1.1.1\n"}))' "$zpath" "$zone_text")
expect "a zone that does not parse is refused" "$(put "$bad")" 400
has "saying where" "$(cat "$T/put.out")" "999.1.1.1"
expect "and the file is as it was" "$(grep -c '999.1.1.1' "$zpath")" 0
expect "a file no dns runtime serves is none of the page's" \
    "$(put "$(python3 -c 'import json; print(json.dumps({"runtime":"ns","path":"/etc/passwd","text":"x"}))')")" 404
expect "and a change needs the page's header" "$(curl -s -o /dev/null -w '%{http_code}' -b "$T/jar" -X PUT --data-binary "$body" "$U/api/zone")" 403

expect "signing out ends the session" "$(code -X DELETE -b "$T/jar" -c "$T/jar" "$U/api/session") $(code -b "$T/jar" "$U/api/runtimes")" "204 401"

# ─── without credentials ────────────────────────────────────────────────────
daemon_stop
daemon_isolate dash2
cat > "$SOCKETLEY_TMPD/daemon.lua" <<EOF
daemon = { metrics_port = $M }
EOF
export SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/daemon.lua"
daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
expect "without credentials the figures are read as before" "$(code "$U/api/runtimes")" 200
expect "and nobody signs in" "$(code -X POST -u "$ADMIN" "$U/api/session")" 403
expect "or changes anything" "$(code -H 'X-Socketley-Dashboard: 1' -d '{"args":["ls"]}' "$U/api/run")" 403

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
