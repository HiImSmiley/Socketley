#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the latency histograms of proxy, server, cache, db, idp, mail and storage reach the daemon's
# /metrics as Prometheus histograms, and their counts follow the requests sent.
#
# What each part would catch:
#   * a histogram family missing or under another TYPE, which histogram_quantile cannot read
#   * buckets out of order, not cumulative, without +Inf, or a +Inf that is not the _count: a scrape Prometheus refuses
#   * a runtime whose requests are not observed, or observed at a point no request reaches: a count that does not rise
#   * two shards' lines not added together: a sharded proxy's count short of the requests it answered
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"
exec 2>&1
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: latency histograms in /metrics ==="
daemon_isolate metricslat
T=$SOCKETLEY_TMPD
B=$((SL_PORT_BASE + 1700))
PM=$((B+0)); PS=$((B+1)); PX=$((B+2)); PC=$((B+3)); PD=$((B+4)); PI=$((B+5)); PST=$((B+6)); PL=$((B+7))
PRL=$((B+8)); PX2=$((B+9))
unset SOCKETLEY_CONFIG
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s\n}\n' "$PM" > "$HOME/.config/socketley/config.lua"
cleanup() {
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

mkdir -p "$T/site" "$T/st" "$T/relay"
printf '<p>hello</p>\n' > "$T/site/index.html"
python3 "$HERE/lib_smtp_sink.py" "$PRL" "$T/relay" --auth 'x:y' >/dev/null 2>&1 &
SINK_PID=$!
ready_tcp 127.0.0.1 "$PRL" || bad "the smarthost listens" "-"
daemon_start "$BIN"

KEY=AKIAMETRICSLATENCY00
SEC=metricslatencysecretmetricslat00
printf 'backend metricslatencysecret0123\n' > "$T/keys"
made() {  # name, then the create's arguments
    local name=$1; shift
    local out
    out=$("$BIN" create "$@" -s 2>&1) || bad "$name is made" "$out"
}
made server  server srv -p "$PS" --http "$T/site"
made proxy   proxy px -p "$PX" --backend "127.0.0.1:$PS"
made proxy   proxy px2 -p "$PX2" --backend "127.0.0.1:$PS" --shards 2
made cache   cache ca -p "$PC"
made db      db dbx -p "$PD" --keys "$T/keys"
made idp     idp auth -p "$PI" --issuer "http://127.0.0.1:$PI"
made storage storage st -p "$PST" --dir "$T/st" --access-key "$KEY" --secret-key "$SEC"
made mail    mail ml -p "$PL" --mail-domain example.test --relay "smtp://x:y@127.0.0.1:$PRL"
for p in "$PS" "$PX" "$PX2" "$PC" "$PD" "$PI" "$PST" "$PL"; do
    ready_tcp 127.0.0.1 "$p" || bad "the runtime on $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done

get() { curl -s -m 8 "http://127.0.0.1:$PM/metrics"; }
FAMILIES="socketley_proxy_request_duration_seconds socketley_proxy_backend_connect_duration_seconds
socketley_proxy_backend_first_byte_seconds socketley_server_http_request_duration_seconds
socketley_cache_batch_duration_seconds socketley_db_request_duration_seconds socketley_idp_sign_in_duration_seconds
socketley_storage_request_duration_seconds socketley_mail_delivery_duration_seconds"

# count <metrics text> <family> <name label>: the family's _count for that runtime, 0 when it has none.
count() {
    awk -v s="$2_count{name=\"$3\"}" '$1==s{print $2; f=1; exit} END{if(!f) print 0}' <<<"$1"
}

# Before: every family is there for a runtime that has served nothing, its count 0.
M0=""
for _ in $(seq 1 40); do
    M0=$(get)
    all=1
    for f in $FAMILIES; do grep -qx "# TYPE $f histogram" <<<"$M0" || all=0; done
    [ "$all" = 1 ] && break
    sleep 0.25
done
for f in $FAMILIES; do
    grep -qx "# TYPE $f histogram" <<<"$M0" && ok || bad "$f is a histogram before any request" \
        "$(grep -F "$f" <<<"$M0" | head -3 | tr '\n' ' ')"
done

# ── the requests each histogram must count ──
for i in 1 2 3 4 5; do
    curl -s -o /dev/null "http://127.0.0.1:$PS/index.html"
    curl -s -o /dev/null "http://127.0.0.1:$PX/px/index.html"
done
BODY=$(curl -s "http://127.0.0.1:$PX/px/index.html")
[ "$(head -1 <<<"$BODY")" = "<p>hello</p>" ] && ok || bad "the proxy answers with the backend's page" "'$BODY'"
for i in $(seq 1 12); do curl -s -o /dev/null "http://127.0.0.1:$PX2/px2/index.html"; done
python3 - "$PC" <<'PY'
import socket, sys
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
for a in ([b"SET", b"k", b"v"], [b"GET", b"k"], [b"GET", b"k"]):
    c.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
    got = b""
    while not got.endswith(b"\r\n"):
        got += c.recv(4096)
PY
DBK="Authorization: Bearer metricslatencysecret0123"
curl -s -o /dev/null -X PUT -H "$DBK" -H 'Content-Type: application/json' --data '{"a":1}' "http://127.0.0.1:$PD/c/notes/n1"
curl -s -o /dev/null -H "$DBK" "http://127.0.0.1:$PD/c/notes/n1"
curl -s -o /dev/null -H "$DBK" "http://127.0.0.1:$PD/c/notes/n1"
for i in 1 2; do
    curl -s -o /dev/null -H "Origin: http://127.0.0.1:$PI" --data 'username=nobody&password=wrongwrong' \
        "http://127.0.0.1:$PI/login"
done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$PST/docs"
printf 'hello' | S -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$PST/docs/a.txt"
S -o /dev/null "http://127.0.0.1:$PST/docs/a.txt"
python3 - "$PL" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1])); s.ehlo("t")
s.sendmail("s@example.test", ["p@far.test"], b"From: s@example.test\r\nSubject: t\r\n\r\nbody\r\n")
s.quit()
PY

# After: polled until every worker's figures have reached the daemon.
want() {  # family runtime least
    [ "$(count "$M" "$1" "$2")" -ge "$3" ] 2>/dev/null
}
M=""
for _ in $(seq 1 80); do
    M=$(get)
    want socketley_proxy_request_duration_seconds px 6 && want socketley_server_http_request_duration_seconds srv 16 &&
        want socketley_proxy_request_duration_seconds px2 12 &&
        want socketley_cache_batch_duration_seconds ca 3 && want socketley_db_request_duration_seconds dbx 3 &&
        want socketley_idp_sign_in_duration_seconds auth 2 && want socketley_storage_request_duration_seconds st 3 &&
        want socketley_mail_delivery_duration_seconds ml 1 && break
    sleep 0.25
done

rose() {  # family runtime least
    local before after
    before=$(count "$M0" "$1" "$2"); after=$(count "$M" "$1" "$2")
    if [ "$before" = 0 ] && [ "$after" -ge "$3" ] 2>/dev/null; then ok
    else bad "$1{name=\"$2\"} counts its requests" "before $before, after $after, wanted at least $3"; fi
}
rose socketley_proxy_request_duration_seconds          px   6
rose socketley_proxy_backend_first_byte_seconds        px   6
rose socketley_proxy_backend_connect_duration_seconds  px   1
rose socketley_server_http_request_duration_seconds    srv  16
rose socketley_cache_batch_duration_seconds            ca   3
rose socketley_db_request_duration_seconds             dbx  3
rose socketley_idp_sign_in_duration_seconds            auth 2
rose socketley_storage_request_duration_seconds        st   3
rose socketley_mail_delivery_duration_seconds          ml   1
# Each of two shards answers its own share, and the daemon's figure is both added together.
[ "$(count "$M" socketley_proxy_request_duration_seconds px2)" = 12 ] && ok \
    || bad "a sharded proxy's two histograms are added" "$(count "$M" socketley_proxy_request_duration_seconds px2) of 12"
# Exactly the requests sent, so a request is not observed twice on its way through.
[ "$(count "$M" socketley_proxy_request_duration_seconds px)" = 6 ] && ok \
    || bad "each proxied request is observed once" "$(count "$M" socketley_proxy_request_duration_seconds px) of 6"
[ "$(count "$M" socketley_idp_sign_in_duration_seconds auth)" = 2 ] && ok \
    || bad "each sign-in is observed once" "$(count "$M" socketley_idp_sign_in_duration_seconds auth) of 2"

# ── the structure Prometheus requires of every histogram on the page ──
printf '%s\n' "$M" > "$T/metrics.txt"
STRUCT=$(python3 - "$FAMILIES" "$T/metrics.txt" <<'PY'
import re, sys
want = sys.argv[1].split()
text = open(sys.argv[2]).read()
types = dict(re.findall(r"^# TYPE (\S+) (\S+)$", text, re.M))
problems, seen = [], {}
line_re = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)$')
for line in text.splitlines():
    if not line or line.startswith("#"):
        continue
    m = line_re.match(line)
    if not m:
        problems.append("unreadable line: " + line); continue
    name, labels, value = m.group(1), m.group(2) or "", float(m.group(3))
    for suffix in ("_bucket", "_sum", "_count"):
        if name.endswith(suffix) and types.get(name[:-len(suffix)]) == "histogram":
            fam = name[:-len(suffix)]
            ls = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', labels))
            le = ls.pop("le", None)
            key = (fam, tuple(sorted(ls.items())))
            h = seen.setdefault(key, {"buckets": [], "sum": None, "count": None})
            if suffix == "_bucket":
                if le is None:
                    problems.append("a bucket without le: " + line)
                else:
                    h["buckets"].append((le, value))
            elif suffix == "_sum":
                h["sum"] = value
            else:
                h["count"] = value
for (fam, ls), h in seen.items():
    where = fam + str(dict(ls))
    b = h["buckets"]
    if not b or b[-1][0] != "+Inf":
        problems.append(where + ": the last bucket is not +Inf"); continue
    bounds = [float(le) for le, _ in b]
    if bounds != sorted(bounds) or len(set(bounds)) != len(bounds):
        problems.append(where + ": le is not ascending")
    counts = [v for _, v in b]
    if any(later < earlier for earlier, later in zip(counts, counts[1:])):
        problems.append(where + ": buckets are not cumulative")
    if h["count"] is None or h["count"] != counts[-1]:
        problems.append(where + ": _count %s is not the +Inf bucket %s" % (h["count"], counts[-1]))
    if h["sum"] is None or h["sum"] < 0:
        problems.append(where + ": no _sum")
    if len(b) != 20:
        problems.append(where + ": %d buckets" % len(b))
for f in want:
    if types.get(f) != "histogram":
        problems.append(f + " is not a histogram")
    if not any(k[0] == f for k in seen):
        problems.append(f + " has no series")
print("\n".join(problems) if problems else "ok %d" % len(seen))
PY
)
case "$STRUCT" in
    ok*) ok ;;
    *) bad "every histogram is cumulative, ascending, ends in +Inf and counts to its _count" "$STRUCT" ;;
esac
# A real duration reaches a bucket past the first: the mail attempt is a connection, a greeting and a transaction.
SUM=$(awk -v s='socketley_mail_delivery_duration_seconds_sum{name="ml"}' '$1==s{print $2}' <<<"$M")
python3 -c "import sys; sys.exit(0 if float('${SUM:-0}') > 0 else 1)" && ok \
    || bad "a mail delivery takes some time" "sum '${SUM:-}'"

echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
