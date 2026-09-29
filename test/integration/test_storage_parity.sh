#!/usr/bin/env bash
# Integration test: what a storage runtime shares with the other runtime types.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   node        a storage runtime with a port has a companion node beside it,
#               serves S3 over it, and stop removes it; a proxy naming the
#               runtime dials the node and not the port
#   proxy       a proxy in front -- tcp mode by name and by @group, and http mode
#               under its prefix -- carries a 30 MiB PUT and GET byte for byte,
#               a Range read and an error status
#   idle        --idle-timeout closes a keep-alive connection that has sat idle,
#               counts it in `timeouts`, and leaves a runtime with none alone
#   stats       `stats` counts what was asked (gets, heads, puts, deletes,
#               lists), what was answered with an error by its S3 code, the
#               objects and bytes held, and `total_messages` follows requests
#   metrics     the Prometheus endpoint carries the same as storage series, and
#               each moves when the runtime is used
#   restart     a daemon restart brings a running TLS runtime back with its
#               settings, its objects and its listener
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

unset SOCKETLEY_CONFIG
daemon_isolate stgpar

B=$((SL_PORT_BASE+1630))
MPORT=$((B+9))
T="$SOCKETLEY_TMPD"
NODEDIR="$SOCKETLEY_SOCKET.rt"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

RUNTIMES="sp_stg sp_ptcp sp_pgrp sp_phttp sp_idle sp_noidle sp_stats sp_tls"
cleanup() {
    for r in $RUNTIMES; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $RUNTIMES; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage next to the other runtime types ==="
for tool in curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done

# The metrics port is read once at startup, from the dev-mode config path.
mkdir -p "$HOME/.config/socketley"
cat > "$HOME/.config/socketley/config.lua" <<LUA
config = {
    metrics_port = $MPORT
}
LUA
daemon_start "$BIN"

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # url
    for _ in $(seq 1 100); do
        [ "$(code --max-time 2 "$1")" = 200 ] && return 0
        sleep 0.1
    done
    return 1
}
stat_of() {   # runtime key
    "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2://p" | head -1
}
# `stats` is published when the worker's figures change, so a figure is read
# until it holds the wanted value rather than once.
stat_is() {   # label runtime key want
    local got=""
    for _ in $(seq 1 50); do
        got=$(stat_of "$2" "$3")
        [ "$got" = "$4" ] && { ok "$1"; return 0; }
        sleep 0.1
    done
    bad "$1" "stats $2 $3 is '$got', want '$4'"
}

# ── a storage runtime with a node ───────────────────────────────────────────
"$BIN" create storage sp_stg -p "$B" --dir "$T/o1" --anonymous --group spg -s >/dev/null 2>&1 \
    || bad "create" "sp_stg was not created"
wait_up "http://127.0.0.1:$B/" || bad "up" "no answer on $B"
NODE="$NODEDIR/sp_stg.sock"
if [ -S "$NODE" ]; then ok "a storage runtime with a port has a companion node"; else bad "companion node" "no socket at $NODE"; fi
usock() { curl -s --unix-socket "$NODE" "$@"; }
usock -X PUT http://x/nodebkt -o /dev/null
head -c 31457280 /dev/urandom > "$T/big"
want=$(md5sum < "$T/big" | cut -d' ' -f1)
expect "a 30 MiB put over the node is 200" "$(usock -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$T/big" http://x/nodebkt/big)" 200
expect "and comes back byte for byte over the node" "$(usock http://x/nodebkt/big | md5sum | cut -d' ' -f1)" "$want"
expect "the port serves what the node stored" "$(curl -s "http://127.0.0.1:$B/nodebkt/big" | md5sum | cut -d' ' -f1)" "$want"

# ── a proxy in front ────────────────────────────────────────────────────────
"$BIN" create proxy sp_ptcp -p $((B+1)) --protocol tcp --backend sp_stg -s >/dev/null 2>&1 || bad "create" "sp_ptcp"
"$BIN" create proxy sp_pgrp -p $((B+2)) --protocol tcp --backend @spg -s >/dev/null 2>&1 || bad "create" "sp_pgrp"
"$BIN" create proxy sp_phttp -p $((B+3)) --backend sp_stg -s >/dev/null 2>&1 || bad "create" "sp_phttp"
wait_up "http://127.0.0.1:$((B+1))/" || bad "up" "the tcp proxy is not answering"
wait_up "http://127.0.0.1:$((B+2))/" || bad "up" "the group proxy is not answering"
for _ in $(seq 1 100); do [ "$(code "http://127.0.0.1:$((B+3))/sp_phttp/")" = 200 ] && break; sleep 0.1; done

via() {   # label base-url
    local url=$2
    expect "$1: a 30 MiB put is 200" "$(code -X PUT --data-binary @"$T/big" "$url/nodebkt/via-$1")" 200
    expect "$1: and comes back byte for byte" "$(curl -s "$url/nodebkt/via-$1" | md5sum | cut -d' ' -f1)" "$want"
    local got want_r
    got=$(curl -s -H 'Range: bytes=5000000-6999999' "$url/nodebkt/via-$1" | md5sum | cut -d' ' -f1)
    want_r=$(tail -c +5000001 "$T/big" | head -c 2000000 | md5sum | cut -d' ' -f1)
    expect "$1: a Range read is exact" "$got" "$want_r"
    expect "$1: a missing key is 404" "$(code "$url/nodebkt/no-such-key")" 404
    expect "$1: an object put through it is the same object on the runtime" \
        "$(curl -s "http://127.0.0.1:$B/nodebkt/via-$1" | md5sum | cut -d' ' -f1)" "$want"
}
via tcp "http://127.0.0.1:$((B+1))"
via group "http://127.0.0.1:$((B+2))"
via http "http://127.0.0.1:$((B+3))/sp_phttp"

# The proxy dialled the node: while a connection through it is open, the
# runtime has an AF_UNIX peer and no TCP peer other than the one we gave it.
if command -v ss >/dev/null 2>&1; then
    python3 - "$((B+1))" > "$T/held.out" 2>&1 <<'PYEOF' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET /nodebkt/via-tcp HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\n\r\n")
s.settimeout(5)
d = s.recv(4096)
print("HELD", d[:12])
time.sleep(6)
PYEOF
    HELD=$!
    sleep 2
    unixpeers=$(ss -xnH 2>/dev/null | grep -c "sp_stg.sock")
    tcpbackend=$(ss -tnH state established "( sport = :$B )" 2>/dev/null | wc -l)
    if [ "${unixpeers:-0}" -ge 1 ]; then ok "a proxy naming the runtime holds a connection on its node"
    else bad "a proxy dials the node" "no AF_UNIX socket on sp_stg.sock: $(ss -xnH 2>/dev/null | head -5)"; fi
    if [ "${tcpbackend:-0}" -eq 0 ]; then ok "and none to its TCP port"
    else bad "a proxy dials the node and not the port" "$tcpbackend TCP connections to :$B"; fi
    kill "$HELD" 2>/dev/null; wait "$HELD" 2>/dev/null
fi

# The old worker outlives its stop by a few tens of milliseconds, and the next
# worker binds the same path.  The old one is held with SIGSTOP the moment its
# node is gone, the runtime is started, and the old one is let go once the new
# node is there: its exit must not take the new node with it.  A worker that has
# already gone when it is held is tried again.
HELDPID=""
trap '[ -n "$HELDPID" ] && kill -CONT "$HELDPID" 2>/dev/null; cleanup' EXIT
held_old=0
for attempt in 1 2 3 4 5 6; do
    oldpid=$(stat_of sp_stg pid)
    [ -n "$oldpid" ] || { sleep 0.3; continue; }
    "$BIN" stop sp_stg >/dev/null 2>&1
    for _ in $(seq 1 500); do [ -e "$NODE" ] || break; sleep 0.01; done
    if [ "$attempt" = 1 ]; then
        if [ -e "$NODE" ]; then bad "stop removes the node" "$NODE is still there"; else ok "stop removes the node"; fi
    fi
    if kill -STOP "$oldpid" 2>/dev/null; then HELDPID=$oldpid; held_old=1; fi
    "$BIN" start sp_stg >/dev/null 2>&1
    wait_up "http://127.0.0.1:$B/" || bad "restart" "no answer"
    for _ in $(seq 1 50); do [ -S "$NODE" ] && break; sleep 0.1; done
    if [ "$held_old" = 1 ]; then
        kill -CONT "$oldpid" 2>/dev/null
        for _ in $(seq 1 100); do kill -0 "$oldpid" 2>/dev/null || break; sleep 0.05; done
        HELDPID=""
        sleep 0.2
        break
    fi
done
if [ "$held_old" = 1 ]; then ok "the old worker was held across the start ($attempt tries)"; else bad "holding the old worker" "it had exited every time"; fi
if [ -S "$NODE" ]; then ok "start makes the node again, and the old worker's exit leaves it alone"; else bad "the new node survives the old worker's exit" "no socket in $(ls "$NODEDIR" 2>&1 | tr "\n" " ")"; fi
expect "the objects are served over the new node" "$(usock http://x/nodebkt/big | md5sum | cut -d' ' -f1)" "$want"

# ── --idle-timeout ──────────────────────────────────────────────────────────
"$BIN" create storage sp_idle -p $((B+5)) --dir "$T/o3" --anonymous --idle-timeout 2 -s >/dev/null 2>&1 || bad "create" "sp_idle"
"$BIN" create storage sp_noidle -p $((B+6)) --dir "$T/o4" --anonymous -s >/dev/null 2>&1 || bad "create" "sp_noidle"
wait_up "http://127.0.0.1:$((B+5))/" || bad "up" "sp_idle"
wait_up "http://127.0.0.1:$((B+6))/" || bad "up" "sp_noidle"
idle_probe() {   # port wait
python3 - "$1" "$2" <<'PYEOF'
import socket, sys, time
port, wait = int(sys.argv[1]), float(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
s.settimeout(5)
d = s.recv(65536)
assert d.startswith(b"HTTP/1.1 200"), d[:40]
t0 = time.time()
s.settimeout(wait)
try:
    d = s.recv(10)
    print("closed" if d == b"" else "data", round(time.time() - t0, 1))
except socket.timeout:
    print("open", round(time.time() - t0, 1))
PYEOF
}
r=$(idle_probe $((B+5)) 10)
set -- $r
if [ "$1" = closed ] && awk -v t="$2" 'BEGIN{exit !(t>=1.5 && t<=6)}'; then ok "an idle keep-alive connection is closed at --idle-timeout ($r)"
else bad "--idle-timeout closes an idle connection" "$r"; fi
stat_is "and the close is counted in timeouts" sp_idle timeouts 1
r=$(idle_probe $((B+6)) 5)
set -- $r
expect "a runtime with no --idle-timeout leaves an idle connection alone" "$1" open

# ── stats ───────────────────────────────────────────────────────────────────
"$BIN" create storage sp_stats -p $((B+7)) --dir "$T/o5" --anonymous -s >/dev/null 2>&1 || bad "create" "sp_stats"
wait_up "http://127.0.0.1:$((B+7))/" || bad "up" "sp_stats"
S="http://127.0.0.1:$((B+7))"
# The probe that waited for the runtime listed the buckets, and how many times
# depends on how long it waited, so the count is taken from here.
prev=""; for _ in $(seq 1 20); do cur=$(stat_of sp_stats lists); [ -n "$cur" ] && [ "$cur" = "$prev" ] && break; prev=$cur; sleep 0.3; done
LISTS0=${cur:-0}
curl -s -X PUT "$S/statbkt" -o /dev/null
curl -s -X PUT --data-binary "twelve bytes" "$S/statbkt/a" -o /dev/null
curl -s -X PUT --data-binary "0123456789" "$S/statbkt/b" -o /dev/null
curl -s "$S/statbkt/a" -o /dev/null
curl -s -I "$S/statbkt/a" -o /dev/null
curl -s "$S/statbkt/missing1" -o /dev/null
curl -s "$S/statbkt/missing2" -o /dev/null
curl -s "$S/nosuchbucket/k" -o /dev/null
curl -s "$S/statbkt?list-type=2" -o /dev/null
curl -s -X DELETE "$S/statbkt/b" -o /dev/null
curl -s -X PUT "$S/x" -o /dev/null
stat_is "stats counts the puts" sp_stats puts 2
stat_is "stats counts the gets" sp_stats gets 4
stat_is "stats counts the heads" sp_stats heads 1
stat_is "stats counts the deletes" sp_stats deletes 1
stat_is "stats counts the lists" sp_stats lists $((LISTS0 + 1))
stat_is "stats holds the objects" sp_stats objects 1
stat_is "stats holds the bytes" sp_stats bytes 12
stat_is "stats counts NoSuchKey by its code" sp_stats error_NoSuchKey 2
stat_is "stats counts NoSuchBucket by its code" sp_stats error_NoSuchBucket 1
stat_is "stats counts InvalidBucketName by its code" sp_stats error_InvalidBucketName 1
stat_is "and the client errors in all" sp_stats client_errors 4
tm=""; rq=""
for _ in $(seq 1 50); do
    tm=$(stat_of sp_stats total_messages); rq=$(stat_of sp_stats requests)
    [ -n "$tm" ] && [ "$tm" = "$rq" ] && break
    sleep 0.1
done
if [ -n "$tm" ] && [ "$tm" = "$rq" ]; then ok "total_messages follows the requests served ($tm)"; else bad "total_messages follows requests" "total_messages=$tm requests=$rq"; fi
bo=""
for _ in $(seq 1 50); do bo=$(stat_of sp_stats bytes_out); [ "${bo:-0}" -gt 500 ] && break; sleep 0.1; done
if [ "${bo:-0}" -gt 500 ]; then ok "bytes_out counts what was sent ($bo)"; else bad "bytes_out" "$bo"; fi

# ── the metrics endpoint ────────────────────────────────────────────────────
metrics() { curl -s --max-time 5 "http://127.0.0.1:$MPORT/metrics"; }
series() {   # name-with-labels -> value
    metrics | awk -v n="$1" '$1==n {print $2; exit}'
}
series_is() {   # label series want
    local got=""
    for _ in $(seq 1 50); do
        got=$(series "$2")
        [ "$got" = "$3" ] && { ok "$1"; return 0; }
        sleep 0.2
    done
    bad "$1" "$2 is '$got', want '$3'"
}
series_is "metrics: objects held" 'socketley_storage_objects{name="sp_stats"}' 1
series_is "metrics: bytes held" 'socketley_storage_bytes_stored{name="sp_stats"}' 12
series_is "metrics: buckets held" 'socketley_storage_buckets{name="sp_stats"}' 1
series_is "metrics: puts" 'socketley_storage_requests_total{name="sp_stats",op="put"}' 2
series_is "metrics: gets" 'socketley_storage_requests_total{name="sp_stats",op="get"}' 4
series_is "metrics: NoSuchKey answers" 'socketley_storage_errors_total{name="sp_stats",code="NoSuchKey"}' 2
bin=$(series 'socketley_storage_bytes_received_total{name="sp_stats"}')
if [ "${bin:-0}" -gt 200 ]; then ok "metrics: bytes received ($bin)"; else bad "metrics: bytes received" "'$bin'"; fi
curl -s -X PUT --data-binary "third" "$S/statbkt/c" -o /dev/null
series_is "metrics: the object count moves with a put" 'socketley_storage_objects{name="sp_stats"}' 2
curl -s "$S/statbkt/gone" -o /dev/null
series_is "metrics: an error count moves with an error" 'socketley_storage_errors_total{name="sp_stats",code="NoSuchKey"}' 3
contains "the JSON API carries the same text" "$(curl -s "http://127.0.0.1:$MPORT/api/runtime/sp_stats")" "error_NoSuchKey:3"

# ── a daemon restart brings a TLS runtime back ──────────────────────────────
if command -v openssl >/dev/null 2>&1; then
    CERTS="$T/certs"; mkdir -p "$CERTS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/k.pem" -out "$CERTS/c.pem" \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
    if [ -s "$CERTS/c.pem" ]; then
        "$BIN" create storage sp_tls -p $((B+8)) --dir "$T/o6" --anonymous --tls --cert "$CERTS/c.pem" --key "$CERTS/k.pem" \
            --idle-timeout 77 --max-connections 33 --max-bytes 9M -s >/dev/null 2>&1 || bad "create" "sp_tls"
        https() { curl -s --cacert "$CERTS/c.pem" "$@"; }
        for _ in $(seq 1 100); do [ "$(https -o /dev/null -w '%{http_code}' "https://localhost:$((B+8))/")" = 200 ] && break; sleep 0.1; done
        https -X PUT "https://localhost:$((B+8))/keepbkt" -o /dev/null
        https -X PUT --data-binary "survives a restart" "https://localhost:$((B+8))/keepbkt/k" -o /dev/null
        kill "$SOCKETLEY_DPID" 2>/dev/null
        for _ in $(seq 1 100); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
        : > "$SOCKETLEY_DLOG"
        daemon_start "$BIN"
        for _ in $(seq 1 100); do [ "$(https -o /dev/null -w '%{http_code}' "https://localhost:$((B+8))/")" = 200 ] && break; sleep 0.1; done
        expect "after a daemon restart the TLS runtime is serving again" "$(https -o /dev/null -w '%{http_code}' "https://localhost:$((B+8))/")" 200
        expect "with the object it held" "$(https "https://localhost:$((B+8))/keepbkt/k")" "survives a restart"
        expect "and is still not served in the clear" "$(code --max-time 3 "http://127.0.0.1:$((B+8))/")" 000
        shown=$("$BIN" show sp_tls 2>&1)
        contains "show says tls" "$shown" '"tls": true'
        contains "show keeps the idle timeout" "$shown" '"idle_timeout": 77'
        contains "show keeps the connection limit" "$shown" '"max_connections": 33'
        contains "show keeps the quota" "$shown" '"max_bytes": 9437184'
    else
        echo "  SKIP: openssl could not make a certificate; the TLS restart is not run"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
