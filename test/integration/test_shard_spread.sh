#!/usr/bin/env bash
# Integration test: the connections to a sharded runtime reach every shard.
#
# A shard set is worth its count only if the work spreads over it, and nothing
# asserted that: a dns runtime answering a resolver from one port ran every
# query on one shard of four (400/1/0/0) and every test stayed green.  The
# kernel picks a shard per connection by its addresses and ports, so 64
# connections from 64 client ports must land on every shard of four -- the
# odds of a shard taking fewer than 4 of them by chance are about 1 in 10,000.
#
#   every type    each listening type that shards over one port: server, cache,
#                 web, idp, proxy, mqtt, mcp, storage, db and mail's IMAP port
#   restart       a shard killed and started again by the daemon rejoins the
#                 port's group and takes its share of the next connections
#   oversubscribed  four shards on a daemon held to two CPUs still each take a
#                 share: placement is per CPU, the spread is per connection
#
# dns's UDP spread from one asking port is test_dns's.  mail's SMTP port is
# shard 0's alone by design (ebc28ee9), so mail is read on its IMAP port.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

daemon_isolate shardspread
T=$SOCKETLEY_TMPD
NAMES="sv ca we au px mq mc st db ml mlid mlst"
cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# Holds 64 connections to a port while the shards are read, then lets them go.
spread() {
    local name=$1 port=$2
    python3 - "$port" "$BIN" "$name" <<'PY'
import socket, subprocess, sys, time
port, binary, name = int(sys.argv[1]), sys.argv[2], sys.argv[3]
socks = []
for _ in range(64):
    try:
        socks.append(socket.create_connection(("127.0.0.1", port), timeout=5))
    except OSError:
        pass
deadline = time.time() + 6
counts = []
while time.time() < deadline:
    out = subprocess.run([binary, "stats", name], capture_output=True, text=True).stdout
    counts = [int(l.split(":", 1)[1]) for l in out.splitlines() if l.startswith("shard_connections:")]
    if len(counts) == 4 and sum(counts) >= len(socks):
        break
    time.sleep(0.25)
print(len(socks), " ".join(map(str, counts)))
PY
}

judge() {
    local label=$1 opened=$2; shift 2
    local counts=("$@")
    if [ "$opened" != 64 ] || [ "${#counts[@]}" -ne 4 ]; then
        bad "$label: $opened of 64 connected, shards read '${counts[*]}'"
        return
    fi
    local least=64 most=0 c
    for c in "${counts[@]}"; do
        [ "$c" -lt "$least" ] && least=$c
        [ "$c" -gt "$most" ] && most=$c
    done
    if [ "$least" -ge 4 ] && [ "$most" -le 32 ]; then
        ok "$label: 64 connections over four shards (${counts[*]})"
    else
        bad "$label: 64 connections over four shards went ${counts[*]}"
    fi
}

up() {  # a port that accepts, waited for rather than slept for
    local i
    for i in $(seq 1 80); do
        python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), timeout=0.5).close()" 2>/dev/null && return 0
        sleep 0.25
    done
    return 1
}

mkdir -p "$T/www" "$T/st" "$T/mlst"
echo hi > "$T/www/index.html"
printf 'k1 spreadsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
printf 'items private level name\n' > "$T/schema"
: > "$T/clients"

B=$SL_PORT_BASE
P_SV=$((B+1440)); P_CA=$((B+1441)); P_WE=$((B+1442)); P_AU=$((B+1443)); P_PX=$((B+1444))
P_MQ=$((B+1445)); P_MC=$((B+1446)); P_ST=$((B+1447)); P_DB=$((B+1448))
P_MLID=$((B+1449)); P_MLST=$((B+1450)); P_ML=$((B+1451)); P_IMAP=$((B+1452))

echo "== every listening type, four shards =="
"$BIN" create server  sv -p $P_SV --shards 4 -s >/dev/null 2>&1
"$BIN" create cache   ca -p $P_CA --shards 4 -s >/dev/null 2>&1
"$BIN" create web     we -p $P_WE --root "$T/www" --shards 4 -s >/dev/null 2>&1
"$BIN" create idp     au -p $P_AU --issuer "http://127.0.0.1:$P_AU" --shards 4 -s >/dev/null 2>&1
"$BIN" create proxy   px -p $P_PX --backend "127.0.0.1:$P_SV" --shards 4 -s >/dev/null 2>&1
"$BIN" create mqtt    mq -p $P_MQ --anonymous --shards 4 -s >/dev/null 2>&1
"$BIN" create mcp     mc -p $P_MC --anonymous --shards 4 -s >/dev/null 2>&1
"$BIN" create storage st -p $P_ST --dir "$T/st" --access-key AKIDSPREAD --secret-key spreadsecretspreadsecret --shards 4 -s >/dev/null 2>&1
"$BIN" create db      db -p $P_DB --schema "$T/schema" --keys "$T/keys" --shards 4 -s >/dev/null 2>&1
"$BIN" create idp     mlid -p $P_MLID --clients "$T/clients" --issuer "http://127.0.0.1:$P_MLID" -s >/dev/null 2>&1
"$BIN" create storage mlst -p $P_MLST --dir "$T/mlst" --anonymous -s >/dev/null 2>&1
"$BIN" create mail    ml -p $P_ML --mail-domain example.test --idp mlid --storage mlst/mail --imap $P_IMAP --shards 4 -s >/dev/null 2>&1

for pair in "sv:$P_SV:server" "ca:$P_CA:cache" "we:$P_WE:web" "au:$P_AU:idp" "px:$P_PX:proxy" "mq:$P_MQ:mqtt" \
            "mc:$P_MC:mcp" "st:$P_ST:storage" "db:$P_DB:db" "ml:$P_IMAP:mail (IMAP)"; do
    IFS=: read -r name port label <<<"$pair"
    if ! up "$port"; then
        bad "$label: never listened on $port"
        continue
    fi
    read -r opened rest < <(spread "$name" "$port")
    # shellcheck disable=SC2086
    judge "$label" "$opened" $rest
done

echo "== a shard killed and started again takes its share =="
# One of the four processes listening on the server's port, its shard 1 or another.
victim=$(ss -ltnpH "sport = :$P_SV" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u | sed -n 2p)
if [ -n "$victim" ] && kill -9 "$victim" 2>/dev/null; then
    # Gone, then four listeners again once the daemon has started its replacement.
    for _ in $(seq 1 80); do
        kill -0 "$victim" 2>/dev/null || break
        sleep 0.1
    done
    for _ in $(seq 1 80); do
        [ "$(ss -ltnH "sport = :$P_SV" 2>/dev/null | wc -l)" -ge 4 ] && break
        sleep 0.25
    done
    sleep 1
    read -r opened rest < <(spread sv "$P_SV")
    # shellcheck disable=SC2086
    judge "server after a shard was killed and restarted" "$opened" $rest
else
    bad "a shard of the server to kill was not found"
fi

echo "== four shards on two CPUs =="
"$BIN" stop sv >/dev/null 2>&1; "$BIN" remove sv >/dev/null 2>&1
daemon_stop
daemon_isolate shardspread2
export SOCKETLEY_CPUS=0-1
daemon_start "$BIN"
unset SOCKETLEY_CPUS
"$BIN" create server sv -p $P_SV --shards 4 -s >/dev/null 2>&1
if up "$P_SV"; then
    read -r opened rest < <(spread sv "$P_SV")
    # shellcheck disable=SC2086
    judge "server of four shards on two CPUs" "$opened" $rest
else
    bad "server on two CPUs never listened"
fi

echo
echo "shard spread: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
