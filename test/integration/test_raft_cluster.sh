#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# test_raft proves the core in a simulation where messages are function calls
# and the disk is a vector.  This file proves the host: real daemons, a real
# TCP transport, a real WAL fsynced through io_uring, real kill -9.  Raft mode
# is opt-in (`socketley daemon --raft-listen ...`) and experimental; nothing
# here touches a daemon started without it.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#  refusals        a --raft-* command line that runs in cleartext without
#                  --raft-insecure, founds and joins at once, advertises a
#                  wildcard, or starts with no state and no --raft-init/--join
#  three nodes     a joiner that never becomes a member, a learner never
#                  promoted, two nodes that disagree about the leader, a
#                  cluster whose commit index never converges
#  learner first   a joiner added straight as a voter, skipping the learner
#                  stage that lets it catch up without counting in a quorum
#  kill -9 leader  no new leader within the bound (elections, check-quorum,
#                  elapsed-time ticks), or the dead leader's id still named
#  restart         a WAL that recovers nothing (the log is empty after a
#                  restart), a node id that changes across restarts, a
#                  restarted node that cannot rejoin as a follower
#  snapshot join   compaction every 4 entries, so the fourth node can only
#                  catch up through InstallSnapshot, and its membership book
#                  arrives in the snapshot
#  graceful stop   a SIGTERM'd leader that does not hand over (the successor
#                  would then have waited out an election timeout and run a
#                  pre-vote, which TimeoutNow skips)
#  mutual TLS      a cluster that does not form over mTLS, a node whose
#                  certificate names someone else admitted, a certificate
#                  from another CA admitted
#
# Not covered here: network partitions.  They need netns or iptables, which
# need root; test/docker is where they belong (design note, M2).  Disk fault
# injection is not covered either.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0; TOTAL=0
T=$(mktemp -d /tmp/socketley-raft-XXXXXX)
PB=$((SL_PORT_BASE + 1700))
NODES=()

echo "=== Integration: Raft between daemons (experimental, opt-in) ==="

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

sock() { echo "$T/$1.sock"; }

# Start node $1 with the remaining flags, its own HOME, socket and log.
node_start() {
    local n=$1; shift
    mkdir -p "$T/$n/home"
    # A restart appends to the same log, so it waits for one more "daemon started" than the log already holds.
    local before
    before=$(grep -c "daemon started" "$T/$n.log" 2>/dev/null || true)
    HOME="$T/$n/home" SOCKETLEY_SOCKET="$(sock "$n")" SOCKETLEY_RAFT_COMPACT_EVERY=4 \
        "$BIN" daemon "$@" >>"$T/$n.log" 2>&1 &
    echo $! >"$T/$n.pid"
    NODES+=("$n")
    local i
    for i in $(seq 1 100); do
        [ "$(grep -c "daemon started" "$T/$n.log" 2>/dev/null || true)" -gt "${before:-0}" ] && return 0
        kill -0 "$(cat "$T/$n.pid")" 2>/dev/null || break
        sleep 0.1
    done
    echo "  FATAL: node $n never came up"; tail -5 "$T/$n.log" | sed 's/^/         /'
    exit 2
}

# Only a live node is asked, because the CLI starts a daemon on a dead socket; its pid, since daemon_alive walks every fd on the machine and costs seconds per poll.
status() {
    kill -0 "$(cat "$T/$1.pid" 2>/dev/null)" 2>/dev/null || return 0
    HOME="$T/$1/home" SOCKETLEY_SOCKET="$(sock "$1")" "$BIN" cluster raft-status 2>/dev/null || true
}
field() { status "$1" | awk -v k="$2:" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'; }
role()   { field "$1" role; }
leader() { field "$1" leader | awk '{ print substr($1, 1, 16) }'; }
myid()   { field "$1" node | awk '{ print substr($1, 1, 16) }'; }
voters() { field "$1" voters | sed 's/^none$//' | wc -w; }

# Poll `cond` every 0.2 s for at most $1 seconds.
wait_for() {
    local secs=$1; shift
    local i
    for i in $(seq 1 $((secs * 5))); do
        if eval "$*"; then return 0; fi
        sleep 0.2
    done
    return 1
}

leader_of() {
    local n
    for n in "$@"; do
        [ "$(role "$n")" = "leader" ] && { echo "$n"; return 0; }
    done
    return 1
}

cleanup() {
    set +e
    local n
    for n in "${NODES[@]}"; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then echo "  kept: $T" >&2; else rm -rf "$T"; fi
}
trap cleanup EXIT

# ─── refusals ───────────────────────────────────────────────────────────────
refuse() {
    local want=$1 needle=$2; shift 2
    local out rc=0
    mkdir -p "$T/refuse/home"
    out=$(HOME="$T/refuse/home" SOCKETLEY_SOCKET="$T/refuse.sock" timeout 10 "$BIN" daemon "$@" 2>&1) || rc=$?
    daemon_sweep "$T/refuse.sock"
    if [ "$rc" = "$want" ] && grep -q -- "$needle" <<<"$out"; then ok
    else bad "daemon $* exited $rc (wanted $want) saying: $out"; fi
}
refuse 1 "mutual TLS"      --raft-listen 127.0.0.1:$PB --raft-init
refuse 1 "give one of"     --raft-listen 127.0.0.1:$PB --raft-init --raft-join 127.0.0.1:$((PB+1)) --raft-insecure
refuse 1 "wildcard"        --raft-listen 0.0.0.0:$PB --raft-init --raft-insecure
refuse 1 "need --raft-listen" --raft-init
refuse 1 "numeric"         --raft-listen localhost:$PB --raft-init --raft-insecure
refuse 2 "no Raft state"   --raft-listen 127.0.0.1:$PB --raft-insecure

# ─── three nodes form a cluster, each joiner a learner first ───────────────
node_start a --raft-listen 127.0.0.1:$PB --raft-init --raft-insecure --raft-name a
node_start b --raft-listen 127.0.0.1:$((PB+1)) --raft-join 127.0.0.1:$PB --raft-insecure --raft-name b
node_start c --raft-listen 127.0.0.1:$((PB+2)) --raft-join 127.0.0.1:$PB --raft-insecure --raft-name c

formed() { [ "$(voters a)" = 3 ] && [ "$(voters b)" = 3 ] && [ "$(voters c)" = 3 ] \
           && [ -n "$(leader a)" ] && [ "$(leader a)" = "$(leader b)" ] && [ "$(leader b)" = "$(leader c)" ]; }
check 'wait_for 20 formed' "three daemons did not agree on three voters and one leader within 20 s"

L=$(leader_of a b c || true)
check '[ -n "$L" ]' "no node reports itself leader"
leaders=0
for n in a b c; do [ "$(role "$n")" = leader ] && leaders=$((leaders+1)); done
check '[ "$leaders" = 1 ]' "$leaders nodes report themselves leader"
check 'grep -q "adding .*(b) as a learner" "$T/a.log" && grep -q "adding .*(c) as a learner" "$T/a.log"' \
      "the founder did not add the joiners as learners"
check 'grep -qE "membership at [0-9]+: voters [0-9a-f]+\(a\); learners" "$T/a.log"' \
      "no committed membership ever held a learner"
check 'grep -q "promoting .*(b) to voter" "$T/a.log" && grep -q "promoting .*(c) to voter" "$T/a.log"' \
      "a learner was never promoted"
check 'wait_for 5 "grep -q \"joined the cluster as a voter\" $T/b.log"' "b never said it had joined"
converged() { local x; x=$(field a commit); [ -n "$x" ] && [ "$x" = "$(field b commit)" ] && [ "$x" = "$(field c commit)" ]; }
check 'wait_for 10 converged' "the three commit indexes did not converge"
check '[ "$(HOME=$T/a/home SOCKETLEY_SOCKET=$(sock a) "$BIN" cluster raft-status >/dev/null 2>&1; echo $?)" = 0 ]' \
      "raft-status did not exit 0 on a healthy cluster"
check 'status a | grep -q "cleartext (--raft-insecure)"' "status does not say the transport is cleartext"

# ─── kill -9 the leader: a new one within the bound ────────────────────────
old_id=$(myid "$L")
old_term=$(field "$L" term)
survivors=()
for n in a b c; do [ "$n" != "$L" ] && survivors+=("$n"); done
kill -9 "$(cat "$T/$L.pid")"
wait "$(cat "$T/$L.pid")" 2>/dev/null || true
t0=$(date +%s%N)
new_leader() { local n; n=$(leader_of "${survivors[@]}") || return 1; [ "$(myid "$n")" != "$old_id" ]; }
if wait_for 10 new_leader; then
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    ok
    echo "  new leader $(leader_of "${survivors[@]}") elected ${ms} ms after kill -9 of $L"
else
    bad "no new leader among ${survivors[*]} within 10 s of kill -9 of the leader $L"
fi
L2=$(leader_of "${survivors[@]}" || true)
check '[ -n "$L2" ] && [ "$(field "$L2" term)" -gt "$old_term" ]' "the new leader's term is not above $old_term"
check '[ -n "$L2" ] && status "$L2" | grep -q "^quorum: *reachable (2 of 3"' "the survivors do not report a reachable quorum"

# ─── restart it: same id, log recovered, a follower of the new leader ──────
case $L in a) port=$PB;; b) port=$((PB+1));; c) port=$((PB+2));; esac
node_start "$L" --raft-listen 127.0.0.1:$port --raft-insecure --raft-name "$L"
recovered=$(grep -oE 'snapshot [0-9]+ and [0-9]+ entries recovered' "$T/$L.log" | tail -1)
snap_at=$(awk '{print $2}' <<<"$recovered"); entries=$(awk '{print $4}' <<<"$recovered")
check '[ -n "$recovered" ] && [ $((snap_at + entries)) -gt 0 ]' "the restarted node recovered nothing from its WAL ($recovered)"
check '[ "$(myid "$L")" = "$old_id" ]' "the restarted node has a different id"
rejoined() { [ "$(role "$L")" = follower ] && [ "$(leader "$L")" = "$(myid "$L2")" ]; }
check 'wait_for 10 rejoined' "the restarted node did not follow the new leader within 10 s"
check 'wait_for 10 "[ \"\$(field $L commit)\" = \"\$(field $L2 commit)\" ]"' "the restarted node's commit did not catch up"

# ─── a fourth node joins through a snapshot and is promoted ────────────────
node_start d --raft-listen 127.0.0.1:$((PB+3)) --raft-join 127.0.0.1:$((PB+1)) --raft-insecure --raft-name d
four() { [ "$(voters "$L2")" = 4 ] && [ "$(voters d)" = 4 ] && [ "$(role d)" = follower ]; }
check 'wait_for 20 four' "the fourth node did not become a voter within 20 s"
check 'grep -q "installed a snapshot at" "$T/d.log"' "the fourth node caught up without a snapshot though the leader compacts every 4 entries"
check 'grep -q "adding .*(d) as a learner" "$T/$L2.log" && grep -q "promoting .*(d) to voter" "$T/$L2.log"' \
      "d was not added as a learner and then promoted"
check 'status d | grep -q "voters:.*(a).*" && status d | grep -q "(b)" && status d | grep -q "(c)"' \
      "d's membership book, which arrives in the snapshot, lacks a member's name"

# ─── graceful stop: the leader hands over ───────────────────────────────────
term_before=$(field "$L2" term)
rest=()
for n in a b c d; do [ "$n" != "$L2" ] && rest+=("$n"); done
kill -TERM "$(cat "$T/$L2.pid")"
wait "$(cat "$T/$L2.pid")" 2>/dev/null || true
check 'grep -q "leadership handed over to" "$T/$L2.log"' "the stopping leader did not hand over"
L3=""
check 'wait_for 5 "L3=\$(leader_of ${rest[*]})"' "no leader among ${rest[*]} after the handover"
check '[ -n "$L3" ] && [ "$(field "$L3" term)" = $((term_before + 1)) ]' \
      "the successor's term is not exactly one above the old leader's"
# TimeoutNow skips pre-vote, so a successor that went through one was elected by timeout, not handed the lead.
check '[ -n "$L3" ] && ! grep -q "term $term_before: this node is pre-candidate" "$T/$L3.log"' \
      "the successor ran a pre-vote: it was elected after a timeout rather than handed leadership"

# ─── mutual TLS ─────────────────────────────────────────────────────────────
for n in "${NODES[@]}"; do kill -9 "$(cat "$T/$n.pid")" 2>/dev/null || true; daemon_sweep "$(sock "$n")"; done

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: mutual TLS (no openssl CLI to make certificates)"
else
    C="$T/certs"; mkdir -p "$C"
    mkcert() {  # name ca-prefix
        openssl req -newkey rsa:2048 -nodes -keyout "$C/$1-key.pem" -out "$C/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
        printf 'subjectAltName=DNS:%s,IP:127.0.0.1\n' "$1" >"$C/$1.ext"
        openssl x509 -req -in "$C/$1.csr" -days 2 -CA "$C/$2.pem" -CAkey "$C/$2-key.pem" -CAcreateserial \
            -extfile "$C/$1.ext" -out "$C/$1.pem" >/dev/null 2>&1
    }
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$C/ca-key.pem" -out "$C/ca.pem" \
        -subj "/CN=socketley-raft-test-ca" >/dev/null 2>&1 || true
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$C/rogue-key.pem" -out "$C/rogue.pem" \
        -subj "/CN=someone-else" >/dev/null 2>&1 || true
    for n in t1 t2 t3; do mkcert "$n" ca || true; done
    mkcert t9 rogue || true
    if [ ! -s "$C/t3.pem" ] || [ ! -s "$C/t9.pem" ]; then
        echo "  SKIP: mutual TLS (openssl could not make the certificates)"
    else
        tls() { echo --raft-cert "$C/$1.pem" --raft-key "$C/$1-key.pem" --raft-ca "$C/ca.pem" --raft-name "$1"; }
        # shellcheck disable=SC2046
        node_start t1 --raft-listen 127.0.0.1:$((PB+10)) --raft-init $(tls t1)
        # shellcheck disable=SC2046
        node_start t2 --raft-listen 127.0.0.1:$((PB+11)) --raft-join 127.0.0.1:$((PB+10)) $(tls t2)
        # shellcheck disable=SC2046
        node_start t3 --raft-listen 127.0.0.1:$((PB+12)) --raft-join 127.0.0.1:$((PB+10)) $(tls t3)
        tformed() { [ "$(voters t1)" = 3 ] && [ "$(voters t3)" = 3 ] && [ -n "$(leader t2)" ]; }
        check 'wait_for 20 tformed' "three daemons did not form a cluster over mutual TLS within 20 s"
        check 'status t2 | grep -q "mutual TLS"' "status does not say the transport is mutual TLS"

        # A CA-signed certificate for t2, presented by a node calling itself t4.
        node_start t4 --raft-listen 127.0.0.1:$((PB+13)) --raft-join 127.0.0.1:$((PB+10)) \
            --raft-cert "$C/t2.pem" --raft-key "$C/t2-key.pem" --raft-ca "$C/ca.pem" --raft-name t4
        # A certificate from another CA.
        node_start t9 --raft-listen 127.0.0.1:$((PB+14)) --raft-join 127.0.0.1:$((PB+10)) \
            --raft-cert "$C/t9.pem" --raft-key "$C/t9-key.pem" --raft-ca "$C/ca.pem" --raft-name t9
        sleep 4
        check '[ "$(voters t1)" = 3 ] && ! status t1 | grep -qE "\((t4|t9)\)"' "an impostor was admitted to the cluster"
        check 'grep -q "certificate does not name t4" "$T/t1.log"' "t4's mismatched certificate was not the stated reason"
        check '[ "$(role t4)" != leader ] && [ "$(voters t4)" = 0 ]' "t4 believes it is a member"
        check '[ "$(voters t9)" = 0 ]' "t9, signed by another CA, believes it is a member"
    fi
fi

echo "  SKIP: network partitions (netns/iptables need root; they belong in test/docker)"
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
