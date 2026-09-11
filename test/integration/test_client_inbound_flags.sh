#!/usr/bin/env bash
# Integration test: a client refuses the flags that describe inbound traffic.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# --rate-limit, --max-connections and --idle-timeout only mean something for a
# runtime that ACCEPTS connections.  A client opens one connection outward and
# listens on nothing, so none of them has anything to act on — and
# client_instance.cpp contains no code for any of the three.
#
# They were taken anyway.  The common flags are applied through a
# runtime_instance*, which does not know what it is, so all three reached a
# client, were stored, and were reported back:
#
#     socketley create client c -t host:port --rate-limit 5     -> exit 0
#     socketley show c                                          -> "rate_limit": 5
#
# An operator reading that was told a control was in force which did not exist.
# --maxmemory and --eviction were already refused for the same reason, so the
# answer's shape was established; these three escaped it.
#
# ─── WHY REFUSED AND NOT IMPLEMENTED ────────────────────────────────────────
#
# Each could be given a meaning, and each meaning is a decision rather than a
# translation.  An outbound throttle has to say what becomes of a message that
# may not go yet — queue it and report success for something that leaves in ten
# seconds, fail the send, or drop it.  An idle timeout has to say what happens
# after the close, since every connection loss in this runtime goes through
# drop_connection() into schedule_reconnect(): closing on idle reconnects at
# once, which is churn rather than a saving.  Until such a feature exists, "no"
# is the honest answer and a stored number is not.
#
# ─── WHAT IS ASSERTED, AND WHY EACH REFUSAL IS PAIRED ───────────────────────
#
# Every refusal here is paired with a case that must keep working, because a
# build that refused these flags everywhere would satisfy the refusals alone:
# the same flag on a server, a cache and a proxy must still be accepted, and a
# plain client must still be created.  And the round trip `show | import` must
# still succeed on a client, or the guard has broken the ordinary path while
# closing the bypass.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate clientflags
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a client refuses inbound-only flags ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 700))
TARGET=$((P + 1))

"$BIN" create server cf_target -p "$TARGET" --mode in -s >/dev/null 2>&1 || true
sleep 0.4

# Five, not three.  --global-rate-limit caps the total across all inbound
# connections and --drain flushes their write queues before closing them;
# check_global_rate_limit() and get_drain() are read by the server, the proxy
# and the cache and by no client code at all, and both were stored and reported
# by `show` exactly as the first three were.
FLAGS=("--rate-limit 5" "--max-connections 7" "--idle-timeout 30"
       "--global-rate-limit 10" "--drain")

# ─── create refuses, and says which flag and why ────────────────────────────
n=0
for f in "${FLAGS[@]}"; do
    n=$((n + 1))
    OUT=$("$BIN" create client "cf_c$n" -t "127.0.0.1:$TARGET" $f -s 2>&1) && RC=0 || RC=$?

    if [ "$RC" -eq 1 ]; then ok
    else bad "create client $f is refused" \
             "exit $RC — 1 is this project's code for bad input" "said: $OUT"; fi

    # The message has to name the flag, or an operator cannot tell which of
    # several on one command line was the problem.
    if grep -q -- "${f%% *}" <<<"$OUT"; then ok
    else bad "the refusal names $f" "said: $OUT"; fi

    # And it must not have been half-created.
    if ! "$BIN" ls 2>/dev/null | grep -q "cf_c$n"; then ok
    else bad "the refused client was not created" "cf_c$n exists after a refused create"; fi
done

# ─── The control: a client without them is still created ────────────────────
if "$BIN" create client cf_plain -t "127.0.0.1:$TARGET" -s >/dev/null 2>&1; then ok
else bad "a plain client is still created" \
         "the guard refuses clients outright, which every refusal above would also satisfy"; fi

# ─── The other three runtimes still take all three flags ────────────────────
if "$BIN" create server cf_srv -p $((P + 2)) --rate-limit 5 --max-connections 7 \
        --idle-timeout 30 --global-rate-limit 10 --drain -s >/dev/null 2>&1; then ok
else bad "a server still takes all five" "the guard is not restricted to clients"; fi

if "$BIN" create cache cf_cache -p $((P + 3)) --rate-limit 5 --max-connections 7 \
        --idle-timeout 30 --global-rate-limit 10 --drain -s >/dev/null 2>&1; then ok
else bad "a cache still takes all five" "the guard is not restricted to clients"; fi

if "$BIN" create proxy cf_prox -p $((P + 4)) --backend "127.0.0.1:$TARGET" \
        --rate-limit 5 --max-connections 7 --idle-timeout 30 \
        --global-rate-limit 10 --drain -s >/dev/null 2>&1; then ok
else bad "a proxy still takes all five" "the guard is not restricted to clients"; fi

# ─── edit is the second door ────────────────────────────────────────────────
#
# Refusing at create alone would leave the field settable one command later.
for f in "${FLAGS[@]}"; do
    OUT=$("$BIN" edit cf_plain $f 2>&1) && RC=0 || RC=$?
    if [ "$RC" -eq 1 ]; then ok
    else bad "edit client $f is refused" "exit $RC, said: $OUT"; fi
done

if "$BIN" edit cf_srv --rate-limit 9 >/dev/null 2>&1; then ok
else bad "edit still works on a server" "the guard reaches runtimes it should not"; fi

# ─── import is the third door, and it bypasses the flag parser entirely ─────
#
# This is the one that was still open after create and edit were closed: import
# writes the config fields directly, so a validation living in the flag parser
# is not on its path at all.  Same shape as 2cf7a4e, where import could give a
# runtime a name create would have refused.
if command -v python3 >/dev/null 2>&1; then
    "$BIN" show cf_plain > "$SOCKETLEY_TMPD/c.json" 2>/dev/null || true

    for field in rate_limit max_connections idle_timeout global_rate_limit drain; do
        python3 - "$SOCKETLEY_TMPD/c.json" "$field" \
                  "$SOCKETLEY_TMPD/mod.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if isinstance(d, list): d = d[0]
d[sys.argv[2]] = 5
json.dump(d, open(sys.argv[3], 'w'))
PY
        OUT=$(timeout 20 "$BIN" import cf_plain < "$SOCKETLEY_TMPD/mod.json" 2>&1) && RC=0 || RC=$?

        if [ "$RC" -eq 1 ]; then ok
        else bad "import of a client with $field is refused" \
                 "exit $RC — import writes the field without passing the flag parser" \
                 "said: $OUT"; fi

        # Refused means nothing applied, not "reported and applied anyway".
        if ! "$BIN" show cf_plain 2>/dev/null | grep -q "\"$field\""; then ok
        else bad "the refused import applied nothing" \
                 "$field is set on the client after a refused import"; fi
    done

    # The control that matters most: the ordinary round trip is untouched.
    "$BIN" show cf_plain > "$SOCKETLEY_TMPD/rt.json" 2>/dev/null || true
    if timeout 20 "$BIN" import cf_plain < "$SOCKETLEY_TMPD/rt.json" >/dev/null 2>&1; then ok
    else bad "show | import still round-trips a client" \
             "the guard broke the ordinary path while closing the bypass"; fi

    # And a server's round trip still carries the field it is allowed to have.
    "$BIN" show cf_srv > "$SOCKETLEY_TMPD/srt.json" 2>/dev/null || true
    if timeout 20 "$BIN" import cf_srv < "$SOCKETLEY_TMPD/srt.json" >/dev/null 2>&1; then ok
    else bad "show | import still round-trips a server carrying rate_limit" \
             "the guard reaches a runtime the field is valid on"; fi

    if "$BIN" show cf_srv 2>/dev/null | grep -q '"rate_limit"'; then ok
    else bad "the server kept its rate_limit across the round trip" \
             "the field was dropped rather than carried"; fi
else
    echo "  (python3 absent — the import assertions did not run)"
fi

# ─── The other direction: a client flag on the three that are not ──────────
#
# --reconnect re-dials a connection this runtime MADE.  get_reconnect() is read
# in client_instance.cpp and nowhere else, and the man page documents it under
# CLIENT FLAGS -- so on a server, a proxy and a cache it was stored, persisted
# and reported by `show` with nothing to act on it.  The same shape as the five
# above, pointing the other way.
RC_PORT=$((P + 20))
for t in server proxy cache; do
    case "$t" in
        proxy) EXTRA="--backend 127.0.0.1:$TARGET" ;;
        *)     EXTRA="" ;;
    esac
    RC_PORT=$((RC_PORT + 1))
    # shellcheck disable=SC2086
    OUT=$("$BIN" create "$t" "cf_rc_$t" -p "$RC_PORT" $EXTRA --reconnect 5 2>&1) \
        && RC=0 || RC=$?
    if [ "$RC" -eq 1 ]; then ok
    else bad "create $t --reconnect is refused" "exit $RC, said: $OUT"; fi
    if grep -q -- "--reconnect" <<<"$OUT"; then ok
    else bad "the refusal names --reconnect" "said: $OUT"; fi
    if ! "$BIN" ls 2>/dev/null | grep -q "cf_rc_$t"; then ok
    else bad "the refused $t was not created" "cf_rc_$t exists"; fi
done

# Paired, like every refusal in this file: the flag must still work where it is
# read, or refusing it everywhere would satisfy the three cases above.
if "$BIN" create client cf_rc_cli -t "127.0.0.1:$TARGET" --reconnect 5 -s >/dev/null 2>&1
then ok
else bad "a client still takes --reconnect" "the guard is not restricted to the other three"; fi

# And import, the door that does not go through the flag parser -- which is
# where the first three were last closed.
if command -v python3 >/dev/null 2>&1; then
    "$BIN" show cf_srv > "$SOCKETLEY_TMPD/rc.json" 2>/dev/null || true
    python3 - "$SOCKETLEY_TMPD/rc.json" "$SOCKETLEY_TMPD/rcmod.json" <<'RCPY'
import json, sys
d = json.load(open(sys.argv[1]))
if isinstance(d, list): d = d[0]
d["reconnect"] = 5
json.dump(d, open(sys.argv[2], "w"))
RCPY
    if timeout 20 "$BIN" import cf_srv < "$SOCKETLEY_TMPD/rcmod.json" >/dev/null 2>&1
    then bad "import cannot give a server a reconnect either" \
             "the document door is still open"
    else ok; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
