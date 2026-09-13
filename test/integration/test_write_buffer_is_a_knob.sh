#!/usr/bin/env bash
# Integration test: how much may be owed to one connection is configurable.
#
# ─── WHY THIS IS ARITHMETIC AND NOT A PREFERENCE ────────────────────────────
#
# The write queue's bound was two compile-time constants in write_queue.h --
# 8 MiB to close, 4 MiB to pace -- and therefore the same number for a runtime
# serving four large transfers and one serving ten thousand small ones. The
# ceiling that follows is a multiplication:
#
#     100 streams       800 MB
#     1,000 streams       8 GB      (this box has 11 GiB)
#     10,000 streams     80 GB      impossible
#
# nginx serves ten thousand with 32-64 KB per connection, or about 600 MB. The
# difference is the buffer size and not the code. 4 MiB is right for "a few
# large transfers" and wrong by a factor of about sixty for "many streams", and
# nothing could say which a runtime was.
#
# One knob and not two: the watermark is derived from the bound -- half of it
# while the runtime is keeping up, and that budget over the live connections when
# it is not -- which is the ratio the
# constants had. A pair would let them be set inconsistently -- a watermark
# above the bound is a runtime that paces only after it has already closed the
# connection.
#
# ─── AND THE REASON self.watermark BECAME A CALL ────────────────────────────
#
# Making it editable is what broke it as a field. Measured, with the Lua binding
# assigning a number when the script's table was built:
#
#     before edit          self.watermark -> 4194304
#     edit --write-buffer 512K
#     after edit           self.watermark -> 4194304      <- stale
#     after a restart      self.watermark ->  262144
#
# The runtime's bound had moved and the script went on pacing against the old
# number, which is the worse direction: pacing against 4 MiB under a 512 KB
# bound means every send past the bound is refused and the connection closed,
# by a producer that believed it was being careful.
#
# The cache's mode() carries this same note -- "a call and not a field, because
# --mode is editable and a field written when this table was built would go
# stale" -- so this is the second instance of one rule rather than a new one.
# Case 6 is the assertion that holds it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate writebuffer

P_DEF=$((SL_PORT_BASE+1962))
P_SMALL=$((SL_PORT_BASE+1964))
NAMES="wb_def wb_small"
LUA="$SOCKETLEY_TMPD/wb.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

cat > "$LUA" <<'LUAEOF'
local CHUNK = string.rep("w", 65536)

function on_client_message(id, msg)
    if msg == "probe" then
        socketley.log("WB probe name=" .. self.name
            .. " watermark=" .. tostring(self.watermark()))
        self.send(id, "PROBE-OK")

    elseif msg == "flood" then
        -- How many 64 KB messages are taken before the bound refuses one is
        -- the bound, divided. That is the behavioural half: a build that
        -- reported the right number from self.watermark() and went on using
        -- the constant would answer case 1 and fail this one.
        local sent, failed = 0, 0
        for _ = 1, 400 do
            if self.send(id, CHUNK) then sent = sent + 1 else failed = failed + 1 end
        end
        socketley.log("WB flood name=" .. self.name
            .. " sent=" .. sent .. " failed=" .. failed)
    end
end
LUAEOF

echo "=== Integration: the write bound is a knob, not a constant ==="
daemon_start "$BIN"

f() { "$BIN" show "$1" 2>/dev/null | sed -n 's/^ *"write_buffer": *\([0-9]*\).*/\1/p' | head -1; }
poke() {  # $1=port $2=word ; answers the last matching log line
    timeout 20 python3 - "$1" "$2" <<'PYEOF' 2>/dev/null || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
s.sendall((sys.argv[2] + "\n").encode())
time.sleep(3)
s.close()
PYEOF
    sleep 0.6
}

create_ok "a server with the default bound" "$BIN" create server wb_def \
    -p "$P_DEF" --lua "$LUA" -s
create_ok "and one with a small one"        "$BIN" create server wb_small \
    -p "$P_SMALL" --write-buffer 256K --lua "$LUA" -s
ready_tcp 127.0.0.1 "$P_DEF"   >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SMALL" >/dev/null 2>&1 || true

g() { grep -o "WB $1 name=$2 .*" "$SOCKETLEY_DLOG" | tail -1; }
v() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

# ─── 1. The number each runtime reports ─────────────────────────────────────
poke "$P_DEF" probe
poke "$P_SMALL" probe
check "a default runtime paces at 4 MiB" "4194304" "$(v watermark "$(g probe wb_def)")"
check "and a 256K one at 128 KiB"        "131072"  "$(v watermark "$(g probe wb_small)")"

# ─── 2. And the number it actually uses ─────────────────────────────────────
# The behavioural half. A build that reported the field correctly and compared
# against the constant would pass case 1 and fail here.
poke "$P_DEF" flood
poke "$P_SMALL" flood
D=$(v sent "$(g flood wb_def)")
S=$(v sent "$(g flood wb_small)")
if [ "${D:-0}" -gt 0 ] && [ "${S:-0}" -gt 0 ]; then ok; else
    bad "both floods ran" "default sent=$D, small sent=$S"; fi
# 8 MiB against 256 KB is a factor of 32, so "several times fewer" is far
# outside anything the machine's timing contributes.
if [ "${S:-0}" -lt "${D:-0}" ] 2>/dev/null; then ok; else
    bad "a smaller bound takes fewer messages" \
        "default took $D and the 256K runtime took $S -- the bound is being" \
        "reported and not applied"; fi
if [ $((${D:-0} / 4)) -gt "${S:-0}" ] 2>/dev/null; then ok; else
    bad "and by a wide margin" \
        "default $D vs small $S; a 32x smaller bound should not be within 4x"; fi

# ─── 3. show carries it, and only when it differs ───────────────────────────
check "the configured one is in show" "262144" "$(f wb_small)"
if [ -z "$(f wb_def)" ]; then ok; else
    bad "and a default runtime's record is unchanged" \
        "show printed write_buffer=$(f wb_def) for a runtime nobody configured"; fi

# ─── 4. A value too small to hold one message is raised, not refused ────────
# Half the bound is the watermark's CEILING, and the largest single entry these
# queues build is WRITE_COALESCE_LIMIT at 64 KiB -- so the floor on the bound is
# twice that, whatever the pacing point is doing at the time.
"$BIN" edit wb_small --write-buffer 1K >/dev/null 2>&1 || true
check "a bound under one message is floored" "131072" "$(f wb_small)"

# ─── 5. And a value that is not a size is refused ───────────────────────────
RC=0; OUT=$("$BIN" edit wb_small --write-buffer banana 2>&1) || RC=$?
check "a non-size value is refused" "1" "$RC"
case "$OUT" in *"K/M/G"*) ok ;;
    *) bad "and says what a size looks like" "got '$OUT'" ;; esac
check "and changed nothing" "131072" "$(f wb_small)"

# ─── 6. A live edit reaches the running script ──────────────────────────────
# The assertion that holds self.watermark() as a call: a field assigned when
# the script's table was built answers the old number here, and a producer
# pacing against a stale 4 MiB under a 512 KB bound closes its own connections.
"$BIN" edit wb_small --write-buffer 512K >/dev/null 2>&1 || true
check "the record moved"  "524288" "$(f wb_small)"
poke "$P_SMALL" probe
check "and the running script sees it without a restart" "262144" \
      "$(v watermark "$(g probe wb_small)")"

# ─── 7. It survives show/import ─────────────────────────────────────────────
"$BIN" show wb_small > "$SOCKETLEY_TMPD/cfg.json" 2>/dev/null
"$BIN" import wb_small < "$SOCKETLEY_TMPD/cfg.json" >/dev/null 2>&1 || true
check "a round trip through show/import keeps it" "524288" "$(f wb_small)"

# ─── 8. And the runtime with the default is still the default ───────────────
# A build that stored the knob on the wrong object would move both.
poke "$P_DEF" probe
check "the other runtime is untouched" "4194304" "$(v watermark "$(g probe wb_def)")"

echo "  measured: default sent=$D, 256K sent=$S"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else
    grep -o 'WB .*' "$SOCKETLEY_DLOG" | tail -8 | sed 's/^/    log: /'
    echo "  FAILED"
fi
[ "$FAIL" -eq 0 ]
