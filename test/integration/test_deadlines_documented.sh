#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# Three bounds landed this week that a peer can be disconnected by, none of
# them configurable and none of them in the manual: a 30-second TLS handshake
# deadline on every runtime type, the same 30 seconds on a client runtime's
# dial, and a 10-second header deadline on a server.  An operator whose
# connection dies at thirty seconds had nowhere to read why.
#
# The proxy's own header deadline HAS been documented since it was written --
# including the sentence explaining why --idle-timeout cannot stand in for it,
# which is the exact defect the server turned out to have.  The page knew; the
# server's half of it was never written.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The numbers in the page against the constants in the source, in both
# directions, so neither can drift from the other.  Reading the roff rather
# than a rendered page, the way the command reference does, so this needs no
# man(1); and reading the constants out of the headers rather than restating
# them here, because a test that hardcodes both sides compares itself.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MAN="$ROOT/man/socketley.1"
PASS=0; FAIL=0; TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: the bounds a peer is dropped by are in the manual ==="

# ─── What the source says ───────────────────────────────────────────────────
HS=$(grep -oP 'tls_handshake_deadline_secs\s*=\s*\K[0-9]+' \
     "$ROOT/socketley/shared/crypto/tls_context.h" | head -1 || true)
HD=$(grep -oP 'http_header_deadline_secs\s*=\s*\K[0-9]+' \
     "$ROOT/socketley/shared/http/http_framing.h" | head -1 || true)

if [ -n "$HS" ]; then pass
else fail "the handshake deadline is a named constant" \
          "no tls_handshake_deadline_secs in shared/crypto/tls_context.h"; fi
if [ -n "$HD" ]; then pass
else fail "the header deadline is a named constant" \
          "no http_header_deadline_secs in shared/http/http_framing.h"; fi
[ -z "$HS" ] && HS=0
[ -z "$HD" ] && HD=0

# One place, not three: a constant copied per runtime is the drift this pair of
# assertions exists to prevent.
for f in server cache proxy client; do
    n=$(grep -c "= 30;\s*//\|tls_handshake_deadline_secs = " \
        "$ROOT/socketley/runtime/$f/${f}_instance.h" 2>/dev/null || true)
    if [ "${n:-0}" -eq 0 ]; then pass
    else fail "the $f does not keep a handshake deadline of its own" \
              "found ${n:-0} definitions in its header"; fi
done

# ─── What the page says ─────────────────────────────────────────────────────
#
# The handshake paragraph, found by the sentence that carries the number rather
# than by a line number, which would rot on the next edit above it.
HS_PARA=$(awk '/never finishes the handshake is dropped/{f=1} f{print; if(NR>n && /^\.PP$/ && c++)exit}' \
          "$MAN" 2>/dev/null || true)
if [ -n "$HS_PARA" ]; then pass
else fail "the page says a handshake that never finishes is dropped" \
          "no such sentence in $MAN"; fi

if grep -qE "handshake is dropped[[:space:]]*(after $HS seconds|$HS seconds)" \
        <<<"$(tr '\n' ' ' <<<"$HS_PARA")"; then pass
else fail "and says it in the number the source uses" \
          "the source says $HS" \
          "the page says: $(tr '\n' ' ' <<<"$HS_PARA" | grep -oE 'dropped[^.]*\.' || echo '<not found>')"; fi

# The three things the paragraph has to settle, because each was a question
# somebody had to measure to answer.
for want in "not configurable" "idle-timeout" "max-connections"; do
    if grep -qF -- "$want" <<<"$(sed 's/\\-/-/g' <<<"$HS_PARA")"; then pass
    else fail "the handshake paragraph mentions $want" \
              "an operator cannot tell this bound from the idle timeout without it"; fi
done

# And that later bytes do not renew it, which is the half that was wrong in the
# code for a day.
if grep -qiE "later bytes do not move it|dribbles" <<<"$HS_PARA"; then pass
else fail "and says the clock is not renewed by later bytes" \
          "a reader would otherwise assume it is an inactivity timeout"; fi

# ─── The server's header deadline ───────────────────────────────────────────
SRV_PARA=$(awk '/^\.SS Request Framing$/{f=1;next} f&&/^\.SS /{exit} f{print}' "$MAN" 2>/dev/null || true)
if grep -qE "$HD second[[:space:]]*$|$HD second header deadline" <<<"$SRV_PARA"; then pass
else fail "the server's request framing names a $HD second header deadline" \
          "the proxy's section has named one since it was written" \
          "got: $(grep -m1 '16 KiB header limit' <<<"$SRV_PARA" || echo '<no line>')"; fi

# Both runtimes, same deadline, different detection rate -- stated rather than
# left to be discovered from a stopwatch.
if grep -q "between 10 and 40 seconds" "$MAN"; then pass
else fail "the page states how fast the server notices it" \
          "the deadline is $HD seconds but the sweep runs every 30"; fi

# The deadline is answered, not dropped -- stated because a bare close and a
# status line are the same event to the slot and different ones to the client.
if grep -q "408 Request Timeout" <<<"$SRV_PARA"; then pass
else fail "the server's paragraph names the status the deadline answers with" \
          "a reader would otherwise expect a silent close"; fi

# ─── The proxy's, which must not have been disturbed ────────────────────────
if grep -q "and a $HD second header deadline" "$MAN"; then pass
else fail "the proxy's own header deadline still reads the same number" \
          "the constant moved to shared/, and the page must have moved with it"; fi

echo "  source: handshake ${HS}s, header ${HD}s — both named in the page"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
