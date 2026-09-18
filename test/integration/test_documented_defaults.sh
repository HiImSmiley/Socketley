#!/usr/bin/env bash
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
#
# The manual quotes defaults, and a default that has drifted is worse than an
# undocumented one: a reader sizing a deployment against "Default 1M" and
# "defaults to 0" gets a number, acts on it, and is wrong.
#
# These two decide together how much memory a peer can bind, which is why they
# are the first pair here: --read-buffer is what one connection may accumulate,
# --max-connections is how many connections there may be, and the page now
# states the product because measurement showed it is unbounded at both
# defaults -- 13 KB for a connection that has sent nothing, up to the whole
# read buffer for one holding an unfinished command.
#
# Read from the roff rather than a rendered page: roff justifies with multiple
# spaces, so "nothing bounds the sum" does not match its own rendering.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MAN="$ROOT/man/socketley.1"
SRC="$ROOT/socketley/shared/runtime_instance.h"
PASS=0; FAIL=0; TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: the defaults the manual quotes are the defaults in the code ==="

# ─── --read-buffer ──────────────────────────────────────────────────────────
RB=$(grep -oP 'm_read_buffer\s*=\s*\K[0-9u*\s]+' "$SRC" | head -1 | tr -d ' u' || true)
RB_BYTES=$(python3 -c "print($RB)" 2>/dev/null || echo 0)
if [ "${RB_BYTES:-0}" -gt 0 ]; then pass
else fail "the read buffer default is readable from the source" \
          "no m_read_buffer initialiser in shared/runtime_instance.h"; fi

if [ "${RB_BYTES:-0}" -eq $((1024 * 1024)) ]; then
    if grep -q "Default 1M" "$MAN"; then pass
    else fail "the page quotes the read buffer default it has" \
              "the source says 1 MiB" \
              "got: $(grep -m1 -A2 'read\\-buffer " "size"' "$MAN" | grep -o 'Default [0-9A-Za-z]*' || echo '<no Default line>')"; fi
else
    fail "the read buffer default is still 1 MiB" \
         "the source says $RB_BYTES bytes, and the page's 'Default 1M' and its" \
         "sizing paragraph were both written against 1 MiB"
fi

# ─── --max-connections ──────────────────────────────────────────────────────
MC=$(grep -oP 'm_max_connections\s*=\s*\K[0-9]+' "$SRC" | head -1 || true)
if [ -n "$MC" ]; then pass
else fail "the connection cap default is readable from the source" \
          "no m_max_connections initialiser in shared/runtime_instance.h"; fi

if [ "${MC:-x}" = "0" ]; then pass
else fail "the connection cap still defaults to no limit" \
          "the source says $MC, and the page's sizing paragraph says 0"; fi

# ─── And the sentence that ties them, which is the point ────────────────────
if grep -q "nothing bounds the sum but" "$MAN"; then pass
else fail "the page states that the buffer is per connection" \
          "each bound in this tree is per connection and only this says so"; fi

if grep -q "max\\\\-connections" "$MAN" && \
   grep -A6 "nothing bounds the sum but" "$MAN" | grep -q "max\\\\-connections"; then pass
else fail "and names the flag that bounds the count" \
          "a reader told the buffer is per connection needs the other half"; fi

if grep -A8 "nothing bounds the sum but" "$MAN" | grep -q "descriptor limit"; then pass
else fail "and says what the ceiling is when neither is set" \
          "measured: the worker's limit is over a million here"; fi

echo "  source: read buffer $RB_BYTES bytes, connection cap $MC — both as the page says"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
