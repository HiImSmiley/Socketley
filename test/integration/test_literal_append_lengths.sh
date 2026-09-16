#!/usr/bin/env bash
# Integration test: a string literal appended with a length nobody counted
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The reply buffers here are written as `rb.append("error: ...\n", 21)`, with the
# length spelled out beside the text.  There are 312 of those, and six of them
# were wrong.
#
# Wrong in two directions, and both are defects rather than untidiness:
#
#   TOO LONG reads past the end of the literal.  `append("... float\n", 34)` on a
#   33-byte literal appends the terminating NUL and whatever the linker put next,
#   into a reply that goes out on a socket.  It was found by reading the text
#   protocol's answer to `size type hash` and seeing "\0" before the number --
#   which is what this class of bug looks like from outside, when it is visible
#   at all.
#
#   TOO SHORT truncates the message, and what it truncates first is the trailing
#   newline -- so a line protocol's reply runs into the next one and a client
#   reading by line waits for an end it has already been sent.
#
# Neither is caught by a compiler, and neither is caught by a test of the command
# unless that test compares the reply BYTE for byte, which almost none do.  This
# reads the source instead: every literal appended with a length, and whether the
# two agree.  It is not a style rule.  Six bugs is the reason.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
exec 2>&1

echo "=== Integration: every literal appended with its own length ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

REPORT=$(python3 - "$ROOT" <<'PY'
import re, os, sys
root = sys.argv[1]
pat = re.compile(r'\.append\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*(\d+)\s*\)')
checked = 0
wrong = []
for base, dirs, files in os.walk(os.path.join(root, 'socketley')):
    dirs[:] = [d for d in dirs if d != 'thirdparty']
    for fn in sorted(files):
        if not fn.endswith(('.cpp', '.h')):
            continue
        p = os.path.join(base, fn)
        s = open(p, encoding='utf-8', errors='replace').read()
        for m in pat.finditer(s):
            checked += 1
            try:
                real = m.group(1).encode().decode('unicode_escape')
            except Exception:
                continue          # an escape this cannot read is not a finding
            n = int(m.group(2))
            if len(real) != n:
                wrong.append("%s:%d said %d, the literal is %d: %r"
                             % (os.path.relpath(p, root),
                                s[:m.start()].count('\n') + 1,
                                n, len(real), real[:50]))
print(checked)
for w in wrong:
    print(w)
PY
)
CHECKED=$(echo "$REPORT" | head -1)
WRONG=$(echo "$REPORT" | tail -n +2 | grep -c . || true)

if [ "${CHECKED:-0}" -gt 100 ]; then
    ok "the scan found $CHECKED literal appends to check"
else
    bad "the scan found the appends at all" \
        "only $CHECKED found, and there were 312 when this was written" \
        "-- a pattern that matches nothing passes every assertion below it"
fi

if [ "${WRONG:-0}" -eq 0 ]; then
    ok "every one of them names its own length"
else
    bad "every literal append names its own length" "$WRONG disagree" \
        "$(echo "$REPORT" | tail -n +2)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
