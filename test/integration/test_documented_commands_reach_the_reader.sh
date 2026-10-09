#!/usr/bin/env bash
# Integration test: every verb the CLI dispatches is one the reader can find.
#
# ─── WHY THE VERBS NEEDED THEIR OWN GUARD ───────────────────────────────────
#
# test_documented_flags_exist.sh asks whether a flag the manual names exists,
# and test_edit_flag_surface.sh walks the flag parsers. Neither looks at the
# verb table in cli.cpp, and nothing else did either: `git-sync` and `ping`
# were both dispatched, both documented in socketley.1, and neither appeared
# anywhere in the interactive help -- for `git-sync` from the day it was added.
# A user who runs socketley-help.sh to see what the binary can do was told it
# could not do them.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
# Each verb reached by `case fnv1a("x")` in cli.cpp is named in the manual and
# in the help, with one exception: `proxy-worker` is how the daemon execs
# itself with the control socket on descriptor 3, so it is not a verb anyone
# types. Flags that happen to be dispatched there (-h, -v, --help, --lua,
# --version) are the other tests' subject and are skipped here.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
MAN="$HERE/../../man/socketley.1"
HELP="$HERE/../../man/socketley-help.sh"
CLI="$HERE/../../socketley/cli/cli.cpp"
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "=== Integration: the CLI's verbs are documented where a reader looks ==="

VERBS=$(grep -oE 'fnv1a\("[a-z][a-z-]*"\)' "$CLI" | sed 's/fnv1a("//;s/")//' | sort -u)
# The COMMANDS section alone: a verb named only under ENVIRONMENT or FILES is not an entry a reader finds by looking
# the command up, and the first draft of this file passed git-sync on exactly that.
CMDS=$(mktemp); trap 'rm -f "$CMDS"' EXIT
awk '/^\.SH COMMANDS$/{on=1;next} /^\.SH /{on=0} on' "$MAN" > "$CMDS"
for v in $VERBS; do
    # The daemon execs itself with this; it is not typed.
    [ "$v" = "proxy-worker" ] && continue
    # groff escapes every hyphen and quotes a verb that takes arguments: .BI "add " "path "...
    esc=$(printf '%s' "$v" | sed 's/-/\\\\-/g')
    grep -qE "^\.B(I|R)? +\"?$esc([ \"]|$|\\\\)" "$CMDS" && ok || bad "the manual's COMMANDS gives $v an entry of its own"
    # Either an example to copy, or the verb opening an entry's bold title.
    grep -qE "(socketley |[{]BOLD[}])$v([^a-z-]|$)" "$HELP" && ok || bad "socketley-help.sh has an entry for $v"
done

# The guard on the guard: a broken extraction would pass every line above.
TOTAL=$((TOTAL+1))
COUNT=$(printf '%s\n' "$VERBS" | grep -c .)
if [ "$COUNT" -ge 20 ]; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); echo "  FAIL: only $COUNT verbs read out of cli.cpp -- the pattern broke"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
