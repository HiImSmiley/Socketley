#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# One thread serves every runtime in a process, so a call that waits stops all
# of them.  Six places in this tree do.  Exactly one of them said so -- the
# warning at socketley.http's own entry -- and the other five were found by
# going looking, after a survey that set out expecting two.
#
# The cost of that is not hypothetical: the one everybody knew about is the one
# that is hardest to fix, and the five nobody had written down include a
# getaddrinfo on a client's reconnect path, which holds the loop for as long as
# a broken resolver takes to time out.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# That the section exists and still names every site, and -- the half that
# matters -- that each named site is still IN THE SOURCE.  A list of blocking
# calls is only worth keeping while the calls are there: when one is made
# asynchronous, this test goes red and whoever fixed it strikes it from the
# page, which is the point.  A page that still warns about a call nobody makes
# any more is worse than no page.
#
# Read out of the roff rather than a rendered man(1), the way the rest of the
# documentation tests here do.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MAN="$ROOT/man/socketley.1"
SRC="$ROOT/socketley"
PASS=0; FAIL=0; TOTAL=0

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: every place the event loop can block is written down ==="

# The section itself, by its heading rather than by a line number.
if grep -q '^\.SS What can stop the event loop' "$MAN"; then pass
else fail "section" "the manual has no \"What can stop the event loop\""; fi

# Everything from the heading to the next one, which is the scope of the claims.
SECTION=$(awk '/^\.SS What can stop the event loop/{f=1;next} /^\.SS /{f=0} f' "$MAN")

named() {  # label, needle in the section
    case "$SECTION" in
        *"$2"*) pass ;;
        *) fail "named: $1" "the section does not mention $2" ;;
    esac
}

named "the Lua HTTP client"  "socketley.http()"
named "the static file open" ".BR open (2)"
named "the resolver"         "getaddrinfo"
named "the journal flush"    "journal"
named "the snapshot fsync"   "fsync"
named "the state file"       "state file"

# ─── And that each is still there to warn about ─────────────────────────────
still_there() {  # label, grep -E pattern, path under socketley/
    TOTAL=$((TOTAL+1))
    if grep -rqE "$2" "$SRC/$3" 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$1]: the manual warns about this and the source no longer does it"
        echo "        If it was made asynchronous, take it out of the section too."
    fi
}

still_there "socketley.http is synchronous" \
            'socketley_http_call' shared/lua/lua_context.cpp
still_there "the static file path opens on the loop" \
            '(^|[^_a-zA-Z0-9>.])open\(resolved' runtime/server/server_instance.cpp
still_there "the resolver on a client's first dial" \
            'lookup_now\(' runtime/client/client_instance.cpp
still_there "the journal writes from the loop" \
            'journal_flush_now|m_journal\.flush' runtime/cache/cache_instance.cpp
# The state file is named as written off the loop, which holds while its writer is a thread.
if grep -qE 'std::thread\(&state_persistence::writer_loop' "$SRC/shared/persist/state_persistence.cpp"; then pass
else fail "the state file is written off the loop" "the section says a thread writes it and the source no longer does"; fi

# The measured claim that is NOT a blocking site, kept because a suspicion
# tested and rejected is worth as much as one confirmed -- and because without
# it the next person profiling this path will chase the same 7.3 per cent.
case "$SECTION" in
    *"fourteen minor page faults"*) pass ;;
    *) fail "rejected suspicion" \
            "the section no longer records that the page clearing was measured and is not ours" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
