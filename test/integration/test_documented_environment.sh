#!/usr/bin/env bash
# Integration test: the ENVIRONMENT section names every variable the code reads,
# and names each of them once.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# The section had sixteen entries for ten variables.  SOCKETLEY_SOCKET and
# SOCKETLEY_CPUS appeared twice word for word; SOCKETLEY_CACHE_TTL_SWEEP_MS
# appeared three times.  That is not merely untidy, and the untidiness is not
# what this file is about:
#
#     SOCKETLEY_CACHE_BUF_SIZE, first copy   no default given
#     SOCKETLEY_CACHE_BUF_SIZE, second copy  "Default 4096", and why
#
# A reader who found the first copy found no default and stopped looking.  The
# thin copies came first, so that was the likely reading.
#
# Eight variables the code reads were in no copy at all -- among them
# SOCKETLEY_HUGEPAGE, whose whole purpose is to be an operator's veto over a
# behaviour they did not ask for, and which another test in this directory
# already asserts is read.  A veto nobody can look up is not one.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
# Both directions of the same claim, derived rather than listed, so a variable
# added to the code adds a row here on the next run:
#
#   completeness   every getenv("SOCKETLEY_...") in socketley/ has an entry
#   no duplicates  no entry name appears twice in the section
#
# It deliberately does not check what the entries SAY.  Prose cannot be derived
# from source, and a test that tried would either be a second copy of the page
# or would pass on anything.  What it can hold is that the page has one place
# to look per variable and that the place exists.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE/../.."
MAN="$ROOT/man/socketley.1"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: every environment variable the code reads is in the manual ==="

if [ ! -f "$MAN" ]; then
    echo "  SKIP: $MAN not found (running against an installed binary?)"
    exit 0
fi

# Not an operational knob: it turns on progress lines from the invariant
# checker, which is a thing you reach for while debugging this daemon and not
# while running one.  Anything else added here needs a sentence like this.
EXCLUDED="SOCKETLEY_INV_PROGRESS_REPORT"

# ── what the code reads ─────────────────────────────────────────────────────
# Digits too: SOCKETLEY_STORAGE_HTTP2 and the HTTP3 ones were invisible to [A-Z_]+ and went undocumented.
IN_CODE=$(grep -rhoE 'getenv\("SOCKETLEY_[A-Z0-9_]+"\)' "$ROOT/socketley/" 2>/dev/null |
          sed 's/.*getenv("//; s/").*//' | sort -u)
if [ -z "$IN_CODE" ]; then
    bad "the source was read at all" "no getenv(\"SOCKETLEY_...\") found under socketley/" \
        "the extractor keys off 'getenv(\"SOCKETLEY_' -- if that spelling changed, so must this"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi
ok

# ── what the page documents ─────────────────────────────────────────────────
# The section only, not the whole page: a variable mentioned in passing in an
# example is not an entry an operator can look up.
# An entry is a .B on the line after a .TP.  Counting every .B instead takes
# the ones inside bodies -- this section names SOCKETLEY_RECV_MULTISHOT in the
# prose under SOCKETLEY_RECV_BUNDLE, to say the two read their values by
# opposite rules -- and reports a cross-reference as a second entry.  That is
# what the first run of this file did.
IN_MAN=$(awk '
    /^\.SH ENVIRONMENT/ { on = 1; next }
    /^\.SH /            { on = 0 }
    on && prev == ".TP" && /^\.B[RI]? [A-Z0-9_]+/ { print $2 }
    { prev = $0 }
' "$MAN" | sed 's/=.*//' | sort)
if [ -z "$IN_MAN" ]; then
    bad "the ENVIRONMENT section was found" "no .TP/.B entries between .SH ENVIRONMENT and the next .SH"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi
ok

COUNT_CODE=$(printf '%s\n' "$IN_CODE" | grep -c .)
COUNT_MAN=$(printf '%s\n' "$IN_MAN" | sort -u | grep -c .)
echo "  $COUNT_CODE variables read by the code, $COUNT_MAN entries in the section"

# ── completeness ────────────────────────────────────────────────────────────
MISSING=""
while read -r v; do
    [ -n "$v" ] || continue
    case " $EXCLUDED " in *" $v "*) continue ;; esac
    grep -qxF -- "$v" <<<"$IN_MAN" || MISSING="$MISSING $v"
done <<< "$IN_CODE"

if [ -z "$MISSING" ]; then ok; else
    bad "every variable the code reads has an entry" "undocumented:$MISSING" \
        "add a .TP entry under .SH ENVIRONMENT, or list it in EXCLUDED with a reason"
fi

# ── no duplicates ───────────────────────────────────────────────────────────
DUPES=$(printf '%s\n' "$IN_MAN" | uniq -d | tr '\n' ' ')
if [ -z "${DUPES// /}" ]; then ok; else
    bad "no variable is documented twice" "repeated: $DUPES" \
        "two entries for one variable means two places to look and one of them" \
        "is the one somebody stops at -- which is how a default went missing"
fi

# ── and the exclusion list is not quietly stale ─────────────────────────────
# An excluded name that the code no longer reads is a rule about nothing, and
# it would go on excusing a variable that came back under the same name.
STALE=""
for v in $EXCLUDED; do
    grep -qxF -- "$v" <<<"$IN_CODE" || STALE="$STALE $v"
done
if [ -z "$STALE" ]; then ok; else
    bad "the exclusion list still describes the code" "no longer read:$STALE" \
        "delete it from EXCLUDED rather than leaving it to excuse a future one"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
