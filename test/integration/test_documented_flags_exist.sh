#!/usr/bin/env bash
# Integration test: a flag the manual names is a flag the binary answers to
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# test_edit_flag_surface.sh walks the flag parsers and asks whether the manual
# mentions each one.  That direction catches a NEW flag nobody documented.  It
# cannot catch the opposite, and the opposite is what a user meets: the manual
# named --max-conns, --persist-interval and --http-dir, and typing any of the
# three got "unknown flag" and exit 1.  --cluster-addr was worse -- it was
# offered as the source of the advertised address, which actually comes from
# gethostname(2), so a reader searching for the flag to set it found a name
# that never existed in this tree at all.
#
# ─── HOW IT READS THE PAGE ──────────────────────────────────────────────────
# groff escapes every hyphen, so a flag is written \-\-read\-buffer and a naive
# pattern stops at the first backslash and reports "--read" missing.  The first
# draft of this file did exactly that and produced sixteen false alarms.
#
# ─── THE FOUR THAT ARE SUPPOSED TO BE ABSENT ────────────────────────────────
# The page documents four flags precisely BECAUSE they do not exist, so that a
# reader coming from an older version finds out what happened.  They are named
# here one by one rather than filtered by a pattern, because a pattern would
# also swallow the next real drift.
set -euo pipefail

MAN="$(dirname "$0")/../../man/socketley.1"
SRC="$(dirname "$0")/../../socketley"
PASS=0; FAIL=0; TOTAL=0

# Deliberately documented as gone.  Each names the section that explains it.
declare -A ABSENT_ON_PURPOSE=(
    ["--rings"]="documented as removed"
    ["--daemon-process"]="documented as never having existed"
    ["--in-daemon"]="documented as never having existed"
    ["--out-of-process"]="documented as never having existed"
)

# `--circuit-*` and `--health-*` are the page's own glob notation for a family.
# The members are documented separately and get checked on their own lines.
while read -r flag; do
    case "$flag" in
        --circuit|--health) continue ;;   # the stem of a \-\-x\-* glob
    esac
    TOTAL=$((TOTAL+1))
    if grep -rqF -- "\"$flag\"" "$SRC" 2>/dev/null; then
        PASS=$((PASS+1))
    elif [ -n "${ABSENT_ON_PURPOSE[$flag]:-}" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: the manual names $flag and no parser answers to it"
        echo "        (grep -rn -- '\"$flag\"' socketley/ is empty; either the"
        echo "         page means a different flag or the flag was removed)"
    fi
done < <(grep -oE '\\-\\-[a-z0-9]+(\\-[a-z0-9]+)*' "$MAN" | sed 's/\\-/-/g' | sort -u)

# The guard on the guard: if the extraction breaks again the loop above goes
# quiet and passes, so assert it found a plausible number of flags.
TOTAL=$((TOTAL+1))
COUNT=$(grep -oE '\\-\\-[a-z0-9]+(\\-[a-z0-9]+)*' "$MAN" | sort -u | wc -l)
if [ "$COUNT" -ge 50 ]; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); echo "  FAIL: only $COUNT flags extracted from the page -- the pattern broke"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
