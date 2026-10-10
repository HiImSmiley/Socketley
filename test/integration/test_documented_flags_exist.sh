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
# ─── THERE IS NO ALLOWLIST, AND THAT IS THE POINT ───────────────────────────
# The page used to explain four flags precisely BECAUSE they were gone --
# --rings, --daemon-process, --out-of-process, --in-daemon -- so that a reader
# on an older version would learn what happened.  The first version of this
# file let them through by name.  They are now deleted from the page instead:
# a manual is what a user types from, and a flag that cannot be typed does not
# belong in it whatever the surrounding sentence says.  What survived the
# deletion is the behaviour that is still live -- a config file carrying
# `daemon_process` is refused by name (cli_config.cpp:232) -- because that is
# a thing the binary still does rather than a thing it no longer has.
#
# So every flag the page names must exist.  No exceptions, and adding one is
# the wrong repair for the next failure.
set -euo pipefail

MAN="$(dirname "$0")/../../man/socketley.1"
SRC="$(dirname "$0")/../../socketley"
PASS=0; FAIL=0; TOTAL=0

# `--circuit-*` and `--health-*` are the page's own glob notation for a family.
# The members are documented separately and get checked on their own lines.
while read -r flag; do
    case "$flag" in
        --circuit|--health) continue ;;   # the stem of a \-\-x\-* glob
    esac
    TOTAL=$((TOTAL+1))
    # A parser's case label or comparison, not the name quoted in a comment, a message or a removed-flag table.
    if grep -rqF -e "case fnv1a(\"$flag\")" -e "== \"$flag\"" -e "!= \"$flag\"" "$SRC" 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: the manual names $flag and no parser answers to it"
        echo "        (no 'case fnv1a(\"$flag\")' or '== \"$flag\"' in socketley/; either the"
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
