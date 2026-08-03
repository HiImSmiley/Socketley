#!/usr/bin/env bash
# Integration test: every flag `edit` accepts, against every runtime type.
#
# ─── WHY THIS IS GENERATED AND NOT WRITTEN ──────────────────────────────────
#
# `create` and `edit` are separate parsers — parse_common_flags against
# parse_common_edit_flags, and so on per type — and nothing holds them level.
# The whole suite drove `edit` from three files and fourteen invocations,
# against forty-six case branches across four parsers, so a flag could be moved,
# renamed or forgotten in the edit half and no test would notice.
#
# It did happen. --out-of-process moved to the common CREATE parser so a cache
# or a server could take it; its refusal stayed behind in parse_proxy_edit_flags.
# For a whole release `edit proxy x --out-of-process` answered
#
#     --out-of-process can only be set when the proxy is created
#
# and `edit server x --out-of-process` answered
#
#     unknown flag: --out-of-process
#
# for the same request against the same field. Nothing was wrong with either
# message. What was wrong was that they differed, and no fixture in this
# directory was ever going to say so.
#
# ─── WHAT IT ASSERTS, AND WHAT IT DELIBERATELY DOES NOT ─────────────────────
#
# The flag list is read out of flag_handlers.cpp, so adding a case to a parser
# adds a row here on the next run and cannot be forgotten.
#
# The assertion is REACHABILITY, not effect: for each (type, flag) the CLI must
# answer `unknown flag` exactly when the source says that parser does not have
# it. A flag with a missing value answers "--x requires a value", a boolean flag
# succeeds — both mean reachable, which is all that is being claimed.
#
# It is worth being plain about the limit. Nothing here proves a flag DOES
# anything: every assertion below would stay green if the body of every case
# were deleted and only the `case` label left. Proving effect needs a value and
# a place in `inspect` to read it back, per flag, and that is written by hand
# where it matters. What this catches is the other failure — a flag that stops
# being reachable, or that is reachable for one type and not its neighbour —
# and that is the failure the parsers have actually had.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/../../socketley/daemon/flag_handlers.cpp"
MAN="$HERE/../../man/socketley.1"
HELP="$HERE/../../man/socketley-help.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate editsurface

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for r in efs_server efs_client efs_proxy efs_cache; do
        "$BIN" remove "$r" >/dev/null 2>&1
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the edit flag surface ==="

if [ ! -f "$SRC" ]; then
    echo "  SKIP: $SRC not found (running against an installed binary?)"
    exit 0
fi

# ── the surface, read out of the parsers ────────────────────────────────────
#
# One line per flag: "<flag> <parser>".  A flag listed under the common parser
# is reachable from every type; one under a per-type parser only from that type.
SURFACE=$(python3 - "$SRC" <<'PY'
import re, sys
fn = None
for line in open(sys.argv[1]):
    m = re.match(r'^int (parse_\w+)\(', line)
    if m:
        fn = m.group(1)
        continue
    if fn and fn.endswith('_edit_flags'):
        for f in re.findall(r'case fnv1a\("(-[^"]+)"\)', line):
            print(f, fn)
PY
)

if [ -z "$SURFACE" ]; then
    bad "the parsers were read at all" "no edit flags extracted from $SRC" \
        "the extractor keys off 'int parse_*_edit_flags(' and 'case fnv1a(\"-...\")'"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit 1
fi
COUNT=$(printf '%s\n' "$SURFACE" | grep -c .)
echo "  $COUNT edit flags across $(printf '%s\n' "$SURFACE" | awk '{print $2}' | sort -u | wc -l) parsers"

# ── layer 1: the docs, which need no daemon ─────────────────────────────────
#
# A flag the operator cannot look up is a flag they will not use.  Both
# directions are worth having; only this one is cheap, because the reverse needs
# to know which mentions in a 4000-line man page are about `edit`.
# The man page escapes hyphens as \- , so it is de-escaped once into a file
# rather than through a pipe per flag.  Not only for speed: `sed x | grep -q`
# under `set -o pipefail` reports FAILURE on a match — grep exits at the first
# hit, sed dies of SIGPIPE, and the pipeline takes sed's status.  Every
# documented flag would then be reported as missing, which is exactly what the
# first version of this file did.  That inversion has now been found four times
# in this repository; the fix is always to not put grep -q at the end of a pipe.
MAN_FLAT=$(mktemp)
sed 's/\\-/-/g' "$MAN" > "$MAN_FLAT" 2>/dev/null
trap 'rm -f "$MAN_FLAT"; cleanup' EXIT

UNDOC=""
while read -r flag _; do
    grep -qF -- "$flag" "$HELP"     2>/dev/null || UNDOC="$UNDOC $flag(help)"
    grep -qF -- "$flag" "$MAN_FLAT" 2>/dev/null || UNDOC="$UNDOC $flag(man)"
done <<< "$SURFACE"

if [ -z "$UNDOC" ]; then ok; else
    bad "every editable flag appears in the man page and the help script" \
        "undocumented:$UNDOC"
fi

# ── layer 2: reachability, one runtime per type ─────────────────────────────
daemon_start "$BIN"

"$BIN" create server efs_server -p 31711                          >/dev/null 2>&1
"$BIN" create client efs_client -t 127.0.0.1:31799                >/dev/null 2>&1
"$BIN" create proxy  efs_proxy  -p 31712 --backend 127.0.0.1:31799 >/dev/null 2>&1
"$BIN" create cache  efs_cache  -p 31713                          >/dev/null 2>&1

MISSING=""
for t in server client proxy cache; do
    "$BIN" show "efs_$t" >/dev/null 2>&1 || MISSING="$MISSING efs_$t"
done
if [ -z "$MISSING" ]; then ok; else
    bad "the four runtimes exist to be edited" \
        "not created:$MISSING — every reachability result below is void"
fi

# Which parser answers for which type.
parser_for() {                      # $1 = type -> the per-type parser name
    case "$1" in
        server) echo parse_server_edit_flags ;;
        client) echo parse_client_edit_flags ;;
        proxy)  echo parse_proxy_edit_flags  ;;
        cache)  echo parse_cache_edit_flags  ;;   # does not exist; see below
    esac
}

MISMATCH=""
CHECKED=0
# One row per flag, with every parser that declares it.  A flag can appear in
# more than one — `--mode` and `--udp` are in both the server's and the
# client's — and deciding per row rather than per flag would expect `--mode` to
# be unknown to a client on the strength of the server's row.  That was this
# file's own first bug, and it is the same shape as the defect it exists to
# catch: a conclusion about a flag drawn from one parser when several have it.
FLAGS=$(printf '%s\n' "$SURFACE" | awk '{print $1}' | sort -u)
while read -r flag; do
    parsers=$(printf '%s\n' "$SURFACE" | awk -v f="$flag" '$1 == f {print $2}' | sort -u)
    for t in server client proxy cache; do
        # Reachable if any parser holding it is the common one or this type's.
        want=unknown
        for p in $parsers; do
            if [ "$p" = "parse_common_edit_flags" ] || [ "$p" = "$(parser_for "$t")" ]; then
                want=reachable
            fi
        done

        out=$("$BIN" edit "efs_$t" "$flag" 2>&1 | head -1)
        case "$out" in
            "unknown flag:"*) got=unknown   ;;
            *)                got=reachable ;;
        esac
        CHECKED=$((CHECKED+1))

        if [ "$want" != "$got" ]; then
            MISMATCH="$MISMATCH
        $t $flag: source says $want, the CLI says $got ('$out')"
        fi
    done
done <<< "$FLAGS"

if [ -z "$MISMATCH" ]; then ok; else
    bad "every flag is reachable from exactly the types its parser serves" \
        "$CHECKED combinations checked" "$MISMATCH"
fi

# ── the asymmetry this found, held down so it cannot drift further ──────────
#
# There is no parse_cache_edit_flags.  A cache is editable only through the
# common flags, so nothing a cache is actually configured with — --resp,
# --maxmemory, --eviction, the replication flags — can be changed after create;
# `edit` answers `unknown flag`, which reads like a typo rather than a missing
# parser.  Recorded rather than fixed, because widening `edit` is a decision
# about the CLI and not a bug in it.  If a cache edit parser is added, this
# assertion goes red and should be deleted along with this paragraph.
CACHE_ONLY=$("$BIN" edit efs_cache --resp 2>&1 | head -1)
case "$CACHE_ONLY" in
    "unknown flag:"*) ok ;;
    *) bad "a cache still has no edit parser of its own" \
           "edit efs_cache --resp answered '$CACHE_ONLY'" \
           "if a cache edit parser was added, delete this assertion" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
