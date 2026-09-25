#!/usr/bin/env bash
# Run one territory's integration tests instead of all of them.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# The whole suite is 25 minutes and it is flat: measured over 141 sections, the
# most expensive one is 5.2% of the run and the median is 5.5s.  There is no
# slow test to fix.  What there is, is 145 files run one after another when 117
# of them bring their own daemon, their own HOME and their own port window and
# could run at the same time.
#
# Measured on this tree, Release, 16 CPUs:
#
#     24 isolating files, serial      219s
#     24 isolating files, -P6          80s      2.7x, zero failures
#     32 proxy files,     -P6          77s
#
# So somebody changing the proxy can have an answer in about a minute and a
# half rather than half an hour.  That is the whole point: the full suite stays
# what you run before a merge, and this is what you run while you work.
#
# ─── HOW MANY AT ONCE ───────────────────────────────────────────────────────
#
# As many as lib_ports.sh has free windows, counted at the start, because a job
# past that fails in a second and xargs hands its slot the next file, which
# fails the same way: at -P12 with ten free windows 279 of 280 files died with
# "no free 2000-port window".  A file that still meets one waits for it.
#
# ─── MEMBERSHIP IS DERIVED, NEVER LISTED ────────────────────────────────────
#
# run_all.sh globs its files rather than naming them, and its comment gives the
# reason: "a list of names goes stale the moment somebody adds a test and
# forgets one file, and it goes stale silently, which is the one property a
# test runner must not have."  The same rule holds here, so the file list is
# always the glob and a group is a FILTER over it.
#
# A file belongs to a group when it carries the group's name prefix or when it
# creates that kind of runtime -- with one exception that had to be measured
# before it could be written down.  96 of 145 files create a server, because a
# server is what a proxy test uses as a backend.  "Creates a server" therefore
# means scenery far more often than subject, so a file counts as a SERVER test
# only when it creates a server and no proxy, cache or client alongside it.
#
# The `daemon` group is everything no other group claimed, so the union of the
# groups is the glob itself.  A new file is always reachable by `all`, and if
# its name and its contents say nothing about a territory it lands in `daemon`
# where somebody will see it, rather than in nothing.
#
# ─── WHAT CANNOT BE PARALLELISED ────────────────────────────────────────────
#
# Two kinds, both detected rather than listed:
#
#   * A file that never calls daemon_isolate shares the suite's daemon.  28 of
#     them.  They run serially, after the parallel pass.
#
#   * A file that measures TIME or CPU is not measuring anything under a load
#     of six.  test_worker_idle_cost.sh asserts microseconds per second;
#     test_lua_callback_deadline.sh times a 400ms block and its own comment
#     records it going red "under the sanitizer build while three other jobs
#     were running".  These declare themselves with a `# suite: quiet` line and
#     run serially too.
#
# Usage:
#     test/run_group.sh proxy              one territory
#     test/run_group.sh proxy cache        several
#     test/run_group.sh -l proxy           list what would run, run nothing
#     test/run_group.sh -P 3 lua           fewer workers
#     test/run_group.sh all                every file, still grouped and parallel
#
# The verdict is the child's EXIT CODE, which is what run_all.sh's run_test()
# uses.  It is not the output: four different result-line formats live in this
# suite -- "Results: 9/9 passed (0 failed)", "passed: 3 / 3", "26 passed,
# 0 failed" and "8/8 passed" -- and a runner that reads text calls green files
# red.  That happened twice while this script was being written.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INT="$SCRIPT_DIR/integration"

SOCKETLEY_CONFIG="${SOCKETLEY_CONFIG:-Release}"
BIN_DIR="${SOCKETLEY_BIN_DIR:-$ROOT/bin/$SOCKETLEY_CONFIG}"
BIN="${BIN:-$BIN_DIR/socketley}"
. "$SCRIPT_DIR/lib_suite.sh"
PAR="${SUITE_PAR:-$(suite_free_windows)}"
LIST_ONLY=""

while getopts ":P:lh" opt; do
    case "$opt" in
        P) PAR="$OPTARG" ;;
        l) LIST_ONLY=1 ;;
        h) sed -n '/^# Usage:/,/^# The verdict/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "usage: run_group.sh [-P N] [-l] <group>..." >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [ "$#" -eq 0 ]; then
    echo "usage: run_group.sh [-P N] [-l] <group>...   (proxy lua cache server client cluster daemon all)" >&2
    exit 1
fi

# Checked where it is needed, not here: `-l` answers "what is in this group",
# which is a question about the test files and not about a build.  Refusing to
# answer it without a binary is how a listing becomes useless in a fresh
# worktree.

# ─── Classification ─────────────────────────────────────────────────────────
#
# One pass over the glob, in awk-free bash, so the answer to "what is in this
# group" is produced by the same code that runs it and the two cannot drift.

classify() {   # classify <file> -> prints the groups it belongs to, one per line
    local f="$1" base body
    base="$(basename "$f")"; base="${base#test_}"; base="${base%.sh}"
    body="$(cat "$f" 2>/dev/null)"

    local hit=""
    case "$base" in
        proxy*|backend*|upstream*|rate*|route*|relay*|service*) hit="$hit proxy" ;;
    esac
    case "$base" in cache*|resp*|pubsub*)      hit="$hit cache" ;;   esac
    case "$base" in client*)                   hit="$hit client" ;;  esac
    case "$base" in lua*|master*)              hit="$hit lua" ;;     esac
    case "$base" in cluster*)                  hit="$hit cluster" ;; esac
    case "$base" in server*|http*|ws*|websocket*|udp*) hit="$hit server" ;; esac

    # Subject, not scenery -- see the header.
    case "$body" in *"create proxy"*)  hit="$hit proxy" ;;  esac
    case "$body" in *"create cache"*)  hit="$hit cache" ;;  esac
    case "$body" in *"create client"*) hit="$hit client" ;; esac
    case "$body" in *"--lua"*)         hit="$hit lua" ;;    esac
    if [[ "$body" == *"create server"* ]] \
       && [[ "$body" != *"create proxy"*  ]] \
       && [[ "$body" != *"create cache"*  ]] \
       && [[ "$body" != *"create client"* ]]; then
        hit="$hit server"
    fi

    # Nothing claimed it: it is daemon/CLI surface.  Never nothing.
    [ -z "${hit// /}" ] && hit="daemon"
    printf '%s\n' $hit | sort -u
}

wants_quiet() { suite_wants_serial "$1"; }

# ─── Selection ──────────────────────────────────────────────────────────────

PARALLEL_LIST="$(mktemp)"; QUIET_LIST="$(mktemp)"
trap 'rm -f "$PARALLEL_LIST" "$QUIET_LIST"' EXIT

for f in "$INT"/test_*.sh; do
    [ -f "$f" ] || continue
    groups="$(classify "$f")"
    take=""
    for want in "$@"; do
        [ "$want" = "all" ] && { take=1; break; }
        printf '%s\n' "$groups" | grep -qx "$want" && { take=1; break; }
    done
    [ -n "$take" ] || continue
    if wants_quiet "$f"; then echo "$f" >> "$QUIET_LIST"; else echo "$f" >> "$PARALLEL_LIST"; fi
done

NPAR=$(wc -l < "$PARALLEL_LIST" 2>/dev/null || echo 0)
NQUI=$(wc -l < "$QUIET_LIST" 2>/dev/null || echo 0)

if [ "$((NPAR + NQUI))" -eq 0 ]; then
    echo "no test file belongs to: $*" >&2
    echo "groups are: proxy lua cache server client cluster daemon all" >&2
    exit 1
fi

echo "=============================="
echo " Socketley — group: $*"
echo "=============================="
echo " build     $SOCKETLEY_CONFIG"
echo " parallel  $NPAR files, $PAR at a time"
echo " serial    $NQUI files (shared daemon, or declared quiet)"
echo ""

if [ -n "$LIST_ONLY" ]; then
    echo "--- parallel ---"; sed 's|.*/||' "$PARALLEL_LIST" 2>/dev/null
    echo "--- serial ---";   sed 's|.*/||' "$QUIET_LIST"    2>/dev/null
    exit 0
fi

# ─── Running ────────────────────────────────────────────────────────────────
#
# Each child gets no SL_PORT_BASE, so lib_ports.sh claims a window of its own
# and its lock file is what keeps two children apart.  Handing one down from
# here would put every child in the same window, which is the serialisation
# this script exists to remove.

[ -x "$BIN" ] || { echo "no binary at $BIN -- build first, or set SOCKETLEY_CONFIG" >&2; exit 2; }

LOGDIR="$(mktemp -d)"
export LOGDIR BIN SOCKETLEY_CONFIG
one() {
    local f="$1" name; name="$(basename "$f")"
    local rc tries=0
    while :; do
        ( unset SL_PORT_BASE
          BIN="$BIN" timeout 600 bash "$f" >"$LOGDIR/${name}.log" 2>&1 )
        rc=$?
        # A window still held by a file tearing down is a wait, not a failure.
        if [ "$rc" = 2 ] && grep -q 'no free 2000-port window' "$LOGDIR/${name}.log" &&
           [ "$tries" -lt 300 ]; then
            tries=$((tries + 1)); sleep 1; continue
        fi
        break
    done
    if [ $rc -eq 0 ]; then printf '  ok    %s\n' "$name"
    else printf '  FAIL  %s  (exit %d, log: %s)\n' "$name" "$rc" "$LOGDIR/${name}.log"; fi
    return $rc
}
export -f one

FAILED=0
if [ "$NPAR" -gt 0 ]; then
    echo "--- parallel ---"
    # --halt never: one red file must not hide the others' verdicts, which is
    # the whole reason for running a group rather than a single file.
    if ! xargs -a "$PARALLEL_LIST" -n1 -P"$PAR" -I{} bash -c 'one "$@"' _ {}; then FAILED=1; fi
    echo ""
fi

if [ "$NQUI" -gt 0 ]; then
    echo "--- serial (shared daemon / declared quiet) ---"
    while IFS= read -r f; do one "$f" || FAILED=1; done < "$QUIET_LIST"
    echo ""
fi

if [ "$FAILED" -eq 0 ]; then
    echo "OK — $((NPAR + NQUI)) files, group: $*"
    echo "logs: $LOGDIR"
    exit 0
fi
echo "FAILED — see the logs above"
echo "logs: $LOGDIR"
exit 1
