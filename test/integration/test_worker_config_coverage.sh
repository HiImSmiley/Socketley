#!/usr/bin/env bash
# Integration test: every field of runtime_config reaches a worker's runtime.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The daemon and a worker build a runtime from the same struct — the daemon from
# a state file, the worker from a frame on its control socket — and for a long
# time they did it from two hand-written lists. The worker's applied 37 of 62
# fields, and the seventeen it silently dropped did not produce a missing
# feature. They produced a DIFFERENT RUNTIME, started cleanly, bound its port,
# pushed its figures and answered `stats`:
#
#     create client x --udp     ran a TCP client
#     create server x --master-pw ...            never authenticated anyone
#     create server x --http-dir ...             answered 404 for its own files
#     create cache  x --replicate ...            replicated nothing
#     create proxy  x --cpus 0-1                 pinned nothing, reported cpus:0-1
#
# Nothing could report it. Every setter the worker did call succeeded; the
# question was never asked about the ones it did not.
#
# ─── WHAT THIS ASSERTS ──────────────────────────────────────────────────────
#
# The field list is read out of state_persistence.h and checked against what
# runtime_config_apply.cpp and proxy_worker.cpp actually read. A field that is
# neither applied nor named in the exception list below is a failure, so adding
# one to runtime_config forces a decision rather than allowing a silent drop.
#
# This is a source check and it proves reachability of the FIELD, not that the
# setter behind it works — the same limit test_edit_flag_surface.sh states about
# itself. The behaviour half is the pair of end-to-end assertions at the bottom,
# which are worth more per line and cost more to write, so there are two of them
# rather than seventeen.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE/../.."
. "$HERE/lib_daemon.sh"

daemon_isolate wcfgcov

# The two ports this file binds, out of this run's window.
WC_UDP_PORT=$((SL_PORT_BASE+1932))
WC_HTTP_PORT=$((SL_PORT_BASE+1931))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for r in wc_udp wc_http; do
        "$BIN" stop "$r" >/dev/null 2>&1; "$BIN" remove "$r" >/dev/null 2>&1
    done
    rm -rf "${WWW:-/nonexistent}"
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker's runtime is the one that was asked for ==="

SP="$ROOT/socketley/shared/state_persistence.h"
if [ ! -f "$SP" ]; then
    echo "  SKIP: sources not present"
    exit 0
fi

REPORT=$(python3 - "$ROOT" <<'PY'
import re, sys, os
root = sys.argv[1]

sp = open(os.path.join(root, 'socketley/shared/state_persistence.h')).read()
m  = re.search(r'struct runtime_config\s*\{(.*?)\n\};', sp, re.S)
fields = list(dict.fromkeys(
    re.findall(r'^\s*(?:std::)?[\w:<>,\s]+?\s+(\w+)\s*(?:=|;)', m.group(1), re.M)))

applied = set()
for f in ('socketley/shared/runtime_config_apply.cpp',
          'socketley/runtime/proxy/proxy_worker.cpp'):
    applied |= set(re.findall(r'cfg\.(\w+)', open(os.path.join(root, f)).read()))

# Fields a worker has no business applying, each with the reason it is here.
# Adding to this list is a decision; adding to runtime_config without touching
# either list is what this test refuses.
excused = {
    'name':             'the worker is told its name when the runtime is created',
    'type':             'likewise -- create_runtime(cfg.type, cfg.name)',
    'id':               'applied directly, not through the shared applier',
    'was_running':      "the daemon's restart bookkeeping; a worker has no state file",
    'owner':            'ownership cascades are resolved in the daemon',
    'child_policy':     'likewise',
    'out_of_process':   'the answer to where this runs; the worker IS the answer',
    'external_runtime': 'an external runtime is never put in a worker',
    'managed':          'likewise',
    'exec_path':        'likewise',
    'pid':              "the daemon's record of a managed child",
    'lua_script':       'loaded by the worker itself: a failure to load means '
                        'different things on the two sides (exit_config_refused)',
    'present':          'not configuration at all -- it records which keys the '
                        'JSON document named, so that `import` can leave a field '
                        'alone rather than clearing it.  A worker is handed a '
                        'complete config frame over the worker protocol, never a '
                        'document, so it is empty there and there is nothing '
                        'conditional for the applier to do',
}

missing = [f for f in fields if f not in applied and f not in excused]
print(f"FIELDS {len(fields)}")
print(f"APPLIED {len([f for f in fields if f in applied])}")
print(f"EXCUSED {len([f for f in fields if f in excused])}")
print("MISSING " + (" ".join(missing) if missing else "-"))
PY
)

FIELDS=$(printf '%s\n' "$REPORT" | awk '/^FIELDS/{print $2}')
MISSING=$(printf '%s\n' "$REPORT" | sed -n 's/^MISSING //p')
echo "  runtime_config: $FIELDS fields, $(printf '%s\n' "$REPORT" | awk '/^APPLIED/{print $2}') applied, $(printf '%s\n' "$REPORT" | awk '/^EXCUSED/{print $2}') excused"

if [ "$MISSING" = "-" ]; then ok; else
    bad "every runtime_config field is applied in a worker or excused by name" \
        "unaccounted for: $MISSING" \
        "either apply it in runtime_config_apply.cpp or add it to the excused" \
        "list in this file with the reason -- a field that is neither is one a" \
        "worker silently drops, and nothing at runtime can notice"
fi

# ── and two that prove the wire, not the source ─────────────────────────────
daemon_start "$BIN"

# 1. --udp, proved by a datagram rather than by asking.
#
#    `show` and `stats` read the placeholder, which has every field the operator
#    typed whether or not any of them reached the worker — so asking the daemon
#    what the runtime is cannot answer this.  A datagram can: without --udp the
#    worker binds a stream socket, the kernel drops the datagram, and nothing
#    moves.
#
#    This assertion used to be `--udp --tls`, which fails as a pair.  That pair
#    is refused at create now, on both paths, so it no longer reaches a worker
#    at all — a better answer, and a worse test.
"$BIN" create server wc_udp -p "$WC_UDP_PORT" --udp -s >/dev/null 2>&1
sleep 2.5
if command -v nc >/dev/null 2>&1; then
    printf 'hello-from-a-datagram\n' | timeout 3 nc -u -q1 127.0.0.1 "$WC_UDP_PORT" >/dev/null 2>&1 || true
    sleep 2.5      # one stats push from the worker
    # total_messages, not bytes_in.  The datagram path does not add to bytes_in
    # at all — measured, and identically for a server in the daemon and one in a
    # worker, so it is a property of the UDP path rather than of the boundary
    # and not this file's business.  Reading the wrong counter here would have
    # reported a defect that is not there.
    MSGS=$("$BIN" stats wc_udp 2>/dev/null | sed -n 's/^total_messages:\(.*\)$/\1/p' | head -1)
    if [ -n "$MSGS" ] && [ "$MSGS" -gt 0 ] 2>/dev/null; then ok; else
        bad "a worker binds the datagram socket it was told to" \
            "total_messages is '${MSGS:-none}' after one datagram" \
            "zero is what --udp not arriving looks like: the worker bound a" \
            "stream socket and the kernel dropped the datagram"
    fi
else
    echo "  (nc absent — the --udp assertion did not run)"
fi

# 2. A configuration that must be HONOURED once it arrives.  --http-dir is one
#    of the seventeen: the server came up, served, and answered 404 for every
#    file it had been pointed at.
WWW=$(mktemp -d)
echo "<h1>from the worker</h1>" > "$WWW/index.html"
"$BIN" create server wc_http -p "$WC_HTTP_PORT" --http "$WWW" -s >/dev/null 2>&1
for _ in $(seq 1 40); do
    curl -s -o /dev/null "http://127.0.0.1:$WC_HTTP_PORT/index.html" 2>/dev/null && break
    sleep 0.25
done

if command -v curl >/dev/null 2>&1; then
    BODY=$(curl -s --max-time 5 "http://127.0.0.1:$WC_HTTP_PORT/index.html" 2>/dev/null)
    case "$BODY" in
        *"from the worker"*) ok ;;
        *) bad "a worker serves the directory it was given" \
               "got '$(printf '%s' "$BODY" | head -c 80)'" \
               "404 is what --http-dir not arriving looks like" ;;
    esac
else
    echo "  (curl absent — the --http-dir assertion did not run)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
