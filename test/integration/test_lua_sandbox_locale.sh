#!/usr/bin/env bash
# Integration test: one script cannot change how every other one spells a number.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# A handler's interpreter nils exactly two os names — os.exit and os.setlocale
# — and neither removal is a security boundary.  A handler runs with the
# daemon's full privileges: io.popen is a shell, io.open(path,"w") truncates,
# package.loadlib maps native code.  (Four more names, os.execute, os.remove,
# os.rename and os.tmpname, used to be nil too; they were restored because
# removing them denied nothing and advertised a fence with an open gate.  What
# limits who may supply a handler is the IPC socket's permission — see
# test_ipc_socket_permissions.sh — not this interpreter.)
#
# The test the two survivors pass is narrower and is about accidents, not
# attackers: one call damages the process every OTHER runtime shares.  os.exit
# ends the daemon from inside a callback, which is what a standalone script
# copied in as written does.  And setlocale, this file's subject:
# setlocale(LC_ALL, ...) is process-wide, this daemon serves every runtime from
# one process, and two of its own primitives read the C locale —
# socketley.json_encode formats with "%.14g" and json_decode parses with
# std::stod, both of which take the decimal separator from LC_NUMERIC.
#
# Measured on the parent commit, two runtimes, the second created after the
# first had run its on_start:
#
#     vandal   os.setlocale("de_DE.UTF-8")  -> "de_DE.UTF-8"
#     victim   json_encode({v = 1.5})       -> {"v":1,5}      (no parser takes this)
#     victim   json_decode('{"v":1.5}').v   -> 1             (truncated at the '.')
#
# for as long as the daemon lives, and a cache holding "1,5" does not become
# "1.5" again when the script that did it is removed.
#
# ─── WHY THE TEST BUILDS A LOCALE ───────────────────────────────────────────
#
# The damage is only observable where a comma-decimal locale exists, and this
# machine ships C, C.utf8, POSIX and en_US.utf8 — all of them '.'.  localedef
# writes one into a directory of this test's own and LOCPATH points glibc at it,
# so the daemon can reach de_DE.UTF-8 without anything being installed.  Where
# localedef is missing that half is skipped and the reachability half — which
# needs no locale at all — still runs.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Removing a name from a sandbox is easy to overdo, so:
#
#   * os.time, os.clock, os.date and os.difftime must still be callable.  They
#     are the reads; setlocale is the write, and only the write is the problem.
#   * os.exit must still be nil, so a build that restored the whole os table
#     would not pass this file.
#   * os.execute, os.remove, os.rename and os.tmpname must be present, because
#     their absence is what this tree decided NOT to keep pretending to.  A
#     build that quietly nils them again puts the misleading fence back, and
#     the man page then describes an interpreter that does not exist.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate lualocale

PB=${PB:-23020}
VANDAL_PORT=$((PB + 0))
VICTIM_PORT=$((PB + 1))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   loc_vandal loc_victim >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove loc_vandal loc_victim >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: os.setlocale is not a script's to call ==="

# ── A de_DE.UTF-8 the daemon can reach, without installing anything ─────────
HAVE_LOCALE=0
LOCDIR="$SOCKETLEY_TMPD/locale"
if command -v localedef >/dev/null 2>&1; then
    mkdir -p "$LOCDIR/de_DE.UTF-8"
    if localedef -i de_DE -f UTF-8 "$LOCDIR/de_DE.UTF-8" >/dev/null 2>&1; then
        export LOCPATH="$LOCDIR"
        HAVE_LOCALE=1
    fi
fi
[ "$HAVE_LOCALE" = "1" ] || echo "  NOTE: no localedef — the damage half is skipped"

daemon_start "$BIN"

# said PATTERN [TIMEOUT_S] — wait for a line in the daemon's log
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# ── The vandal ──────────────────────────────────────────────────────────────
#
# Guarded on os.setlocale being there at all, so this same script runs against
# both builds and the difference shows up in what the VICTIM prints rather than
# in whether the vandal loaded.
VANDAL="$SOCKETLEY_TMPD/vandal.lua"
cat > "$VANDAL" <<'LUAEOF'
function on_start()
    if os.setlocale then
        socketley.log("LOC reachable=" .. tostring(os.setlocale("de_DE.UTF-8")))
    else
        socketley.log("LOC removed")
    end
    -- The reads stay.  A sandbox that took the whole os table with it would
    -- break every script that timestamps anything.
    socketley.log("LOC reads=" ..
        tostring(type(os.time)) .. "," .. tostring(type(os.clock)) .. "," ..
        tostring(type(os.date)) .. "," .. tostring(type(os.difftime)))
    socketley.log("LOC exit=" .. tostring(os.exit))
    -- And the four that were restored.  Their absence used to be reported as
    -- a boundary; it never was one, and a build that nils them again must not
    -- pass this file with the man page saying otherwise.
    socketley.log("LOC back=" ..
        type(os.execute) .. "," .. type(os.remove) .. "," ..
        type(os.rename) .. "," .. type(os.tmpname))
end
LUAEOF

create_ok "the vandal runtime created" "$BIN" create server loc_vandal \
    -p "$VANDAL_PORT" --lua "$VANDAL" --daemon-process -s
said "LOC reads=" 10 || true

# ── os.setlocale is gone ────────────────────────────────────────────────────
if grep -qa "LOC removed" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    REACH=$(grep -a "LOC reachable=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "os.setlocale is not in the sandbox" \
         "the script found it: ${REACH:-<no line at all>}" \
         "the five names beside it are nil; this is the one that reaches every" \
         "other runtime in the process without the script doing anything else"
fi

# ── Control: the reads are still there ──────────────────────────────────────
if grep -qa "LOC reads=function,function,function,function" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    READS=$(grep -a "LOC reads=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "control: os.time/clock/date/difftime still work" \
         "got: ${READS:-<no line at all>}" \
         "setlocale is the write; the reads are what a script legitimately needs"
fi

# ── Control: os.exit is still nil ───────────────────────────────────────────
if grep -qa "LOC exit=nil" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GONE=$(grep -a "LOC exit=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "control: os.exit is still nil" \
         "got: ${GONE:-<no line at all>}" \
         "a build that restored the whole os table must not pass this file;" \
         "os.exit() ends the daemon from inside a callback, by accident, in" \
         "any handler that grew out of a standalone script"
fi

# ── Control: the four that were restored really are back ────────────────────
if grep -qa "LOC back=function,function,function,function" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    BACK=$(grep -a "LOC back=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "control: execute/remove/rename/tmpname are present" \
         "got: ${BACK:-<no line at all>}" \
         "nilling them denies nothing — io.popen is a shell and io.open(p,'w')" \
         "truncates — and it tells a script author the daemon guards its files"
fi

# ── The damage, in a runtime that did nothing ───────────────────────────────
if [ "$HAVE_LOCALE" = "1" ]; then
    VICTIM="$SOCKETLEY_TMPD/victim.lua"
    cat > "$VICTIM" <<'LUAEOF'
function on_start()
    socketley.log("NUM encoded=" .. socketley.json_encode({ v = 1.5 }))
    socketley.log("NUM decoded=" .. tostring(socketley.json_decode('{"v":1.5}').v))
end
LUAEOF
    create_ok "the victim runtime created" "$BIN" create server loc_victim \
        -p "$VICTIM_PORT" --lua "$VICTIM" --daemon-process -s
    said "NUM decoded=" 10 || true

    ENC=$(grep -a "NUM encoded=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    case "$ENC" in
        *'{"v":1.5}'*) pass ;;
        *) fail "another runtime's json_encode still spells 1.5 with a point" \
                "got: ${ENC:-<no line at all>}" \
                "json_encode formats with %.14g, which reads LC_NUMERIC — and" \
                "LC_NUMERIC belongs to the process, not to the script that set it" ;;
    esac

    DEC=$(grep -a "NUM decoded=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    case "$DEC" in
        *"decoded=1.5"*) pass ;;
        *) fail "another runtime's json_decode still reads 1.5 as 1.5" \
                "got: ${DEC:-<no line at all>}" \
                "json_decode parses with std::stod, which stops at the '.' under" \
                "a comma locale — every fraction in every message truncates" ;;
    esac
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
