#!/usr/bin/env bash
# Integration test: a runtime that failed can be found from `ps`.
#
# `ps` lists runtimes whose state is `running` and nothing else, so a runtime in
# `failed` produces no row — and when nothing else is up, no output whatsoever.
# The operator who just watched a runtime not come up types the command named
# after "what is running", gets an empty screen, and concludes the runtime does
# not exist rather than that it exists and is broken.  It cost an agent a
# debugging detour in this tree; `ls` is the only place the state appears.
#
# 294f927 raised the price.  A worker whose script does not load now exits
# `exit_config_refused` and the supervisor leaves the runtime `failed` instead
# of forking five more copies of it — which is the right behaviour, and which
# makes `failed` reachable by an ordinary configuration mistake rather than only
# by a crash.
#
# ─── WHAT IS NOT CHANGED ────────────────────────────────────────────────────
#
# Bare `ps` still lists running runtimes and only running runtimes.  Twenty-odd
# files in this directory and a dozen in examples/ run `ps` and grep it for a
# name or awk a column out of it, and `docker ps` means the same thing
# everywhere else; widening the default would break both.  The failed runtime is
# reachable through `-a`, which is where a reader of `docker ps -a` already
# looks, and it carries its state in the STATUS column so a script that opts in
# can still tell the rows apart.
#
# So the assertions come in pairs, deliberately: each "the failed runtime is
# visible under -a" is matched by "and is still absent without it".  An
# assertion that only checked the second half stays green on a build where `-a`
# does nothing at all — which is exactly the build this test was written
# against.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate psfailed

BROKEN_PORT=$((SL_PORT_BASE+891))
SRV_PORT=$((SL_PORT_BASE+890))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# Does HAYSTACK contain NEEDLE.
#
# NOT `printf '%s' "$x" | grep -q "$n"`.  This file runs under `set -o
# pipefail` and `grep -q` exits at its first match, which hands the writer a
# SIGPIPE; the pipeline then reports 141 and the `if` takes the "no match"
# branch precisely when it matched.  lib_daemon.sh carries the same warning
# over daemon_starting_pids, where it is latent.
#
# Here it was not latent, and it is worth recording how it surfaced: the
# man-page assertion at the bottom of this file was written as an awk range fed
# into `grep -qi`, went green, and turned red the moment the section it reads
# grew by a paragraph -- because awk was then still writing when grep exited.
# A test that reports "the documentation does not say this" about documentation
# that does say it is worse than no test.  A case statement has no pipeline and
# cannot do that.
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

cleanup() {
    rm -f "${BROKEN_LUA:-}"
    "$BIN" stop   upsrv brokencli 2>/dev/null || true
    sleep 0.2
    "$BIN" remove upsrv brokencli 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a runtime that failed can be found from ps ==="

daemon_start "$BIN"

# The control: something that IS running, so every "absent" below is absence of
# the failed runtime and not absence of output.
"$BIN" create server upsrv -p "$SRV_PORT" -s >/dev/null 2>&1 || true

# The failure: a script whose top level reaches for the cross-runtime management
# API.  In a worker that API is refused by name, the script does not load, and
# the worker exits saying so — which is a failure NOTHING on the daemon side can
# decide in advance, because the daemon only compiles and discards a worker's
# script.  Created without -s on purpose: `create -s` unwinds a runtime whose
# start fails and leaves nothing behind, and a runtime that does not exist is
# not the case under test.
#
# THREE earlier triggers stopped working, and why is worth keeping.  `--tls` on
# a UDP client was a question about two flags, so it moved to where every other
# impossible TLS combination is answered and is now refused at create.  A port
# conflict is not a failure at all here: the listener sets SO_REUSEPORT, so a
# second runtime binds the same port and both come up.  And socketley.list(),
# which is what stood on this line, stopped raising the day a worker was handed
# the runtime map — it answers out there now, the script loads, brokencli comes
# up `running`, and five assertions below go red about `ps` output that was
# never the subject.  Watched, not predicted: 7/12.
#
# So the trigger has to come from the half of the API that is refused
# PERMANENTLY, not the half that is waiting on a transport.  socketley.create
# changes the runtime map, and a worker being handed a copy of that map is not
# permission to alter it — there is no build in which this call starts working
# from out here, which is exactly the property this line needs.  It raises
# before it builds anything, so no runtime is created on either path.
#
# What is left is a failure that genuinely cannot be known until the process
# that will serve the runtime tries, which is the only honest kind for this
# file.
BROKEN_LUA="$(mktemp "${TMPDIR:-/tmp}/psfailed-XXXXXX.lua")"
printf 'socketley.create("server", "psfailed_never_built", { port = 0 })\n' > "$BROKEN_LUA"
"$BIN" create server brokencli -p "$BROKEN_PORT" --lua "$BROKEN_LUA" >/dev/null 2>&1 || true
"$BIN" start brokencli >/dev/null 2>&1 || true
sleep 3

# The premise.  Without this, every assertion below is being made about a
# runtime that is in some other state and the file proves nothing.
LS=$("$BIN" ls 2>&1 || true)
if printf '%s' "$LS" | awk '$2 == "brokencli" && $7 == "Failed" { found=1 } END { exit !found }'; then
    ok
else
    bad "the premise: brokencli is in state failed" \
        "ls does not show it as Failed, so nothing below is about a failed runtime:" \
        "  $(printf '%s' "$LS" | tr '\n' '|')"
fi

# ─── 1. the failed runtime is reachable from ps ──────────────────────────────
PSA=$("$BIN" ps -a 2>&1 || true)
if has "$PSA" "brokencli"; then ok; else
    bad "ps -a lists a runtime that failed" \
        "an operator whose runtime did not come up gets nothing from ps, and" \
        "ps -a is where the docker reflex sends them.  Got:" \
        "  ${PSA:-<no output at all>}"
fi

if printf '%s' "$PSA" | awk '$2 == "brokencli" && $7 == "Failed" { found=1 } END { exit !found }'; then
    ok
else
    bad "ps -a shows the state, not just the name" \
        "a row without a state is a row a script cannot tell from a running one:" \
        "  $(printf '%s' "$PSA" | tr '\n' '|')"
fi

# ─── 2. and the machine-readable form agrees ─────────────────────────────────
#
# The JSON writer emitted the literal string "running" for every row it printed,
# because every row it could print was running.  A row for a failed runtime that
# still claims "running" is worse than no row.
#
# Read as JSON rather than matched as a substring.  This asserted a contiguous
# `"name":...,"type":...,"port":...,"status":...` run, which makes it a test of
# the field ORDER and of which fields exist between them -- neither of which is
# what it is for.  Adding `listen` between `port` and `status`, so that a server
# on a unix socket has somewhere to report its address, broke both of these and
# neither for a reason a reader of the failure could act on.  What it means is
# "the row named brokencli says failed", so that is what it now asks.
row_status() {   # row_status <json> <name>
    printf '%s' "$1" | python3 -c "
import json, sys
try:    rows = json.load(sys.stdin)
except Exception: sys.stdout.write('NOT-JSON'); raise SystemExit
for r in rows:
    if r.get('name') == '$2':
        sys.stdout.write(str(r.get('status')))
        raise SystemExit
sys.stdout.write('NO-SUCH-ROW')
" 2>/dev/null || printf 'ERROR'
}

PSAJ=$("$BIN" ps -a --json 2>&1 || true)
if [ "$(row_status "$PSAJ" brokencli)" = "failed" ]; then
    ok
else
    bad "ps -a --json reports the real state" \
        "expected brokencli with status failed; got:" \
        "  ${PSAJ:-<no output at all>}"
fi

# ─── 3. PAIRED: the default is untouched ─────────────────────────────────────
#
# These are the assertions that would stay green on a no-op build, which is why
# each one is stated next to its opposite above rather than on its own.
PS=$("$BIN" ps 2>&1 || true)
if has "$PS" "brokencli"; then
    bad "bare ps still lists running runtimes and only those" \
        "a failed runtime appeared in default ps output; every script in" \
        "test/integration and examples/ that greps ps now sees rows it never saw"
else
    ok
fi

PSJ=$("$BIN" ps --json 2>&1 || true)
if has "$PSJ" "brokencli"; then
    bad "bare ps --json is unchanged too" \
        "the failed runtime leaked into the default JSON listing: $PSJ"
else
    ok
fi

# ─── 4. CONTROL: -a is additive ──────────────────────────────────────────────
if has "$PS" "upsrv"; then ok; else
    bad "the running runtime is still in bare ps" \
        "ps lost a running runtime, so the 'absent' assertions above are" \
        "measuring an empty listing rather than a filtered one:  ${PS:-<nothing>}"
fi

if has "$PSA" "upsrv"; then ok; else
    bad "the running runtime is still in ps -a" \
        "-a replaced the listing instead of widening it: ${PSA:-<nothing>}"
fi

# Asked of the same snapshot as the brokencli row above, and in the same shape,
# so that "one row went to its real state" and "the other stayed running" are
# two readings of one listing rather than two listings taken a moment apart.
if [ "$(row_status "$PSAJ" upsrv)" = "running" ]; then
    ok
else
    bad "ps -a --json still reports a running runtime as running" \
        "the status field used to be the literal 'running' for every row; making" \
        "it real must not have made it wrong for the rows it was right about." \
        "expected upsrv with status running; got:" \
        "  ${PSAJ:-<no output at all>}"
fi

# ─── 5. the documentation says where to look ─────────────────────────────────
#
# The other half of the fix.  A flag nobody is told about is a flag that costs
# the next operator the same detour.
MAN=$HERE/../../man/socketley.1
HELP=$HERE/../../man/socketley-help.sh

if grep -q '^\.B ps \\fR\[\\fB\\-a\\fR' "$MAN" 2>/dev/null; then
    ok
else
    bad "the man page documents ps -a" \
        "the ps synopsis in man/socketley.1 does not mention -a/--all"
fi

# The ps entry alone, from its synopsis to the .RE that closes it.  Bounded on
# the .RE rather than on the next .SH, so that the word being looked for has to
# appear in the ps entry and not merely somewhere in the 3700 lines after it.
PS_SECTION=$(awk '/^\.B ps \\fR\[/ { f = 1 } f { print } f && /^\.RE$/ { exit }' "$MAN")

if has "$PS_SECTION" "failed" && has "$PS_SECTION" "ps \\-a"; then
    ok
else
    bad "the man page says a failed runtime is not in bare ps, and where it is" \
        "the ps entry has to name the state an operator goes looking for and" \
        "point at the flag that shows it.  The entry reads:" \
        "  $(printf '%s' "$PS_SECTION" | tr '\n' '|' | head -c 300)"
fi

if grep -q "ps -a" "$HELP" 2>/dev/null; then ok; else
    bad "the interactive help mentions ps -a" \
        "man/socketley-help.sh never shows the flag"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
