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
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate psfailed

SRV_PORT=19890

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
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

# The failure, by ordinary configuration mistake: --tls on a UDP client would
# need DTLS, so the runtime is created and then refuses to start.  Created
# without -s on purpose — `create -s` unwinds a runtime whose start fails and
# leaves nothing behind, and a runtime that does not exist is not the case
# under test.
"$BIN" create client brokencli -t 127.0.0.1:19999 --udp --tls >/dev/null 2>&1 || true
"$BIN" start brokencli >/dev/null 2>&1 || true
sleep 0.3

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
if printf '%s' "$PSA" | grep -q "brokencli"; then ok; else
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
PSAJ=$("$BIN" ps -a --json 2>&1 || true)
if printf '%s' "$PSAJ" | grep -q '"name":"brokencli","type":"client","port":0,"status":"failed"'; then
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
if printf '%s' "$PS" | grep -q "brokencli"; then
    bad "bare ps still lists running runtimes and only those" \
        "a failed runtime appeared in default ps output; every script in" \
        "test/integration and examples/ that greps ps now sees rows it never saw"
else
    ok
fi

PSJ=$("$BIN" ps --json 2>&1 || true)
if printf '%s' "$PSJ" | grep -q "brokencli"; then
    bad "bare ps --json is unchanged too" \
        "the failed runtime leaked into the default JSON listing: $PSJ"
else
    ok
fi

# ─── 4. CONTROL: -a is additive ──────────────────────────────────────────────
if printf '%s' "$PS" | grep -q "upsrv"; then ok; else
    bad "the running runtime is still in bare ps" \
        "ps lost a running runtime, so the 'absent' assertions above are" \
        "measuring an empty listing rather than a filtered one:  ${PS:-<nothing>}"
fi

if printf '%s' "$PSA" | grep -q "upsrv"; then ok; else
    bad "the running runtime is still in ps -a" \
        "-a replaced the listing instead of widening it: ${PSA:-<nothing>}"
fi

if printf '%s' "$PSA" | grep -q '"name":"upsrv"' || \
   printf '%s' "$("$BIN" ps -a --json 2>&1)" | grep -q '"name":"upsrv","type":"server".*"status":"running"'; then
    ok
else
    bad "ps -a --json still reports a running runtime as running" \
        "got: $PSAJ"
fi

# ─── 5. the documentation says where to look ─────────────────────────────────
#
# The other half of the fix.  A flag nobody is told about is a flag that costs
# the next operator the same detour.
MAN=$HERE/../../man/socketley.1
HELP=$HERE/../../man/socketley-help.sh

if grep -q '^\.B ps \\fR\[\\fB\\-a\\fR' "$MAN" 2>/dev/null || \
   grep -qE '^\\fB\\-a\\fR, \\fB\\-\\-all\\fR' "$MAN" 2>/dev/null; then
    ok
else
    bad "the man page documents ps -a" \
        "the ps synopsis in man/socketley.1 does not mention -a/--all"
fi

if grep -q "failed" "$MAN" && \
   awk '/^\.B ps /,/^\.SS|^\.SH/' "$MAN" | grep -qi "failed"; then
    ok
else
    bad "the man page says a failed runtime is not in bare ps" \
        "the ps section never mentions the state an operator goes looking for"
fi

if grep -q "ps -a" "$HELP" 2>/dev/null; then ok; else
    bad "the interactive help mentions ps -a" \
        "man/socketley-help.sh never shows the flag"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
