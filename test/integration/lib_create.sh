# A refused `create` is a failed test, and says so where it happened.
#
# Not a test — run_all.sh globs test_*.sh, so this file is only ever sourced.
# It is the third of the setup libraries: lib_daemon.sh gives each test a daemon
# nobody else can reach, lib_ready.sh replaces "sleep and hope it is up" with
# "ask it to do its job", and this one makes the step between them — building the
# runtimes to be measured — able to fail.
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
#
# Fifty-odd creates across this directory were written as
#
#     "$BIN" create cache testcache -p "$PORT" -s 2>&1 || true
#
# and the `|| true` is not incidental: under `set -euo pipefail` a bare create
# ends the run at the create, with no result line, so something had to swallow
# the status.  What was chosen swallows it whole.  A create that the daemon
# refused is then indistinguishable from one that worked, and the file goes on
# to measure a runtime that does not exist.
#
# What that looks like is on record.  With a foreign daemon holding the default
# socket, test_cache.sh printed
#
#     runtime already exists: testcache      <- refused, and discarded here
#       FAIL [SET]: got '', expected 'ok'    <- nothing was listening on 19150
#       ... 20 more of those ...
#
# — twenty-one red assertions naming a protocol nobody spoke, produced by a
# binary with nothing wrong with it.  The cause is on the first line and the
# test never says it.
#
# ─── WHY NOW AND NOT BEFORE ─────────────────────────────────────────────────
#
# `|| true` used to be half-defensible.  Every test shared one socket, so some
# other daemon might already hold the name and `runtime already exists` was
# noise no test could prevent.  Since 3ffde3c each test brings up its own daemon
# on its own socket with its own state directory, and the runtime table starts
# empty.  On that daemon a refused create can only mean the test's own setup is
# wrong or the binary is — both worth a red line, neither worth hiding.
#
# ─── THE SHAPE ──────────────────────────────────────────────────────────────
#
# A failed create is counted and reported and the run carries on.  It is not
# fatal, unlike a daemon that never came up: the assertions below still say what
# they have to say, and "the create was refused, and then eleven things did not
# work" is a far better report than either half alone.

# create_ok LABEL COMMAND [ARGS...]
#
# Run COMMAND — normally `"$BIN" create ...`, but the cluster tests route through
# a per-node wrapper function, so the whole command is passed rather than just
# the create's arguments — and count one assertion on its exit status.
#
# On refusal it prints the label, the status, and what the CLI said.  The reason
# is not always in that message: a create that got as far as binding reports
# `could not start runtime` and exits 2, with the actual cause in the daemon's
# log, so the tail of $SOCKETLEY_DLOG goes out too when the caller has one.
#
# Always returns 0.  Under `set -e` a non-zero return from a bare call would end
# the run at the create — which is what `|| true` was there to prevent, and
# reintroducing it under a better name would be no improvement.  Callers that
# genuinely want to branch read $CREATE_RC, which holds the status.
create_ok() {
    local label=$1; shift
    local out
    CREATE_RC=0
    out=$("$@" 2>&1) || CREATE_RC=$?
    TOTAL=$((TOTAL+1))
    if [ "$CREATE_RC" -eq 0 ]; then
        PASS=$((PASS+1))
        return 0
    fi
    FAIL=$((FAIL+1))
    echo "  FAIL [$label]: create refused, exit $CREATE_RC — everything below that"
    echo "        needs this runtime is measuring one that does not exist"
    printf '%s\n' "${out:-<nothing>}" | sed 's/^/        create said: /'
    if [ -n "${SOCKETLEY_DLOG:-}" ] && [ -r "${SOCKETLEY_DLOG:-}" ]; then
        tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/^/        daemon:      /'
    fi
    return 0
}
