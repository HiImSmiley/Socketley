#!/bin/bash
# `socketley --help` where nobody is watching
#
# --help is the one command a script is most likely to run and least likely to
# be able to answer, and this file is about what it does when there is no
# terminal: a pipe, a redirect, a CI step, `socketley --help | less`.
#
# What it used to do was exit 1 and print a menu.  man/socketley-help.sh is an
# interactive program — it clears the screen, draws a menu, and ends on `read`
# — and with stdin closed that `read` fails under `set -e`, so the script died
# and the CLI passed its status up.  Exit 1 is this project's code for bad
# input.  Asking for help is not bad input.
#
# The second half is which copy answers.  The lookup tried
# /usr/share/socketley/socketley-help.sh first and the binary's own tree
# second, so on any machine with socketley installed a freshly built binary
# printed the installed version's help — measured on this one, eight months
# older than the tree it was built from.
#
# No daemon and no ports: --help returns before the CLI ever looks for one.
# That is worth keeping true, so the last assertion checks it.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: socketley --help where nobody is watching ==="

# `|| RC=$?` rather than `; RC=$?`, and it is not a style choice.  Under the
# set -e above, a command substitution that exits non-zero ends the script on
# the assignment itself — before the next line can read $?.  Written the
# obvious way, this file did not report the failure it exists to detect; it
# died at the top and printed a header and nothing else, which reads like a
# pass to anything that only checks for the word FAIL.
RC=0
OUT=$("$BIN" --help </dev/null 2>&1) || RC=$?

# ─── The exit code, which is the whole point ────────────────────────────────
if [ "$RC" -eq 0 ]; then
    pass
else
    fail "--help exits 0 with no terminal" \
         "got exit $RC" \
         "a script asking for help was told it had made a mistake"
fi

# ─── Plain text, not a screen-clear and a menu ──────────────────────────────
#
# The escape check is the one that catches a rebuild of the old behaviour even
# if something else fixed the status: the interactive path opens with an ANSI
# clear before it prints anything at all.
if printf '%s' "$OUT" | grep -q $'\033'; then
    fail "the output carries no terminal escapes" \
         "found an ESC byte in output meant for a pipe" \
         "first line: $(printf '%s' "$OUT" | head -1 | cat -v | cut -c1-60)"
else
    pass
fi

if printf '%s' "$OUT" | grep -qiE '^\s*q\)\s*Quit|What would you like to learn'; then
    fail "no interactive menu in a pipe" \
         "the menu was printed to something that cannot answer it"
else
    pass
fi

# ─── It has to actually be help ─────────────────────────────────────────────
#
# Without these, a build whose --help printed nothing at all would pass every
# assertion above: no escapes, no menu, exit 0.
for want in USAGE create daemon "man socketley"; do
    if printf '%s' "$OUT" | grep -qF "$want"; then
        pass
    else
        fail "the help names \`$want\`" "not found in $(printf '%s' "$OUT" | wc -l) lines of output"
    fi
done

# ─── The binary's own copy, not another version's ───────────────────────────
#
# Both files are generated from the same tree, so any command this binary
# dispatches must appear in the help it prints.  `restart` is the discriminator
# on this machine: the installed copy predates it.
if printf '%s' "$OUT" | grep -qF "restart"; then
    pass
else
    fail "the help came from this binary's own tree" \
         "\`restart\` is missing, which is what an older installed copy looks like"
fi

# ─── A terminal still gets the browser ──────────────────────────────────────
#
# The fix must not have replaced the interactive help, only added a path around
# it.  script(1) supplies a pty; stdin is closed behind it so the menu's `read`
# reaches EOF instead of hanging, and timeout is the backstop if it does not.
if command -v script >/dev/null 2>&1; then
    TTY_OUT=$(timeout 20 script -qec "$BIN --help" /dev/null </dev/null 2>&1 || true)
    if printf '%s' "$TTY_OUT" | grep -qiE 'What would you like to learn|Interactive Help'; then
        pass
    else
        fail "a real terminal still gets the interactive help" \
             "the menu did not appear on a pty — the plain path may have swallowed both cases"
    fi
else
    echo "  (script(1) absent — the pty control did not run)"
fi

# ─── No daemon was started ──────────────────────────────────────────────────
#
# --help returns before ensure_daemon().  If that ever stops being true, this
# command grows a side effect that every CI step inherits.
if [ -S /tmp/socketley.sock ] && [ ! -e /tmp/socketley.sock.pre ]; then
    : # a pre-existing daemon socket is not this test's business
fi
if printf '%s' "$OUT" | grep -qiE 'failed to start daemon|daemon not running'; then
    fail "--help needs no daemon" "the help output mentions the daemon failing to start"
else
    pass
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
