#!/usr/bin/env bash
#
# Bring a machine that runs socketley from a clone up to the newest commit of
# its branch: pull, build, install, restart the daemon, check it, and put the
# old binary back when the new one does not come up.
#
# ─── WHY THIS FILE AND NOT install-from-source.sh AGAIN ─────────────────────
#
# install-from-source.sh sets a machine up: packages, liburing, the vendored
# libraries, a user, directories, the unit.  Run a second time it does all of
# that again -- OpenSSL alone is minutes -- and then `systemctl start`s a daemon
# that is already running, which leaves the old binary serving.  An update
# needs less and one thing more: build what changed, swap the binary, restart.
# A machine where socketley is not installed yet is handed to that script.
#
# ─── WHAT IT DOES ───────────────────────────────────────────────────────────
#
#   1. git fetch; fast-forward the branch, never reset or merge -- a clone with
#      changes of its own, or one that has diverged, is reported and left alone
#   2. the vendored LuaJIT, OpenSSL, ngtcp2 and nghttp3 are built only when an
#      archive is missing or bin/build-thirdparty.sh pins another version
#   3. premake5 gmake2, make the socketley target, check the binary runs
#   4. note which runtimes are running; keep the installed binary as
#      /var/lib/socketley/socketley.prev; install binary, man page, help, unit
#   5. systemctl restart socketley; wait for the socket; the runtimes that were
#      running before must be running again, else the old binary goes back
#
# Runtimes are stopped for the seconds the restart takes.  The daemon starts
# again every runtime that was running; their data and configuration are under
# /var/lib/socketley and /etc/socketley and are not touched.  An upload in the
# web interface pauses meanwhile and goes on by itself.
#
# ─── USE ────────────────────────────────────────────────────────────────────
#
#   bash scripts/update.sh                 # update to the newest commit of this branch
#   bash scripts/update.sh --check         # only say what is new, change nothing
#   bash scripts/update.sh --branch NAME   # follow another branch from now on
#   bash scripts/update.sh --force         # rebuild and restart even when current
#   bash scripts/update.sh --rollback      # put the previous binary back
#
set -Eeuo pipefail

# All of it is one function, read whole before any of it runs: the pull below may rewrite this very file, and bash
# reads a script as it goes, so it would otherwise run on into the middle of the new one.
main() {
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ARGS=("$@")

# Where an install by install-from-source.sh puts things.  The SOCKETLEY_UPDATE_* variables move them, for trying
# this script out on a machine without touching its installed socketley; SOCKETLEY_SOCKET is the CLI's own.
PREFIX="${SOCKETLEY_UPDATE_PREFIX:-/usr}"
BIN="$PREFIX/bin/socketley"
STAMP="$PREFIX/share/socketley/installed-commit"
PREV="${SOCKETLEY_UPDATE_PREV:-/var/lib/socketley/socketley.prev}"
UNIT="${SOCKETLEY_UPDATE_UNIT:-/usr/lib/systemd/system/socketley.service}"
SOCK="${SOCKETLEY_SOCKET:-/run/socketley/socketley.sock}"
TP_STAMP="$ROOT/thirdparty/.built-versions"

BRANCH=""
CHECK=0
FORCE=0
ROLLBACK=0
ASSUME_YES=0
JOBS=""

STEP="startup"; HINT=""
step() { STEP="$1"; HINT="${2:-}"; printf '==> %s\n' "$1"; }
note() { printf '    %s\n' "$*"; }
fail() { printf 'error: %s\n' "$1" >&2; shift; local l; for l in "$@"; do printf '  %s\n' "$l" >&2; done; exit 2; }
on_err() {
    local rc=$?
    printf '\nerror: %s failed (exit %d)\n' "$STEP" "$rc" >&2
    if [ -n "$HINT" ]; then printf '  %s\n' "$HINT" >&2; fi
    exit 2
}
trap on_err ERR

show_help() { sed -n '/^# ─── USE/,/^set -Eeuo/p' "${BASH_SOURCE[0]}" | sed -e '1d' -e '$d' -e 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --branch)    [ $# -ge 2 ] || fail "--branch needs a name"; BRANCH="$2"; shift 2 ;;
        --branch=*)  BRANCH="${1#*=}"; shift ;;
        --jobs)      [ $# -ge 2 ] || fail "--jobs needs a number"; JOBS="$2"; shift 2 ;;
        --jobs=*)    JOBS="${1#*=}"; shift ;;
        --check)     CHECK=1; shift ;;
        --force)     FORCE=1; shift ;;
        --rollback)  ROLLBACK=1; shift ;;
        --yes|-y)    ASSUME_YES=1; shift ;;
        -h|--help)   show_help; exit 0 ;;
        *)           fail "unknown option: $1" "see: bash $0 --help" ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
else SUDO=""; fi
as_root() { if [ -n "$SUDO" ]; then "$SUDO" "$@"; else "$@"; fi; }
need_root() {
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then fail "installing needs root and there is no sudo here" "run it as root"; fi
}
have_service() { command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT" ]; }

# The names of the running runtimes, one a line, sorted; empty when the daemon does not answer.  The CLI is asked only
# while the socket is there: finding none, it would start a daemon of its own, outside the service.
running() { [ -S "$SOCK" ] || return 0; as_root "$BIN" ps 2>/dev/null | awk 'NR > 1 && NF { print $2 }' | sort || true; }

wait_daemon() {
    local _
    for _ in $(seq 1 75); do
        if [ -S "$SOCK" ] && as_root "$BIN" ls >/dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    return 1
}

# ── --rollback ──────────────────────────────────────────────────────────────
if [ "$ROLLBACK" = 1 ]; then
    need_root
    [ -x "$PREV" ] || fail "there is no previous binary at $PREV" "it is kept by the first update that installs over one"
    step "putting the previous binary back" "check: systemctl status socketley"
    as_root install -m755 "$PREV" "$BIN"
    as_root rm -f "$STAMP"
    if have_service; then as_root systemctl restart socketley.service; wait_daemon || fail "the daemon did not come up" "journalctl -u socketley -n 50 --no-pager"; fi
    note "socketley $("$BIN" version 2>/dev/null) is installed again"
    note "the next update builds the branch again; to stay here, do not run it"
    exit 0
fi

# ── Where the clone stands ──────────────────────────────────────────────────
step "checking the clone" "this script runs from inside a git clone of socketley"
command -v git >/dev/null 2>&1 || fail "git is not installed"
git rev-parse --git-dir >/dev/null 2>&1 || fail "$ROOT is not a git clone"
CUR="$(git symbolic-ref --quiet --short HEAD || true)"
if [ -z "$BRANCH" ]; then
    [ -n "$CUR" ] || fail "the clone is on a detached HEAD" "name the branch to follow: bash $0 --branch ui/web"
    BRANCH="$CUR"
fi
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    git status --short --untracked-files=no >&2
    fail "the clone has changes of its own (listed above)" \
         "they would be mixed into the build, so nothing was changed." \
         "keep them:    git stash        then run this again, and  git stash pop  after" \
         "drop them:    git checkout -- .  then run this again"
fi
note "$ROOT on $BRANCH"

step "fetching origin/$BRANCH" "check the network and that the branch exists: git ls-remote origin $BRANCH"
for i in 1 2 3 4; do
    if git fetch --quiet origin "$BRANCH"; then break; fi
    [ "$i" = 4 ] && fail "git fetch failed four times"
    sleep $((2 ** i))
done
REMOTE="$(git rev-parse FETCH_HEAD)"

if [ "$CUR" != "$BRANCH" ]; then
    if git show-ref --verify --quiet "refs/heads/$BRANCH"; then git checkout --quiet "$BRANCH"
    else git checkout --quiet -b "$BRANCH" --track "origin/$BRANCH" 2>/dev/null || git checkout --quiet -b "$BRANCH" "$REMOTE"; fi
    note "switched to $BRANCH"
fi
HEAD_NOW="$(git rev-parse HEAD)"
INSTALLED="$(cat "$STAMP" 2>/dev/null || true)"

NEW=0
if [ "$HEAD_NOW" != "$REMOTE" ]; then
    if ! git merge-base --is-ancestor "$HEAD_NOW" "$REMOTE"; then
        fail "the local $BRANCH has commits origin/$BRANCH does not" \
             "it was not reset, so nothing is lost; look with:  git log --oneline origin/$BRANCH..$BRANCH"
    fi
    NEW="$(git rev-list --count "$HEAD_NOW..$REMOTE")"
fi

if [ "$CHECK" = 1 ]; then
    if [ "$NEW" -gt 0 ]; then
        printf '%s new commit(s) on origin/%s:\n' "$NEW" "$BRANCH"
        git log --oneline "$HEAD_NOW..$REMOTE"
    else
        printf 'the clone is at origin/%s\n' "$BRANCH"
    fi
    if [ -x "$BIN" ]; then
        if [ "$INSTALLED" = "$REMOTE" ]; then echo "and the installed binary is built from it"
        elif [ -n "$INSTALLED" ]; then echo "the installed binary is built from ${INSTALLED:0:12}"
        else echo "the installed binary was not installed by this script"; fi
    else
        echo "socketley is not installed at $BIN"
    fi
    exit 0
fi

if [ "$NEW" -gt 0 ]; then
    step "fast-forwarding $BRANCH by $NEW commit(s)"
    git log --oneline "$HEAD_NOW..$REMOTE" | sed 's/^/    /'
    git merge --quiet --ff-only "$REMOTE"
    # A newer version of this script does the rest.
    if ! git diff --quiet "$HEAD_NOW" HEAD -- scripts/update.sh; then
        note "scripts/update.sh itself changed: the new one goes on"
        exec bash "$ROOT/scripts/update.sh" --branch "$BRANCH" "${ARGS[@]}"
    fi
fi
HEAD_NOW="$(git rev-parse HEAD)"

# ── Not installed yet: the full installer does that ─────────────────────────
if [ ! -x "$BIN" ]; then
    step "socketley is not installed at $BIN: handing over to install-from-source.sh"
    args=(); [ "$ASSUME_YES" = 1 ] && args+=(--yes); [ -n "$JOBS" ] && args+=(--jobs "$JOBS")
    bash "$ROOT/scripts/install-from-source.sh" "${args[@]}"
    as_root install -Dm644 /dev/stdin "$STAMP" <<<"$HEAD_NOW"
    exit 0
fi
if command -v dpkg >/dev/null 2>&1 && dpkg -S "$BIN" >/dev/null 2>&1; then
    fail "$BIN belongs to the socketley .deb" \
         "writing over it leaves dpkg believing in a file that is no longer its own." \
         "either update the package (install.sh), or remove it first:  sudo apt remove socketley" \
         "and then run this script, which installs from the clone"
fi

if [ "$INSTALLED" = "$HEAD_NOW" ] && [ "$FORCE" = 0 ]; then
    echo "socketley is current: the installed binary is built from ${HEAD_NOW:0:12} ($BRANCH)"
    echo "  rebuild and restart anyway:  bash $0 --force"
    exit 0
fi

# ── Build ───────────────────────────────────────────────────────────────────
if [ -z "$JOBS" ]; then
    NPROC="$(nproc 2>/dev/null || echo 1)"
    MEM_KB="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
    BY_MEM=$(( ${MEM_KB:-0} / 1572864 )); [ "$BY_MEM" -ge 1 ] || BY_MEM=1
    JOBS=$(( NPROC < BY_MEM ? NPROC : BY_MEM ))
fi

# A pin changed in bin/build-thirdparty.sh is a different library: built again, as a missing archive is.
PINS="$(grep -E '^[A-Z0-9_]+_TAG=' bin/build-thirdparty.sh | sha256sum | cut -c1-16)"
if [ "$(cat "$TP_STAMP" 2>/dev/null || true)" != "$PINS" ]; then rm -f "$TP_STAMP"; REBUILD_TP=1; else REBUILD_TP=0; fi
if [ "$REBUILD_TP" = 1 ] || [ ! -f thirdparty/luajit/libluajit.a ]; then
    step "building the vendored LuaJIT" "bin/build-thirdparty.sh luajit needs git and a network"
    bash bin/build-thirdparty.sh luajit
fi
if [ "$REBUILD_TP" = 1 ] || [ ! -f thirdparty/openssl/lib/libssl.a ] || [ ! -f thirdparty/ngtcp2/lib/libngtcp2.a ] \
   || [ ! -f thirdparty/ngtcp2/lib/libngtcp2_crypto_ossl.a ] || [ ! -f thirdparty/nghttp3/lib/libnghttp3.a ]; then
    step "building OpenSSL 3.5, ngtcp2 and nghttp3 for HTTP/3 (a few minutes)" \
         "bin/build-thirdparty.sh http3 needs perl, cmake, git and a network"
    bash bin/build-thirdparty.sh http3
fi
echo "$PINS" > "$TP_STAMP"

step "generating makefiles" "./bin/premake5 gmake2 failed"
./bin/premake5 gmake2 >/dev/null 2>&1 || ./bin/premake5 gmake2

step "building Release with -j$JOBS" "read the compiler's last lines above; with little memory try --jobs 1"
LOG="$ROOT/make/update-build.log"
if ! make -C make config=release_x64 -j"$JOBS" socketley > "$LOG" 2>&1; then
    grep -E 'error|Error' "$LOG" | head -20 >&2 || tail -20 "$LOG" >&2
    fail "the build failed; nothing was installed" "all of its output: $LOG"
fi

NEWBIN="$ROOT/bin/Release/socketley"
step "checking the new binary runs" "ldd $NEWBIN  names a missing library as 'not found'"
NEWVER="$("$NEWBIN" version 2>/dev/null || true)"
[ -n "$NEWVER" ] || fail "$NEWBIN version printed nothing" "run it by hand to see why:  $NEWBIN version"
if ldd "$NEWBIN" | grep -q 'not found'; then ldd "$NEWBIN" | grep 'not found' >&2; fail "the new binary has unresolved libraries" "bash scripts/install-liburing.sh, then run this again"; fi
note "socketley $NEWVER from ${HEAD_NOW:0:12}"

# ── Install and restart ─────────────────────────────────────────────────────
need_root
if [ "$ASSUME_YES" = 0 ] && [ -t 0 ] && have_service; then
    printf '    the daemon restarts now, and its runtimes are down for a few seconds. go on? [Y/n] '
    read -r a; case "$a" in [nN]*) echo "    nothing installed; the build stays in bin/Release"; exit 0 ;; esac
fi

BEFORE="$(running)"
step "installing" "check that $PREFIX is writable by root"
as_root install -Dm755 "$BIN" "$PREV"
as_root install -m755 "$NEWBIN" "$BIN"
as_root install -Dm644 man/socketley.1 "$PREFIX/share/man/man1/socketley.1"
as_root install -Dm755 man/socketley-help.sh "$PREFIX/share/socketley/socketley-help.sh"
if have_service && ! cmp -s packaging/socketley.service "$UNIT"; then
    as_root install -Dm644 packaging/socketley.service "$UNIT"
    as_root systemctl daemon-reload
    note "the systemd unit changed and was reloaded"
fi

rollback() {
    printf '\nerror: %s\n' "$1" >&2
    printf '  putting the previous binary back\n' >&2
    as_root install -m755 "$PREV" "$BIN"
    as_root systemctl restart socketley.service || true
    if wait_daemon; then printf '  the previous binary runs again\n' >&2
    else printf '  and the previous one did not come up either: journalctl -u socketley -n 50 --no-pager\n' >&2; fi
    printf '  what the new one said: journalctl -u socketley -n 80 --no-pager --since "-3 min"\n' >&2
    exit 2
}

if have_service; then
    step "restarting the daemon"
    as_root systemctl restart socketley.service || rollback "systemctl restart failed"
    wait_daemon || rollback "the new daemon did not answer on $SOCK within 15 seconds"
    # The runtimes come back one after another; a slow one is waited for a moment.
    MISSING=""
    for _ in $(seq 1 40); do
        AFTER="$(running)"
        MISSING="$(comm -23 <(printf '%s\n' "$BEFORE" | sed '/^$/d') <(printf '%s\n' "$AFTER" | sed '/^$/d'))"
        [ -z "$MISSING" ] && break
        sleep 0.25
    done
    [ -z "$MISSING" ] || rollback "these runtimes ran before and do not now: $(echo $MISSING)"
    note "the daemon answers; running: $(echo $AFTER)"
else
    note "no systemd service here: restart the daemon yourself for the new binary to serve"
fi

as_root install -Dm644 /dev/stdin "$STAMP" <<<"$HEAD_NOW"

printf '\nsocketley %s from %s (%s) is installed and running.\n' "$NEWVER" "${HEAD_NOW:0:12}" "$BRANCH"
printf '  the one before:  bash %s --rollback\n' "$0"
printf '  logs:            journalctl -u socketley -f\n'
}

main "$@"
exit $?
