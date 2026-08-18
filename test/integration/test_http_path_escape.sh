#!/usr/bin/env bash
# Integration test: --http must not serve anything outside its document root
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# serve_http's disk mode calls fs::canonical() on the requested path and then
# checks the result still begins with the canonical root.  That check is the
# only thing between `--http /var/www` and the rest of the filesystem, and
# nothing in this suite exercised it -- grepped, and the only symlink tests are
# about state files.
#
# It is being pinned now because the check is about to be replaced.
# fs::canonical resolves every path component with readlink: measured on a root
# nine directories deep, 9.01 readlink syscalls per request, 43.9 us of the
# 42.5 us that a connection costs beyond its own connect and its own request
# work.  The replacement is openat2(RESOLVE_BENEATH), which asks the kernel to
# enforce the same rule inside the open itself.
#
# So these assertions are the specification, and they must pass identically
# before and after.  They also cover a hole the current code has and the
# replacement closes: fs::canonical() and the open() that follows it are two
# syscalls against a path that can change in between.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# Each one asks for a file whose contents are known and asserts the SECRET is
# not in the answer.  A status check alone would pass against a build that
# served the file with a 200 and the wrong body, and a body check alone would
# pass against one that 404'd for an unrelated reason -- so both are asserted.

set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate httpesc
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
trap 'rc=$?; echo "  ABORTED at line $LINENO (exit $rc): ${BASH_COMMAND}"; exit $rc' ERR
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: --http serves nothing outside its root ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1580))

SECRET='TOP-SECRET-OUTSIDE-THE-ROOT'
mkdir -p "$WORK/root/sub" "$WORK/outside"
echo "$SECRET"           > "$WORK/outside/secret.txt"
echo "inside-the-root"   > "$WORK/root/ok.html"
echo "inside-sub"        > "$WORK/root/sub/deep.html"
ln -s "$WORK/outside/secret.txt" "$WORK/root/link-out.txt"     # symlink escape
ln -s "$WORK/outside"            "$WORK/root/dir-out"          # symlink'd directory

"$BIN" create server esc -p $((P+1)) --http "$WORK/root" -s >/dev/null 2>&1 || true
sleep 1.2

get(){ curl -s -m 5 -o "$WORK/body" -w '%{http_code}' "http://127.0.0.1:$((P+1))$1" 2>/dev/null || echo 000; }

# 1. the control: a real file inside the root IS served, or nothing below means anything
code=$(get /ok.html)
if [ "$code" = "200" ] && grep -q inside-the-root "$WORK/body"; then pass
else fail "a file inside the root is served" "got $code, body '$(head -c 40 "$WORK/body" 2>/dev/null)'"; fi

# 2. a nested file, so the depth of the path is exercised too
code=$(get /sub/deep.html)
if [ "$code" = "200" ] && grep -q inside-sub "$WORK/body"; then pass
else fail "a nested file inside the root is served" "got $code"; fi

# 3-6. every way out, and the secret must appear in none of them
for spec in "/link-out.txt|a symlink to a file outside the root" \
            "/dir-out/secret.txt|a symlink to a directory outside the root" \
            "/../outside/secret.txt|a ../ traversal" \
            "/sub/../../outside/secret.txt|a ../ traversal from a subdirectory"; do
    path=${spec%%|*}; what=${spec##*|}
    code=$(get "$path")
    if [ "$code" != "200" ] && ! grep -q "$SECRET" "$WORK/body" 2>/dev/null; then pass
    else fail "$what is refused" \
              "got HTTP $code and the body $(grep -q "$SECRET" "$WORK/body" 2>/dev/null && echo 'CONTAINS THE SECRET' || echo 'did not contain it')" \
              "path requested: $path"; fi
done

echo
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ] || exit 1
