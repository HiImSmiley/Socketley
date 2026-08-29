#!/usr/bin/env bash
# Integration test: every SDK example still builds against the tree it documents.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# There are fourteen programs under sdk/examples/ and exactly one of them was
# ever compiled by this suite -- greeter_worker.cpp, as a side effect of
# test_registered_type.sh needing a worker binary.  The other thirteen, every
# one of basic/ and advanced/ among them, were only ever read.
#
# They are the SDK's documentation.  A header that changes shape breaks them
# silently, and the first person to find out is someone following the file that
# was supposed to teach them.  libsocketley_sdk.a gained socketley/daemon/**
# and server_instance gained a method on the same day this was written; nothing
# in the tree would have said if either had broken an example.
#
# ─── WHAT THIS DOES NOT DO ──────────────────────────────────────────────────
#
# It compiles and links.  It does not run anything, so it catches an example
# that no longer builds and nothing else -- and that limit is worth stating,
# because the three SDK defects found the week this was written all compiled
# perfectly and failed at runtime.  The end-to-end coverage is in
# test_sdk_daemon.sh and test_registered_type.sh; this file only holds the
# floor.
#
# The builds run in parallel because serially they cost 1m48s here, which is
# too much to pay twice per suite for a check this shallow.  The cap is well
# under nproc: each translation unit pulls in sol2, and the box this runs on
# has 11 GiB.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BINDIR=$(dirname "$BIN")

PASS=0; FAIL=0; TOTAL=0

echo "=== Integration: every SDK example builds ==="

if ! command -v g++ >/dev/null 2>&1; then
    echo "  SKIP: g++ is required"
    exit 0
fi
if [ ! -f "$BINDIR/libsocketley_sdk.a" ]; then
    echo "  SKIP: $BINDIR/libsocketley_sdk.a is not built"
    exit 0
fi

WORK=$(mktemp -d /tmp/socketley-exbuild-XXXXXX)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

SANFLAGS=""
case "$BINDIR" in *Sanitize*) SANFLAGS="-fsanitize=address,undefined";; esac

# Exported for the subshells xargs spawns, which do not inherit shell functions.
export ROOT BINDIR WORK SANFLAGS

build_one() {
    local src=$1
    local tag
    tag=$(printf '%s' "${src#"$ROOT"/sdk/examples/}" | tr '/' '_')
    if g++ -std=c++23 $SANFLAGS "$src" \
         -I"$ROOT" -I"$ROOT/include/linux" \
         -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit" \
         -L"$BINDIR" -L"$ROOT/thirdparty/luajit" -L"$ROOT/thirdparty/liburing" \
         -lsocketley_sdk -lluajit -luring -lssl -lcrypto -pthread \
         -o "$WORK/$tag.bin" 2>"$WORK/$tag.err"
    then
        printf 'ok %s\n' "$tag" >> "$WORK/results"
    else
        printf 'bad %s\n' "$tag" >> "$WORK/results"
    fi
}
export -f build_one

: > "$WORK/results"

mapfile -t SOURCES < <(find "$ROOT/sdk/examples" -name '*.cpp' | sort)

# An empty list would report "all examples build" while building none, which is
# the one result this file must never produce.
if [ "${#SOURCES[@]}" -eq 0 ]; then
    echo "  FAIL [there are examples to build]: sdk/examples holds no .cpp at all"
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
fi

printf '%s\n' "${SOURCES[@]}" | xargs -P 4 -I{} bash -c 'build_one "$@"' _ {}

for src in "${SOURCES[@]}"; do
    tag=$(printf '%s' "${src#"$ROOT"/sdk/examples/}" | tr '/' '_')
    TOTAL=$((TOTAL+1))
    if grep -qx "ok $tag" "$WORK/results" 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [${src#"$ROOT"/}]: does not build against this tree"
        sed 's/^/        /' "$WORK/$tag.err" 2>/dev/null | head -6
    fi
done

# Every source must have produced a verdict: a build killed by the OOM killer
# writes no line, and counting only the ok lines would read that as a pass.
LINES=$(wc -l < "$WORK/results")
TOTAL=$((TOTAL+1))
if [ "$LINES" -eq "${#SOURCES[@]}" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [every example was actually attempted]: ${#SOURCES[@]} sources,"
    echo "        $LINES verdicts -- a build that produced neither is not a pass"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
