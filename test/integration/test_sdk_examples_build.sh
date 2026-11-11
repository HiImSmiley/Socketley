#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: every SDK example still builds against the tree it documents.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Of the programs under sdk/examples/, exactly one was ever compiled by this
# suite -- greeter_worker.cpp, as a side effect of test_registered_type.sh
# needing a worker binary.  The others, every one of basic/ and advanced/ among
# them, were only ever read.
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
# It also links one example without gcc's linker plugin.  The Release archive
# was once LTO bytecode, which links only with the gcc that wrote it and made
# every example compile the whole library again: four at once ran 64 lto1
# processes and pushed a full gate past its two hours.
#
# The builds run in parallel because serially they cost 1m48s here, which is
# too much to pay twice per suite for a check this shallow.  The cap is well
# under nproc: each translation unit pulls in sol2, and the box this runs on
# has 11 GiB.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_sdk.sh"
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

SDKFLAGS=$("$ROOT/sdk/socketley-config" --config "$(basename "$BINDIR")" --cflags --libs) || {
    echo "  FAIL [socketley-config answers]: $SDKFLAGS"
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
}

# Exported for the subshells xargs spawns, which do not inherit shell functions.
export ROOT BINDIR WORK SANFLAGS SDKFLAGS

build_one() {
    local src=$1
    local tag
    tag=$(printf '%s' "${src#"$ROOT"/sdk/examples/}" | tr '/' '_')
    # The flags come from socketley-config and nowhere else, which is the
    # assertion: -I<repo-root> used to be on this line, so every public header
    # was free to reach into the source tree and no test could tell.  An
    # example that needs a path this script does not pass is an example nobody
    # outside the checkout can build.
    if sdk_cxx "$src" $SDKFLAGS \
         -o "$WORK/$tag.bin" 2>"$WORK/$tag.err"
    then
        printf 'ok %s\n' "$tag" >> "$WORK/results"
    else
        printf 'bad %s\n' "$tag" >> "$WORK/results"
    fi
    # Only the verdict is kept, since a sanitizer build of an example is half a gigabyte and 23 of them filled the disk.
    rm -f "$WORK/$tag.bin"
}
export -f build_one sdk_cxx

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

# Another compiler links only machine code, so one example is linked without gcc's linker plugin, which alone reads
# an archive of LTO bytecode.
TOTAL=$((TOTAL+1))
if sdk_cxx -fno-use-linker-plugin "${SOURCES[0]}" $SDKFLAGS -o "$WORK/noplugin.bin" 2>"$WORK/noplugin.err"; then
    rm -f "$WORK/noplugin.bin"
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the archive is machine code]: ${SOURCES[0]#"$ROOT"/} does not link without gcc's LTO plugin"
    sed 's/^/        /' "$WORK/noplugin.err" | head -6

    # Which members, and when they were compiled -- because the usual cause is
    # not the flags but make: -fno-lto arrived in premake5.lua and make rebuilds
    # on times, not flags, so objects older than that change keep their GIMPLE
    # and the archive stays mixed.  Naming them turns an ld dump into one rm.
    OBJDIR="$ROOT/make/obj/x64/$(basename "$BINDIR")/socketley_sdk"
    STALE=""
    for o in "$OBJDIR"/*.o; do
        [ -e "$o" ] || continue
        [ "$(readelf -S "$o" 2>/dev/null | grep -c gnu.lto)" -gt 0 ] || continue
        STALE="$STALE $(basename "$o")($(stat -c %y "$o" 2>/dev/null | cut -c1-10))"
    done
    if [ -n "$STALE" ]; then
        echo "        LTO objects still in $OBJDIR:$STALE"
        echo "        make rebuilds on times and not on flags, so these predate -fno-lto"
        echo "        and survive every later make; delete them and build again"
    elif ! command -v readelf >/dev/null 2>&1; then
        echo "        no readelf here, so which members are GIMPLE was not asked"
    else
        echo "        no LTO object in $OBJDIR, so this is the flags and not a stale"
        echo "        object: check -fno-lto is on the sdk projects in premake5.lua"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
