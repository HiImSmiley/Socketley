#!/usr/bin/env bash
# Build the fuzz targets against libFuzzer.
#
# ─── CLANG IS A TESTING TOOLCHAIN, NOT A BUILD DEPENDENCY ───────────────────
#
# Nobody needs clang to build socketley.  The shipped binary is built with GCC,
# by premake, and that does not change.  clang is used here, and only here, to
# produce coverage-guided fuzz binaries, because libFuzzer is a clang feature
# and GCC has no equivalent.  If you are building socketley, ignore this file.
#
# libFuzzer is the *primary* fuzzing path: it is coverage-guided, so it explores
# rather than replaying.  The GCC replay driver that premake builds
# (bin/<config>/fuzz_*) remains as a floor for machines with no clang — it needs
# nothing but the project's own compiler — but a run that silently fell back to
# it has not fuzzed in any meaningful sense.  Set REQUIRE_LIBFUZZER=1 anywhere
# the toolchain is known-good (CI runners) so that fallback cannot pass as a
# real run.
#
#   ./test/fuzz/build_libfuzzer.sh              build if possible, skip if not
#   REQUIRE_LIBFUZZER=1 ./test/fuzz/...         fail loudly if not possible
#
# Exit codes:  0 built   1 unavailable (or unavailable+required)   2 build failed
#
# Output: bin/fuzz-libfuzzer/{fuzz_resp,fuzz_ws_frame,fuzz_cache_ops,fuzz_http_response,
#         fuzz_event_loop,fuzz_http_request,fuzz_server_ops,fuzz_client_ops,
#         fuzz_proxy_ops}
#
# ─── WHY THERE IS NO MEMORYSANITIZER BUILD HERE ─────────────────────────────
#
# MSan is the obvious next sanitizer to reach for and it is deliberately absent.
# It reports a false positive for every byte that passes through code it did not
# instrument, which means it needs libc++ *and* every dependency — liburing,
# OpenSSL, LuaJIT — rebuilt with -fsanitize=memory.  LuaJIT in particular is
# hand-written assembly that MSan cannot instrument at all.  That is a project
# of its own, not a flag to add to this script; adding MSan without the
# instrumented dependency stack produces a wall of noise that gets the whole
# sanitizer switched off.  ASan+UBSan here, TSan in the nightly, is the set that
# actually holds.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/bin/fuzz-libfuzzer"
REQUIRE="${REQUIRE_LIBFUZZER:-0}"

# Which targets to build.  Default is all nine.  The per-push CI job narrows
# this to the five cheap ones, because the four SDK-linking targets
# (fuzz_http_request, fuzz_server_ops, fuzz_client_ops, fuzz_proxy_ops) drag in
# fifteen SDK translation units between them and that is a nightly cost, not a
# per-push one.  Narrowing is always an explicit decision by the caller —
# nothing here drops a target because building it happened to fail.
ALL_TARGETS="fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_response fuzz_event_loop fuzz_http_request fuzz_server_ops fuzz_client_ops fuzz_proxy_ops"
WANT="${LIBFUZZER_TARGETS:-$ALL_TARGETS}"

want() {
    case " $WANT " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

for t in $WANT; do
    case " $ALL_TARGETS " in
        *" $t "*) ;;
        *) echo "libfuzzer build: unknown target '$t' in LIBFUZZER_TARGETS"; exit 2 ;;
    esac
done

unavailable() {
    echo "libfuzzer build: $1"
    if [ "$REQUIRE" = "1" ]; then
        echo "libfuzzer build: REQUIRE_LIBFUZZER=1 was set, so this is a failure."
        exit 1
    fi
    echo "libfuzzer build: skipping (the GCC replay targets still run)."
    exit 1
}

CLANG="${CLANG:-}"
if [ -z "$CLANG" ]; then
    for c in clang++-19 clang++-18 clang++-17 clang++; do
        command -v "$c" >/dev/null 2>&1 && { CLANG="$c"; break; }
    done
fi
[ -n "$CLANG" ] || unavailable "no clang++ on PATH"

# -fsanitize=fuzzer needs libclang_rt.fuzzer-*.a, which ships in a separate
# package on Debian/Ubuntu (libclang-rt-<v>-dev).  Probe by compiling, not by
# guessing at paths.
probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT
cat > "$probe/p.cc" <<'EOF'
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }
EOF
if ! "$CLANG" -fsanitize=fuzzer,address,undefined "$probe/p.cc" -o "$probe/p" 2>"$probe/err"; then
    echo "libfuzzer build: probe failed with $CLANG:"
    sed 's/^/    /' "$probe/err" | head -10
    unavailable "clang cannot link -fsanitize=fuzzer (install libclang-rt-*-dev)"
fi

echo "libfuzzer build: using $($CLANG --version | head -1)"
mkdir -p "$OUT"

FLAGS=(
    -std=c++20 -g -O1
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
    -I"$ROOT/socketley"
    -I"$ROOT/test/fuzz"
)

rc=0

build() {
    local name="$1"; shift
    echo "  $name"
    if ! "$CLANG" "${FLAGS[@]}" "$@" -o "$OUT/$name" 2>"$probe/$name.err"; then
        echo "  FAILED: $name"
        sed 's/^/    /' "$probe/$name.err" | head -30
        rc=2
    fi
}

want fuzz_resp     && build fuzz_resp "$ROOT/test/fuzz/fuzz_resp.cpp"
want fuzz_ws_frame && build fuzz_ws_frame "$ROOT/test/fuzz/fuzz_ws_frame.cpp" -lssl -lcrypto

# fuzz_cache_ops needs one .cpp out of the runtime, not the whole SDK:
# cache_store.cpp includes nothing but libc headers, so it compiles here as
# cheaply as a header-only target.  That is why this target belongs in the
# per-push job alongside the two parsers and fuzz_http_request does not.
want fuzz_cache_ops && build fuzz_cache_ops \
    "$ROOT/test/fuzz/fuzz_cache_ops.cpp" "$ROOT/socketley/runtime/cache/cache_store.cpp"

# fuzz_http_response is as cheap as the two parser targets even though it fuzzes
# the proxy: the response framing was lifted out of handle_backend_read into
# runtime/proxy/http_response_framing.h, which includes <charconv> and
# <string_view> and nothing else.  One translation unit, no libraries, no SDK —
# which is why this one is in the per-push job and fuzz_http_request is not.
want fuzz_http_response && build fuzz_http_response "$ROOT/test/fuzz/fuzz_http_response.cpp"

# fuzz_event_loop needs one .cpp out of shared/, not the SDK: event_loop.cpp
# includes liburing and logging.h and nothing else of ours, so this target is
# two translation units and one system library.  It never opens a ring — see the
# header of fuzz_event_loop.cpp for why handing its SQEs to a kernel would be a
# hazard rather than a test — so -luring is a link-time dependency only and the
# binary runs anywhere, including a container with io_uring blocked.
want fuzz_event_loop && build fuzz_event_loop \
    "$ROOT/test/fuzz/fuzz_event_loop.cpp" "$ROOT/socketley/shared/event_loop.cpp" -luring

# ─── the targets that link the runtime ──────────────────────────────────────
#
# fuzz_http_request, fuzz_server_ops, fuzz_client_ops and fuzz_proxy_ops all
# need the runtime itself.  parse_http_request_line lives in proxy_instance.cpp
# and there is no smaller unit that contains it; the three operation-sequence
# targets drive a real server_instance, client_instance and proxy_instance
# against a real io_uring event_loop, which is the whole point of them.  None of
# the four can link premake's GCC archive —
# that archive is built with GCC's ASan, and one process cannot host both GCC's
# and clang's sanitizer runtimes — so the SDK sources are compiled here with
# clang as well.  That is a real cost (fifteen translation units, the slowest
# being lua_context.cpp against sol2) so the objects are cached in $SDK_OBJ,
# shared by all three, and only rebuilt when a source is newer.
#
# SOCKETLEY_INVARIANTS is defined for these objects and nowhere else.  It is what
# makes the calls in socketley/shared/invariants.h live: the pool-safety check in
# server_instance::pool_release and the reachability check in on_cqe compile to
# nothing without it, and those two are half of what fuzz_server_ops exists to
# assert.  For fuzz_proxy_ops it also turns on inv_check_pair and inv_sweep_all,
# which state the proxy's own half of the same rule over a *pair* rather than
# over one connection.  It costs the shipped binary nothing, because the shipped binary is not
# built from these objects.
#
# This does NOT make clang a build dependency of socketley.  These objects are
# instrumented fuzzing artifacts under bin/; the shipped binary is still GCC's.
if want fuzz_http_request || want fuzz_server_ops || want fuzz_client_ops || \
   want fuzz_proxy_ops; then
SDK_OBJ="$OUT/sdk-obj"
mkdir -p "$SDK_OBJ"

SDK_INC=(-I"$ROOT" -I"$ROOT/socketley" -I"$ROOT/include/linux" -I"$ROOT/test/fuzz"
         -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit")
SDK_DEF=(-DSOCKETLEY_LINUX -DDEBUG -DSOCKETLEY_INVARIANTS)

# The cache below is keyed on mtime, which says nothing about the flags an
# object was built with.  Adding SOCKETLEY_INVARIANTS to the set would therefore
# have been silently ignored for every source that had not changed since — the
# targets would link objects with the invariant calls compiled out and report a
# clean run for checks that were never in the binary.  So the flag set is
# recorded next to the objects and a change to it empties the cache.
SDK_STAMP="$SDK_OBJ/.flags"
SDK_KEY="$CLANG|${SDK_DEF[*]}|c++23"
if [ "$(cat "$SDK_STAMP" 2>/dev/null)" != "$SDK_KEY" ]; then
    rm -f "$SDK_OBJ"/*.o "$SDK_OBJ"/*.d
    printf '%s' "$SDK_KEY" > "$SDK_STAMP"
fi

# Is a cached object still usable, or does it have to be built again?
#
# Comparing it against its own .cpp is not enough, and the way that fails is
# silent.  A layout-changing edit to a *header* leaves every .cpp that includes
# it untouched, so the old check kept the object — while the fuzz target's own
# translation unit, which is recompiled on every run, picked the new header up.
# One binary then carried two disagreeing pictures of the same class.
#
# Measured here on 2026-08-13: client_instance.cpp.o was eight days older than
# client_instance.h.  sizeof(client_instance) had gone 1192 → 1352 and
# m_connected 1024 → 1136 across that gap, so the cached constructor initialised
# the field at the offset its header gave it and the target's check_instance()
# read the byte the new one names.  The nightly reported that as a UBSan failure
# in the client runtime, with a 7-byte reproducer that replays perfectly clean
# against a correctly built binary.  ASan cannot see it: the older class was the
# smaller of the two, so every write landed inside the allocation.
#
# It had happened before and was not recognised as a cause — 75afc3a adopted a
# seed literally named stale_binary_artifact-f57f22fc, "produced by a libFuzzer
# binary built five proxy commits before it was replayed", and left the build
# that produced it alone.
#
# So the compiler records what it actually opened and that record decides.  A
# prerequisite newer than the object rebuilds it; so does one that has since
# been deleted, and so does a missing record — an object that cannot show what
# went into it is not one to reuse.
sdk_object_current() {
    local obj=$1 src=$2 dep="${obj%.o}.d" p
    [ -f "$obj" ]      || return 1
    [ "$obj" -nt "$src" ] || return 1
    [ -f "$dep" ]      || return 1
    while read -r p; do
        [ -n "$p" ] || continue
        [ -e "$p" ] || return 1
        [ "$obj" -nt "$p" ] || return 1
    done < <(sed -e 's/^[^:]*://' -e 's/\\$//' "$dep" | tr -s ' \t' '\n' | grep -v '^$')
    return 0
}

# The source list is read out of premake's generated makefile rather than
# duplicated here, so a file added to the SDK cannot silently go un-fuzzed.
SDK_MAKE="$ROOT/make/socketley_sdk.make"
if [ ! -f "$SDK_MAKE" ]; then
    echo "  runtime targets: $SDK_MAKE not found — run ./bin/premake5 gmake2 first"
    rc=2
else
    mapfile -t SDK_SRCS < <(grep -oE '\.\./[A-Za-z0-9_/.-]+\.cpp' "$SDK_MAKE" | sort -u | sed "s|^\.\./|$ROOT/|")
    if [ "${#SDK_SRCS[@]}" -eq 0 ]; then
        echo "  runtime targets: no sources parsed out of $SDK_MAKE"
        rc=2
    else
        echo "  runtime targets: ${#SDK_SRCS[@]} SDK sources"
        sdk_objs=()
        sdk_fail=0
        for src in "${SDK_SRCS[@]}"; do
            obj="$SDK_OBJ/$(echo "${src#"$ROOT/"}" | tr '/' '_').o"
            sdk_objs+=("$obj")
            if sdk_object_current "$obj" "$src"; then
                continue
            fi
            # -MD, not -MMD: the record has to name every header the compiler
            # opened, system ones included.  sol2 and luajit arrive through
            # -isystem and a bump to either changes the layout of what the
            # objects hold just as surely as one of ours does.
            if ! "$CLANG" -std=c++23 -g -O1 \
                    -fsanitize=fuzzer-no-link,address,undefined \
                    -fno-sanitize-recover=all -fno-omit-frame-pointer \
                    -MD -MF "${obj%.o}.d" \
                    "${SDK_DEF[@]}" "${SDK_INC[@]}" \
                    -c "$src" -o "$obj" 2>"$probe/sdk.err"; then
                echo "  FAILED (SDK): ${src#"$ROOT/"}"
                sed 's/^/    /' "$probe/sdk.err" | head -20
                sdk_fail=1
                break
            fi
        done

        if [ "$sdk_fail" -ne 0 ]; then
            rc=2
        else
            # -std=c++23 comes after FLAGS' -std=c++20 and therefore wins: the
            # runtime headers these targets pull in need it, the header-only
            # ones do not.
            RT_LINK=(-std=c++23 "${SDK_INC[@]}" "${SDK_DEF[@]}"
                     -L"$ROOT/thirdparty/luajit" -lluajit -luring -lssl -lcrypto -ldl -lpthread)

            want fuzz_http_request && build fuzz_http_request \
                "$ROOT/test/fuzz/fuzz_http_request.cpp" "${sdk_objs[@]}" "${RT_LINK[@]}"
            want fuzz_server_ops && build fuzz_server_ops \
                "$ROOT/test/fuzz/fuzz_server_ops.cpp" "${sdk_objs[@]}" "${RT_LINK[@]}"
            want fuzz_client_ops && build fuzz_client_ops \
                "$ROOT/test/fuzz/fuzz_client_ops.cpp" "${sdk_objs[@]}" "${RT_LINK[@]}"
            want fuzz_proxy_ops && build fuzz_proxy_ops \
                "$ROOT/test/fuzz/fuzz_proxy_ops.cpp" "${sdk_objs[@]}" "${RT_LINK[@]}"
        fi
    fi
fi
fi

if [ "$rc" -ne 0 ]; then
    echo "libfuzzer build: one or more targets failed to build"
    exit "$rc"
fi

# A build step that produced nothing must not report success.  Checked per
# requested target rather than by counting files: a count is satisfied by a
# stale binary left over from a previous run, which is the same silent
# degradation in a slower disguise.
missing=0
for t in $WANT; do
    if [ ! -x "$OUT/$t" ]; then
        echo "libfuzzer build: $t was requested but $OUT/$t does not exist"
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 2

echo "libfuzzer build: built [$WANT] in $OUT"
exit 0
