#!/usr/bin/env bash
# clang is used here and only here, because libFuzzer is a clang feature and
# GCC has no equivalent, while the shipped binary is still GCC's -- with the
# GCC replay driver kept as a floor for machines with no clang and
# REQUIRE_LIBFUZZER=1 so a silent fallback cannot pass as a real run (exit 0
# built, 1 unavailable, 2 build failed); MemorySanitizer is deliberately
# absent, because it needs every dependency rebuilt under it and LuaJIT is
# hand-written assembly it cannot instrument at all.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/bin/fuzz-libfuzzer"
REQUIRE="${REQUIRE_LIBFUZZER:-0}"

# All nine by default, narrowed by the per-push CI job to the five cheap ones
# because the SDK-linking targets drag in fifteen translation units -- and
# narrowing is always the caller's explicit decision, never a target dropped
# because building it failed.
ALL_TARGETS="fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_response fuzz_event_loop fuzz_http_request fuzz_server_ops fuzz_client_ops fuzz_proxy_ops fuzz_raft_msg fuzz_s3_sigv4 fuzz_bucket_policy fuzz_dns"
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

# -fsanitize=fuzzer needs a runtime that ships in a separate package on Debian,
# probed by compiling rather than by guessing at paths.
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
want fuzz_raft_msg && build fuzz_raft_msg "$ROOT/test/fuzz/fuzz_raft_msg.cpp" \
    "$ROOT/socketley/shared/raft_codec.cpp" "$ROOT/socketley/shared/raft.cpp"
want fuzz_s3_sigv4 && build fuzz_s3_sigv4 "$ROOT/test/fuzz/fuzz_s3_sigv4.cpp" \
    "$ROOT/socketley/shared/s3_sigv4.cpp" -lcrypto
want fuzz_bucket_policy && build fuzz_bucket_policy "$ROOT/test/fuzz/fuzz_bucket_policy.cpp" \
    "$ROOT/socketley/runtime/storage/bucket_policy.cpp"
want fuzz_dns && build fuzz_dns "$ROOT/test/fuzz/fuzz_dns.cpp" "$ROOT/socketley/runtime/dns/dns_wire.cpp" \
    "$ROOT/socketley/runtime/dns/dns_zone.cpp" "$ROOT/socketley/runtime/dns/dns_answer.cpp"

# fuzz_cache_ops needs one .cpp out of the runtime rather than the whole SDK,
# because cache_store.cpp includes nothing but libc headers.
want fuzz_cache_ops && build fuzz_cache_ops \
    "$ROOT/test/fuzz/fuzz_cache_ops.cpp" "$ROOT/socketley/runtime/cache/cache_store.cpp"

# fuzz_http_response is as cheap as the parser targets because the response
# framing was lifted into a header that includes nothing else of ours.
want fuzz_http_response && build fuzz_http_response "$ROOT/test/fuzz/fuzz_http_response.cpp"

# fuzz_event_loop is two translation units and one system library, and it never
# opens a ring, so -luring is a link-time dependency only and the binary runs
# anywhere.
want fuzz_event_loop && build fuzz_event_loop \
    "$ROOT/test/fuzz/fuzz_event_loop.cpp" "$ROOT/socketley/shared/event_loop.cpp" -luring

# ─── the targets that link the runtime ──────────────────────────────────────
# The four runtime-linking targets cannot use premake's GCC archive, because
# one process cannot host both GCC's and clang's sanitizer runtimes, so the SDK
# sources are compiled here with clang and cached -- with SOCKETLEY_INVARIANTS
# defined for these objects and nowhere else, since the pool-safety and
# reachability checks compile to nothing without it and are half of what these
# targets exist to assert.
if want fuzz_http_request || want fuzz_server_ops || want fuzz_client_ops || \
   want fuzz_proxy_ops; then
SDK_OBJ="$OUT/sdk-obj"
mkdir -p "$SDK_OBJ"

SDK_INC=(-I"$ROOT" -I"$ROOT/socketley" -I"$ROOT/include/linux" -I"$ROOT/test/fuzz"
         -isystem "$ROOT/thirdparty/sol2" -isystem "$ROOT/thirdparty/luajit")
SDK_DEF=(-DSOCKETLEY_LINUX -DDEBUG -DSOCKETLEY_INVARIANTS)

# The cache is keyed on mtime, which says nothing about flags, so the flag set
# is recorded next to the objects and a change to it empties the cache.
SDK_STAMP="$SDK_OBJ/.flags"
SDK_KEY="$CLANG|${SDK_DEF[*]}|c++23"
if [ "$(cat "$SDK_STAMP" 2>/dev/null)" != "$SDK_KEY" ]; then
    rm -f "$SDK_OBJ"/*.o "$SDK_OBJ"/*.d
    printf '%s' "$SDK_KEY" > "$SDK_STAMP"
fi

# The compiler records what it actually opened and that record decides, because
# comparing an object against its own .cpp misses a layout-changing header edit
# -- which produced one binary carrying two disagreeing pictures of the same
# class, reported as a UBSan failure with a reproducer that replays clean
# against a correctly built binary; a missing record rebuilds too, since an
# object that cannot show what went into it is not one to reuse.
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
            # -MD rather than -MMD, because the record has to name every header
            # the compiler opened and a bump to sol2 or luajit changes the
            # layout just as surely as one of ours.
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

# Checked per requested target rather than by counting files, because a count
# is satisfied by a stale binary left over from a previous run.
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
