# What the binary under test was built as -- not a test, only ever sourced (lib_daemon.sh does).
#
# A bound on time or memory is a statement about one build: ASan's redzones and quarantine, TSan's shadow (five to
# eight times the memory) and an unoptimized build's uninlined calls each move it, and a check written for one of
# them alone (`nm | grep __asan_`) asserted Release's numbers of a TSan daemon.  Every file asks here instead.
#
#   build_kind        release, debug, asan or tsan
#   build_sanitized   0 when a sanitizer is compiled in, whose costs no bound written for Release can hold
#   build_cost        what the same work costs in this build, as socketley/shared/util/build_cost.h says it
#   build_sanflags    the flags a program linked against this build's libsocketley_sdk.a must carry
#   build_defers_signals  0 under TSan, which runs a signal's handler only when the thread next enters its runtime --
#                     never, for a loop in LuaJIT's virtual machine, so a deadline the stop signal enforces cannot fire

build_kind() {
    local rt
    # The runtime the binary loads, which gcc links as a shared library: one readelf of the dynamic section, where nm
    # reads a quarter of a gigabyte of symbols.
    rt=$(readelf -d "${BIN:-}" 2>/dev/null | grep -oE 'lib(tsan|asan)\.so' | head -1)
    case "$rt" in
        libtsan.so) echo tsan ;;
        libasan.so) echo asan ;;
        *) case "${BIN:-}" in
               */bin/Debug/*|*/bin/Coverage/*) echo debug ;;
               *) echo release ;;
           esac ;;
    esac
}

build_sanitized() {
    case "$(build_kind)" in asan|tsan) return 0 ;; *) return 1 ;; esac
}

build_cost() {
    case "$(build_kind)" in asan|tsan) echo 64 ;; debug) echo 8 ;; *) echo 1 ;; esac
}

build_sanflags() {
    case "$(build_kind)" in
        asan)  echo "-fsanitize=address,undefined" ;;
        tsan)  echo "-fsanitize=thread" ;;
    esac
}

build_defers_signals() {
    [ "$(build_kind)" = tsan ]
}
