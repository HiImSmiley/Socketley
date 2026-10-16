# Building a program against the SDK -- only ever sourced, since run_all.sh
# globs test_*.sh.

# A sanitizer link of the SDK holds about 1.2 GiB, and seven files link one
# beside the others: five at once passed the cgroup's memory.high and each took
# five minutes in reclaim, so under a sanitizer one machine-wide lock lets one
# build run at a time.
sdk_cxx() {   # g++ arguments -> g++'s exit, with -std=c++23 and $SANFLAGS
    if [ -n "${SANFLAGS:-}" ]; then
        flock /tmp/socketley-sdk-build.lock g++ -std=c++23 $SANFLAGS "$@"
    else
        g++ -std=c++23 "$@"
    fi
}
