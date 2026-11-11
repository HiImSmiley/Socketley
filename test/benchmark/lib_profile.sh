#!/usr/bin/env bash
# Profiling on this box — the parts that are not about any one runtime.
#
# profile_cache_commands.sh worked out what it takes to get a profile out of
# this machine at all, and every one of the four steps below is a run that
# produced a complete, plausible, entirely worthless table before somebody
# looked.  A second profiler for the proxy needs exactly the same four, so they
# live here: two copies of this drift, and the one that drifts is the one
# nobody is reading when it reports zeroes as a finding.
#
# ─── THE FOUR WAYS A PROFILE HERE COMES BACK BLIND ──────────────────────────
#
#   THE WRAPPER.  `perf` on this box is a shim that refuses when the running
#   kernel has no matching linux-tools package, which is the normal state after
#   a kernel bump.  The binary underneath is fine, so it is found directly.
#
#   perf_event_paranoid.  The hardened Ubuntu default is 4, which denies
#   profiling even your own process, and fails with rc=255 and no useful
#   message.  kptr_restrict is what makes kernel symbols resolve rather than
#   printing bare addresses.  Both are lost on reboot.
#
#   A STRIPPED BINARY.  Release links with -s, so perf resolves nothing and the
#   report is a list of hex offsets that sums to zero under any grouping.  This
#   links its own copy WITH symbols, into its own directory, and still calls it
#   `socketley` so a cleanup sweep matching on the process name can find it.
#
#   ROOT-OWNED perf.data.  perf record runs under sudo, so the file lands 0600
#   root; read back as the invoking user it fails, awk sums an empty stream, and
#   every cell reports 0.0%.  That is why the report is read under sudo too, and
#   why every caller must check that a cell's shares sum to more than nothing.
#
# Hardware counters are not exposed to this guest -- `perf stat -e cycles` says
# `<not supported>` -- so everything here is `cpu-clock`, a software event.  It
# gives a share of time.  It cannot give IPC or cache misses.  A share survives
# the host's governor moving under us, which an absolute number does not.

# The perf binary, past the wrapper.
profile_find_perf() {
    local p=${PERF:-}
    if [ -z "$p" ]; then
        p=$(ls -d /usr/lib/linux-tools/*/perf 2>/dev/null | tail -1)
        [ -z "$p" ] && p=$(command -v perf)
    fi
    [ -x "${p:-}" ] || return 1
    printf '%s' "$p"
}

# Raises paranoid if it can, and fails loudly rather than sampling nothing.
profile_require_perf() {
    local par
    par=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
    if [ "$par" -gt 1 ]; then
        sudo -n sysctl -q -w kernel.perf_event_paranoid=1 kernel.kptr_restrict=0 2>/dev/null
        par=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
    fi
    [ "$par" -le 1 ]
}

# A socketley perf can read, at bin/Profile/socketley.
#
# Same objects, same optimisation, same LTO -- only the strip flag differs, so
# what is measured is the shipped code and not a debug build.  The tree is put
# back the way it is packaged afterwards, and the stripped Release rebuilt, so
# nobody inherits an unstripped Release from having profiled once.
profile_symbol_build() {   # ROOT LOGFILE -> path on stdout
    local root=$1 log=$2
    local bin=$root/bin/Profile/socketley
    if [ -x "$bin" ] && [ ! "$root/bin/Release/socketley" -nt "$bin" ]; then
        printf '%s' "$bin"; return 0
    fi
    (
        cd "$root" || exit 2
        ./scripts/premake5 gmake2 >/dev/null 2>&1 || exit 2
        sed -i 's/-m64 -s -flto=auto/-m64 -flto=auto/' make/socketley.make
        rm -f "$root/bin/Release/socketley"
        if ! make -C make config=release_x64 -j"$(nproc)" >"$log" 2>&1; then
            ./scripts/premake5 gmake2 >/dev/null 2>&1
            exit 2
        fi
        mkdir -p "$root/bin/Profile"
        cp "$root/bin/Release/socketley" "$bin"
        ./scripts/premake5 gmake2 >/dev/null 2>&1
        rm -f "$root/bin/Release/socketley"
        make -C make config=release_x64 -j"$(nproc)" >>"$log" 2>&1 || exit 2
    ) || return 1
    file "$bin" | grep -q 'not stripped' || return 1
    printf '%s' "$bin"
}

# Sums a report by where the sample landed: kernel, the named binary, or a
# library, and names the two fattest symbols.
#
# --percent-limit 0 because a ranking built from a truncated report puts a case
# with one fat symbol above a case with fifty thin ones.  Under sudo because the
# data file is root's; see the header.
profile_parse_report() {   # PERF FILE OWN_DSO -> "kernel ours libs top1 pct1 top2 pct2"
    sudo -n "$1" report -i "$2" --stdio --no-children -g none --percent-limit 0 2>/dev/null \
    | awk -v own="$3" '
        /^[[:space:]]*[0-9.]+%/ {
            pct = $1; sub(/%/, "", pct)
            dso = $3; sym = ""
            for (i = 5; i <= NF; i++) sym = sym (i > 5 ? " " : "") $i
            # Cut at the argument list and squeeze what is left: a demangled C++
            # name carries spaces, and a space in a field shifts every column
            # behind it in the tables built from this line.
            sub(/\(.*/, "", sym); gsub(/[ \t]+/, "_", sym)
            # A demangled template instantiation runs to eight hundred
            # characters, which is one table cell nobody can read.  The tail is
            # the interesting half of a C++ name, so the middle goes.
            if (length(sym) > 64)
                sym = substr(sym, 1, 24) "..." substr(sym, length(sym) - 33)
            if (dso ~ /kallsyms/)  { k += pct }
            else if (dso == own)   { o += pct; if (pct > b1p) { b2 = b1; b2p = b1p; b1 = sym; b1p = pct }
                                     else if (pct > b2p)     { b2 = sym; b2p = pct } }
            else                   { l += pct; if (pct > b1p) { b2 = b1; b2p = b1p; b1 = sym "@" dso; b1p = pct }
                                     else if (pct > b2p)     { b2 = sym "@" dso; b2p = pct } }
        }
        END { printf "%.1f %.1f %.1f %s %.1f %s %.1f",
                     k, o, l, (b1 == "" ? "-" : b1), b1p, (b2 == "" ? "-" : b2), b2p }'
}
