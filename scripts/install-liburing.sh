#!/usr/bin/env bash
#
# Install a liburing socketley can actually be built against.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
# The distro's liburing 2.5 does not compile this tree, and there is one copy
# of the fix because it had been four copies of the same three apt lines that
# came to disagree with the Dockerfile -- so every caller bumps LIBURING_TAG
# here and nowhere else.
# ─── USE ────────────────────────────────────────────────────────────────────
# Installs the pinned tag, with LIBURING_TAG and LIBURING_JOBS as overrides,
# and idempotent: if the installed headers already satisfy the floor it costs a
# version check and exits 0.
set -euo pipefail

# The tested version; the supported floor is lower and is declared in
# socketley/shared/loop/liburing_version.h.
LIBURING_TAG="${LIBURING_TAG:-liburing-2.15}"
LIBURING_JOBS="${LIBURING_JOBS:-$(nproc)}"

# Kept in step with the minimums in socketley/shared/loop/liburing_version.h, which
# the compiler is the authority on -- this is only so the script can skip work
# already done.
MIN_MAJOR=2
MIN_MINOR=7

log() { printf '%s\n' "install-liburing: $*" >&2; }

# CI runners are a non-root user with passwordless sudo and the Docker builder
# is root with no sudo binary, so both have to work.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    log "not root and no sudo available"
    exit 1
fi

# ─── Is a good enough one already here? ─────────────────────────────────────
# The two macros are read out of the installed header rather than from the
# package manager, because this project's own box reports 2.5 to dpkg while
# carrying 2.14 headers -- and the header is what the compiler will read.
version_header() {
    for d in /usr/include /usr/local/include; do
        if [ -r "$d/liburing/io_uring_version.h" ]; then
            printf '%s\n' "$d/liburing/io_uring_version.h"
            return 0
        fi
    done
    return 1
}

installed_is_new_enough() {
    local hdr major minor
    hdr="$(version_header)" || return 1
    major="$(sed -n 's/^#define IO_URING_VERSION_MAJOR \([0-9]\+\).*/\1/p' "$hdr")"
    minor="$(sed -n 's/^#define IO_URING_VERSION_MINOR \([0-9]\+\).*/\1/p' "$hdr")"
    [ -n "$major" ] && [ -n "$minor" ] || return 1
    log "found liburing $major.$minor at $hdr"
    # Compared as two integers deliberately, because 2.5 is older than 2.15 and
    # any comparison that reads them as decimals concludes the opposite.
    if [ "$major" -gt "$MIN_MAJOR" ]; then return 0; fi
    if [ "$major" -eq "$MIN_MAJOR" ] && [ "$minor" -ge "$MIN_MINOR" ]; then return 0; fi
    return 1
}

if [ "${LIBURING_FORCE:-0}" != "1" ] && installed_is_new_enough; then
    log "already >= $MIN_MAJOR.$MIN_MINOR, nothing to do"
    exit 0
fi

log "installing $LIBURING_TAG from source (need >= $MIN_MAJOR.$MIN_MINOR)"

# --libdir is the multiarch directory the loader searches first, because
# installing beside the distro's copy rather than over it produces a build that
# compiles against the new headers and runs against the old shared object --
# and gcc knows the triplet, which hardcoding would get wrong on an arm runner.
MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
if [ -n "$MULTIARCH" ]; then
    LIBDIR="/usr/lib/$MULTIARCH"
else
    LIBDIR="/usr/lib"
fi

SRC="$(mktemp -d)"
trap 'rm -rf "$SRC"' EXIT

git clone --depth 1 --branch "$LIBURING_TAG" \
    https://github.com/axboe/liburing "$SRC/liburing"

cd "$SRC/liburing"
./configure --prefix=/usr --libdir="$LIBDIR"

# `library` rather than the default `all`, which also builds ~250 test binaries
# this project never runs, and `install` does not depend on it.
make -j"$LIBURING_JOBS" library
$SUDO make install

# The loader cache has to learn about the new shared object, or a binary linked
# against it finds the distro's on the next exec.
$SUDO ldconfig || true

# ─── Say what actually landed ───────────────────────────────────────────────
# `make install` exiting 0 is not the same as the headers a compiler picks up
# having changed, since an older liburing in /usr/local/include takes
# precedence on some toolchains -- so the check is a re-read rather than a
# trust.
if ! installed_is_new_enough; then
    log "ERROR: installed $LIBURING_TAG but the headers on the include path are still too old"
    exit 1
fi
log "ok: $LIBURING_TAG installed into /usr (libdir $LIBDIR)"
