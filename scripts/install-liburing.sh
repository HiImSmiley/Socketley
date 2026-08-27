#!/usr/bin/env bash
#
# Install a liburing socketley can actually be built against.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# `apt install liburing-dev` on Ubuntu 24.04 installs liburing 2.5 (April 2024).
# Since 5593ee1 (2026-07-28) the event loop names IORING_SETUP_NO_SQARRAY and
# io_uring_register_napi (both 2.6) and IORING_ACCEPT_POLL_FIRST (2.7), so 2.5
# does not compile this tree — not "compiles with warnings", does not compile.
# CI installed it on every run and was red from that day until 2026-08-01, the
# README told contributors to install it, and the release job built with it.
#
# There is one copy of the fix and this is it.  It had been four copies of the
# same three apt lines, which is how they came to disagree with the Dockerfile
# in the first place: the Dockerfile was corrected on the day the break landed
# and the four workflow/README sites were not, because nothing tied them
# together.  Every caller now bumps LIBURING_TAG here and nowhere else.
#
# ─── USE ────────────────────────────────────────────────────────────────────
#
#   bash scripts/install-liburing.sh                 # install the pinned tag
#   LIBURING_TAG=liburing-2.14 bash scripts/...      # override the pin
#   LIBURING_JOBS=4 bash scripts/...                 # override parallelism
#
# Idempotent: if the headers already installed satisfy the floor it does
# nothing, so re-running it in a job that already has a good liburing — or on a
# development box that built one by hand — costs a version check and exits 0.
#
set -euo pipefail

# The tested version.  The *supported* floor is lower and is declared in
# socketley/shared/liburing_version.h; see that file for why the two differ.
LIBURING_TAG="${LIBURING_TAG:-liburing-2.15}"
LIBURING_JOBS="${LIBURING_JOBS:-$(nproc)}"

# Keep in step with SOCKETLEY_LIBURING_MIN_{MAJOR,MINOR} in
# socketley/shared/liburing_version.h.  The compiler is the authority; this is
# only so the script can skip work that is already done.
MIN_MAJOR=2
MIN_MINOR=7

log() { printf '%s\n' "install-liburing: $*" >&2; }

# CI runners are a non-root user with passwordless sudo; the Docker builder is
# root with no sudo binary installed.  Both have to work.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    log "not root and no sudo available"
    exit 1
fi

# ─── Is a good enough one already here? ─────────────────────────────────────
#
# Read the two macros out of the installed header rather than trusting the
# package manager: this project's own development box reports liburing-dev
# 2.5-1build1 to dpkg while carrying 2.14 headers, so `dpkg -l` is not evidence
# of anything.  The header is what the compiler will read, so the header is what
# gets asked.
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
    # Compared as two integers, deliberately.  2.5 is older than 2.15 and any
    # comparison that reads them as decimals concludes the opposite.
    if [ "$major" -gt "$MIN_MAJOR" ]; then return 0; fi
    if [ "$major" -eq "$MIN_MAJOR" ] && [ "$minor" -ge "$MIN_MINOR" ]; then return 0; fi
    return 1
}

if [ "${LIBURING_FORCE:-0}" != "1" ] && installed_is_new_enough; then
    log "already >= $MIN_MAJOR.$MIN_MINOR, nothing to do"
    exit 0
fi

log "installing $LIBURING_TAG from source (need >= $MIN_MAJOR.$MIN_MINOR)"

# ─── Build and install over the distro's copy ───────────────────────────────
#
# --libdir is the multiarch directory, not the default /usr/lib.  The loader
# searches the multiarch path first, so a liburing installed beside the distro's
# rather than over it produces a build that compiles against the new headers and
# runs against the old shared object — the same version skew as before, moved to
# where it fails at runtime instead of at compile time.  gcc knows the triplet;
# hardcoding x86_64-linux-gnu would quietly do the wrong thing on an arm runner.
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

# `library`, not the default `all`.  `all` also builds liburing's ~250 test
# binaries and its examples, none of which is installed and none of which this
# project runs — several minutes of compiling, in nine CI jobs and in the image
# layer.  `install` does not depend on `all` (checked from 2.7 through 2.15), so
# the library alone is both sufficient and what gets copied out.
make -j"$LIBURING_JOBS" library
$SUDO make install

# The loader cache has to learn about the new shared object, or a binary linked
# against it finds the distro's on the next exec.
$SUDO ldconfig || true

# ─── Say what actually landed ───────────────────────────────────────────────
#
# `make install` exiting 0 is not the same as the headers a compiler will pick
# up having changed: an older liburing left in /usr/local/include takes
# precedence over /usr/include on some toolchains.  So the check is a re-read,
# not a trust.
if ! installed_is_new_enough; then
    log "ERROR: installed $LIBURING_TAG but the headers on the include path are still too old"
    exit 1
fi
log "ok: $LIBURING_TAG installed into /usr (libdir $LIBDIR)"
