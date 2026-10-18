# Multi-stage build for Socketley
#
# Build:  docker build -t socketley .
# Run:    docker run --rm socketley daemon
#
# ─── ON LIBURING: WHY IT IS BUILT HERE INSTEAD OF INSTALLED ──────────────────
#
# This image used to `apt-get install liburing-dev` and that stopped producing a
# binary on 2026-07-28.  Ubuntu 24.04 ships liburing 2.5, and since 5593ee1 the
# event loop uses three things that release does not have at all:
#
#     IORING_SETUP_NO_SQARRAY     event_loop.cpp:853
#     IORING_ACCEPT_POLL_FIRST    event_loop.cpp:164, 1345, 1369, 1375
#     io_uring_register_napi      event_loop.cpp:2078  (and struct io_uring_napi)
#
# so the build stops at event_loop.cpp and no image is produced.  Measured on a
# clean ubuntu:24.04 with liburing-dev 2.5-1build1, that is seven errors: six
# `not declared in this scope`, plus `io_uring_napi` as an incomplete type.  None
# of them mentions liburing or a version.  There is nothing to probe or fall back
# to at compile time — the identifiers are simply not declared — so the
# dependency is a hard floor, not a capability the daemon negotiates at run time
# the way it negotiates opcodes.  socketley/shared/loop/liburing_version.h now states
# that floor before any of this is reached.
#
# This file used to be the only place that had been corrected, and it said so:
# README.md still told contributors to `apt install liburing-dev`, and ci.yml,
# release.yml and nightly.yml still installed it on ubuntu-24.04 runners.  All of
# those now call scripts/install-liburing.sh, and so does this image — the source
# build that used to be written out here in full lives in that script, because
# four hand-copied versions of it is precisely how this file came to be right
# while the other four were wrong.  The pinned tag lives there and only there.
#
# ─── ON PARALLELISM: WHY THE DEFAULT IS 1 ───────────────────────────────────
#
# The Release configuration compiles and links with `-flto=auto`, and `auto`
# means GCC fans the link itself out to one job per CPU.  `make -jN` therefore
# does not cost N heavy processes, it costs up to N link steps each running nproc
# LTO jobs, and a single cc1plus on this tree has been measured at 1.1 GB
# resident.  On a four-core machine `-j$(nproc)` — which is what this line used
# to say — is how you ask for sixteen of those.
#
# A container build has no swap to hide that in and the OOM reaper's answer
# inside BuildKit is `exit code: 2` with no mention of memory anywhere, which is
# a bad half-hour for whoever meets it first.  So the default is the value that
# cannot do it: one make job, LTO still parallel underneath it.  Machines with
# memory to spare say so explicitly and get the whole build:
#
#     docker build --build-arg BUILD_JOBS="$(nproc)" -t socketley .
#
ARG BUILD_JOBS=1
# Empty on purpose: scripts/install-liburing.sh holds the pin, and an unset value
# there means "use it".  A second default here would be a second number to keep
# in step with the first.  Override to build the image against another release:
#     docker build --build-arg LIBURING_TAG=liburing-2.14 -t socketley .
ARG LIBURING_TAG=

# ─── Builder ───────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder
ARG BUILD_JOBS
ARG LIBURING_TAG

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev cmake libluajit-5.1-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copied on its own, before the tree, so that editing socketley source does not
# invalidate this layer — a clone and a library build have no reason to repeat
# because a .cpp changed.  The script installs over the distro's headers and
# shared object rather than beside them, and explains there why that matters.
COPY scripts/install-liburing.sh /tmp/install-liburing.sh
RUN LIBURING_TAG="$LIBURING_TAG" LIBURING_JOBS="$BUILD_JOBS" \
        bash /tmp/install-liburing.sh \
    && rm -f /tmp/install-liburing.sh

WORKDIR /src
COPY . .

# The static archives this tree links but does not track.  This line used to say
# "same trick as CI" and copy libluajit-5.1.a by hand -- one of nine hand-written
# copies of the same three commands, and one of the two that had no error check.
# scripts/install-liburing.sh already ended that argument for the other archive.
RUN bash bin/build-thirdparty.sh luajit && bash bin/build-thirdparty.sh http3

RUN ./bin/premake5 gmake2 && cd make && make config=release_x64 -j"$BUILD_JOBS"

# A build that "succeeded" without producing a binary is the failure this image
# used to pass along to whoever ran the container.
RUN test -x bin/Release/socketley

# ─── Runtime ───────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/socketley /var/lib/socketley/runtimes

# liburing comes from the builder for the same reason it is built there: the
# package archive has no version this binary can be loaded against.
COPY --from=builder /usr/lib/x86_64-linux-gnu/liburing.so.2* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /src/bin/Release/socketley /usr/bin/socketley

# The Release configuration builds with -march=native, so this image is only
# portable to machines with the CPU features of the one that built it.  Fine for
# a test cluster and for a local run; not a thing to push to a registry.
RUN socketley version

ENTRYPOINT ["socketley"]
