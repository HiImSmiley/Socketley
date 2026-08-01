# Multi-stage build for Socketley
#
# Build:  docker build -t socketley .
# Run:    docker run --rm socketley daemon
#
# ─── ON LIBURING: WHY IT IS BUILT HERE INSTEAD OF INSTALLED ──────────────────
#
# This image used to `apt-get install liburing-dev` and that stopped producing a
# binary on 2026-07-28.  Ubuntu 24.04 ships liburing 2.5, and since 6c5c110 the
# event loop uses three things that release does not have at all:
#
#     IORING_SETUP_NO_SQARRAY     event_loop.cpp:853
#     IORING_ACCEPT_POLL_FIRST    event_loop.cpp:164, 1345, 1369, 1375
#     io_uring_register_napi      event_loop.cpp:2078  (and struct io_uring_napi)
#
# so the build stops at event_loop.cpp with five errors and no image is
# produced.  There is nothing to probe or fall back to at compile time — the
# identifiers are simply not declared — so the dependency is a hard floor, not a
# capability the daemon negotiates at run time the way it negotiates opcodes.
#
# Building it here pins the floor to something the image can state.  It does not
# fix the same problem anywhere else: README.md still tells a contributor to
# `apt install liburing-dev`, and ci.yml and release.yml still install it on
# ubuntu-24.04 runners, all of which are the version this file just stopped
# using.  A machine that builds socketley today has a hand-installed liburing on
# it and does not know it.
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
ARG LIBURING_TAG=liburing-2.14

# ─── Builder ───────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder
ARG BUILD_JOBS
ARG LIBURING_TAG

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libluajit-5.1-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Over the distro's headers and shared object, not beside them: the loader looks
# in the multiarch directory first, so a liburing left in /usr/lib would compile
# against 2.14 and run against 2.5.
RUN git clone --depth 1 --branch "$LIBURING_TAG" \
        https://github.com/axboe/liburing /tmp/liburing \
    && cd /tmp/liburing \
    && ./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu \
    && make -j"$BUILD_JOBS" \
    && make install \
    && rm -rf /tmp/liburing

WORKDIR /src
COPY . .

# Copy system libluajit into thirdparty (same trick as CI)
RUN cp "$(find /usr/lib -name 'libluajit-5.1.a' | head -1)" thirdparty/luajit/libluajit.a

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
