# Multi-stage build for Socketley
# Build:  docker build -t socketley .
# Run:    docker run --rm socketley daemon

# ─── Builder ───────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential liburing-dev libssl-dev libluajit-5.1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Copy system libluajit into thirdparty (same trick as CI)
RUN cp "$(find /usr/lib -name 'libluajit-5.1.a' | head -1)" thirdparty/luajit/libluajit.a

RUN ./bin/premake5 gmake2 && cd make && make config=release_x64 -j$(nproc)

# ─── Runtime ───────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        liburing2 libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/socketley /var/lib/socketley/runtimes

COPY --from=builder /src/bin/Release/socketley /usr/bin/socketley

ENTRYPOINT ["socketley"]
