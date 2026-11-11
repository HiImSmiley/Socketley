# Socketley

A Linux daemon and CLI that runs network services as runtimes, in a Docker-like style: servers, clients, proxies,
Redis-compatible caches, websites with Lua pages and PHP, S3 storage, DNS, sign-in, documents, MQTT, mail, tunnels,
metrics and MCP servers. Each runtime is one command away, runs in a supervised worker process of its own on an
io_uring event loop, can be scripted in Lua, and comes back after a reboot.

**[Documentation](https://hiimsmiley.github.io/Socketley/)** — every runtime, [flag](https://hiimsmiley.github.io/Socketley/#/flags), [Lua function](https://hiimsmiley.github.io/Socketley/#/lua) and
[benchmark](https://hiimsmiley.github.io/Socketley/#/bench).

```bash
socketley create server chat -p 9000 -s      # a TCP/WebSocket server, started
socketley create cache kv -p 6379 --resp -s  # speaks Redis's protocol
socketley create web site -p 8080 --root /srv/site --lua-pages -s
socketley ls
```

## Install

On Debian or Ubuntu, the newest release:

```bash
curl -fsSL https://raw.githubusercontent.com/HiImSmiley/Socketley/main/install.sh | sudo sh
```

It asks before installing each missing dependency and stops, changing nothing, where the package does not fit the
machine. Later releases come with `sudo socketley update` (`--check` only looks).

From a clone, on any distribution with a 5.19+ kernel and GCC 12+:

```bash
git clone https://github.com/HiImSmiley/Socketley
cd Socketley
bash scripts/install-from-source.sh  # builds and installs; --dry-run shows each step first
bash scripts/update.sh               # later: the newest commit, built and swapped in
```

The daemon then runs as the systemd service `socketley`. Root and members of the `socketley` group reach it:
`sudo usermod -aG socketley $USER`, then log in again.

## Runtimes

| Type | What it is |
|---|---|
| [`server`](https://hiimsmiley.github.io/Socketley/#/rt/server) | TCP, UDP and WebSocket on one port, with `--http` for the page that talks to it |
| [`client`](https://hiimsmiley.github.io/Socketley/#/rt/client) | Outbound connections that reconnect, for consumers, load and bridges |
| [`proxy`](https://hiimsmiley.github.io/Socketley/#/rt/proxy) | HTTP and TCP reverse proxy, and the entrance that ends TLS and HTTP/2 for every `--domain` |
| [`cache`](https://hiimsmiley.github.io/Socketley/#/rt/cache) | In-memory store with Redis's protocol, streams, pub/sub, persistence, replication and sharding |
| [`web`](https://hiimsmiley.github.io/Socketley/#/rt/web) | A site of files, its `.lua` pages with `--lua-pages`, and its `.php` files through php-fpm |
| [`storage`](https://hiimsmiley.github.io/Socketley/#/rt/storage) | S3 for unmodified clients, with a web interface for files, links, media and git |
| [`sync`](https://hiimsmiley.github.io/Socketley/#/rt/sync) | A directory carried to a storage, out, in or both ways |
| [`idp`](https://hiimsmiley.github.io/Socketley/#/rt/idp) | OpenID Connect sign-in for everything else here |
| [`db`](https://hiimsmiley.github.io/Socketley/#/rt/db) | JSON documents with indexed queries, transactions and a change stream |
| [`dns`](https://hiimsmiley.github.io/Socketley/#/rt/dns) | Authoritative DNS for zone files and for the runtimes' names |
| [`mqtt`](https://hiimsmiley.github.io/Socketley/#/rt/mqtt) | MQTT 3.1 to 5.0 on TCP, TLS and WebSocket |
| [`mail`](https://hiimsmiley.github.io/Socketley/#/rt/mail) | SMTP, IMAP, POP3 and JMAP, with webmail |
| [`tunnel`](https://hiimsmiley.github.io/Socketley/#/rt/tunnel) | A machine with no address of its own reached through an edge |
| [`metrics`](https://hiimsmiley.github.io/Socketley/#/rt/metrics) | Prometheus-compatible collection and storage |
| [`mcp`](https://hiimsmiley.github.io/Socketley/#/rt/mcp) | An MCP server whose tools are Lua functions |

`socketley --help` and `man socketley` cover the same ground as the documentation, offline.

## In your own program

Every runtime also runs inside an application, with no daemon ([reference](https://hiimsmiley.github.io/Socketley/#/man/c-sdk)): the `socketley-dev` package carries `libsocketley.so`,
the C header `socketley/capi.h` and a pkg-config file, and [sdk/rust](sdk/rust) and [sdk/node](sdk/node) wrap it for
Rust and Node. A program with its own website, API, cache and MCP tools for a model:

```js
const { Engine } = require('socketley');

const engine = new Engine();  // one thread and one io_uring ring for all of its runtimes
const kv = engine.runtime('cache', 'kv', '-p 8081').start();

const site = engine.runtime('web', 'site', '-p 8080 --root /srv/site');
site.handle('/api/count', () => kv.command('incr count'));
site.start();

const tools = engine.runtime('mcp', 'tools', '-p 9600 --anonymous');
tools.tool('count', { description: 'How often /api/count was asked.' }, () => kv.command('get count'));
tools.start();
```

A runtime takes the same flags as `socketley create`, and a C program builds with
`cc app.c $(pkg-config --cflags --libs socketley)`.

## A research project

Socketley is about the technology more than about a product. It asks how far a handful of ideas carry when they are
followed all the way through: one io_uring event loop per process, owned by a single thread, every service a
runtime of the same binary, and each runtime a worker process of its own on such a loop.

## How it is tested

Most of the work on Socketley is proving it. Nothing that touches the engine lands on `main` before the whole suite has
passed on that exact tree, in two builds, and that has happened hundreds of times:

- **765 test files and more than 13,000 checks per run.** 687 integration tests start a real daemon and drive it over
  real sockets with real clients; beside them run 64 unit test programs and 28 fuzz targets over a corpus of more than
  a thousand inputs.
- **Every run twice.** Once as the optimised release build, and once under AddressSanitizer and
  UndefinedBehaviorSanitizer with recovery off, where a single report fails the run. Both builds compile with zero
  warnings.
- **A test counts once it has failed.** A new test is put against the defect it is about before it is trusted; a test
  that passes with the bug still in measures nothing.
- **Benchmarks against the established tool for each job**, such as Redis for the cache, measured A/B and interleaved
  on a quiet machine, with the CPU spent beside the latency.
- **Every release in clean Ubuntu and Debian containers**, where it creates all 15 runtimes, comes back from a restart
  with its runtimes intact, and serves apps in C, Rust and Node built against the SDK while they are under load.

## About Me and the Project

Hi, I'm Smiley. This project was born out of a university module called Networked Systems, where I spent a lot of time working with Docker, proxies, sockets, caches, and the protocols that tie them all together. While reading into virtual threads, I stumbled upon Linux's io_uring interface and was immediately hooked.

What bothered me was how many moving parts you need to set up a proper networked system - separate tools for servers, proxies, caches, each with their own config and lifecycle. My goal with Socketley was to combine all of that into something simpler and more unified, at least in my opinion and hope.

I've been programming for over a decade, but this project pushed me into entirely new territory: io_uring internals, protocol design, benchmarking methodology, hot-path optimization, and rapid prototyping. It's also been my first deep dive into AI-assisted development with Claude Code, which has been a genuinely exciting experiment in seeing how far that workflow can go.

It's been an amazing journey so far, and I hope others see the same potential in this project that I do. I'll keep building with the same mindset and love I started with.

## More

- [CHANGELOG.md](CHANGELOG.md) — what changed, release by release
- [examples/](examples/) — ready-to-run setups, from an echo server to a cluster

## License

Apache 2.0 — see [LICENSE](LICENSE). The components socketley vendors or links, all under permissive licences, are
listed with their licence texts in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
