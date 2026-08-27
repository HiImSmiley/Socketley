# Third-Party Notices

Socketley is licensed under the Apache License 2.0 (see `LICENSE`).

It vendors, links against, or builds with the components listed below.  Each is
distributed under its own licence.  None of them is Apache-2.0, and none is
covered by Socketley's own licence.

Two separate questions decide what has to accompany what, and they have
different answers here:

- **What this repository redistributes** — everything under `thirdparty/`,
  because those files are checked in.  Their licence text ships with the source.
- **What the binary carries** — only what is *statically* linked.  `ldd` is the
  authority for that, not this document; the table below records what it said.

## Vendored under `thirdparty/`

Checked into this repository and therefore redistributed with the source.

| Component | Version | Licence | Licence text | Linked | Upstream |
|---|---|---|---|---|---|
| **LuaJIT** | 2.1 (Lua 5.1.4 API) | MIT | `thirdparty/luajit/COPYRIGHT` | **static** | https://luajit.org/ |
| **liburing** | 2.15 | MIT | `thirdparty/liburing/LICENSE` | dynamic | https://github.com/axboe/liburing |
| **sol2** | 3.5.0 | MIT | `thirdparty/sol2/LICENSE.txt` | header-only | https://github.com/ThePhD/sol2 |
| **doctest** | 2.4.12 | MIT | `thirdparty/doctest/LICENSE.txt` | header-only, tests only | https://github.com/doctest/doctest |

**LuaJIT is the one component compiled into the shipped binary.**  It is linked
from `thirdparty/luajit/libluajit.a`, and MIT requires its copyright notice and
permission notice to accompany any distribution of the software or a
substantial portion of it.  A *binary* release of Socketley must therefore carry
the LuaJIT notice; the `.deb` built by `packaging/build-deb.sh` installs all of
these to `/usr/share/doc/socketley/copyright`.

**sol2 is header-only** — it is compiled into the binary as source, which is the
same obligation as static linking.  Its notice ships too.

**liburing is linked dynamically**, despite living under `thirdparty/`.  Only
its headers are vendored; the shared object comes from the host, which is why
the `.deb` declares `Depends: liburing2 (>= 2.6)` rather than shipping it.
Verified rather than assumed:

```
$ ldd bin/Release/socketley | grep uring
        liburing.so.2 => /lib/x86_64-linux-gnu/liburing.so.2
```

**doctest is test-only.**  It is compiled into the unit test binaries under
`bin/<config>/test_*`, and is in neither the daemon, the CLI, nor the `.deb`.
It is listed here because it is vendored, and so redistributed with the source.

### A note on `liburing/liburing/io_uring.h`

That one file is the kernel UAPI header and carries a different SPDX line from
the rest of liburing:

```
SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT
```

It is a dual licence and Socketley takes it **under the MIT arm**, which is what
lets this project be Apache-2.0.  The GPL-2.0 text is kept at
`thirdparty/liburing/COPYING.GPL` and the syscall note at
`thirdparty/liburing/COPYING`, so the other arm of the choice is documented —
not because Socketley exercises it.

## Linked dynamically, not redistributed

Resolved from the host at build and run time, and declared as package
dependencies rather than shipped.

| Component | Version built against | Licence |
|---|---|---|
| **OpenSSL** (libssl, libcrypto) | 3.0.13 | Apache-2.0 |
| **libstdc++** | host toolchain | GPL-3.0 with GCC Runtime Library Exception |
| **glibc** | host toolchain | LGPL-2.1-or-later |

## Build tooling, not linked

| Component | Version | Licence | Note |
|---|---|---|---|
| **premake5** | 5.0.0-beta8 | BSD-3-Clause | `bin/premake5`, generates the makefiles.  Present in no build output. |
