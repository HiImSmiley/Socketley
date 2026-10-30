-- The machine's own architecture, or --arch=x64|arm64 when the makefiles are for another one.
newoption { trigger = "arch", value = "x64|arm64", description = "The architecture to build for, this machine's by default",
            allowed = { { "x64", "x86-64" }, { "arm64", "64-bit ARM" } } }
target_arch = _OPTIONS["arch"] or ((os.outputof("uname -m") or ""):match("aarch64") and "arm64" or "x64")

workspace "Socketley"
    system "linux"
    -- Sanitize = ASan + UBSan.  TSan = ThreadSanitizer, separate because the two
    -- runtimes cannot be loaded into the same process.
    --
    -- ON TSAN BEING QUIET.  The event loop is single-threaded today: one io_uring
    -- per daemon, every handler running on the same thread, so TSan is expected
    -- to report nothing at all and a clean tsan_x64 run proves very little right
    -- now.  It is here because the project is heading for one process per runtime
    -- and threads after that, and the moment the first shared structure crosses a
    -- thread boundary is exactly the moment nobody wants to also be discovering
    -- that the build does not have a TSan configuration, that the SDK archives do
    -- not build under it, and that the integration suite has never been run with
    -- it.  Standing the configuration up while it is trivially green is cheap;
    -- standing it up on the day it is needed is not.
    --
    -- Expect: tsan_x64 builds, tests pass, TSan says nothing.  If TSan ever does
    -- say something before the threading work lands, it is a genuine finding —
    -- most likely a signal handler or a std::atomic used across the daemon's
    -- fork boundary — and not a false positive to be suppressed.
    configurations { "Debug", "Dev", "Release", "Sanitize", "TSan", "Coverage" }
    -- One platform, the one being built for, so a config is release_x64 on x86-64 and release_arm64 on ARM.
    platforms { target_arch }
    filter "platforms:arm64"
        architecture "ARM64"
    filter {}
    location "make"

    -- Every project, since the SDK and the tests use event_loop.h too and a system without liburing has none.
    externalincludedirs { "thirdparty/liburing" }
    libdirs { "thirdparty/liburing" }

    -- HTTP/3: OpenSSL 3.5, ngtcp2 and nghttp3 as bin/build-thirdparty.sh http3
    -- leaves them in thirdparty/, put before the system's so every project
    -- compiles and links against the one OpenSSL, statically.  Without them the
    -- tree builds as before against the system's OpenSSL, and a storage runtime
    -- speaks HTTP/1.1 and HTTP/2 only.
    http3 = os.isfile("thirdparty/openssl/lib/libssl.a") and os.isfile("thirdparty/ngtcp2/lib/libngtcp2.a")
        and os.isfile("thirdparty/ngtcp2/lib/libngtcp2_crypto_ossl.a") and os.isfile("thirdparty/nghttp3/lib/libnghttp3.a")
    -- The TLS libraries a project links, the QUIC ones first when HTTP/3 is built in, since a static archive is
    -- searched once, in order.
    function tls_libs()
        if http3 then
            return { "ngtcp2_crypto_ossl", "ngtcp2", "nghttp3", "ssl", "crypto" }
        end
        return { "ssl", "crypto" }
    end
    if http3 then
        includedirs { "thirdparty/openssl/include", "thirdparty/ngtcp2/include", "thirdparty/nghttp3/include" }
        libdirs { "thirdparty/openssl/lib", "thirdparty/ngtcp2/lib", "thirdparty/nghttp3/lib" }
        defines { "SOCKETLEY_HTTP3=1" }
    end

    -- ccache when it is present.  The workflow this pays for is toggling
    -- CPPFLAGS (trace, invariants): make does not notice that change, so the
    -- objects have to be deleted and everything recompiled although no source
    -- moved.  Without a cache that is eight minutes, with one it is under a
    -- minute.  Absent ccache the variables stay empty and nothing changes.
    if os.findlib and os.outputof then
        local cc = os.outputof("command -v ccache 2>/dev/null")
        if cc and cc ~= "" then
            premake.tools.gcc.tools.cc  = "ccache gcc"
            premake.tools.gcc.tools.cxx = "ccache g++"
        end
    end

    -- Which linker Dev can actually use, asked rather than assumed.
    --
    -- This was `-fuse-ld=lld-18`, and it meant Dev did not link at all under the
    -- default toolchain: gcc rejects the versioned spelling outright
    -- ("unrecognized command-line option '-fuse-ld=lld-18'").  The unversioned
    -- spelling does not rescue it either -- gcc accepts the option and then
    -- fails with "collect2: cannot find 'ld'", because lld installs as
    -- ld.lld-18 and there is no unsuffixed ld.lld for gcc to find.  clang knows
    -- where its own lld lives and needs neither.
    --
    -- So the flag is added only when an unsuffixed ld.lld is on PATH, which is
    -- the one case every driver can resolve.  Without it Dev links with the
    -- default linker and is still the fast configuration: the speed comes from
    -- having no LTO, and lld only ever shortened what was left.
    local dev_linker = ""
    if os.outputof then
        local lld = os.outputof("command -v ld.lld 2>/dev/null")
        if lld and lld ~= "" then
            dev_linker = "-fuse-ld=lld"
        end
    end

    -- Workspace-wide Release hardening (applies to ALL projects)
    -- Dev: for iteration, tests and fuzzing.  No LTO, because LTO runs at every
    -- link no matter how much came out of the cache, and it is half the eight
    -- minutes.  NOT a replacement for Release: both crashes found on 2026-07-30
    -- reproduced only in the Release build and neither appeared in Debug, so a
    -- change is verified against Release or it is not verified.
    filter "configurations:Dev"
        optimize "On"
        symbols "On"
        buildoptions { "-fstack-protector-strong", "-march=native" }
        linkoptions { dev_linker, "-Wl,--as-needed" }
    filter {}

    -- ─── Release is the configuration that gets PACKAGED ────────────────────
    --
    -- packaging/build-deb.sh refuses to run without `make config=release_x64`,
    -- so whatever is set here ends up in socketley_*_amd64.deb — and a .deb
    -- tagged amd64 promises to run on any x86-64.
    --
    -- It was built with -march=native, which lets the compiler use every
    -- instruction the BUILD machine happens to have.  A package built on a
    -- recent host then dies with SIGILL on an older one, not at the feature
    -- that needed the instruction but wherever the code path is first reached.
    --
    -- x86-64-v2 is the floor: SSE4.2 and POPCNT, which is every x86-64 CPU
    -- since about 2009.  v3 (AVX2, ~2013) is a defensible choice too and is
    -- measurably faster for the masking in ws_protocol.h — but it is a decision
    -- about which machines the package supports, not a compiler detail, so it
    -- is written here as one line to change rather than inferred from whoever
    -- ran the build.
    --
    -- -mtune stays native: it only reorders for the local CPU and emits nothing
    -- an older one cannot execute.  For a package it is a no-op worth keeping
    -- because Dev and Release then schedule alike.
    filter "configurations:Release"
        optimize "Full"
        buildoptions {
            "-flto=auto",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "-fvisibility=hidden",
            "-mtune=native"
        }
        -- ─── HOW TO CHECK THIS, IF IT IS EVER CHANGED AGAIN ─────────────────
        --
        -- Two things made the first attempt at this report the wrong answer,
        -- and both are worth knowing before touching the line above.
        --
        -- `make` does not rebuild on a flag change.  Editing this file and
        -- running make recompiles nothing, because no source moved — so the
        -- binary still carries whatever the previous flags produced and
        -- measuring it measures the old build.  `make config=release_x64 clean`
        -- first, or the number is meaningless.  That is what made -march look
        -- as though it were being ignored.
        --
        -- And the object files cannot answer the question.  With -flto they
        -- hold GIMPLE, not machine code, so `objdump -d` over them reports no
        -- AVX2 whatever the flags say — including when there is AVX2 in the
        -- final binary.  The linked binary is the only thing worth
        -- disassembling in an LTO build:
        --
        --     objdump -d bin/Release/socketley | grep -cw vinserti128
        --
        -- Measured after a clean rebuild: 26 before this change, 0 after, with
        -- -march on the compile line alone.  gcc carries each translation
        -- unit's options into the LTO backend, so repeating it here buys
        -- nothing and is left out.
        linkoptions {
            "-flto=auto",
            "-Wl,-z,relro,-z,now",
            "-Wl,--as-needed"
        }
    filter {}
    -- The floor per architecture: x86-64-v2 as above, and armv8-a, which is every 64-bit ARM CPU.
    filter { "configurations:Release", "platforms:x64" }
        buildoptions { "-march=x86-64-v2" }
    filter { "configurations:Release", "platforms:arm64" }
        buildoptions { "-march=armv8-a" }
    filter {}

    -- Workspace-wide Sanitize settings (applies to ALL projects), matching the
    -- TSan block below.
    --
    -- -fno-sanitize-recover=all is the important part: without it UBSan prints a
    -- diagnostic and carries on, so an integration run under UBSan finishes with
    -- exit status 0 and a defect buried in the log.  A CI job that goes green on
    -- a run that found something is worse than no job.
    --
    -- -fsanitize=address,undefined is here rather than only in the per-project
    -- filters because a project that forgets it does not build at all: every
    -- object in libsocketley_sdk.a carries calls to __asan_* and __ubsan_*, so an
    -- executable linked without the runtime fails with several hundred undefined
    -- references and takes the whole job down with it.  bench_conn_transfer was
    -- added without a Sanitize filter and did exactly that, which is what the
    -- nightly's "Build (Sanitize)" step was failing on.  TSan has never been able
    -- to break this way because it was always stated once, here; Sanitize was
    -- stated sixteen times, and the seventeenth project was the one that mattered.
    -- The per-project filters keep their copies — repeating a flag costs nothing,
    -- and they still carry the symbols/optimize settings that differ per project.
    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                       "-fno-sanitize-recover=all" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

    -- Workspace-wide coverage settings (applies to ALL projects).
    --
    -- Stated once here for the reason the Sanitize comment above gives: a
    -- per-project copy is a list that goes stale silently, and the project it
    -- forgets is the one whose coverage you wanted.
    --
    -- NDEBUG, not DEBUG.  Coverage is only worth reading against the semantics
    -- that ship, and sol2's safety checks follow NDEBUG — a DEBUG-flavoured
    -- report would measure branches Release never executes.
    --
    -- `optimize "Off"` because line attribution is what is being asked for; an
    -- optimised build merges and reorders lines and answers a different
    -- question.  `-fprofile-update=atomic` because the daemon forks workers and
    -- non-atomic counters race across them, which silently undercounts.
    --
    -- gcov writes .gcda at process exit, so a process killed with SIGKILL
    -- contributes nothing, and the suite does sweep daemons that way as a
    -- fallback.  That was expected to gut the runtime numbers and does not:
    -- measured over a full run, all of daemon.cpp, proxy_instance.cpp,
    -- server_instance.cpp, lua_context.cpp, event_loop.cpp and
    -- runtime_manager.cpp record data, because the tests shut their daemons
    -- down cleanly and the sweep only ever catches stragglers.  Stated because
    -- the fear is the obvious one and it is worth knowing it was checked.
    --
    -- Run it as `SOCKETLEY_CONFIG=Coverage bash test/run_all.sh`.  Running a
    -- single test file directly will NOT use this build: the files default to
    -- bin/Release/socketley and only run_all.sh exports BIN.
    filter "configurations:Coverage"
        defines { "NDEBUG" }
        symbols "On"
        optimize "Off"
        buildoptions { "--coverage", "-fprofile-update=atomic" }
        linkoptions { "--coverage" }
    filter {}

    -- Workspace-wide TSan settings (applies to ALL projects).
    filter "configurations:TSan"
        defines { "DEBUG" }
        symbols "On"
        optimize "Off"
        buildoptions { "-fsanitize=thread", "-fno-omit-frame-pointer", "-fno-sanitize-recover=all" }
        linkoptions { "-fsanitize=thread" }
    filter {}

    -- Warnings are part of the build contract: the tree must stay clean under
    -- -Wall -Wextra.  Vendored headers go through externalincludedirs below so
    -- they are included with -isystem and cannot drown out our own diagnostics.
    warnings "Extra"

project "socketley"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    cdialect "C17"
    characterset "MBCS"
    buildoptions { "-pipe" }
    multiprocessorcompile "On"

    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    externalincludedirs {
        "thirdparty/liburing",
        "thirdparty/sol2",
        "thirdparty/luajit"
    }
    includedirs {
        "socketley",
        -- The SDK's public headers, because worker_api.cpp implements one.
        "include/linux"
    }

    -- The liburing floor, checked before anything in this project compiles.
    --
    -- liburing_version.h is also included by event_loop.h and
    -- runtime_instance.h, which is what makes the check correct; force-including
    -- it here is what makes it *legible*.  Without this the first file `make`
    -- happens to reach is whatever -j ordering picked, and on a system with
    -- liburing 2.5 the build prints several unrelated-looking errors from deep
    -- inside event_loop.cpp before anyone sees the one line that names the
    -- cause.  With it, the very first translation unit compiled fails with the
    -- required and found versions and the command that fixes it.
    --
    -- It costs two #defines per TU: the header includes
    -- <liburing/io_uring_version.h>, not <liburing.h>.
    forceincludes { "socketley/shared/loop/liburing_version.h" }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    -- liburing from its archive only, so no binary loads a liburing.so other than the version it was compiled against.
    links { "luajit", "uring:static" } links(tls_libs())

    files {
        "socketley/**.h",
        "socketley/**.cpp"
    }

    filter "system:linux"
        systemversion "latest"
        defines { "SOCKETLEY_LINUX" }
    filter {}

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG", "RELEASE" }
        optimize "Full"
        staticruntime "Off"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
        optimize "Off"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── SDK: socketley_sdk static library ───

project "socketley_sdk"
    kind "StaticLib"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    externalincludedirs {
        "thirdparty/sol2",
        "thirdparty/luajit"
    }
    includedirs {
        ".",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }

    files {
        "socketley/shared/**.h",
        "socketley/shared/**.cpp",
        "socketley/runtime/**.h",
        "socketley/runtime/**.cpp",
        -- The daemon too, because an SDK binary may serve the control socket
        -- itself via <socketley/daemon.h>.
        "socketley/daemon/**.h",
        "socketley/daemon/**.cpp"
    }

    filter "system:linux"
        systemversion "latest"
        defines { "SOCKETLEY_LINUX" }
    filter {}

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG", "RELEASE" }
        optimize "Full"
        staticruntime "Off"
        -- An archive of GIMPLE links only with this gcc and compiles the whole library again at every link.
        buildoptions { "-fno-lto" }
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
        optimize "Off"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── SDK: socketley_sdk_nolua static library (SOCKETLEY_NO_LUA) ───

project "socketley_sdk_nolua"
    kind "StaticLib"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    externalincludedirs {
        "thirdparty/sol2",
        "thirdparty/luajit"
    }
    includedirs {
        ".",
        "socketley",
        "include/linux"
    }

    defines { "SOCKETLEY_NO_LUA" }

    files {
        "socketley/shared/**.h", "socketley/shared/**.cpp",
        "socketley/runtime/**.h", "socketley/runtime/**.cpp",
        "socketley/daemon/**.h", "socketley/daemon/**.cpp"
    }

    filter "system:linux"
        systemversion "latest"
        defines { "SOCKETLEY_LINUX" }
    filter {}

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG", "RELEASE" }
        optimize "Full"
        staticruntime "Off"
        -- An archive of GIMPLE links only with this gcc and compiles the whole library again at every link.
        buildoptions { "-fno-lto" }
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        staticruntime "Off"
        optimize "Off"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: command hashing ───

project "test_command_hashing"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_command_hashing.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: fd placement ───

project "test_fd_placement"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_fd_placement.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: cache store ───

project "test_cache_store"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley"
    }

    files {
        "test/unit/test_cache_store.cpp",
        "socketley/runtime/cache/cache_store.cpp",
        "socketley/runtime/cache/cache_store.h"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the key-to-slot-to-shard map ───

project "test_cache_slots"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    -- Header-only on purpose: cache_shard_map.h answers a question with no
    -- state in it, and a test that had to link the cache runtime could not
    -- assert over all 16384 slots at four shard counts without an event loop.
    files {
        "test/unit/test_cache_slots.cpp",
        "socketley/shared/ipc/cache_shard_map.h"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the two shared shard regions ───

project "test_shard_stats"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    -- Header-only, and deliberately so: the whole of shard_stats.h depends on
    -- runtime_definitions.h for one constant, so this test links no runtime and
    -- can fork freely.  A test that had to bring up an event loop could not.
    files {
        "test/unit/test_shard_stats.cpp",
        "socketley/shared/ipc/shard_stats.h",
        "socketley/shared/ipc/shard_clients.h"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: RESP parser ───

project "test_resp_parser"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_resp_parser.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: name resolver ───

project "test_name_resolver"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_name_resolver.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: flag value parsers ───
--
-- Header-only, so nothing links against the daemon: the four parsers are
-- inline in flag_handlers.h and that is the whole dependency.

project "test_flag_parsers"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_flag_parsers.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: managed runtime ───

project "test_request_channel"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_request_channel.cpp",
            "socketley/shared/ipc/request_channel.cpp",
            "socketley/shared/loop/event_loop.cpp" }

    links { "uring:static" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: managed runtime ───

project "test_managed_runtime"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_managed_runtime.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the runtime map a worker keeps ───

project "test_write_queue"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_write_queue.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the write queue's coalescing decision ───

project "test_worker_map"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_worker_map.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: WebSocket parser ───

project "test_ws_parser"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links(tls_libs())

    files { "test/unit/test_ws_parser.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: SDK control.h (header-only, no libs) ───

project "test_sdk_control"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs { "include/linux" }

    files { "test/unit/test_sdk_control.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: floor_relay ───
--
-- The same idea as floor_server one hop further out: what four handoffs cost
-- when nothing between them is ours.  See the header of test/benchmark/floor_relay.c.

project "floor_relay"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    files { "test/benchmark/floor_relay.c" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: floor_sockmap ───
--
-- The same four handoffs with the relay taken out of the loop entirely: a BPF
-- sockmap moves the bytes between the two sockets inside the kernel.  Needs
-- root to run (unprivileged BPF is off on this kernel) and answers one
-- question -- what the relay's own syscalls and copies are worth.  See the
-- header of test/benchmark/floor_sockmap.c.

project "floor_sockmap"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    files { "test/benchmark/floor_sockmap.c" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: floor_pingpong ───
--
-- One duplex exchange, AF_UNIX against loopback TCP, interleaved -- the number
-- that sizes any change moving a leg between families, and the one that shows
-- CPU and latency coming apart.  See the header of test/benchmark/floor_pingpong.c.

project "floor_pingpong"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    files { "test/benchmark/floor_pingpong.c" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: floor_server ───
--
-- The irreducible cost of the server benchmarks' traffic: accept, read, write.
-- Built alongside socketley_bench because it is only meaningful when driven by
-- it -- see the header of test/benchmark/floor_server.c.

project "floor_server"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    files { "test/benchmark/floor_server.c" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: socketley_bench ───

project "socketley_bench"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    -- ssl and crypto because the fanout category can drive TLS connections, and
    -- one client for both arms is the whole point: a separate TLS load
    -- generator would compare two clients as well as two runtimes.
    links { "pthread", "m" } links(tls_libs())

    files { "test/benchmark/bench.c" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: SDK engine headers (links libsocketley_sdk.a) ───

project "test_sdk_engine"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "include/linux",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_sdk_engine.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: SDK wrappers, functionally (links libsocketley_sdk.a) ───
-- test_sdk_engine is a compile test by design; this one starts the wrappers'
-- event loops and talks to them over real sockets.

project "test_sdk_runtime"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "include/linux",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "thirdparty/doctest",
        "socketley"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_sdk_runtime.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: SDK ws_client.h (header-only, no libs) ───

project "test_sdk_ws_client"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs { "include/linux" }

    files { "test/unit/test_sdk_ws_client.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Fuzz targets ───
--
-- Each target is one LLVMFuzzerTestOneInput.  These projects link it against
-- test/fuzz/fuzz_replay_main.cpp — a deterministic corpus replayer that needs
-- nothing but the compiler this project already builds with.  The
-- coverage-guided libFuzzer builds of the same sources are produced separately
-- by test/fuzz/build_libfuzzer.sh, which needs clang and is best-effort.
--
-- ASan+UBSan are forced on in every configuration except TSan, rather than left
-- to the Sanitize config.  A fuzz target built without sanitizers explores
-- inputs and reports nothing, which looks exactly like a target that found no
-- bugs.  The TSan exclusion is not optional: ASan and TSan cannot coexist in one
-- process, and these targets have no threads for TSan to look at anyway.
--
-- Recommended: make config=sanitize_x64 fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_response fuzz_proxy_tunnel fuzz_event_loop fuzz_http_request

local function fuzz_target_settings()
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    filter "configurations:not TSan"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                       "-fno-sanitize-recover=all" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
        symbols "On"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        optimize "Off"
    filter {}
end

-- ─── Fuzz: RESP2 command parsing (header-only, no libs) ───

project "fuzz_resp"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_resp.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: the MQTT codec and broker ───────────────────────────────────────
--
-- What every peer of an mqtt runtime reaches with its first bytes, read with
-- the broker's whole state machine behind it on four connections at once.

project "fuzz_mqtt"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_mqtt.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/mqtt/mqtt_codec.cpp",
        "socketley/runtime/mqtt/mqtt_topics.cpp",
        "socketley/runtime/mqtt/mqtt_broker.cpp",
        "socketley/runtime/mqtt/mqtt_broker_store.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: what a mail runtime reads from others ─────────────────────────────
--
-- An SMTP client's bytes, a message as IMAP parses it, its DKIM signatures,
-- address lists and aliases, quoted-printable, and a Sieve script run on a message.

project "fuzz_mail"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_mail.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/mail/smtp_session.cpp",
        "socketley/runtime/mail/mail_compose.cpp",
        "socketley/runtime/mail/mail_dkim.cpp",
        "socketley/runtime/mail/mail_mime.cpp",
        "socketley/runtime/mail/mail_aliases.cpp",
        "socketley/runtime/mail/mail_sieve.cpp",
        "socketley/runtime/mail/mail_sieve_store.cpp",
        "socketley/runtime/mail/managesieve_session.cpp",
        "socketley/runtime/mail/imap_order.cpp",
        "socketley/runtime/mail/pop3_session.cpp",
        "socketley/runtime/mail/mail_mbox.cpp",
        "socketley/runtime/mail/mail_arc.cpp",
        "socketley/runtime/mail/mail_srs.cpp",
        "socketley/runtime/mail/mail_tls_policy.cpp",
        "socketley/shared/util/base64.cpp"
    }
    links(tls_libs())

    fuzz_target_settings()

-- ─── Fuzz: the JSON pair behind socketley.json_decode / json_encode ─────────
--
-- The one binding written to be pointed at data from the network, and the one
-- that had no depth limit: a few hundred kilobytes of nesting was a SIGSEGV.
-- It became fuzzable when the pair moved out of lua_context.cpp into
-- lua_json.h — see the header for why it had to.  Needs LuaJIT, because the
-- decoder builds Lua values.

project "fuzz_lua_json"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz", "thirdparty/sol2", "thirdparty/luajit" }
    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "luajit" }

    files {
        "test/fuzz/fuzz_lua_json.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: WebSocket frame parsing (needs OpenSSL for the accept-key path) ───

project "fuzz_ws_frame"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }
    links(tls_libs())

    files {
        "test/fuzz/fuzz_ws_frame.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: the Raft wire codec and the frame splitting in front of it ───
--
-- Reachable by whoever can open a TCP connection to --raft-listen, before the
-- sender is known to be a member.  Two translation units of the tree and no
-- libraries, so it is as cheap as the parser targets.

project "fuzz_raft_msg"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_raft_msg.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/cluster/raft_codec.cpp",
        "socketley/shared/cluster/raft.cpp",
        "socketley/shared/cluster/cluster_state.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the tunnel's multiplexing, and the SSH certificate reader ───

project "fuzz_tunnel_mux"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_tunnel_mux.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/net/tunnel_mux.cpp"
    }

    fuzz_target_settings()

project "fuzz_ssh_cert"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_ssh_cert.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/crypto/ssh_cert.cpp",
        "socketley/shared/crypto/ed25519.cpp",
        "socketley/shared/crypto/key_file.cpp",
        "socketley/shared/crypto/jws.cpp",
        "socketley/shared/util/base64.cpp"
    }
    links { "crypto" }

    fuzz_target_settings()

-- ─── Fuzz: SigV4 request verification and the aws-chunked decoder ───
--
-- Reachable by anything that can send an HTTP request to a storage runtime, before the request is otherwise looked at.
-- One translation unit of the tree and libcrypto.

project "fuzz_s3_sigv4"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }
    links { "crypto" }

    files {
        "test/fuzz/fuzz_s3_sigv4.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/storage/s3_sigv4.cpp",
        "socketley/shared/util/base64.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: a storage bucket's policy, its JSON reader and its compiler ───
--
-- Reachable by any access key through PutBucketPolicy, and by the bucket's directory at every start.
-- One translation unit of the tree, and nothing to link.

project "fuzz_bucket_policy"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_bucket_policy.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/storage/bucket_policy.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the dns runtime's query answerer and zone file reader ───

project "fuzz_dns"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_dns.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/dns/dns_wire.cpp",
        "socketley/runtime/dns/dns_zone.cpp",
        "socketley/runtime/dns/dns_answer.cpp",
        "socketley/runtime/dns/dns_sign.cpp",
        "socketley/shared/crypto/jws.cpp", "socketley/shared/crypto/key_file.cpp", "socketley/shared/util/base64.cpp",
        "socketley/shared/net/dns_feed.cpp", "socketley/shared/persist/paths.cpp"
    }
    links { "crypto" }

    fuzz_target_settings()

-- ─── Fuzz: the db runtime's readers of a query, a patch, a document and a schema ───

project "fuzz_db"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }
    links { "crypto" }

    files {
        "test/fuzz/fuzz_db.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/db/db_doc.cpp",
        "socketley/runtime/db/db_schema.cpp",
        "socketley/runtime/db/db_store.cpp",
        "socketley/runtime/db/db_log.cpp",
        "socketley/shared/crypto/jws.cpp", "socketley/shared/crypto/key_file.cpp", "socketley/shared/util/base64.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the metrics runtime's chunk codec, block reader and head log reader ───

project "fuzz_metrics_chunk"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_metrics_chunk.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/metrics/metrics_chunk.cpp",
        "socketley/runtime/metrics/metrics_block.cpp",
        "socketley/shared/util/crc.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the metrics runtime's reader of the Prometheus text format ───

project "fuzz_metrics_text"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_metrics_text.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/metrics/metrics_text.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the metrics runtime's PromQL parser and evaluator over a small store ───

project "fuzz_metrics_query"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz", "test/unit" }

    files {
        "test/fuzz/fuzz_metrics_query.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/metrics/metrics_query.cpp", "socketley/runtime/metrics/metrics_promql_parse.cpp",
        "socketley/runtime/metrics/metrics_promql_eval.cpp", "socketley/runtime/metrics/metrics_regex.cpp",
        "socketley/runtime/metrics/metrics_text.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the metrics runtime's rules file, its templates and one evaluation over a small store ───

project "fuzz_metrics_rules"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz", "test/unit" }

    files {
        "test/fuzz/fuzz_metrics_rules.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/metrics/metrics_rules.cpp",
        "socketley/runtime/metrics/metrics_query.cpp", "socketley/runtime/metrics/metrics_promql_parse.cpp",
        "socketley/runtime/metrics/metrics_promql_eval.cpp", "socketley/runtime/metrics/metrics_regex.cpp",
        "socketley/runtime/metrics/metrics_text.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: the metrics runtime's remote-write codec, Snappy and the WriteRequest protobuf ───

project "fuzz_metrics_remote"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_metrics_remote.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/metrics/metrics_remote.cpp"
    }

    fuzz_target_settings()


-- ─── Fuzz: the storage runtime's parsers of whole inputs ───
--
-- An LZ4 block and a compressed body's table, a SelectObjectContent request and its records, an ACL and grant headers,
-- and a JWT against a JWK Set: what a client sends and what the disk holds, each read whole.  Links the SDK, whose
-- storage files they are.

project "fuzz_storage_parsers"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { ".", "socketley", "test/fuzz", "thirdparty/sol2", "thirdparty/luajit", "include/linux" }
    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files {
        "test/fuzz/fuzz_storage_parsers.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: cache_store as an operation sequence ───
--
-- Not a parser target.  It decodes the fuzzer's bytes into a program —
-- SET/GET/DEL/APPEND/EXPIRE, the collection commands, maxmemory and eviction
-- changes, save/load — and checks the store's invariants after every step.  See
-- the header comment in test/fuzz/fuzz_cache_ops.cpp for why the parsers cannot
-- reach the defects this one is for.
--
-- It compiles cache_store.cpp directly instead of linking socketley_sdk.  That
-- file needs nothing but libc, so the target stays three translation units and
-- is cheap enough for the per-push job, where fuzz_http_request is not.

project "fuzz_cache_ops"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_cache_ops.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/runtime/cache/cache_store.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: proxy HTTP response framing + pooling decision ───
--
-- The counterpart to fuzz_http_request, and the cheap one.  The response parser
-- used to be a block of statements inside handle_backend_read, reachable only
-- from a running daemon; it is now shared/http/http_framing.h, which
-- includes <charconv> and <string_view> and nothing else.  So this target is
-- three translation units like fuzz_resp, links no libraries, and belongs in
-- the per-push job — unlike fuzz_http_request, which still needs the whole SDK.

project "fuzz_http_response"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_http_response.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/http/http_framing.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: the tunnel half of that same scanner ───────────────────────────
--
-- Same header, different question, and a separate target because the question
-- has to be *directed*.  fuzz_http_response explores response framing; nothing
-- in it or its corpus pins a 101, so the state a connection enters when it
-- stops carrying HTTP is reached only by coincidence.  This target builds the
-- switch itself on every input and then attacks what follows it, asserting the
-- one predicate both of the proxy's pooling paths ask — a live tunnel socket
-- must never become poolable.  See the header of test/fuzz/fuzz_proxy_tunnel.cpp.

project "fuzz_proxy_tunnel"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }

    files {
        "test/fuzz/fuzz_proxy_tunnel.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/http/http_framing.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: event_loop completion handling as a scripted order of CQEs ───
--
-- Not a parser target either.  It decodes the fuzzer's bytes into a sequence of
-- completions — op type, result, flags, owner slot, epoch — feeds them to
-- event_loop::dispatch_cqe(), and checks the loop's own accounting after every
-- one: the owner ledger, the per-descriptor counts, the provided-buffer groups.
-- The order completions arrive in is the kernel's to choose and is where every
-- lifetime defect this project found came from; this target makes that order an
-- input.  See the header comment in test/fuzz/fuzz_event_loop.cpp.
--
-- It compiles event_loop.cpp directly rather than linking socketley_sdk: that
-- file needs liburing and logging.h and nothing else of ours, so the target
-- stays three translation units.  liburing is a link dependency only — the
-- target never opens a ring.

project "fuzz_event_loop"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }
    links { "uring:static" }

    files {
        "test/fuzz/fuzz_event_loop.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h",
        "socketley/shared/loop/event_loop.cpp"
    }

    fuzz_target_settings()

-- ─── Fuzz: proxy HTTP request line + header block ───
--
-- This one links the whole runtime.  parse_http_request_line and
-- rewrite_http_request are private members of proxy_instance defined in
-- proxy_instance.cpp, and there is no smaller translation unit that contains
-- them — so the target links socketley_sdk and reaches them through the
-- explicit-instantiation access idiom.  See the header comment in
-- test/fuzz/fuzz_http_request.cpp for why, and for the two-line change in
-- socketley/ that would make this unnecessary.
--
-- Consequence for CI: this target costs a full SDK build, so it belongs in the
-- nightly job rather than the per-push one.

project "fuzz_http_request"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs {
        ".",
        "socketley",
        "test/fuzz",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files {
        "test/fuzz/fuzz_http_request.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: server and client runtimes as operation sequences ───
--
-- Not parser targets and not even byte targets.  Each decodes the fuzzer's
-- bytes into a program of lifecycle and connection operations — start, stop,
-- destroy, connect, send, reset, restart — and runs it against a real runtime on
-- a real io_uring event_loop, checking after every step that no completion can
-- outlive its owner, that every arm has its disarm, that no descriptor number is
-- named by a queued SQE after it was released, and that no connection struct
-- goes back to its pool with anything armed on it.  See the header comment in
-- test/fuzz/fuzz_runtime_ops.h for why none of that is reachable by mutating a
-- byte buffer.
--
-- They link socketley_sdk for the same reason fuzz_http_request does — the code
-- under test is the runtime — so they cost a full SDK build and belong in the
-- nightly job rather than the per-push one.
--
-- One difference from the libFuzzer build: SOCKETLEY_INVARIANTS is not defined
-- here.  These projects link the same socketley_sdk the daemon is built from, and
-- defining it would put the checks in invariants.h into the shipped binary.  The
-- clang build in test/fuzz/build_libfuzzer.sh compiles its own copy of the SDK
-- and does define it, so the in-tree pool-safety and reachability assertions are
-- live there.  The harness's own equivalents run in both.

project "fuzz_server_ops"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs {
        ".",
        "socketley",
        "test/fuzz",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files {
        "test/fuzz/fuzz_server_ops.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_runtime_ops.h",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

project "fuzz_client_ops"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs {
        ".",
        "socketley",
        "test/fuzz",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files {
        "test/fuzz/fuzz_client_ops.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_runtime_ops.h",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Fuzz: the proxy as an operation sequence, with peers at both ends ───
--
-- The same shape as the two above and the same four inherited invariants, with
-- three of its own that the other two have no use for: no client is closed
-- without an answer once it has sent a whole request, no backend socket is
-- pooled off a message boundary, and no response reaches a client that did not
-- ask for it.  Every proxy defect this project found this week broke one of
-- those three and none of them crashed — see the header comment in
-- test/fuzz/fuzz_proxy_ops.cpp.
--
-- Unlike the server and client targets this one has peers on both sides: real
-- client sockets dialling the proxy's listener and real listening sockets the
-- proxy dials as its backends, with what each of them answers, how much of it,
-- and when they hang up all decided by the program.  That is what makes the
-- pool reachable at all.
--
-- It links socketley_sdk and LuaJIT for the same reason as its neighbours — the
-- code under test is the runtime, and the filter chain has no interface but a
-- script — so it costs a full SDK build and belongs in the nightly job.

project "fuzz_proxy_ops"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs {
        ".",
        "socketley",
        "test/fuzz",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files {
        "test/fuzz/fuzz_proxy_ops.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
        "test/fuzz/fuzz_runtime_ops.h",
        "test/fuzz/fuzz_common.h"
    }

    fuzz_target_settings()

-- ─── Test: SDK cache_client.h (header-only, no libs) ───

project "test_sdk_cache_client"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs { "include/linux" }

    files { "test/unit/test_sdk_cache_client.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: connection identity and the two transfer mechanisms ───

project "test_conn_transfer"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_conn_transfer.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the one ear a UDP server has, and what re-arms it ───

project "test_udp_recv_ladder"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_udp_recv_ladder.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: what the event loop does on the oldest kernel it claims, played on this one ───

project "test_loop_kernel_floor"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_loop_kernel_floor.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: Raft, as whole simulated clusters ───
--
-- Its own copy of raft.cpp, built with the planted defects the harness has to
-- catch; the daemon's copy is compiled without them.

project "test_raft"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    defines { "SOCKETLEY_RAFT_FAULTS" }

    files {
        "test/unit/test_raft.cpp",
        "socketley/shared/cluster/raft.cpp",
        "socketley/shared/cluster/raft.h",
        "socketley/shared/cluster/raft_codec.cpp"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: the cluster's replicated desired state and its placement ───
--
-- Pure logic with no I/O, so it is two translation units and no libraries.

project "test_cluster_state"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files {
        "test/unit/test_cluster_state.cpp",
        "socketley/shared/cluster/cluster_state.cpp",
        "socketley/shared/cluster/replica_role.cpp"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: AWS Signature V4 verification, against the published vectors and boto3's own requests ───
--
-- Pure code over libcrypto, so one translation unit of the tree.

-- ─── Storage: a bucket policy's JSON reader and compiler, alone ───

project "test_storage_policy"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files {
        "test/unit/test_storage_policy.cpp",
        "socketley/runtime/storage/bucket_policy.cpp"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_s3_sigv4"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "crypto" }

    files {
        "test/unit/test_s3_sigv4.cpp",
        "socketley/shared/storage/s3_sigv4.cpp",
        "socketley/shared/util/base64.cpp"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: placement, liveness and the serving lease, over real Raft nodes ───
--
-- The brain and the Raft core in virtual time, so a partition, a kill or a
-- late message is a line of the test and the invariant is checked every tick.

project "test_cluster_brain"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files {
        "test/unit/test_cluster_brain.cpp",
        "socketley/shared/cluster/cluster_brain.cpp",
        "socketley/shared/cluster/cluster_state.cpp",
        "socketley/shared/cluster/replica_role.cpp",
        "socketley/shared/cluster/raft.cpp"
    }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Test: Raft's WAL and snapshot files, and the io_uring writer ───

project "test_raft_storage"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_raft_storage.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Storage: the object store, on a real ring and a real directory ───

project "test_object_store"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_object_store.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_multipart"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_storage_multipart.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_select"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_storage_select.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_federation"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_storage_federation.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_compression"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs()) links { "dl" }

    files { "test/unit/test_storage_compression.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_hpack"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_hpack.cpp", "socketley/shared/http/hpack.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_dns"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files {
        "test/unit/test_dns.cpp",
        "socketley/runtime/dns/dns_wire.cpp",
        "socketley/runtime/dns/dns_zone.cpp",
        "socketley/runtime/dns/dns_answer.cpp",
        "socketley/runtime/dns/dns_sign.cpp",
        "socketley/shared/crypto/jws.cpp", "socketley/shared/crypto/key_file.cpp", "socketley/shared/util/base64.cpp",
        "socketley/shared/net/dns_feed.cpp", "socketley/shared/persist/paths.cpp"
    }
    links(tls_libs())

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_inflate"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_storage_inflate.cpp", "socketley/shared/util/inflate.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_sync_index"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_sync_index.cpp", "socketley/runtime/sync/sync_index.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_mutation_journal"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_mutation_journal.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_json"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_json.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_persist"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl", "crypto" }

    files { "test/unit/test_persist.cpp", "socketley/shared/persist/tar_archive.cpp", "socketley/shared/util/deflate.cpp",
            "socketley/shared/util/inflate.cpp", "socketley/shared/util/crc.cpp",
            "socketley/shared/crypto/key_file.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_util"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_util.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_http_framing"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "dl" }

    files { "test/unit/test_http_framing.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_scrypt"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_scrypt.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_https_client"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_https_client.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_shards"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_storage_shards.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_storage_crash"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_storage_crash.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_outbox"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_outbox.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- ─── Benchmark: the two cross-runtime transports against the in-process relay ───

project "bench_conn_transfer"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/benchmark/bench_conn_transfer.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

project "test_idp"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "crypto", "dl" }

    files { "test/unit/test_idp.cpp", "socketley/runtime/idp/idp_logic.cpp", "socketley/runtime/idp/idp_accounts.cpp",
            "socketley/runtime/idp/idp_shard.cpp", "socketley/runtime/idp/idp_ssh_certs.cpp", "socketley/shared/crypto/jws.cpp",
            "socketley/shared/crypto/key_file.cpp", "socketley/shared/crypto/ssh_cert.cpp", "socketley/shared/crypto/ed25519.cpp",
            "socketley/shared/persist/paths.cpp", "socketley/shared/util/base64.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_ssh_ca"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "crypto", "dl" }

    files { "test/unit/test_ssh_ca.cpp", "socketley/shared/crypto/ssh_cert.cpp", "socketley/shared/crypto/ed25519.cpp",
            "socketley/shared/crypto/key_file.cpp", "socketley/shared/crypto/jws.cpp", "socketley/shared/util/base64.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_tunnel_mux"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_tunnel_mux.cpp", "socketley/shared/net/tunnel_mux.cpp", "socketley/runtime/tunnel/tunnel_registry.cpp",
            "socketley/shared/crypto/jws.cpp", "socketley/shared/crypto/key_file.cpp", "socketley/shared/util/base64.cpp",
            "socketley/shared/persist/paths.cpp" }
    links { "crypto", "dl" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_qr_code"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_qr_code.cpp", "socketley/shared/util/qr_code.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_mqtt"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_mqtt.cpp", "socketley/runtime/mqtt/mqtt_codec.cpp", "socketley/runtime/mqtt/mqtt_topics.cpp",
            "socketley/runtime/mqtt/mqtt_auth.cpp", "socketley/shared/crypto/password_file.cpp", "socketley/runtime/mqtt/mqtt_broker.cpp",
            "socketley/runtime/mqtt/mqtt_broker_store.cpp", "socketley/runtime/mqtt/mqtt_routes.cpp",
            "socketley/shared/util/base64.cpp", "socketley/shared/http/http_url.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_mail_more"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        ".",
        "thirdparty/doctest",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit", "thirdparty/liburing" }
    links { "socketley_sdk", "luajit", "uring:static" } links(tls_libs())

    files { "test/unit/test_mail_more.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_mail"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_mail.cpp", "socketley/runtime/mail/smtp_session.cpp", "socketley/runtime/mail/mail_compose.cpp",
            "socketley/runtime/mail/mail_dkim.cpp", "socketley/runtime/mail/mail_aliases.cpp",
            "socketley/runtime/mail/mail_verify.cpp", "socketley/runtime/mail/mail_arc.cpp",
            "socketley/runtime/dns/dns_wire.cpp", "socketley/runtime/mail/mail_mime.cpp",
            "test/unit/test_mail_sieve.cpp", "socketley/runtime/mail/mail_sieve.cpp",
            "socketley/shared/util/base64.cpp", "socketley/runtime/mail/mail_tls_policy.cpp",
            "socketley/shared/net/public_suffix.cpp", "socketley/shared/net/idna.cpp",
            "socketley/runtime/mail/mail_sieve_store.cpp",
            "socketley/runtime/mail/managesieve_session.cpp", "socketley/runtime/mail/imap_order.cpp",
            "socketley/shared/util/deflate.cpp", "socketley/shared/util/inflate.cpp" }
    links(tls_libs())

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_db"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    links { "crypto", "dl" }

    files { "test/unit/test_db.cpp", "socketley/runtime/db/db_doc.cpp", "socketley/runtime/db/db_schema.cpp",
            "socketley/runtime/db/db_store.cpp", "socketley/runtime/db/db_log.cpp", "socketley/runtime/db/db_shard.cpp",
            "socketley/shared/crypto/jws.cpp", "socketley/shared/crypto/key_file.cpp", "socketley/shared/util/base64.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

project "test_metrics_store"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_metrics_store.cpp", "socketley/runtime/metrics/metrics_chunk.cpp",
            "socketley/runtime/metrics/metrics_index.cpp", "socketley/runtime/metrics/metrics_block.cpp",
            "socketley/runtime/metrics/metrics_store.cpp", "socketley/runtime/metrics/metrics_regex.cpp",
            "socketley/runtime/metrics/metrics_query.cpp", "socketley/runtime/metrics/metrics_promql_parse.cpp",
            "socketley/runtime/metrics/metrics_promql_eval.cpp", "socketley/runtime/metrics/metrics_text.cpp",
            "socketley/shared/util/crc.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- The metrics runtime's reader of the Prometheus text format.
project "test_metrics_text"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley",
        "test/unit"
    }

    files { "test/unit/test_metrics_text.cpp", "socketley/runtime/metrics/metrics_text.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- The metrics runtime's PromQL over a vector-backed store with fake tiers, and its regex engine.
project "test_metrics_query"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley",
        "test/unit"
    }

    files { "test/unit/test_metrics_query.cpp",
            "socketley/runtime/metrics/metrics_query.cpp", "socketley/runtime/metrics/metrics_promql_parse.cpp",
            "socketley/runtime/metrics/metrics_promql_eval.cpp", "socketley/runtime/metrics/metrics_regex.cpp",
            "socketley/runtime/metrics/metrics_text.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}


-- The metrics runtime's recording and alerting rules over a real store in a temporary directory.
project "test_metrics_rules"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley",
        "test/unit"
    }

    files { "test/unit/test_metrics_rules.cpp", "socketley/runtime/metrics/metrics_rules.cpp",
            "socketley/runtime/metrics/metrics_query.cpp", "socketley/runtime/metrics/metrics_promql_parse.cpp",
            "socketley/runtime/metrics/metrics_promql_eval.cpp", "socketley/runtime/metrics/metrics_regex.cpp",
            "socketley/runtime/metrics/metrics_text.cpp", "socketley/runtime/metrics/metrics_store.cpp",
            "socketley/runtime/metrics/metrics_chunk.cpp", "socketley/runtime/metrics/metrics_index.cpp",
            "socketley/runtime/metrics/metrics_block.cpp", "socketley/shared/util/crc.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- The metrics runtime's remote-write codec: Snappy blocks and WriteRequests.
project "test_metrics_remote"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_metrics_remote.cpp", "socketley/runtime/metrics/metrics_remote.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}

-- The runtimes' latency histogram, its bucket bounds, and the catalog's histogram families.
project "test_latency_histogram"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs {
        "thirdparty/doctest",
        "socketley"
    }

    files { "test/unit/test_latency_histogram.cpp", "socketley/shared/runtime/metric_catalog.cpp" }

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"
    filter {}

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Full"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}
