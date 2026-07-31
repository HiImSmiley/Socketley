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
    configurations { "Debug", "Dev", "Release", "Sanitize", "TSan" }
    platforms { "x64" }
    location "make"

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
        linkoptions { "-fuse-ld=lld-18", "-Wl,--as-needed" }
    filter {}

    filter "configurations:Release"
        optimize "Full"
        buildoptions {
            "-flto=auto",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "-fvisibility=hidden",
            "-march=native",
            "-mtune=native"
        }
        linkoptions {
            "-flto=auto",
            "-Wl,-z,relro,-z,now",
            "-Wl,--as-needed"
        }
    filter {}

    -- Workspace-wide Sanitize settings.  Each project also carries its own
    -- Sanitize filter; these add the one flag none of them had.
    --
    -- -fno-sanitize-recover=all is the important part: without it UBSan prints a
    -- diagnostic and carries on, so an integration run under UBSan finishes with
    -- exit status 0 and a defect buried in the log.  A CI job that goes green on
    -- a run that found something is worse than no job.
    filter "configurations:Sanitize"
        buildoptions { "-fno-sanitize-recover=all" }
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
        "thirdparty/sol2",
        "thirdparty/luajit"
    }
    includedirs {
        "socketley"
    }

    libdirs { "thirdparty/luajit" }
    links { "luajit", "uring", "ssl", "crypto" }

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

    includedirs {
        ".",
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    libdirs { "thirdparty/luajit" }

    files {
        "socketley/shared/**.h",
        "socketley/shared/**.cpp",
        "socketley/runtime/**.h",
        "socketley/runtime/**.cpp"
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

-- ─── SDK: socketley_sdk_nolua static library (SOCKETLEY_NO_LUA) ───

project "socketley_sdk_nolua"
    kind "StaticLib"
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

    defines { "SOCKETLEY_NO_LUA" }

    files {
        "socketley/shared/**.h", "socketley/shared/**.cpp",
        "socketley/runtime/**.h", "socketley/runtime/**.cpp"
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

    libdirs { "thirdparty/luajit" }
    links { "socketley_sdk", "luajit", "uring", "ssl", "crypto" }

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

    links { "ssl", "crypto" }

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

-- ─── Benchmark: socketley_bench ───

project "socketley_bench"
    kind "ConsoleApp"
    language "C"
    cdialect "C17"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    buildoptions { "-pipe" }

    links { "pthread", "m" }

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

    libdirs { "thirdparty/luajit" }
    links { "socketley_sdk", "luajit", "uring", "ssl", "crypto" }

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

-- ─── Test: SDK ws_client.h (header-only, no libs) ───

project "test_sdk_ws_client"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"
    targetdir ("bin/%{cfg.buildcfg}")
    location("%{wks.location}")

    includedirs { "include/windows" }

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
-- Recommended: make config=sanitize_x64 fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_request

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

-- ─── Fuzz: WebSocket frame parsing (needs OpenSSL for the accept-key path) ───

project "fuzz_ws_frame"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++latest"

    includedirs { "socketley", "test/fuzz" }
    links { "ssl", "crypto" }

    files {
        "test/fuzz/fuzz_ws_frame.cpp",
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

    libdirs { "thirdparty/luajit" }
    links { "socketley_sdk", "luajit", "uring", "ssl", "crypto" }

    files {
        "test/fuzz/fuzz_http_request.cpp",
        "test/fuzz/fuzz_replay_main.cpp",
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

    includedirs { "include/windows" }

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
