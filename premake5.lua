workspace "Socketley"
    system "linux"
    configurations { "Debug", "Release", "Sanitize" }
    platforms { "x64" }
    location "make"

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

    includedirs {
        "thirdparty/sol2",
        "thirdparty/luajit",
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
        optimize "On"
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
        "socketley/runtime/**.cpp",
        "include/linux/**.h"
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
        optimize "On"
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
        "thirdparty/sol2",
        "thirdparty/luajit",
        "socketley",
        "include/linux"
    }

    defines { "SOCKETLEY_NO_LUA" }

    files {
        "socketley/shared/**.h", "socketley/shared/**.cpp",
        "socketley/runtime/**.h", "socketley/runtime/**.cpp",
        "include/linux/**.h"
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
        optimize "On"
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
        optimize "On"
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
        optimize "On"
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
        optimize "On"
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
        optimize "On"
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
        optimize "On"
    filter {}

    filter "configurations:Sanitize"
        defines { "DEBUG" }
        symbols "On"
        buildoptions { "-fsanitize=address,undefined", "-fno-omit-frame-pointer" }
        linkoptions { "-fsanitize=address,undefined" }
    filter {}
