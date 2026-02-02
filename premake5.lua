function setup_project(project_name)
    project(project_name)
        language "C++"
        cppdialect "C++latest"
        cdialect "C17"
        characterset "MBCS"

        targetdir ("%{wks.location}/bin/%{prj.name}-%{cfg.architecture}-%{cfg.buildcfg}")
        location("%{wks.location}/%{prj.name}")

        files {
            "%{prj.location}/**.c",
            "%{prj.location}/**.h",
            "%{prj.location}/**.cpp",
            "%{wks.location}/shared/**.h",
            "%{wks.location}/shared/**.cpp"
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
end

workspace "Socketley"
    system "linux"
    configurations { "Debug", "Release" }
    platforms { "x64" }

    location "./"

    include "socketley/build.lua"
    include "runtime_server/build.lua"
    include "runtime_client/build.lua"
    include "runtime_proxy/build.lua"
    include "runtime_cache/build.lua"