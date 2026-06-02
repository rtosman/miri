local buildRoot = os.getenv("MIRI_BUILD_ROOT") or "E:/miri-build"

workspace "miri"
    architecture "x86_64"
    configurations { "Debug", "Release" }
    startproject "miri-run"
    location (buildRoot .. "/projects")

    multiprocessorcompile "On"

    filter "system:windows"
        systemversion "latest"
        defines {
            "WIN32_LEAN_AND_MEAN",
            "NOMINMAX",
            "_CRT_SECURE_NO_WARNINGS",
            "UNICODE",
            "_UNICODE"
        }

    filter "configurations:Debug"
        symbols "On"
        optimize "Off"
        runtime "Debug"

    filter "configurations:Release"
        symbols "On"
        optimize "Speed"
        runtime "Release"
        linktimeoptimization "On"

project "miri_common"
    kind "StaticLib"
    language "C++"
    cppdialect "C++17"
    targetdir (buildRoot .. "/bin/%{cfg.buildcfg}")
    objdir (buildRoot .. "/obj/%{prj.name}/%{cfg.buildcfg}")

    files {
        "src/miri_common/**.h",
        "src/miri_common/**.cpp"
    }

    includedirs { "src" }

project "miri-run"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++17"
    targetdir (buildRoot .. "/bin/%{cfg.buildcfg}")
    objdir (buildRoot .. "/obj/%{prj.name}/%{cfg.buildcfg}")

    files {
        "src/miri_run/**.cpp",
        "src/miri_run/**.h"
    }

    includedirs { "src" }
    links { "miri_common", "Dbghelp" }

project "miri-hist"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++17"
    targetdir (buildRoot .. "/bin/%{cfg.buildcfg}")
    objdir (buildRoot .. "/obj/%{prj.name}/%{cfg.buildcfg}")

    files {
        "src/miri_hist/**.cpp",
        "src/miri_hist/**.h"
    }

    includedirs { "src" }
    links { "miri_common" }
