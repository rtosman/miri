-- SPDX-License-Identifier: BSD-3-Clause
-- Copyright (c) 2026 Rennie Allen

local buildRoot = os.getenv("MIRI_BUILD_ROOT") or "E:/miri-build"

newoption {
    trigger = "with-tests",
    description = "Build the patch decoder and trampoline regression tests"
}

local function normalizePath(pathValue)
    if pathValue == nil or pathValue == "" then
        return nil
    end

    pathValue = path.translate(pathValue, "/")
    while pathValue:sub(-1) == "/" do
        pathValue = pathValue:sub(1, -2)
    end
    return pathValue
end

local function firstExistingDirectory(candidates)
    for _, candidate in ipairs(candidates) do
        candidate = normalizePath(candidate)
        if candidate ~= nil and os.isdir(candidate) then
            return candidate
        end
    end

    return nil
end

local vsInstallDir = normalizePath(os.getenv("VSINSTALLDIR"))
local diaSdkRoot = normalizePath(os.getenv("MIRI_DIA_SDK_DIR"))
if diaSdkRoot == nil and vsInstallDir ~= nil then
    diaSdkRoot = firstExistingDirectory({ vsInstallDir .. "/DIA SDK" })
end
if diaSdkRoot == nil then
    diaSdkRoot = firstExistingDirectory({
        "E:/Program Files/Microsoft Visual Studio/18/Community/DIA SDK",
        "E:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK",
        "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK",
        "C:/Program Files/Microsoft Visual Studio/2022/Professional/DIA SDK",
        "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/DIA SDK"
    })
end

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
    if diaSdkRoot ~= nil then
        includedirs { diaSdkRoot .. "/include" }
        defines { "MIRI_HAS_DIA=1" }
    end

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
    if diaSdkRoot ~= nil then
        libdirs { diaSdkRoot .. "/lib/amd64" }
        links { "diaguids" }
    end

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

if _OPTIONS["with-tests"] then
    project "miri-patch-tests"
        kind "ConsoleApp"
        language "C++"
        cppdialect "C++17"
        targetdir (buildRoot .. "/bin/%{cfg.buildcfg}")
        objdir (buildRoot .. "/obj/%{prj.name}/%{cfg.buildcfg}")
        files { "tests/remote_patch_tests.cpp", "src/miri_common/StringUtil.cpp" }
        includedirs { "src" }

    project "miri-diagnostics-tests"
        kind "ConsoleApp"
        language "C++"
        cppdialect "C++17"
        targetdir (buildRoot .. "/bin/%{cfg.buildcfg}")
        objdir (buildRoot .. "/obj/%{prj.name}/%{cfg.buildcfg}")
        files { "tests/debug_diagnostics_tests.cpp" }
        includedirs { "src" }
        links { "miri_common", "Dbghelp" }
        if diaSdkRoot ~= nil then
            libdirs { diaSdkRoot .. "/lib/amd64" }
            links { "diaguids" }
        end
end
