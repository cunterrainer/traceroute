workspace "traceroute"
    platforms { "x64", "x86" }
    configurations {
        "Debug",
        "Release"
    }
    startproject "traceroute"

outputdir = "/BIN/%{cfg.buildcfg}/%{cfg.architecture}/"
cwd = os.getcwd() -- get current working directory

targetdir(cwd .. outputdir .. "%{prj.name}/bin") -- set dir for exe
objdir(cwd .. outputdir .. "%{prj.name}/bin-int") -- set dir for obj files

filter { "platforms:x64" }
    architecture "x64"
filter { "platforms:x86" }
    architecture "x86"


filter { "configurations:Debug" }
    defines "DEBUG"
filter { "configurations:Release" }
    defines "RELEASE"


filter { "configurations:Debug" }
    runtime "Debug"
    symbols "on"
    optimize "off"
    floatingpoint "default"
filter { "configurations:Release" }
    runtime "Release"
    symbols "off"
    optimize "Speed"
    floatingpoint "fast"


filter "system:windows"
    defines "WINDOWS"
filter "system:linux"
    defines "LINUX"

    
filter "toolset:msc*"
    warnings "Everything"
    externalwarnings "Default"
    disablewarnings { 
        "4820", -- disable warning C4820: 'added padding'
        "4626", -- C6264 assignment operator was deleted
        "5027", -- C5027 move assignment operator was deleted
        "5045", -- C5045 Spectre mitigation
        "4710", -- C4710 function not inlined
        "4711", -- C4711 function 'function' selected for automatic inline expansion
    }
    buildoptions { "/sdl" }

filter {}

-- only for visual studio
flags {
    "MultiProcessorCompile",
    "FatalWarnings"
}
staticruntime "on"
removeunreferencedcodedata "on"


project "traceroute"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++17"

    files {
        "src/**.cpp",
        "src/**.h"
    }

    links {
        "Ws2_32"
    }