#pragma once

#include "PlatformLinux.h"
#include "PlatformWindows.h"

namespace Platform
{
    static int Main(int argc, char** argv)
    {
        #ifdef WINDOWS
                return Platform::Windows::Main(argc, argv);
        #elif defined LINUX
                return Platform::Linux::Main(argc, argv);
        #endif
    }
}
