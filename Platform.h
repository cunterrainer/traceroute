#pragma once

#include "PlatformLinux.h"
#include "PlatformWindows.h"

namespace Platform
{
    static int Main(int argc, char** argv)
    {
        #ifdef _WIN32
                return Platform::Windows::Main(argc, argv);
        #elif defined __linux__
                return Platform::Linux::Main(argc, argv);
        #endif
    }
}
