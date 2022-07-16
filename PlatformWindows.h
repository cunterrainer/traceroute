#pragma once
#ifdef _WIN32

#include <Windows.h>

namespace Platform::Windows
{
    static int Main(int argc, char** argv)
    {
        // implementation following
        return argc;
    }
}
#endif