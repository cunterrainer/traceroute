#pragma once

#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <sstream>
#include <optional>

// platform independet code
namespace PIndep
{
    namespace CLA
    {
        static inline std::string LowerStr(const std::string& str) noexcept
        {
            std::string strl(str);
            for (char& c : strl)
                c = static_cast<char>(std::tolower(c));
            return strl;
        }

        static inline void PrintHelp(const char* name) noexcept
        {
            std::cout << "\nUsage: " << name << " 'website' [options]\n";
            std::cout << "-h or --help:             print this help message\n";
            std::cout << "-m [n] or --max-hops [n]: Set max hops e.g. [-m 64] hops a maximum of 64 times | default: 32\n";
            std::cout << std::endl;
        }

        struct UInput
        {
            std::string hostname;
            size_t hops = 32;
        };

        static inline std::optional<UInput> Handler(int argc, char** argv) noexcept
        {
            UInput ip;
            if (argc == 1)
            {
                std::cout << "Usage: " << argv[0] << " 'website'\n";
                std::cout << "       [" << argv[0] << " -h] for additional information\n";
                return std::nullopt;
            }

            for (int i = 1; i < argc; ++i)
            {
                std::string str(argv[i]);
                const std::string lstr(LowerStr(str));

                if (lstr == "-h" || lstr == "--help" || lstr == "help")
                {
                    PrintHelp(argv[0]);
                    return std::nullopt;
                }

                if (lstr == "-m" || lstr == "--max-hops")
                {
                    if (i == argc - 1) {
                        PrintHelp(argv[0]);
                        return std::nullopt;
                    }

                    std::stringstream sstream(argv[i + 1]);
                    sstream >> ip.hops;
                }
                else if (lstr[0] == '-')
                {
                    PrintHelp(argv[0]);
                    return std::nullopt;
                }
                else if (LowerStr(argv[i - 1]) != "-m" && LowerStr(argv[i - 1]) != "--max-hops")
                {
                    ip.hostname = std::move(str);
                }
            }

            if (ip.hostname.empty() || ip.hops == 0)
            {
                PrintHelp(argv[0]);
                return std::nullopt;
            }
            return ip;
        }
    }


    namespace Time
    {
        using TimePoint = std::chrono::high_resolution_clock::time_point;
        // TODO: switch to CurrentTime on linux (GetCurrentTime is a macro defined in WinBase.h)
        //static TimePoint GetCurrentTime() noexcept
        //{
        //    return std::chrono::high_resolution_clock::now();
        //}

        static inline TimePoint CurrentTime() noexcept
        {
            return std::chrono::high_resolution_clock::now();
        }

        template<class T>
        static constexpr double DeltaTime(const TimePoint& t1, const TimePoint& t2) noexcept
        {
            return std::chrono::duration<double, T>(t1 - t2).count();
        }

        template<class T>
        static constexpr void Sleep(size_t time) noexcept
        {
            std::this_thread::sleep_for(T(time));
        }
    }


    namespace IO
    {
        static inline void PrintRecv(size_t ttl, const std::string& ipAddPckRecv, double rtt) noexcept
        {
            // TODO: add bytes received
            // 15 == max length for ipv4 address
            size_t spaces = 15 - ipAddPckRecv.size();
            std::string buffer(spaces, ' ');
            std::cout << ttl << ". " << ipAddPckRecv << buffer << " ttl=" << ttl << " rtt=" << rtt << " ms" << std::endl;
        }
    }
}