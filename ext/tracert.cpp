// c++std
#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>
#include <optional>

// cstd
#include <cstring>
#include <cstddef>
#include <fcntl.h>

// net
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>

// platform
#include <unistd.h>


// Define the Packet Constants
#define PING_PKT_S      64      // ping packet size
#define PORT_NO         0       // Automatic port number
#define PING_SLEEP_RATE 1000000 // sleeping time between pings in microseconds
#define RECV_TIMEOUT    1       // timeout delay for receiving packets in seconds


namespace CLA
{
    std::string LowerStr(const std::string& str)
    {
        std::string strl(str);
        for(char& c : strl)
            c = std::tolower(c);
        return strl;
    }

    void PrintHelp(const char* name)
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

    std::optional<UInput> Handler(int argc, char** argv)
    {
        UInput ip;
        if(argc == 1)
        {
            std::cout << "Usage: " << argv[0] << " 'website'\n";
            std::cout << "       [" << argv[0] << " -h] for additional information\n";
            return std::nullopt;
        }

        for(int i = 1; i < argc; ++i)
        {
            const std::string str(argv[i]);
            const std::string lstr(LowerStr(str));

            if(lstr == "-h" || lstr == "--help" || lstr == "help")
            {
                PrintHelp(argv[0]);
                return std::nullopt;
            }

            if(lstr == "-m" || lstr == "--max-hops")
            {
                if(i == argc - 1) {
                    PrintHelp(argv[0]);
                    return std::nullopt;
                }

                std::stringstream sstream(argv[i+1]);
                sstream >> ip.hops;
            }
            else if(lstr[0] == '-')
            {
                PrintHelp(argv[0]);
                return std::nullopt;
            }
            else if(LowerStr(argv[i-1]) != "-m" && LowerStr(argv[i-1]) != "--max-hops")
            {
                ip.hostname = std::move(str);
            }
        }

        if(ip.hostname.empty() || ip.hops == 0)
        {
            PrintHelp(argv[0]);
            return std::nullopt;
        }
        return ip;
    }
}


namespace DNS
{
    std::string Lookup(const std::string& address, sockaddr_in& addrCon)
    {
        const hostent* hostEntity;
        if((hostEntity = gethostbyname(address.c_str())) == nullptr) {
            std::cerr << "DNS lookup failed! Could not resolve hostname!\n";
            return std::string(); // No ip found for this hostname
        }

        const std::string ipAddress(inet_ntoa(*reinterpret_cast<in_addr*>(hostEntity->h_addr)));

        bzero(&addrCon, sizeof(sockaddr_in));
        addrCon.sin_family = hostEntity->h_addrtype;
        addrCon.sin_port = htons(PORT_NO);
        addrCon.sin_addr.s_addr  = *reinterpret_cast<long*>(hostEntity->h_addr);

        return ipAddress;
    }

    std::string ReverseLookup(const std::string& ipAddress)
    {
        socklen_t sockLen = sizeof(sockaddr_in);
        sockaddr_in tempAddr;
        tempAddr.sin_family = AF_INET;
        tempAddr.sin_addr.s_addr = inet_addr(ipAddress.c_str());

        char buffer[NI_MAXHOST];
        if(getnameinfo(reinterpret_cast<sockaddr*>(&tempAddr), sockLen, buffer, sizeof(buffer), nullptr, 0, NI_NAMEREQD))
        {
            std::cerr << "Could not resolve reverse lookup of hostname\n";
            return std::string();
        }

        return std::string(buffer);
    }
}


namespace Time
{
    using TimePoint = std::chrono::high_resolution_clock::time_point;
    TimePoint GetCurrentTime() 
    {
        return std::chrono::high_resolution_clock::now();
    }

    template<class T>
    double DeltaTime(const TimePoint& t1, const TimePoint& t2) 
    {
        return std::chrono::duration<double, T>(t1 - t2).count();
    }

    template<class T>
    void Sleep(size_t time)
    {
        std::this_thread::sleep_for(T(time));
    }
}


class Socket
{
private:
    // ping packet structure
    struct PingPkt
    {
        icmphdr hdr;
        char msg[PING_PKT_S-sizeof(icmphdr)];
    };
private:
    sockaddr_in* m_AddrCon;
    const std::string& m_IpAddress;
    
    int m_SocketFd = -1;
    size_t m_TTL = 1;
    PingPkt m_PingPkt;
private:
    void PrintRecv(const std::string& ipAddPckRecv, double rtt) const noexcept
    {
        // 15 == max length for ipv4 address
        size_t spaces = 15 - ipAddPckRecv.size();
        std::string buffer(spaces, ' ');
        std::cout << m_TTL << ' ' << ipAddPckRecv << buffer << " ttl=" << m_TTL << " rtt=" << rtt << " ms" << std::endl;
    }


    // Calculating the Check Sum
    unsigned short Checksum(void *b, int len) const noexcept
    {   
        unsigned short *buf = static_cast<unsigned short*>(b);
        unsigned int sum=0;
        unsigned short result;
     
        for ( sum = 0; len > 1; len -= 2 )
            sum += *buf++;
        if ( len == 1 )
            sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
    }
    

    PingPkt GetPingPkt() noexcept
    {
        PingPkt pckt;
        bzero(&pckt, sizeof(pckt)); // fill packet with 0 bytes
        
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = htons(1);
        //pckt.hdr.un.echo.id = getpid();

        long unsigned int i;
        for (i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = 0;
        pckt.hdr.checksum = Checksum(&pckt, sizeof(pckt));
        return pckt;
    }


    std::optional<std::string> Ping() noexcept
    {
        Time::Sleep<std::chrono::microseconds>(PING_SLEEP_RATE);
 
        //send packet
        const Time::TimePoint timeStart = Time::GetCurrentTime();
        if (sendto(m_SocketFd, &m_PingPkt, sizeof(m_PingPkt), MSG_WAITALL, (sockaddr*) m_AddrCon, sizeof(*m_AddrCon)) <= 0)
        {
            std::cerr << "Packet Sending Failed! TTL: " << m_TTL << std::endl;
            return std::nullopt;
        }
        
        //receive packet
        sockaddr_in r_addr;
        int addr_len = sizeof(r_addr);
        PingPkt recvPkt;

        if (recvfrom(m_SocketFd, &recvPkt, sizeof(recvPkt), MSG_WAITALL, (sockaddr*)&r_addr, (socklen_t*)&addr_len) <= 0)
        {
            //if(errno != EAGAIN)
            {
                std::cout << "Packet receive failed! TTL: " << m_TTL << " Error: " << strerror(errno) << '\n';
                return std::nullopt;
            }
        }

        const double rttTime = Time::DeltaTime<std::milli>(Time::GetCurrentTime(), timeStart);
        const std::string ipAddPckRecv = std::string(inet_ntoa(r_addr.sin_addr));
        PrintRecv(ipAddPckRecv, rttTime);
        return ipAddPckRecv;
    }
public:
    Socket(sockaddr_in* addrCon, const std::string& ipAddress) noexcept 
        : m_AddrCon(addrCon), m_IpAddress(ipAddress), m_PingPkt(GetPingPkt()) {}
    ~Socket() noexcept 
    {
        if(m_SocketFd == -1)
            return;
        if(close(m_SocketFd) != 0)
            std::cerr << "\nFailed to close socket! ID: [" << m_SocketFd << ']' << std::endl; 
    }


    bool Init() noexcept
    {
        m_SocketFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(m_SocketFd < 0)
        {
            std::cerr << "Failed to open socket! Make sure you are running with root privileges\n";
            return false;
        }

        int flags = fcntl(m_SocketFd, F_GETFL, 0);
        if (flags == -1) 
        {
            std::cerr << "Failed to receive socket flags!\n";
            return false;
        }
        flags = flags & ~O_NONBLOCK; // make socket blocking [(flags | O_NONBLOCK) = non blocking]
        fcntl(m_SocketFd, F_SETFL, flags);

        return true;
    }

    
    // returns the time needed to tracert
    double Trace(size_t hops) noexcept
    {
        const Time::TimePoint startTrace = Time::GetCurrentTime();

        // setting timeout of recv setting
        const timeval tv_out{ .tv_sec=RECV_TIMEOUT, .tv_usec=0 };
        if(setsockopt(m_SocketFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)) != 0)
        {
            std::cerr << "Failed to set receive timeout! Timeout: [" << RECV_TIMEOUT << "] sec/s\n";
            return Time::DeltaTime<std::milli>(Time::GetCurrentTime(), startTrace);
        }
        
        for(size_t i = 0; i < hops; ++i)
        {
            if (setsockopt(m_SocketFd, SOL_IP, IP_TTL, &m_TTL, sizeof(m_TTL)) != 0)
            {
                std::cerr << "Failed to set TTL socket options! TTL: " << m_TTL << std::endl;
                return Time::DeltaTime<std::milli>(Time::GetCurrentTime(), startTrace);
            }
            const std::optional<std::string> ipAddRecv = Ping();
            ++m_TTL;

            if(!ipAddRecv.has_value())
                continue;
            if(ipAddRecv.value() == std::string(m_IpAddress))
            {
                return Time::DeltaTime<std::milli>(Time::GetCurrentTime(), startTrace);
            }
        }
        std::cout << "\nCouldn't trace route to destination in " << hops << " hops" << std::endl;
        return Time::DeltaTime<std::milli>(Time::GetCurrentTime(), startTrace);
    }
};


int main(int argc, char** argv)
{
    const std::optional<CLA::UInput> uip = CLA::Handler(argc, argv);
    if(!uip.has_value())
        return EXIT_SUCCESS;

    const Time::TimePoint startTime = Time::GetCurrentTime();

    sockaddr_in addrCon;
    const std::string ipAddress = DNS::Lookup(uip.value().hostname, addrCon);
    const std::string reverseDNS = DNS::ReverseLookup(ipAddress);
    if(ipAddress.empty() || reverseDNS.empty()) return EXIT_SUCCESS;

    std::cout << "traceroute to '" << uip.value().hostname << "' (" << ipAddress <<  ")" << " reverse DNS '" << reverseDNS << "', " << uip.value().hops << " hops max, " << PING_PKT_S << " bytes packets" << std::endl;

    Socket socket(&addrCon, ipAddress);
    if(!socket.Init())
        return EXIT_SUCCESS;

    const double traceTime = socket.Trace(uip.value().hops);
    const double endTime = Time::DeltaTime<std::milli>(Time::GetCurrentTime(), startTime);
    std::cout << "\nTraceing time:   " << traceTime << " ms | " << (traceTime / 1000.0) << " sec\n";
    std::cout << "Traceroute time: " << endTime << " ms | " << (endTime / 1000.0) << " sec" << std::endl;
}
