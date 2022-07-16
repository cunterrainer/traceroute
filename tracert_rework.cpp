// c++std
#include <asm-generic/socket.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <optional>

// cstd
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

// net
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>


// Define the Packet Constants
#define PING_PKT_S      64      // ping packet size
#define PORT_NO         0       // Automatic port number
#define PING_SLEEP_RATE 1000000 // sleeping time between pings
#define RECV_TIMEOUT    1       // timeout delay for receiving packets in seconds


// ping packet structure
struct ping_pkt
{
    icmphdr hdr;
    char msg[PING_PKT_S-sizeof(icmphdr)];
};
 

// Calculating the Check Sum
unsigned short checksum(void *b, int len)
{    unsigned short *buf = static_cast<unsigned short*>(b);
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


namespace DNS
{
    std::string Lookup(const std::string& address, sockaddr_in& addrCon)
    {
        std::cout << "\nResolving DNS...\n";

        hostent* hostEntity;
        if((hostEntity = gethostbyname(address.c_str())) == nullptr) {
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
            std::cout << "Could not resolve reverse lookup of hostname\n";
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
    static int sm_TTL;
private:
    sockaddr_in* m_AddrCon;
    const char* m_IpAddress;
    const char* m_HostName;
    const char* m_ReverseHostname;

    int m_SocketFd = -1;
public:
    Socket(sockaddr_in* addrCon, const char* ipAddress, const char* hostname, const char* reverseHostname) noexcept
        : m_AddrCon(addrCon), m_IpAddress(ipAddress), m_HostName(hostname), m_ReverseHostname(reverseHostname) {}
    ~Socket() noexcept 
    {
        if(close(m_SocketFd) != 0)
            std::cout << "\nFailed to close socket: " << m_SocketFd << std::endl;
    }


    bool Init() noexcept
    {
        m_SocketFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(m_SocketFd < 0)
        {
            std::cout << "Socket file descriptor not received!\n";
            return false;
        }

        int flags = fcntl(m_SocketFd, F_GETFL, 0);
        if (flags == -1) return false;
        flags = flags & ~O_NONBLOCK; // make socket blocking [(flags | O_NONBLOCK) = non blocking]
        fcntl(m_SocketFd, F_SETFL, flags);

        return true;
    }


    std::optional<std::string> Ping() noexcept
    {
        // setting timeout of recv setting
        const timeval tv_out{ .tv_sec=RECV_TIMEOUT, .tv_usec=0 };
        //setsockopt(m_SocketFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));
        if (setsockopt(m_SocketFd, SOL_IP, IP_TTL, &sm_TTL, sizeof(sm_TTL)) != 0)
        {
            std::cout << "\nSetting socket options to TTL failed!\n";
            return std::nullopt;
        }


        ping_pkt pckt;
        //filling packet
        bzero(&pckt, sizeof(pckt));
        
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid();

        long unsigned int i;
        int msg_count = 0;
        for (i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));
 
        Time::Sleep<std::chrono::microseconds>(PING_SLEEP_RATE);
 
        //send packet
        const Time::TimePoint timeStart = Time::GetCurrentTime();
        if (sendto(m_SocketFd, &pckt, sizeof(pckt), MSG_WAITALL, (sockaddr*) m_AddrCon, sizeof(*m_AddrCon)) <= 0)
        {
            std::cout << "\nPacket Sending Failed!\n";
            return std::nullopt;
        }
        
        //receive packet
        sockaddr_in r_addr;
        int addr_len = sizeof(r_addr);
        
        if (recvfrom(m_SocketFd, &pckt, sizeof(pckt), MSG_WAITALL, (sockaddr*)&r_addr, (socklen_t*)&addr_len) <= 0)
        {
            if(errno != EAGAIN)
            {
                std::cout << "\nPacket receive failed!\n";
                std::cout << "Error: " << strerror(errno) << "\n\n";
                return std::nullopt;
            }
        }

        const double rtt_msec = Time::DeltaTime<std::milli>(Time::GetCurrentTime(), timeStart);
        std::string ipAddPckRecv = std::string(inet_ntoa(r_addr.sin_addr));
        std::cout << "ICMP packet received from " << ipAddPckRecv << " ttl=" << sm_TTL << " rtt=" << rtt_msec << " ms" << '\n';
        ++sm_TTL;
        return ipAddPckRecv;
    }
};
int Socket::sm_TTL = 1;


int main()
{
    const std::string website = "www.google.com";

    sockaddr_in addrCon;

    const std::string ipAddress = DNS::Lookup(website, addrCon);
    if(ipAddress.empty())
    {
        std::cout << "\nDNS lookup failed! Could not resolve hostname!\n";
        return EXIT_FAILURE;
    }

    const std::string reverseHostname = DNS::ReverseLookup(ipAddress);
    if(reverseHostname.empty()) return EXIT_FAILURE;

    std::cout << "Trying to connect to '" << website << "' IP: " << ipAddress << '\n';
    std::cout << "Reverse lookup domain: " << reverseHostname << "\n\n";

    Socket socket(&addrCon, ipAddress.c_str(), website.c_str(), reverseHostname.c_str());
    if(!socket.Init())
        return EXIT_FAILURE;
    for(int i = 0; i < 8; ++i)
    {
        std::optional<std::string> ipAddRecv = socket.Ping();

        if(!ipAddRecv.has_value())
            return EXIT_FAILURE;
        
        if(ipAddRecv.value() == ipAddress)
            return EXIT_SUCCESS;
    }
}
