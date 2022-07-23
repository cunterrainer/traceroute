#pragma once
#ifdef _WIN32

// c++std
#include <iostream>
#include <optional>
#include <array>
#include <string>
#include <string_view>

// platform
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <strsafe.h>

#include "PlatIndep.h"

namespace Platform::Windows
{
    namespace DNS
    {
        static addrinfo* ResolveAddress(const char* addr, const char* port, int af, int type, int proto) noexcept
        {
            addrinfo hints;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_flags = addr ? 0 : AI_PASSIVE;
            hints.ai_family = af;
            hints.ai_socktype = type;
            hints.ai_protocol = proto;

            addrinfo* result = nullptr;
            if (getaddrinfo(addr, port, &hints, &result) != 0)
            {
                std::cerr << "Failed to resolve hostname: '" << addr << "'\n";
                return nullptr;
            }

            return result;
        }


        // get ip as string
        static std::optional<std::string> GetAddress(const addrinfo* aif) noexcept
        {
            std::array<char, NI_MAXHOST> host;
            std::array<char, NI_MAXSERV> serv;

            if (getnameinfo(aif->ai_addr, static_cast<int>(aif->ai_addrlen), host.data(), NI_MAXHOST, serv.data(), NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) != 0)
            {
                std::cerr << "Failed to get name info!\n";
                return std::nullopt;
            }

            return std::string(host.data());
        }


        static std::optional<std::string> ReverseLookup(const addrinfo* aif) noexcept
        {
            std::array<char, NI_MAXHOST> host;

            if (int rc = getnameinfo(aif->ai_addr, static_cast<int>(aif->ai_addrlen), host.data(), NI_MAXHOST, nullptr, 0, 0) != 0)
            {
                std::cerr << "getnameinfo failed: " << rc << std::endl;
                return std::nullopt;
            }
            return std::string(host.data());
        }
    }

    
    class Socket
    {
    private:
        struct ICMP_HDR
        {
            unsigned char   icmp_type;
            unsigned char   icmp_code;
            unsigned short  icmp_checksum;
            unsigned short  icmp_id;
            unsigned short  icmp_sequence;
        };

        static constexpr uint8_t cm_DataSize = 64; // bytes of data to sent
        static constexpr uint8_t cm_PacketLen = sizeof(ICMP_HDR) + cm_DataSize;
    private:
        SOCKET m_Sock = INVALID_SOCKET;
        addrinfo* m_Dest  = nullptr;
        addrinfo* m_Local = nullptr;
        char* m_IcmpBuf   = nullptr;
        WSAOVERLAPPED m_Recvol = WSAOVERLAPPED();
        uint32_t m_TTL = 32;
        bool m_WSAStarted = false;
    private:
        inline int SetTTL() const noexcept
        {
            int optlevel = IPPROTO_IP;
            int option = IP_TTL;
            int rc = NO_ERROR;

            rc = setsockopt(m_Sock, optlevel, option, (char*)&m_TTL, sizeof(m_TTL));
            if (rc == SOCKET_ERROR)
                std::cerr << "Failed to set TTL: " << m_TTL << " | Error: " << WSAGetLastError() << std::endl;
            return rc;
        }


        inline void InitIcmpHeader() const noexcept
        {
            ICMP_HDR* const icmpHdr = reinterpret_cast<ICMP_HDR*>(m_IcmpBuf);

            constexpr int ICMPV4_ECHO_REQUEST_TYPE = 8;
            constexpr int ICMPV4_ECHO_REQUEST_CODE = 0;

            icmpHdr->icmp_type = ICMPV4_ECHO_REQUEST_TYPE;   // Request an ICMP echo
            icmpHdr->icmp_code = ICMPV4_ECHO_REQUEST_CODE;
            icmpHdr->icmp_id = static_cast<USHORT>(GetCurrentProcessId());
            icmpHdr->icmp_checksum = 0;
            icmpHdr->icmp_sequence = 0;

            char* datapart = m_IcmpBuf + sizeof(ICMP_HDR);
            // Place some data in the buffer
            memset(datapart, 'E', cm_DataSize);
        }


        inline void SetIcmpSequence() const noexcept
        {
            ICMP_HDR* const icmpv4 = reinterpret_cast<ICMP_HDR*>(m_IcmpBuf);
            icmpv4->icmp_sequence = static_cast<USHORT>(GetTickCount64());
        }


        inline USHORT Checksum() const noexcept
        {
            USHORT* buf = reinterpret_cast<USHORT*>(m_IcmpBuf);
            unsigned long cksum = 0;
            int size = cm_PacketLen;

            while (size > 1)
            {
                cksum += *buf++;
                size -= sizeof(USHORT);
            }
            if (size)
            {
                cksum += *reinterpret_cast<UCHAR*>(buf);
            }
            cksum = (cksum >> 16) + (cksum & 0xffff);
            cksum += (cksum >> 16);
            return (USHORT)(~cksum);
        }


        inline void ComputeIcmpChecksum() const noexcept
        {
            ICMP_HDR* const icmpv4 = reinterpret_cast<ICMP_HDR*>(m_IcmpBuf);
            icmpv4->icmp_checksum = Checksum();
        }


        inline int PostRecvfrom(SOCKADDR* from, int* fromlen) noexcept
        {
            constexpr uint16_t MAX_RECV_BUF_LEN = 0xFFFF;  // Max incoming packet size. | Length of received packets.
            std::unique_ptr<char[]> recvbuf = std::make_unique<char[]>(MAX_RECV_BUF_LEN); // For received packets

            WSABUF wbuf;
            wbuf.buf = recvbuf.get();
            wbuf.len = MAX_RECV_BUF_LEN;

            DWORD flags = 0;
            DWORD bytes = 0;

            if (WSARecvFrom(m_Sock, &wbuf, 1, &bytes, &flags, from, fromlen, &m_Recvol, nullptr) == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
            {
                std::cerr << "WSARecvFrom failed! Error: " << WSAGetLastError() << std::endl;
                return SOCKET_ERROR;
            }
            return NO_ERROR;
        }
    public:
        inline bool Init(const std::string_view& website) noexcept
        {
            // Load Winsock
            WSADATA wsaData;
            int rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (rc != 0) {
                std::cout << "WSAStartup failed: " << rc << std::endl;
                return false;
            }
            m_WSAStarted = true;


            m_Dest = DNS::ResolveAddress(website.data(), "0", AF_INET, 0, 0);
            if (m_Dest == nullptr) 
                return false;
            const int addressFamiliy = m_Dest->ai_family;
            const int protocol = IPPROTO_ICMP;


            const std::optional<std::string> ipAddress = DNS::GetAddress(m_Dest);
            const std::optional<std::string> reverseDNS = DNS::ReverseLookup(m_Dest);
            if (!ipAddress.has_value() || !reverseDNS.has_value())
                return false;
            std::cout << "traceroute to '" << website << "' (" << ipAddress.value() << ") reverse DNS '" << reverseDNS.value() << "'" << std::endl;


            // Get the bind address
            m_Local = DNS::ResolveAddress(nullptr, "0", AF_INET, 0, 0);
            if (m_Local == nullptr)
                return false;


            // Create raw socket
            m_Sock = socket(addressFamiliy, SOCK_RAW, protocol);
            if (m_Sock == INVALID_SOCKET)
            {
                std::cerr << "Failed to create socket! Error: " << WSAGetLastError() << '\n';
                return false;
            }


            if (SetTTL() == SOCKET_ERROR)
                return false;

            
            // Allocate the buffer that will conatin the ICMP request
            m_IcmpBuf = static_cast<char*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cm_PacketLen));
            if (m_IcmpBuf == nullptr)
            {
                std::cerr << "HeapAlloc failed! Error: " << GetLastError() << std::endl;
                return false;
            }


            // Initialize the ICMP headers
            InitIcmpHeader();


            // Bind the socket -- need to do this since we post a receive first
            rc = bind(m_Sock, m_Local->ai_addr, static_cast<int>(m_Local->ai_addrlen));
            if (rc == SOCKET_ERROR)
            {
                std::cerr << "Failed to bind socket! Error: " << WSAGetLastError() << std::endl;
                return false;
            }


            // Setup the receive operation
            m_Recvol.hEvent = WSA_INVALID_EVENT;
            memset(&m_Recvol, 0, sizeof(m_Recvol));
            m_Recvol.hEvent = WSACreateEvent();
            if (m_Recvol.hEvent == WSA_INVALID_EVENT) {
                std::cerr << "Failed to create WSAEvent! Error: " << WSAGetLastError() << std::endl;
                return false;
            }

            return true;
        }


        constexpr Socket() noexcept { m_Recvol.hEvent = WSA_INVALID_EVENT; }
        inline ~Socket() noexcept
        {
            if (m_Dest)
                freeaddrinfo(m_Dest);
            if (m_Local)
                freeaddrinfo(m_Local);
            if (m_Sock != INVALID_SOCKET)
                closesocket(m_Sock);
            if (m_Recvol.hEvent != WSA_INVALID_EVENT)
                WSACloseEvent(m_Recvol.hEvent);
            if (m_IcmpBuf)
                HeapFree(GetProcessHeap(), 0, m_IcmpBuf);
            if(m_WSAStarted)
                WSACleanup();
        }
        constexpr Socket(const Socket&) = delete;
        constexpr Socket(const Socket&&) = delete;
        constexpr Socket& operator=(const Socket&) = delete;
        constexpr Socket&& operator=(const Socket&&) = delete;


        inline uint8_t Ping(const std::string_view& website) noexcept
        {
            if (!Init(website))
                return EXIT_FAILURE;

            // Post the first overlapped receive
            SOCKADDR_STORAGE from;
            int fromlen = sizeof(from);

            PostRecvfrom((SOCKADDR*)&from, &fromlen);
            for (uint32_t i = 0; i < 32; ++i)
            {
                SetIcmpSequence();
                ComputeIcmpChecksum();

                const PIndep::Time::TimePoint time = PIndep::Time::CurrentTime();
                int rc = sendto(m_Sock, m_IcmpBuf, cm_PacketLen, 0, m_Dest->ai_addr, (int)m_Dest->ai_addrlen);
                if (rc == SOCKET_ERROR)
                {
                    std::cerr << "Failed to send packet! Error: " << WSAGetLastError() << std::endl;
                    return EXIT_FAILURE;
                }


                // Wait for a response
                constexpr uint16_t DEFAULT_RECV_TIMEOUT = 1000;
                rc = WaitForSingleObject(m_Recvol.hEvent, DEFAULT_RECV_TIMEOUT);
                if (rc == WAIT_FAILED)
                {
                    std::cerr << "WaitForSingleObject failed! Error: " << GetLastError() << std::endl;
                    return EXIT_FAILURE;
                }
                else if (rc == WAIT_TIMEOUT)
                {
                    std::cout << "Request timed out" << std::endl;
                }
                else
                {
                    DWORD bytes = 0;
                    DWORD flags = 0;
                    rc = WSAGetOverlappedResult(m_Sock, &m_Recvol, &bytes, FALSE, &flags);
                    if (rc == FALSE)
                    {
                        std::cerr << "WSAGetOverlappedResult failed! Error: " << WSAGetLastError() << std::endl;
                    }
                    
                    WSAResetEvent(m_Recvol.hEvent);

                    addrinfo inf;
                    inf.ai_addr = (SOCKADDR*)&from;
                    inf.ai_addrlen = fromlen;
                    PIndep::IO::PrintRecv(m_TTL, DNS::GetAddress(&inf).value(), PIndep::Time::DeltaTime<std::milli>(PIndep::Time::CurrentTime(), time));

                    if (i < 4 - 1)
                    {
                        fromlen = sizeof(from);
                        PostRecvfrom((SOCKADDR*)&from, &fromlen);
                    }
                }
                PIndep::Time::Sleep<std::chrono::seconds>(1);
            }
            return EXIT_SUCCESS;
        }
    };


    // [[maybe_unused]] attribute because comp keeps complaining, will be removed eventually
    static int Main([[maybe_unused]] int argc, [[maybe_unused]] char** argv)
    {
        // fra16s52-in-f4.1e100.net
        const std::string website = "www.google.com";
        Socket socket;
        return socket.Ping(website);
    }
}
#endif




//hints.ai_family = AF_INET;
//hints.ai_socktype = SOCK_RAW;
//hints.ai_protocol = IPPROTO_ICMP;



//int timeout = 6000;
//setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

//sockaddr fromR;
//int fromRLen = sizeof(fromR);
//iResult = recvfrom(s, recvbuf, recvbuflen, 0, &fromR, &fromRLen);
//if (iResult == SOCKET_ERROR)
//{
//    std::cerr << "recvfrom failed! Error: " << WSAGetLastError() << std::endl;
//    DNS::PrintAddress(&fromR, fromRLen);
//    goto CLEANUP;
//}





/*
    DWORD timeout = 1000;
    setsockopt(m_Sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr fromR;
    int fromRLen = sizeof(fromR);

    constexpr int MAX_RECV_BUF_LEN = 0xFFFF;  // Max incoming packet size.
    std::unique_ptr<char[]> recvbuf = std::make_unique<char[]>(MAX_RECV_BUF_LEN); // For received packets
    int recvbuflen = MAX_RECV_BUF_LEN;        // Length of received packets.

    rc = recvfrom(m_Sock, recvbuf.get(), recvbuflen, 0, &fromR, &fromRLen);
    if (rc == SOCKET_ERROR)
    {
        std::cerr << "recvfrom failed! Error: " << WSAGetLastError() << std::endl;
    }
*/