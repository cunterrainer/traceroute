#pragma once
#ifdef _WIN32

//#define _WIN32_WINNT

// c++std
#include <iostream>
#include <optional>

// platform
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <strsafe.h>

#include "PlatIndep.h"

namespace Platform::Windows
{
    namespace DNS
    {
        static addrinfo* ResolveAddress(const char* addr, const char* port, int af, int type, int proto)
        {
            addrinfo hints;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_flags = addr ? 0 : AI_PASSIVE;
            hints.ai_family = af;
            hints.ai_socktype = type;
            hints.ai_protocol = proto;

            addrinfo* result = nullptr;
            INT dwRetval = getaddrinfo(addr, port, &hints, &result);
            if (dwRetval != 0)
            {
                std::cerr << "Failed to resolve hostname: '" << addr << "'\n";
                return nullptr;
            }

            return result;
        }
        

        static int PrintAddress(const SOCKADDR* sa, int salen)
        {
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];

            int hostlen = NI_MAXHOST;
            int servlen = NI_MAXSERV;

            int rc = getnameinfo(sa, salen, host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV);
            if (rc != 0)
            {
                std::cerr << "Failed to get name info!\n";
                return rc;
            }

            // If port is zero then don't print it
            if (strcmp(serv, "0") != 0)
            {
                if (sa->sa_family == AF_INET)
                    std::cout << "[" << host << "]:" << serv;
                else
                    std::cout << host << ':' << serv;
            }
            else
                std::cout << host;
            return NO_ERROR;
        }


        // get ip as string
        static std::optional<std::string> GetAddress(const addrinfo* aif)
        {
            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];

            const int hostlen = NI_MAXHOST;
            const int servlen = NI_MAXSERV;

            if (getnameinfo(aif->ai_addr, static_cast<int>(aif->ai_addrlen), host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV) != 0)
            {
                std::cerr << "Failed to get name info!\n";
                return std::nullopt;
            }

            return { host };
        }


        static std::optional<std::string> ReverseLookup(const addrinfo* aif)
        {
            char host[NI_MAXHOST];

            int rc = getnameinfo(aif->ai_addr, static_cast<int>(aif->ai_addrlen), host, NI_MAXHOST, nullptr, 0, 0);
            if (rc != 0)
            {
                std::cerr << "getnameinfo failed: " << rc << std::endl;
                return std::nullopt;
            }
            return std::string(host);
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

        static constexpr int cm_DataSize = 64; // bytes of data to sent
        static constexpr int cm_PacketLen = sizeof(ICMP_HDR) + cm_DataSize;
    private:
        SOCKET m_Sock = INVALID_SOCKET;
        addrinfo* m_Dest = nullptr;
        addrinfo* m_Local = nullptr;
        char* m_IcmpBuf = nullptr;
        int m_TTL = 32;
        WSAOVERLAPPED m_Recvol;
    private:
        int SetTTL()
        {
            int optlevel = IPPROTO_IP;
            int option = IP_TTL;
            int rc = NO_ERROR;

            rc = setsockopt(m_Sock, optlevel, option, (char*)&m_TTL, sizeof(m_TTL));
            if (rc == SOCKET_ERROR)
                std::cerr << "Failed to set TTL: " << m_TTL << " | Error: " << WSAGetLastError() << std::endl;
            return rc;
        }


        void InitIcmpHeader()
        {
            ICMP_HDR* icmpHdr = (ICMP_HDR*)m_IcmpBuf;

            constexpr int ICMPV4_ECHO_REQUEST_TYPE = 8;
            constexpr int ICMPV4_ECHO_REQUEST_CODE = 0;

            icmpHdr->icmp_type = ICMPV4_ECHO_REQUEST_TYPE;   // Request an ICMP echo
            icmpHdr->icmp_code = ICMPV4_ECHO_REQUEST_CODE;
            icmpHdr->icmp_id = (USHORT)GetCurrentProcessId();
            icmpHdr->icmp_checksum = 0;
            icmpHdr->icmp_sequence = 0;

            char* datapart = m_IcmpBuf + sizeof(ICMP_HDR);
            // Place some data in the buffer
            memset(datapart, 'E', cm_DataSize);
        }


        void SetIcmpSequence()
        {
            ICMP_HDR* icmpv4 = reinterpret_cast<ICMP_HDR*>(m_IcmpBuf);
            icmpv4->icmp_sequence = static_cast<USHORT>(GetTickCount64());
        }


        USHORT Checksum()
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
                cksum += *(UCHAR*)buf;
            }
            cksum = (cksum >> 16) + (cksum & 0xffff);
            cksum += (cksum >> 16);
            return (USHORT)(~cksum);
        }


        void ComputeIcmpChecksum()
        {
            ICMP_HDR* icmpv4 = reinterpret_cast<ICMP_HDR*>(m_IcmpBuf);
            icmpv4->icmp_checksum = 0;
            icmpv4->icmp_checksum = Checksum();
        }


        int PostRecvfrom(SOCKADDR* from, int* fromlen)
        {
            constexpr int MAX_RECV_BUF_LEN = 0xFFFF;  // Max incoming packet size.
            std::unique_ptr<char[]> recvbuf = std::make_unique<char[]>(MAX_RECV_BUF_LEN); // For received packets
            int recvbuflen = MAX_RECV_BUF_LEN;        // Length of received packets.

            WSABUF wbuf;
            wbuf.buf = recvbuf.get();
            wbuf.len = recvbuflen;

            DWORD flags = 0;
            DWORD bytes;

            int rc = WSARecvFrom(m_Sock, &wbuf, 1, &bytes, &flags, from, fromlen, &m_Recvol, nullptr);
            if (rc == SOCKET_ERROR)
            {
                if (WSAGetLastError() != WSA_IO_PENDING)
                {
                    std::cerr << "WSARecvFrom failed! Error: " << WSAGetLastError() << std::endl;
                    return SOCKET_ERROR;
                }
            }
            return NO_ERROR;
        }
    public:
        bool Init(const std::string& website)
        {
            // Load Winsock
            WSADATA wsaData;
            int rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (rc != 0) {
                std::cout << "WSAStartup failed: " << rc << std::endl;
                return false; // TODO: set error code so WSACleanup won't be called on destruction
            }


            m_Dest = DNS::ResolveAddress(website.c_str(), "0", AF_INET, 0, 0);
            if (m_Dest == nullptr) 
                return false;
            int addressFamiliy = m_Dest->ai_family;
            int protocol = IPPROTO_ICMP;


            std::optional<std::string> ipAddress = DNS::GetAddress(m_Dest);
            std::optional<std::string> reverseDNS = DNS::ReverseLookup(m_Dest);
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


            int packetLen = sizeof(ICMP_HDR);
            packetLen += cm_DataSize;


            // Allocate the buffer that will conatin the ICMP request
            m_IcmpBuf = static_cast<char*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetLen));
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


        ~Socket()
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

            WSACleanup();
        }


        void Ping()
        {
            // Post the first overlapped receive
            SOCKADDR_STORAGE from;
            int fromlen = sizeof(from);
            PostRecvfrom((SOCKADDR*)&from, &fromlen);

            for (int i = 0; i < 4; ++i)
            {
                SetIcmpSequence();
                ComputeIcmpChecksum();

                const PIndep::Time::TimePoint time = PIndep::Time::GetCurrentTimeH();
                int rc = sendto(m_Sock, m_IcmpBuf, cm_PacketLen, 0, m_Dest->ai_addr, (int)m_Dest->ai_addrlen);
                if (rc == SOCKET_ERROR)
                {
                    std::cerr << "Failed to send packet! Error: " << WSAGetLastError() << std::endl;
                    return;
                }

                // recvfrom

                // Wait for a response
                constexpr int DEFAULT_RECV_TIMEOUT = 1000;
                rc = WaitForSingleObject(m_Recvol.hEvent, DEFAULT_RECV_TIMEOUT);
                if (rc == WAIT_FAILED)
                {
                    std::cerr << "WaitForSingleObject failed! Error: " << GetLastError() << std::endl;
                    return;
                }
                else if (rc == WAIT_TIMEOUT)
                {
                    std::cout << "Request timed out " << std::endl;
                }
                else
                {
                    DWORD bytes;
                    DWORD flags;
                    rc = WSAGetOverlappedResult(m_Sock, &m_Recvol, &bytes, FALSE, &flags);
                    if (rc == FALSE)
                    {
                        std::cerr << "WSAGetOverlappedResult failed! Error: " << WSAGetLastError() << std::endl;
                    }

                    WSAResetEvent(m_Recvol.hEvent);

                    addrinfo inf;
                    inf.ai_addr = (SOCKADDR*)&from;
                    inf.ai_addrlen = fromlen;
                    PIndep::IO::PrintRecv(m_TTL, DNS::GetAddress(&inf).value(), PIndep::Time::DeltaTime<std::milli>(time, PIndep::Time::GetCurrentTimeH()));

                    if (i < 4 - 1)
                    {
                        fromlen = sizeof(from);
                        PostRecvfrom((SOCKADDR*)&from, &fromlen);
                    }
                }
                PIndep::Time::Sleep<std::chrono::seconds>(1);
            }
        }
    };


    static int Main(int argc, char** argv)
    {
        // fra16s52-in-f4.1e100.net
        const std::string website = "www.google.com";
        Socket socket;
        if (!socket.Init(website))
            return 1;
        socket.Ping();
        return 0;
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