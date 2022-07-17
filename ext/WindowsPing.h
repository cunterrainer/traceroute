#pragma once
#ifdef _WIN32

//#define _WIN32_WINNT

/*
    - lookup ip from hostname
    - resolve reverse hostname
    - open socket
    - Trace:
        - Send
        - Recieve
    - close socket
*/

// c++std
#include <iostream>

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
            //hints.ai_family = AF_INET;
            //hints.ai_socktype = SOCK_RAW;
            //hints.ai_protocol = IPPROTO_ICMP;

            addrinfo hints;
            ZeroMemory(&hints, sizeof(hints));
            hints.ai_flags = ((addr) ? 0 : AI_PASSIVE);
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


        int PrintAddress(SOCKADDR* sa, int salen)
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
                    std::cout << "[" << host << "]:" << serv;// << std::endl;
                else
                    std::cout << host << ':' << serv;// << std::endl;
            }
            else
                std::cout << host;// << std::endl;
            return NO_ERROR;
        }
    }


    struct ICMP_HDR
    {
        unsigned char   icmp_type;
        unsigned char   icmp_code;
        unsigned short  icmp_checksum;
        unsigned short  icmp_id;
        unsigned short  icmp_sequence;
    }; // ICMP_HDR, * PICMP_HDR, FAR* LPICMP_HDR;


    // ICMP types and codes
    #define ICMPV4_ECHO_REQUEST_TYPE 8
    #define ICMPV4_ECHO_REQUEST_CODE 0
    static void InitIcmpHeader(char* buf, int dataSize)
    {
        ICMP_HDR* icmpHdr = (ICMP_HDR*)buf;
        char* datapart = nullptr;

        icmpHdr->icmp_type = ICMPV4_ECHO_REQUEST_TYPE;   // Request an ICMP echo
        icmpHdr->icmp_code = ICMPV4_ECHO_REQUEST_CODE;
        icmpHdr->icmp_id = (USHORT)GetCurrentProcessId();
        icmpHdr->icmp_checksum = 0;
        icmpHdr->icmp_sequence = 0;

        datapart = buf + sizeof(ICMP_HDR);
        // Place some data in the buffer
        memset(datapart, 'E', dataSize);
    }


    static int SetTTL(SOCKET s, int ttl)
    {
        int optlevel = IPPROTO_IP;
        int option = IP_TTL;
        int rc = NO_ERROR;

        rc = setsockopt(s, optlevel, option, (char*)&ttl, sizeof(ttl));
        if (rc == SOCKET_ERROR)
            std::cerr << "Failed to set TTL: " << ttl << " | Error: " << WSAGetLastError() << std::endl;
        return rc;
    }


    int PostRecvfrom(SOCKET s, char* buf, int buflen, SOCKADDR* from, int* fromlen, WSAOVERLAPPED* ol)
    {
        WSABUF wbuf;
        wbuf.buf = buf;
        wbuf.len = buflen;

        DWORD flags = 0;
        DWORD bytes;

        int rc = WSARecvFrom(s, &wbuf, 1, &bytes, &flags, from, fromlen, ol, nullptr);
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


    void SetIcmpSequence(char* buf)
    {
        ICMP_HDR* icmpv4 = reinterpret_cast<ICMP_HDR*>(buf);
        icmpv4->icmp_sequence = static_cast<USHORT>(GetTickCount());
    }


    USHORT Checksum(USHORT* buffer, int size)
    {
        unsigned long cksum = 0;

        while (size > 1)
        {
            cksum += *buffer++;
            size -= sizeof(USHORT);
        }
        if (size)
        {
            cksum += *(UCHAR*)buffer;
        }
        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);
        return (USHORT)(~cksum);
    }


    void ComputeIcmpChecksum(SOCKET s, char* buf, int packetlen, struct addrinfo* dest)
    {
        ICMP_HDR* icmpv4 = reinterpret_cast<ICMP_HDR*>(buf);
        icmpv4->icmp_checksum = 0;
        icmpv4->icmp_checksum = Checksum((USHORT*)buf, packetlen);
    }


    int ReverseLookup(SOCKADDR* sa, int salen, char* buf, int buflen)
    {
        char    host[NI_MAXHOST];
        int     hostlen = NI_MAXHOST,
            rc;
        HRESULT hRet;

        rc = getnameinfo(
            sa,
            salen,
            host,
            hostlen,
            NULL,
            0,
            0
        );
        if (rc != 0)
        {
            fprintf(stderr, "getnameinfo failed: %d\n", rc);
            return rc;
        }

        buf[0] = '\0';
        if (FAILED(hRet = StringCchCopy(buf, buflen, host)))
        {
            fprintf(stderr, "StringCchCopy failed: 0x%x\n", hRet);
            return (int)hRet;
        }

        return NO_ERROR;
    }


    static int Main(int argc, char** argv)
    {
        // fra16s52-in-f4.1e100.net
        const std::string website = "fra16s52-in-f4.1e100.net";
        
        // Load Winsock
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed: %d\n", iResult);
            return 1;
        }


        addrinfo* dest = DNS::ResolveAddress(website.c_str(), "0", AF_INET, 0, 0);
        if (dest == nullptr) goto CLEANUP;
        int addressFamiliy = dest->ai_family;
        int protocol = IPPROTO_ICMP;

        
        // Get the bind address
        addrinfo* local = DNS::ResolveAddress(nullptr, "0", AF_INET, 0, 0);
        if (local == nullptr) goto CLEANUP;


        // Create raw socket
        SOCKET s = socket(addressFamiliy, SOCK_RAW, protocol);
        if (s == INVALID_SOCKET)
        {
            std::cerr << "Failed to create socket! Error: " << WSAGetLastError() << '\n';
            goto CLEANUP;
        }


        int ttl = 1;
        SetTTL(s, ttl);
        std::cout << "Set ttl" << std::endl;

        int packetLen = sizeof(ICMP_HDR);
        int dataSize = 64; // size of data to send
        packetLen += dataSize;


        // Allocate the buffer that will conatin the ICMP request
        char* icmpBuf = static_cast<char*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetLen));
        if (icmpBuf == nullptr)
        {
            std::cerr << "HeapAlloc failed! Error: " << GetLastError() << std::endl;
            goto CLEANUP;
        }


        // Initialize the ICMP headers
        InitIcmpHeader(icmpBuf, dataSize);


        // Bind the socket -- need to do this since we post a receive first
        iResult = bind(s, local->ai_addr, (int)local->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            std::cerr << "Failed to bind socket! Error: " << WSAGetLastError() << std::endl;
            goto CLEANUP;
        }


        // Setup the receive operation
        WSAOVERLAPPED recvol;
        recvol.hEvent = WSA_INVALID_EVENT;
        memset(&recvol, 0, sizeof(recvol));
        recvol.hEvent = WSACreateEvent();
        if (recvol.hEvent == WSA_INVALID_EVENT) {
            std::cerr << "Failed to create WSAEvent! Error: " << WSAGetLastError() << std::endl;
            goto CLEANUP;
        }


        // Post the first overlapped receive
        SOCKADDR_STORAGE from;
        int fromlen = sizeof(from);

        #define MAX_RECV_BUF_LEN 0xFFFF    // Max incoming packet size.
        char recvbuf[MAX_RECV_BUF_LEN];    // For received packets
        int recvbuflen = MAX_RECV_BUF_LEN; // Length of received packets.
        //PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);


        DNS::PrintAddress(dest->ai_addr, (int)dest->ai_addrlen);
        //ReverseLookup(dest->ai_addr, (int)dest->ai_addrlen, recvbuf, recvbuflen);
        //std::cout << ' ' << recvbuf << std::endl;
        std::cout << std::endl;


        for (int i = 0; i < 4; ++i)
        {
            SetIcmpSequence(icmpBuf);
            ComputeIcmpChecksum(s, icmpBuf, packetLen, dest);

            int time = GetTickCount();
            iResult = sendto(s, icmpBuf, packetLen, 0, dest->ai_addr, (int)dest->ai_addrlen);
            if (iResult == SOCKET_ERROR)
            {
                std::cerr << "Failed to send packet! Error: " << WSAGetLastError() << std::endl;
                goto CLEANUP;
            }

            int timeout = 6000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

            sockaddr fromR;
            int fromRLen = sizeof(fromR);
            iResult = recvfrom(s, recvbuf, recvbuflen, 0, &fromR, &fromRLen);
            if (iResult == SOCKET_ERROR)
            {
                std::cerr << "recvfrom failed! Error: " << WSAGetLastError() << std::endl;
                DNS::PrintAddress(&fromR, fromRLen);
                goto CLEANUP;
            }


            // Wait for a response
            //#define DEFAULT_RECV_TIMEOUT 6000
            //iResult = WaitForSingleObject((HANDLE)recvol.hEvent, DEFAULT_RECV_TIMEOUT);
            if (iResult == WAIT_FAILED)
            {
                std::cerr << "WaitForSingleObject failed! Error: " << GetLastError() << std::endl;
                goto CLEANUP;
            }
            else if (iResult == WAIT_TIMEOUT)
            {
                std::cout << "Request timed out " << std::endl;
                //DNS::PrintAddress((SOCKADDR*)&from, fromlen);
                std::cout << std::endl;
            }
            else
            {
                std::cout << "Got message\n";
                DWORD bytes;
                DWORD flags;
                iResult = WSAGetOverlappedResult(s, &recvol, &bytes, FALSE, &flags);
                if (iResult == FALSE)
                {
                    std::cerr << "WSAGetOverlappedResult failed! Error: " << WSAGetLastError() << std::endl;
                }
                time = GetTickCount() - time;

                WSAResetEvent(recvol.hEvent);

                std::cout << "Reply from: ";
                DNS::PrintAddress((SOCKADDR*)&fromR, fromRLen);
                if (time == 0)
                    printf(": bytes=%d time<1ms TTL=%d\n", dataSize, ttl);
                else
                    printf(": bytes=%d time=%dms TTL=%d\n", dataSize, time, ttl);

                if (i < 4 - 1)
                {
                    fromlen = sizeof(from);
                    //PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);
                }
            }
            PIndep::Time::Sleep<std::chrono::seconds>(1);
            ++ttl;
            SetTTL(s, ttl);
        }



    CLEANUP:
        if (dest)
            freeaddrinfo(dest);
        if (local)
            freeaddrinfo(local);
        if (s != INVALID_SOCKET)
            closesocket(s);
        if (recvol.hEvent != WSA_INVALID_EVENT)
            WSACloseEvent(recvol.hEvent);
        if (icmpBuf)
            HeapFree(GetProcessHeap(), 0, icmpBuf);

        WSACleanup();
        return argc;
    }
}
#endif