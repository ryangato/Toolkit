// This code is part of DNSPing
// Ping with DNS requesting.
// Copyright (C) 2014-2015 Chengr28
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#include "Process.h"

//Send DNS requesting process
size_t __fastcall SendProcess(const sockaddr_storage &Target, const bool LastSend)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[BufferSize]()), RecvBuffer(new char[BufferSize]());
	SSIZE_T DataLength = 0;
#if defined(PLATFORM_WIN)
	LARGE_INTEGER CPUFrequency = {0}, BeforeTime = {0}, AfterTime = {0};
	int AddrLen = 0;
#elif defined(PLATFORM_LINUX)
	timeval BeforeTime = {0}, AfterTime = {0};
	socklen_t AddrLen = 0;
#endif
	SOCKET Socket = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Socket initialization
		AddrLen = sizeof(sockaddr_in6);
		if (RawSocket && RawData)
			Socket = socket(AF_INET6, SOCK_RAW, ServiceName);
		else 
			Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (Socket == INVALID_SOCKET)
		{
			wprintf_s(_T("Socket initialization error, error code is %d.\n"), WSAGetLastError());

			WSACleanup();
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
	//Socket initialization
		AddrLen = sizeof(sockaddr_in);
		if (RawSocket && RawData)
			Socket = socket(AF_INET, SOCK_RAW, ServiceName);
		else 
			Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (Socket == INVALID_SOCKET)
		{
			wprintf_s(_T("Socket initialization error, error code is %d.\n"), WSAGetLastError());

			WSACleanup();
			return EXIT_FAILURE;
		}
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&SocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&SocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif defined(PLATFORM_LINUX)
	if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, &SocketTimeout, sizeof(timeval)) == SOCKET_ERROR ||
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, &SocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		wprintf_s(_T("Set UDP socket timeout error, error code is %d.\n"), WSAGetLastError());
		return EXIT_FAILURE;
	}

//Set IP options.
	if (Protocol == AF_INET6) //IPv6
	{
	#if defined(PLATFORM_WIN)
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, (PSTR)&IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#elif defined(PLATFORM_LINUX)
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, &IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#endif
		{
			wprintf_s(_T("Set HopLimit or TTL flag error, error code is %d.\n"), WSAGetLastError());
			return EXIT_FAILURE;
		}
	}
	else { //IPv4
	#if defined(PLATFORM_WIN)
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IP_TTL, (PSTR)&IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#elif defined(PLATFORM_LINUX)
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IP_TTL, &IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#endif
		{
			wprintf_s(_T("Set HopLimit or TTL flag error, error code is %d.\n"), WSAGetLastError());
			return EXIT_FAILURE;
		}

	//Set "Don't Fragment" flag.
	//All Non-SOCK_STREAM will set "Don't Fragment" flag(Linux).
	#if defined(PLATFORM_WIN)
		int iIPv4_DF = 1;
		if (IPv4_DF && setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, (PSTR)&iIPv4_DF, sizeof(int)) == SOCKET_ERROR)
		{
			wprintf_s(L"Set \"Don't Fragment\" flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	#endif
	}

	dns_hdr *pdns_hdr = nullptr;
//Make packet.
	if (!RawData)
	{
	//DNS requesting
		memcpy_s(Buffer.get() + DataLength, BufferSize, &HeaderParameter, sizeof(dns_hdr));
		if (HeaderParameter.ID == 0)
		{
			pdns_hdr = (dns_hdr *)(Buffer.get() + DataLength);
			pdns_hdr->ID = htons((uint16_t)GetCurrentProcessId());
		}
		DataLength += sizeof(dns_hdr);
		DataLength += CharToDNSQuery((PSTR)TestDomain.c_str(), Buffer.get() + DataLength);
		memcpy_s(Buffer.get() + DataLength, BufferSize, &QueryParameter, sizeof(dns_qry));
		DataLength += sizeof(dns_qry);
		if (EDNS0)
		{
			memcpy_s(Buffer.get() + DataLength, BufferSize, &EDNS0Parameter, sizeof(dns_opt_record));
			DataLength += sizeof(dns_opt_record);
		}
	}
	else {
		if (BufferSize >= RawDataLen)
		{
			memcpy_s(Buffer.get(), BufferSize, RawData.get(), RawDataLen);
			DataLength = RawDataLen;
		}
		else {
			memcpy_s(Buffer.get(), BufferSize, RawData.get(), BufferSize);
			DataLength = BufferSize;
		}
	}

//Send requesting.
#if defined(PLATFORM_WIN)
	if (QueryPerformanceFrequency(&CPUFrequency) == 0 || QueryPerformanceCounter(&BeforeTime) == 0)
	{
		wprintf_s(L"Get current time from High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
		return EXIT_FAILURE;
	}
	sendto(Socket, Buffer.get(), (int)DataLength, 0, (PSOCKADDR)&Target, AddrLen);
#elif defined(PLATFORM_LINUX)
	if (gettimeofday(&BeforeTime, NULL) != 0)
	{
		printf("Get current time error, error code is %d.\n", errno);
		return EXIT_FAILURE;
	}
	sendto(Socket, Buffer.get(), DataLength, MSG_NOSIGNAL, (PSOCKADDR)&Target, AddrLen);
#endif

//Receive response.
#if defined(PLATFORM_WIN)
	DataLength = recvfrom(Socket, RecvBuffer.get(), (int)BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
	if (QueryPerformanceCounter(&AfterTime) == 0)
	{
		wprintf_s(L"Get current time from High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
		return EXIT_FAILURE;
	}
#elif defined(PLATFORM_LINUX)
	DataLength = recvfrom(Socket, RecvBuffer.get(), BufferSize, MSG_NOSIGNAL, (PSOCKADDR)&Target, &AddrLen);
	if (gettimeofday(&AfterTime, NULL) != 0)
	{
		printf("Get current time error, error code is %d.\n", errno);
		return EXIT_FAILURE;
	}
#endif

//Get waiting time.
#if defined(PLATFORM_WIN)
	long double Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);
#elif defined(PLATFORM_LINUX)
	long double Result = (long double)(AfterTime.tv_sec - BeforeTime.tv_sec) * (long double)SECOND_TO_MILLISECOND;
	if (AfterTime.tv_sec >= BeforeTime.tv_sec)
		Result += (long double)(AfterTime.tv_usec - BeforeTime.tv_usec) / (long double)MICROSECOND_TO_MILLISECOND;
	else
		Result += (long double)(AfterTime.tv_usec + SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND - BeforeTime.tv_usec) / (long double)MICROSECOND_TO_MILLISECOND;
#endif

//Print to screen.
	if (DataLength > 0)
	{
	//Validate packet.
		if (Validate && pdns_hdr != nullptr && !ValidatePacket(RecvBuffer.get(), DataLength, pdns_hdr->ID))
		{
		#if defined(PLATFORM_WIN)
			wprintf_s(L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#elif defined(PLATFORM_LINUX)
			printf(("Receive from %s:%u -> %d bytes but validate error, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fprintf(OutputFile, ("Receive from %s:%u -> %d bytes but validate error, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#endif

		//Try to waiting correct packet.
			while (true)
			{
			//Timeout
			#if defined(PLATFORM_WIN)
				if (Result >= SocketTimeout)
					break;
			#elif defined(PLATFORM_LINUX)
				if (Result >= SocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND + SocketTimeout.tv_sec * SECOND_TO_MILLISECOND)
					break;
			#endif

			//Receive.
				memset(RecvBuffer.get(), 0, BufferSize);
			#if defined(PLATFORM_WIN)
				DataLength = recvfrom(Socket, RecvBuffer.get(), (int)BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
				if (QueryPerformanceCounter(&AfterTime) == 0)
				{
					wprintf_s(_T("Get current time from High Precision Event Timer/HPET error, error code is %d.\n"), (int)GetLastError());
					return EXIT_FAILURE;
				}

			//Get waiting time.
				Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);

			#elif defined(PLATFORM_LINUX)
			//Receive.
				DataLength = recvfrom(Socket, RecvBuffer.get(), BufferSize, MSG_NOSIGNAL, (PSOCKADDR)&Target, &AddrLen);

			//Get waiting time.
				if (gettimeofday(&AfterTime, NULL) != 0)
				{
					printf("Get current time error, error code is %d.\n", errno);
					return EXIT_FAILURE;
				}
				Result = (long double)(AfterTime.tv_sec - BeforeTime.tv_sec) * (long double)SECOND_TO_MILLISECOND;
				if (AfterTime.tv_sec >= BeforeTime.tv_sec)
					Result += (long double)(AfterTime.tv_usec - BeforeTime.tv_usec) / (long double)MICROSECOND_TO_MILLISECOND;
				else
					Result += (long double)(AfterTime.tv_usec + SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND - BeforeTime.tv_usec) / (long double)MICROSECOND_TO_MILLISECOND;
			#endif


			//SOCKET_ERROR
				if (DataLength <= 0)
					break;

			//Validate packet.
				if (!ValidatePacket(RecvBuffer.get(), DataLength, pdns_hdr->ID))
				{
				#if defined(PLATFORM_WIN)
					wprintf_s(L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
					if (OutputFile != nullptr)
						fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				#elif defined(PLATFORM_LINUX)
					printf(("Receive from %s:%u -> %d bytes but validate error, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
					if (OutputFile != nullptr)
						fprintf(OutputFile, ("Receive from %s:%u -> %d bytes but validate error, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				#endif
				}
				else {
					break;
				}
			}

			if (DataLength <= 0)
			{
			#if defined(PLATFORM_WIN)
				wprintf_s(_T("Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n"), (int)DataLength, WSAGetLastError(), Result);
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, _T("Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n"), (int)DataLength, WSAGetLastError(), Result);
			#elif defined(PLATFORM_LINUX)
				printf(("Receive error: %d(%d), waiting correct answers timeout(%Lf ms).\n"), (int)DataLength, WSAGetLastError(), Result);
				if (OutputFile != nullptr)
					fprintf(OutputFile, ("Receive error: %d(%d), waiting correct answers timeout(%Lf ms).\n"), (int)DataLength, WSAGetLastError(), Result);
			#endif

				return EXIT_SUCCESS;
			}
			else {
		#if defined(PLATFORM_WIN)
				wprintf_s(_T("Receive from %ls:%u -> %d bytes, waiting %lf ms.\n"), wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, _T("Receive from %ls:%u -> %d bytes, waiting %lf ms.\n"), wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#elif defined(PLATFORM_LINUX)
				printf(("Receive from %s:%u -> %d bytes, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				if (OutputFile != nullptr)
					fprintf(OutputFile, ("Receive from %s:%u -> %d bytes, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#endif
			}
		}
		else {
		#if defined(PLATFORM_WIN)
			wprintf_s(_T("Receive from %ls:%u -> %d bytes, waiting %lf ms.\n"), wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, _T("Receive from %ls:%u -> %d bytes, waiting %lf ms.\n"), wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#elif defined(PLATFORM_LINUX)
			printf(("Receive from %s:%u -> %d bytes, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fprintf(OutputFile, ("Receive from %s:%u -> %d bytes, waiting %Lf ms.\n"), TargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
		#endif
		}

	//Print response result or data.
		if (ShowResponse)
		{
			PrintResponse(RecvBuffer.get(), DataLength);
			if (OutputFile != nullptr)
				PrintResponse(RecvBuffer.get(), DataLength, OutputFile);
		}
		if (ShowResponseHex)
		{
			PrintResponseHex(RecvBuffer.get(), DataLength);
			if (OutputFile != nullptr)
				PrintResponseHex(RecvBuffer.get(), DataLength, OutputFile);
		}

	//Calculate time.
		TotalTime += Result;
		++RecvNum;

	//Mark time.
		if (MaxTime == 0)
		{
			MinTime = Result;
			MaxTime = Result;
		}
		else if (Result < MinTime)
		{
			MinTime = Result;
		}
		else if (Result > MaxTime)
		{
			MaxTime = Result;
		}
	}
	else { //SOCKET_ERROR
	#if defined(PLATFORM_WIN)
		wprintf_s(L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);
		if (OutputFile != nullptr)
			fwprintf_s(OutputFile, L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);
	#elif defined(PLATFORM_LINUX)
		printf(("Receive error: %d(%d), waiting %Lf ms.\n"), (int)DataLength, errno, Result);
		if (OutputFile != nullptr)
			fprintf(OutputFile, ("Receive error: %d(%d), waiting %Lf ms.\n"), (int)DataLength, errno, Result);
	#endif
	}

//Transmission interval
	if (!LastSend)
	{
	#if defined(PLATFORM_WIN)
		if (TransmissionInterval != 0 && TransmissionInterval > Result)
			Sleep((DWORD)(TransmissionInterval - Result));
		else if (Result <= STANDARD_TIME_OUT)
			Sleep(STANDARD_TIME_OUT);
	#elif defined(PLATFORM_LINUX)
		if (TransmissionInterval != 0 && TransmissionInterval > Result)
			usleep(TransmissionInterval - Result);
		else if (Result <= STANDARD_TIME_OUT)
			usleep(STANDARD_TIME_OUT);
	#endif
	}

	return EXIT_SUCCESS;
}

//Print statistics to screen(and/or output result to file)
size_t __fastcall PrintProcess(const bool IsPacketStatistics, const bool IsTimeStatistics)
{
//Packet Statistics
	if (IsPacketStatistics)
	{
	#if defined(PLATFORM_WIN)
		wprintf_s(L"\nPacket statistics for pinging %ls:\n", wTargetString.c_str());
	#elif defined(PLATFORM_LINUX)
		printf(("\nPacket statistics for pinging %s:\n"), TargetString.c_str());
	#endif
		wprintf_s(_T("   Send: %lu\n"), (ULONG)RealSendNum);
		wprintf_s(_T("   Receive: %lu\n"), (ULONG)RecvNum);

	//Output to file.
		if (OutputFile != nullptr)
		{
		#if defined(PLATFORM_WIN)
			fwprintf_s(OutputFile, L"\nPacket statistics for pinging %ls:\n", wTargetString.c_str());
		#elif defined(PLATFORM_LINUX)
			fprintf(OutputFile, ("\nPacket statistics for pinging %s:\n"), TargetString.c_str());
		#endif
			fwprintf_s(OutputFile, _T("   Send: %lu\n"), (ULONG)RealSendNum);
			fwprintf_s(OutputFile, _T("   Receive: %lu\n"), (ULONG)RecvNum);
		}

		if ((SSIZE_T)RealSendNum - (SSIZE_T)RecvNum >= 0)
		{
			wprintf_s(_T("   Lost: %lu"), (ULONG)(RealSendNum - RecvNum));
			if (RealSendNum > 0)
				wprintf_s(_T(" (%lu%%)\n"), (ULONG)((RealSendNum - RecvNum) * 100 / RealSendNum));
			else  //Not any packets.
				wprintf_s(_T("\n"));

		//Output to file.
			if (OutputFile != nullptr)
			{
				fwprintf_s(OutputFile, _T("   Lost: %lu"), (ULONG)(RealSendNum - RecvNum));
				if (RealSendNum > 0)
					fwprintf_s(OutputFile, _T(" (%lu%%)\n"), (ULONG)((RealSendNum - RecvNum) * 100 / RealSendNum));
				else  //Not any packets.
					fwprintf_s(OutputFile, _T("\n"));
			}
		}
		else {
			wprintf_s(_T("   Lost: 0 (0%%)\n"));

		//Output to file.
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, _T("   Lost: 0 (0%%)\n"));
		}
	}

//Time Statistics
	if (IsTimeStatistics && 
		RecvNum > 0 && MaxTime > 0 && MinTime > 0)
	{
	#if defined(PLATFORM_WIN)
		wprintf_s(L"\nTime statistics for pinging %ls:\n", wTargetString.c_str());
		wprintf_s(L"   Minimum time: %lf ms.\n", MinTime);
		wprintf_s(L"   Maximum time: %lf ms.\n", MaxTime);
		wprintf_s(L"   Average time: %lf ms.\n", TotalTime / (long double)RecvNum);
		if (OutputFile != nullptr)
		{
			fwprintf_s(OutputFile, L"\nTime statistics for pinging %ls:\n", wTargetString.c_str());
			fwprintf_s(OutputFile, L"   Minimum time: %lf ms.\n", MinTime);
			fwprintf_s(OutputFile, L"   Maximum time: %lf ms.\n", MaxTime);
			fwprintf_s(OutputFile, L"   Average time: %lf ms.\n", TotalTime / (long double)RecvNum);
		}
	#elif defined(PLATFORM_LINUX)
		printf(("\nTime statistics for pinging %s:\n"), TargetString.c_str());
		printf(("   Minimum time: %Lf ms.\n"), MinTime);
		printf(("   Maximum time: %Lf ms.\n"), MaxTime);
		printf(("   Average time: %Lf ms.\n"), TotalTime / (long double)RecvNum);
		if (OutputFile != nullptr)
		{
			fprintf(OutputFile, ("\nTime statistics for pinging %s:\n"), TargetString.c_str());
			fprintf(OutputFile, ("   Minimum time: %Lf ms.\n"), MinTime);
			fprintf(OutputFile, ("   Maximum time: %Lf ms.\n"), MaxTime);
			fprintf(OutputFile, ("   Average time: %Lf ms.\n"), TotalTime / (long double)RecvNum);
		}
	#endif
	}

	wprintf_s(_T("\n"));
	if (OutputFile != nullptr)
		fwprintf_s(OutputFile, _T("\n"));
	return EXIT_SUCCESS;
}

//Print description to screen
void __fastcall PrintDescription(void)
{
	wprintf_s(_T("\n"));

//Description
	wprintf_s(_T("--------------------------------------------------\n"));
#if defined(PLATFORM_WIN)
	wprintf_s(L"DNSPing v0.1(Windows)\n");
#elif defined(PLATFORM_LINUX)
	printf("DNSPing v0.1(Linux)\n");
#endif
	wprintf_s(_T("Ping with DNS requesting.\n"));
	wprintf_s(_T("Copyright (C) 2014-2015 Chengr28\n"));
	wprintf_s(_T("--------------------------------------------------\n"));

//Usage
	wprintf_s(_T("\nUsage: DNSPing [Options] Test_DomainName Target\n"));

//Options
	wprintf_s(_T("\nOptions:\n"));
	wprintf_s(_T("   ?/-h              Description.\n"));
	wprintf_s(_T("   -t                Pings the specified host until stopped.\n                     To see statistics and continue type Control-Break.\n                     To stop type Control-C.\n"));
	wprintf_s(_T("   -a                Resolve addresses to host names.\n"));
	wprintf_s(_T("   -n Count          Set number of echo requests to send.\n                     Count must between 1 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -f                Set the \"Don't Fragment\" flag in outgoing packets(IPv4).\n                     No available on Linux.\n"));
	wprintf_s(_T("   -i HopLimit/TTL   Specifie a Hop Limit or Time To Live for outgoing packets.\n                     HopLimit/TTL must between 1 - 255.\n"));
	wprintf_s(_T("   -w Timeout        Set a long wait periods (in milliseconds) for a response.\n                     Timeout must between 500 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -id DNS_ID        Specifie DNS header ID.\n                     DNS ID must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -qr               Set DNS header QR flag.\n"));
	wprintf_s(_T("   -opcode OPCode    Specifie DNS header OPCode.\n                     OPCode must between 0x0000 - 0x00FF/255.\n"));
	wprintf_s(_T("   -aa               Set DNS header AA flag.\n"));
	wprintf_s(_T("   -tc               Set DNS header TC flag.\n"));
	wprintf_s(_T("   -rd               Set DNS header RD flag.\n"));
	wprintf_s(_T("   -ra               Set DNS header RA flag.\n"));
	wprintf_s(_T("   -ad               Set DNS header AD flag.\n"));
	wprintf_s(_T("   -cd               Set DNS header CD flag.\n"));
	wprintf_s(_T("   -rcode RCode      Specifie DNS header RCode.\n                     RCode must between 0x0000 - 0x00FF/255.\n"));
	wprintf_s(_T("   -qn Count         Specifie DNS header Question count.\n                     Question count must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -ann Count        Specifie DNS header Answer count.\n                     Answer count must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -aun Count        Specifie DNS header Authority count.\n                     Authority count must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -adn Count        Specifie DNS header Additional count.\n                     Additional count must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -ti IntervalTime  Specifie transmission interval time(in milliseconds).\n"));
	wprintf_s(_T("   -edns0            Send with EDNS0 Label.\n"));
	wprintf_s(_T("   -payload Length   Specifie EDNS0 Label UDP Payload length.\n                     Payload length must between 512 - 0xFFFF/65535.\n"));
	wprintf_s(_T("   -dnssec           Send with DNSSEC requesting.\n                     EDNS0 Label will enable when DNSSEC is enable.\n"));
	wprintf_s(_T("   -qt Type          Specifie Query type.\n                     Query type must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|\n"));
	wprintf_s(_T("                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|\n"));
	wprintf_s(_T("                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|\n"));
	wprintf_s(_T("                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|\n"));
	wprintf_s(_T("                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|\n"));
	wprintf_s(_T("                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|\n"));
	wprintf_s(_T("                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|\n"));
	wprintf_s(_T("                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|\n"));
	wprintf_s(_T("                           CAA|TA|DLV|RESERVED\n"));
	wprintf_s(_T("   -qc Classes       Specifie Query classes.\n                     Query classes must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY\n"));
	wprintf_s(_T("   -p ServiceName    Specifie UDP port/protocol(Sevice names).\n                     UDP port must between 0x0001 - 0xFFFF/65535.\n"));
	wprintf_s(_T("                     Protocol: TCPMUX|ECHO|DISCARD|SYSTAT|DAYTIME|NETSTAT|\n"));
	wprintf_s(_T("                               QOTD|MSP|CHARGEN|FTP|SSH|TELNET|SMTP|\n"));
	wprintf_s(_T("                               TIME|RAP|RLP|NAME|WHOIS|TACACS|DNS|XNSAUTH|MTP|\n"));
	wprintf_s(_T("                               BOOTPS|BOOTPC|TFTP|RJE|FINGER|TTYLINK|SUPDUP|\n"));
	wprintf_s(_T("                               SUNRPC|SQL|NTP|EPMAP|NETBIOSNS|NETBIOSDGM|\n"));
	wprintf_s(_T("                               NETBIOSSSN|IMAP|BFTP|SGMP|SQLSRV|DMSP|SNMP|\n"));
	wprintf_s(_T("                               SNMPTRAP|ATRTMP|ATHBP|QMTP|IPX|IMAP|IMAP3|\n"));
	wprintf_s(_T("                               BGMP|TSP|IMMP|ODMR|RPC2PORTMAP|CLEARCASE|\n"));
	wprintf_s(_T("                               HPALARMMGR|ARNS|AURP|LDAP|UPS|SLP|SNPP|\n"));
	wprintf_s(_T("                               MICROSOFTDS|KPASSWD|TCPNETHASPSRV|RETROSPECT|\n"));
	wprintf_s(_T("                               ISAKMP|BIFFUDP|WHOSERVER|SYSLOG|ROUTERSERVER|\n"));
	wprintf_s(_T("                               NCP|COURIER|COMMERCE|RTSP|NNTP|HTTPRPCEPMAP|\n"));
	wprintf_s(_T("                               IPP|LDAPS|MSDP|AODV|FTPSDATA|FTPS|NAS|TELNETS\n"));
	wprintf_s(_T("   -rawdata RAW_Data Specifie Raw data to send.\n"));
	wprintf_s(_T("                     RAW_Data is hex, but do not add \"0x\" before hex.\n"));
	wprintf_s(_T("                     Length of RAW_Data must between 64 - 1500 bytes.\n"));
	wprintf_s(_T("   -raw ServiceName  Specifie Raw socket type.\n"));
	wprintf_s(_T("                     Service Name: HOPOPTS|ICMP|IGMP|GGP|IPV4|ST|TCP|CBT|EGP|\n"));
	wprintf_s(_T("                                   IGP|BBNRCCMON|NVPII|PUP|ARGUS|EMCON|XNET|\n"));
	wprintf_s(_T("                                   CHAOS|MUX|DCN|HMP|PRM|IDP|TRUNK_1|TRUNK_2\n"));
	wprintf_s(_T("                                   LEAF_1|LEAF_2|RDP|IRTP|ISOTP4|MFE|MERIT|\n"));
	wprintf_s(_T("                                   DCCP|3PC|IDPR|XTP|DDP|IDPRCMTP|TP++|IL|\n"));
	wprintf_s(_T("                                   IPV6|SDRP|ROUTING|FRAGMENT|IDRP|RSVP|GRE|\n"));
	wprintf_s(_T("                                   DSR|BNA|ESP|AH|NLSP|SWIPE|NARP|MOBILE|TLSP|\n"));
	wprintf_s(_T("                                   SKIP|ICMPV6|NONE|DSTOPTS|AHI|CFTP|ALN|SAT|\n"));
	wprintf_s(_T("                                   KRYPTOLAN|RVD|IPPC|ADF|SATMON|VISA|IPCV|\n"));
	wprintf_s(_T("                                   CPNX|CPHB|WSN|PVP|BR|ND|ICLFXBM|WBEXPAK|\n"));
	wprintf_s(_T("                                   ISO|VMTP|SVMTP|VINES|TTP|IPTM|NSFNET|DGP|\n"));
	wprintf_s(_T("                                   TCF|EIGRP|SPRITE|LARP|MTP|AX25|IPIP|MICP|\n"));
	wprintf_s(_T("                                   SCC|ETHERIP|ENCAP|APES|GMTP|IFMP|PNNI|PIM|\n"));
	wprintf_s(_T("                                   ARIS|SCPS|QNX|AN|IPCOMP|SNP|COMPAQ|IPX|PGM|\n"));
	wprintf_s(_T("                                   0HOP|L2TP|DDX|IATP|STP|SRP|UTI|SMP|SM|\n"));
	wprintf_s(_T("                                   PTP|ISIS|FIRE|CRTP|CRUDP|SSCOPMCE|IPLT|\n"));
	wprintf_s(_T("                                   SPS|PIPE|SCTP|FC|RSVPE2E|MOBILITY|UDPLITE|\n"));
	wprintf_s(_T("                                   MPLS|MANET|HIP|SHIM6|WESP|ROHC|TEST-1|\n"));
	wprintf_s(_T("                                   TEST-2|RAW\n"));
	wprintf_s(_T("   -buf Size         Specifie receive buffer size.\n                     Buffer size must between 512 - 4096 bytes.\n"));
	wprintf_s(_T("   -dv               Disable packets validated.\n"));
	wprintf_s(_T("   -show Response    Show result or data of responses.\n"));
	wprintf_s(_T("                     Response: Result|Hex\n"));
	wprintf_s(_T("   -of FileName      Output result to file.\n                     FileName must less than 260 bytes.\n"));
	wprintf_s(_T("   -6                Using IPv6.\n"));
	wprintf_s(_T("   -4                Using IPv4.\n"));
	wprintf_s(_T("   Test_DomainName   A domain name which will make requesting to send\n"));
	wprintf_s(_T("                     to DNS server.\n"));
	wprintf_s(_T("   Target            Target of DNSPing, support IPv4/IPv6 address and domain.\n"));

#if defined(PLATFORM_LINUX)
	printf("\n");
#endif
	return;
}
