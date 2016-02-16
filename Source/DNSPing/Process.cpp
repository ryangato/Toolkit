// This code is part of DNSPing
// Ping with DNS requesting.
// Copyright (C) 2014-2016 Chengr28
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


#include "Base.h"

extern ConfigurationTable ConfigurationParameter;

//Send DNS requesting process
size_t __fastcall SendProcess(
	const sockaddr_storage &Target, 
	const bool LastSend)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[ConfigurationParameter.BufferSize]()), RecvBuffer(new char[ConfigurationParameter.BufferSize]());
	memset(Buffer.get(), 0, ConfigurationParameter.BufferSize);
	memset(RecvBuffer.get(), 0, ConfigurationParameter.BufferSize);
	SSIZE_T DataLength = 0;
#if defined(PLATFORM_WIN)
	LARGE_INTEGER CPUFrequency = {0}, BeforeTime = {0}, AfterTime = {0};
	int AddrLen = 0;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval BeforeTime = {0}, AfterTime = {0};
	socklen_t AddrLen = 0;
#endif
	SOCKET Socket = 0;

//IPv6
	if (ConfigurationParameter.Protocol == AF_INET6)
	{
	//Socket initialization
		AddrLen = sizeof(sockaddr_in6);
		if (ConfigurationParameter.RawSocket && ConfigurationParameter.RawData)
			Socket = socket(AF_INET6, SOCK_RAW, ConfigurationParameter.ServiceType);
		else 
			Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (Socket == INVALID_SOCKET)
		{
			fwprintf_s(stderr, L"Socket initialization error, error code is %d.\n", WSAGetLastError());

			WSACleanup();
			return EXIT_FAILURE;
		}
	}
//IPv4
	else {
	//Socket initialization
		AddrLen = sizeof(sockaddr_in);
		if (ConfigurationParameter.RawSocket && ConfigurationParameter.RawData)
			Socket = socket(AF_INET, SOCK_RAW, ConfigurationParameter.ServiceType);
		else 
			Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (Socket == INVALID_SOCKET)
		{
			fwprintf_s(stderr, L"Socket initialization error, error code is %d.\n", WSAGetLastError());

			WSACleanup();
			return EXIT_FAILURE;
		}
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&ConfigurationParameter.SocketTimeout, sizeof(int)) == SOCKET_ERROR ||
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&ConfigurationParameter.SocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, &ConfigurationParameter.SocketTimeout, sizeof(timeval)) == SOCKET_ERROR ||
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, &ConfigurationParameter.SocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		fwprintf_s(stderr, L"Set UDP socket timeout error, error code is %d.\n", WSAGetLastError());
		return EXIT_FAILURE;
	}

//Set IP options.
	if (ConfigurationParameter.Protocol == AF_INET6) //IPv6
	{
	#if defined(PLATFORM_WIN)
		if (ConfigurationParameter.IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, (PSTR)&ConfigurationParameter.IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (ConfigurationParameter.IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, &ConfigurationParameter.IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#endif
		{
			fwprintf_s(stderr, L"Set HopLimit or TTL flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	}
	else { //IPv4
	#if defined(PLATFORM_WIN)
		if (ConfigurationParameter.IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IP_TTL, (PSTR)&ConfigurationParameter.IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (ConfigurationParameter.IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IP_TTL, &ConfigurationParameter.IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
	#endif
		{
			fwprintf_s(stderr, L"Set HopLimit or TTL flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}

	//Set "Don't Fragment" flag.
	//All Non-SOCK_STREAM will set "Don't Fragment" flag(Linux).
	#if defined(PLATFORM_WIN)
		int iIPv4_DF = 1;
		if (ConfigurationParameter.IPv4_DF && setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, (PSTR)&iIPv4_DF, sizeof(int)) == SOCKET_ERROR)
		{
			fwprintf_s(stderr, L"Set \"Don't Fragment\" flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	#endif
	}

	dns_hdr *pdns_hdr = nullptr;
//Make packet.
	if (!ConfigurationParameter.RawData)
	{
	//DNS requesting
		memcpy_s(Buffer.get() + DataLength, ConfigurationParameter.BufferSize, &ConfigurationParameter.HeaderParameter, sizeof(dns_hdr));
		if (ConfigurationParameter.HeaderParameter.ID == 0)
		{
			pdns_hdr = (dns_hdr *)(Buffer.get() + DataLength);
		#if defined(PLATFORM_MACX)
			pdns_hdr->ID = htons(*(uint16_t *)pthread_self());
		#else
			pdns_hdr->ID = htons((uint16_t)GetCurrentProcessId());
		#endif
		}
		DataLength += sizeof(dns_hdr);
		DataLength += CharToDNSQuery((PSTR)ConfigurationParameter.TestDomain.c_str(), Buffer.get() + DataLength);
		memcpy_s(Buffer.get() + DataLength, ConfigurationParameter.BufferSize, &ConfigurationParameter.QueryParameter, sizeof(dns_qry));
		DataLength += sizeof(dns_qry);
		if (ConfigurationParameter.EDNS0)
		{
			memcpy_s(Buffer.get() + DataLength, ConfigurationParameter.BufferSize, &ConfigurationParameter.EDNS0Parameter, sizeof(dns_opt_record));
			DataLength += sizeof(dns_opt_record);
		}
	}
	else {
		if (ConfigurationParameter.BufferSize >= ConfigurationParameter.RawDataLen)
		{
			memcpy_s(Buffer.get(), ConfigurationParameter.BufferSize, ConfigurationParameter.RawData.get(), ConfigurationParameter.RawDataLen);
			DataLength = ConfigurationParameter.RawDataLen;
		}
		else {
			memcpy_s(Buffer.get(), ConfigurationParameter.BufferSize, ConfigurationParameter.RawData.get(), ConfigurationParameter.BufferSize);
			DataLength = ConfigurationParameter.BufferSize;
		}
	}

//Send requesting.
#if defined(PLATFORM_WIN)
	if (QueryPerformanceFrequency(&CPUFrequency) == 0 || QueryPerformanceCounter(&BeforeTime) == 0)
	{
		fwprintf_s(stderr, L"Get current time from High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
		return EXIT_FAILURE;
	}
	sendto(Socket, Buffer.get(), (int)DataLength, 0, (PSOCKADDR)&Target, AddrLen);

#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (gettimeofday(&BeforeTime, NULL) != 0)
	{
		fwprintf(stderr, L"Get current time error, error code is %d.\n", errno);
		return EXIT_FAILURE;
	}

	#if defined(PLATFORM_LINUX)
		sendto(Socket, Buffer.get(), DataLength, MSG_NOSIGNAL, (PSOCKADDR)&Target, AddrLen);
	#elif defined(PLATFORM_MACX)
		sendto(Socket, Buffer.get(), DataLength, 0, (PSOCKADDR)&Target, AddrLen);
	#endif
#endif

//Receive response.
#if defined(PLATFORM_WIN)
	DataLength = recvfrom(Socket, RecvBuffer.get(), (int)ConfigurationParameter.BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
	if (QueryPerformanceCounter(&AfterTime) == 0)
	{
		fwprintf_s(stderr, L"Get current time from High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());

#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#if defined(PLATFORM_LINUX)
		DataLength = recvfrom(Socket, RecvBuffer.get(), ConfigurationParameter.BufferSize, MSG_NOSIGNAL, (PSOCKADDR)&Target, &AddrLen);
	#elif defined(PLATFORM_MACX)
		DataLength = recvfrom(Socket, RecvBuffer.get(), ConfigurationParameter.BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
	#endif
	if (gettimeofday(&AfterTime, NULL) != 0)
	{
		fwprintf(stderr, L"Get current time error, error code is %d.\n", errno);
#endif
		return EXIT_FAILURE;
	}

//Get waiting time.
#if defined(PLATFORM_WIN)
	long double Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
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
		if (ConfigurationParameter.Validate && pdns_hdr != nullptr && !ValidatePacket(RecvBuffer.get(), DataLength, pdns_hdr->ID))
		{
		#if defined(PLATFORM_WIN)
			fwprintf_s(stderr, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			if (ConfigurationParameter.OutputFile != nullptr)
				fwprintf_s(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			fwprintf(stderr, L"Receive from %ls:%u -> %d bytes but validate error, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			if (ConfigurationParameter.OutputFile != nullptr)
				fwprintf(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
		#endif

		//Try to waiting correct packet.
			for (;;)
			{
			//Timeout
			#if defined(PLATFORM_WIN)
				if (Result >= ConfigurationParameter.SocketTimeout)
					break;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (Result >= ConfigurationParameter.SocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND + ConfigurationParameter.SocketTimeout.tv_sec * SECOND_TO_MILLISECOND)
					break;
			#endif

			//Receive.
				memset(RecvBuffer.get(), 0, ConfigurationParameter.BufferSize);
			#if defined(PLATFORM_WIN)
				DataLength = recvfrom(Socket, RecvBuffer.get(), (int)ConfigurationParameter.BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
				if (QueryPerformanceCounter(&AfterTime) == 0)
				{
					fwprintf_s(stderr, L"Get current time from High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
					return EXIT_FAILURE;
				}

			//Get waiting time.
				Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);

			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			//Receive.
			#if defined(PLATFORM_LINUX)
				DataLength = recvfrom(Socket, RecvBuffer.get(), ConfigurationParameter.BufferSize, MSG_NOSIGNAL, (PSOCKADDR)&Target, &AddrLen);
			#elif defined(PLATFORM_MACX)
				DataLength = recvfrom(Socket, RecvBuffer.get(), ConfigurationParameter.BufferSize, 0, (PSOCKADDR)&Target, &AddrLen);
			#endif

			//Get waiting time.
				if (gettimeofday(&AfterTime, NULL) != 0)
				{
					fwprintf(stderr, L"Get current time error, error code is %d.\n", errno);
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
					fwprintf_s(stderr, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
					if (ConfigurationParameter.OutputFile != nullptr)
						fwprintf_s(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					fwprintf(stderr, L"Receive from %ls:%u -> %d bytes but validate error, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
					if (ConfigurationParameter.OutputFile != nullptr)
						fwprintf(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
				#endif
				}
				else {
					break;
				}
			}

			if (DataLength <= 0)
			{
			#if defined(PLATFORM_WIN)
				fwprintf_s(stderr, L"Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n", (int)DataLength, WSAGetLastError(), Result);
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf_s(ConfigurationParameter.OutputFile, L"Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n", (int)DataLength, WSAGetLastError(), Result);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				fwprintf(stderr, L"Receive error: %d(%d), waiting correct answers timeout(%Lf ms).\n", (int)DataLength, errno, Result);
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf(ConfigurationParameter.OutputFile, L"Receive error: %d(%d), waiting correct answers timeout(%Lf ms).\n", (int)DataLength, errno, Result);
			#endif

				return EXIT_SUCCESS;
			}
			else {
			#if defined(PLATFORM_WIN)
				fwprintf_s(stderr, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf_s(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				fwprintf(stderr, L"Receive from %ls:%u -> %d bytes, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			#endif
			}
		}
		else {
		#if defined(PLATFORM_WIN)
			fwprintf_s(stderr, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			if (ConfigurationParameter.OutputFile != nullptr)
				fwprintf_s(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			fwprintf(stderr, L"Receive from %ls:%u -> %d bytes, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
			if (ConfigurationParameter.OutputFile != nullptr)
				fwprintf(ConfigurationParameter.OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %Lf ms.\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), (int)DataLength, Result);
		#endif
		}

	//Print response result or data.
		if (ConfigurationParameter.ShowResponse)
		{
			PrintResponse(RecvBuffer.get(), DataLength);
			if (ConfigurationParameter.OutputFile != nullptr)
				PrintResponse(RecvBuffer.get(), DataLength, ConfigurationParameter.OutputFile);
		}
		if (ConfigurationParameter.ShowResponseHex)
		{
			PrintResponseHex(RecvBuffer.get(), DataLength);
			if (ConfigurationParameter.OutputFile != nullptr)
				PrintResponseHex(RecvBuffer.get(), DataLength, ConfigurationParameter.OutputFile);
		}

	//Calculate time.
		ConfigurationParameter.TotalTime += Result;
		++ConfigurationParameter.RecvNum;

	//Mark time.
		if (ConfigurationParameter.MaxTime == 0)
		{
			ConfigurationParameter.MinTime = Result;
			ConfigurationParameter.MaxTime = Result;
		}
		else if (Result < ConfigurationParameter.MinTime)
		{
			ConfigurationParameter.MinTime = Result;
		}
		else if (Result > ConfigurationParameter.MaxTime)
		{
			ConfigurationParameter.MaxTime = Result;
		}
	}
	else { //SOCKET_ERROR
	#if defined(PLATFORM_WIN)
		fwprintf_s(stderr, L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);
		if (ConfigurationParameter.OutputFile != nullptr)
			fwprintf_s(ConfigurationParameter.OutputFile, L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		fwprintf(stderr, L"Receive error: %d(%d), waiting %Lf ms.\n", (int)DataLength, errno, Result);
		if (ConfigurationParameter.OutputFile != nullptr)
			fwprintf(ConfigurationParameter.OutputFile, L"Receive error: %d(%d), waiting %Lf ms.\n", (int)DataLength, errno, Result);
	#endif
	}

//Transmission interval
	if (!LastSend)
	{
	#if defined(PLATFORM_WIN)
		if (ConfigurationParameter.TransmissionInterval != 0 && ConfigurationParameter.TransmissionInterval > Result)
			Sleep((DWORD)(ConfigurationParameter.TransmissionInterval - Result));
		else if (Result <= STANDARD_TIME_OUT)
			Sleep(STANDARD_TIME_OUT);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (ConfigurationParameter.TransmissionInterval != 0 && ConfigurationParameter.TransmissionInterval > Result)
			usleep(ConfigurationParameter.TransmissionInterval - Result);
		else if (Result <= STANDARD_TIME_OUT)
			usleep(STANDARD_TIME_OUT);
	#endif
	}

	return EXIT_SUCCESS;
}

//Print statistics to screen(and/or output result to file)
size_t __fastcall PrintProcess(
	const bool IsPacketStatistics, 
	const bool IsTimeStatistics)
{
//Packet Statistics
	if (IsPacketStatistics)
	{
		fwprintf_s(stderr, L"\nPacket statistics for pinging %ls:\n", ConfigurationParameter.wTargetString.c_str());
		fwprintf_s(stderr, L"   Send: %lu\n", (ULONG)ConfigurationParameter.RealSendNum);
		fwprintf_s(stderr, L"   Receive: %lu\n", (ULONG)ConfigurationParameter.RecvNum);

	//Output to file.
		if (ConfigurationParameter.OutputFile != nullptr)
		{
			fwprintf_s(ConfigurationParameter.OutputFile, L"\nPacket statistics for pinging %ls:\n", ConfigurationParameter.wTargetString.c_str());
			fwprintf_s(ConfigurationParameter.OutputFile, L"   Send: %lu\n", (ULONG)ConfigurationParameter.RealSendNum);
			fwprintf_s(ConfigurationParameter.OutputFile, L"   Receive: %lu\n", (ULONG)ConfigurationParameter.RecvNum);
		}

		if ((SSIZE_T)ConfigurationParameter.RealSendNum - (SSIZE_T)ConfigurationParameter.RecvNum >= 0)
		{
			fwprintf_s(stderr, L"   Lost: %lu", (ULONG)(ConfigurationParameter.RealSendNum - ConfigurationParameter.RecvNum));
			if (ConfigurationParameter.RealSendNum > 0)
				fwprintf_s(stderr, L" (%lu%%)\n", (ULONG)((ConfigurationParameter.RealSendNum - ConfigurationParameter.RecvNum) * 100 / ConfigurationParameter.RealSendNum));
			else  //Not any packets.
				fwprintf_s(stderr, L"\n");

		//Output to file.
			if (ConfigurationParameter.OutputFile != nullptr)
			{
				fwprintf_s(ConfigurationParameter.OutputFile, L"   Lost: %lu", (ULONG)(ConfigurationParameter.RealSendNum - ConfigurationParameter.RecvNum));
				if (ConfigurationParameter.RealSendNum > 0)
					fwprintf_s(ConfigurationParameter.OutputFile, L" (%lu%%)\n", (ULONG)((ConfigurationParameter.RealSendNum - ConfigurationParameter.RecvNum) * 100 / ConfigurationParameter.RealSendNum));
				else  //Not any packets.
					fwprintf_s(ConfigurationParameter.OutputFile, L"\n");
			}
		}
		else {
			fwprintf_s(stderr, L"   Lost: 0 (0%%)\n");

		//Output to file.
			if (ConfigurationParameter.OutputFile != nullptr)
				fwprintf_s(ConfigurationParameter.OutputFile, L"   Lost: 0 (0%%)\n");
		}
	}

//Time Statistics
	if (IsTimeStatistics && 
		ConfigurationParameter.RecvNum > 0 && ConfigurationParameter.MaxTime > 0 && ConfigurationParameter.MinTime > 0)
	{
		fwprintf_s(stderr, L"\nTime statistics for pinging %ls:\n", ConfigurationParameter.wTargetString.c_str());

	#if defined(PLATFORM_WIN)
		fwprintf_s(stderr, L"   Minimum time: %lf ms.\n", ConfigurationParameter.MinTime);
		fwprintf_s(stderr, L"   Maximum time: %lf ms.\n", ConfigurationParameter.MaxTime);
		fwprintf_s(stderr, L"   Average time: %lf ms.\n", ConfigurationParameter.TotalTime / (long double)ConfigurationParameter.RecvNum);
		if (ConfigurationParameter.OutputFile != nullptr)
		{
			fwprintf_s(ConfigurationParameter.OutputFile, L"\nTime statistics for pinging %ls:\n", ConfigurationParameter.wTargetString.c_str());
			fwprintf_s(ConfigurationParameter.OutputFile, L"   Minimum time: %lf ms.\n", ConfigurationParameter.MinTime);
			fwprintf_s(ConfigurationParameter.OutputFile, L"   Maximum time: %lf ms.\n", ConfigurationParameter.MaxTime);
			fwprintf_s(ConfigurationParameter.OutputFile, L"   Average time: %lf ms.\n", ConfigurationParameter.TotalTime / (long double)ConfigurationParameter.RecvNum);
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		fwprintf(stderr, L"   Minimum time: %Lf ms.\n", ConfigurationParameter.MinTime);
		fwprintf(stderr, L"   Maximum time: %Lf ms.\n", ConfigurationParameter.MaxTime);
		fwprintf(stderr, L"   Average time: %Lf ms.\n", ConfigurationParameter.TotalTime / (long double)ConfigurationParameter.RecvNum);
		if (ConfigurationParameter.OutputFile != nullptr)
		{
			fwprintf(ConfigurationParameter.OutputFile, L"\nTime statistics for pinging %ls:\n", ConfigurationParameter.wTargetString.c_str());
			fwprintf(ConfigurationParameter.OutputFile, L"   Minimum time: %Lf ms.\n", ConfigurationParameter.MinTime);
			fwprintf(ConfigurationParameter.OutputFile, L"   Maximum time: %Lf ms.\n", ConfigurationParameter.MaxTime);
			fwprintf(ConfigurationParameter.OutputFile, L"   Average time: %Lf ms.\n", ConfigurationParameter.TotalTime / (long double)ConfigurationParameter.RecvNum);
		}
	#endif
	}

	fwprintf_s(stderr, L"\n");
	if (ConfigurationParameter.OutputFile != nullptr)
		fwprintf_s(ConfigurationParameter.OutputFile, L"\n");
	return EXIT_SUCCESS;
}

//Print description to screen
void __fastcall PrintDescription(
	void)
{
	fwprintf_s(stderr, L"\n");

//Description
	fwprintf_s(stderr, L"--------------------------------------------------\n");
#if defined(PLATFORM_WIN)
	fwprintf_s(stderr, L"DNSPing v0.1.2(Windows)\n");
#elif defined(PLATFORM_LINUX)
	fwprintf(stderr, L"DNSPing v0.1.2(Linux)\n");
#elif defined(PLATFORM_MACX)
	fwprintf(stderr, L"DNSPing v0.1.2(Mac)\n");
#endif
	fwprintf_s(stderr, L"Ping with DNS requesting.\n");
	fwprintf_s(stderr, L"Copyright (C) 2014-2016 Chengr28\n");
	fwprintf_s(stderr, L"--------------------------------------------------\n");

//Usage
	fwprintf_s(stderr, L"\nUsage: DNSPing [-options] Test_DomainName Target\n");
	fwprintf_s(stderr, L"  e.g. DNSPing -a -qt AAAA -n 5 -w 500 -edns0 www.google.com 8.8.4.4\n");

//Options
	fwprintf_s(stderr, L"\nOptions:\n");
	fwprintf_s(stderr, L"   ?/-h              Description.\n");
	fwprintf_s(stderr, L"   -t                Pings the specified host until stopped.\n");
	fwprintf_s(stderr, L"                     To see statistics and continue type Control-Break.\n");
	fwprintf_s(stderr, L"                     To stop type Control-C.\n");
	fwprintf_s(stderr, L"   -a                Resolve addresses to host names.\n");
	fwprintf_s(stderr, L"   -n Count          Set number of echo requests to send.\n");
	fwprintf_s(stderr, L"                     Count must between 1 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -f                Set the \"Don't Fragment\" flag in outgoing packets(IPv4).\n");
	fwprintf_s(stderr, L"                     No available on Linux.\n");
	fwprintf_s(stderr, L"   -i HopLimit/TTL   Specifie a Hop Limit or Time To Live for outgoing packets.\n");
	fwprintf_s(stderr, L"                     HopLimit/TTL must between 1 - 255.\n");
	fwprintf_s(stderr, L"   -w Timeout        Set a long wait periods (in milliseconds) for a response.\n");
	fwprintf_s(stderr, L"                     Timeout must between 500 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -id DNS_ID        Specifie DNS header ID.\n");
	fwprintf_s(stderr, L"                     DNS ID must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -qr               Set DNS header QR flag.\n");
	fwprintf_s(stderr, L"   -opcode OPCode    Specifie DNS header OPCode.\n");
	fwprintf_s(stderr, L"                     OPCode must between 0x0000 - 0x00FF/255.\n");
	fwprintf_s(stderr, L"   -aa               Set DNS header AA flag.\n");
	fwprintf_s(stderr, L"   -tc               Set DNS header TC flag.\n");
	fwprintf_s(stderr, L"   -rd               Set DNS header RD flag.\n");
	fwprintf_s(stderr, L"   -ra               Set DNS header RA flag.\n");
	fwprintf_s(stderr, L"   -ad               Set DNS header AD flag.\n");
	fwprintf_s(stderr, L"   -cd               Set DNS header CD flag.\n");
	fwprintf_s(stderr, L"   -rcode RCode      Specifie DNS header RCode.\n");
	fwprintf_s(stderr, L"                     RCode must between 0x0000 - 0x00FF/255.\n");
	fwprintf_s(stderr, L"   -qn Count         Specifie DNS header Question count.\n");
	fwprintf_s(stderr, L"                     Question count must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -ann Count        Specifie DNS header Answer count.\n");
	fwprintf_s(stderr, L"                     Answer count must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -aun Count        Specifie DNS header Authority count.\n");
	fwprintf_s(stderr, L"                     Authority count must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -adn Count        Specifie DNS header Additional count.\n");
	fwprintf_s(stderr, L"                     Additional count must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -ti IntervalTime  Specifie transmission interval time(in milliseconds).\n");
	fwprintf_s(stderr, L"   -edns0            Send with EDNS0 Label.\n");
	fwprintf_s(stderr, L"   -payload Length   Specifie EDNS0 Label UDP Payload length.\n");
	fwprintf_s(stderr, L"                     Payload length must between 512 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"   -dnssec           Send with DNSSEC requesting.\n");
	fwprintf_s(stderr, L"                     EDNS0 Label will enable when DNSSEC is enable.\n");
	fwprintf_s(stderr, L"   -qt Type          Specifie Query type.\n");
	fwprintf_s(stderr, L"                     Query type must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|\n");
	fwprintf_s(stderr, L"                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|\n");
	fwprintf_s(stderr, L"                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|\n");
	fwprintf_s(stderr, L"                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|\n");
	fwprintf_s(stderr, L"                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|\n");
	fwprintf_s(stderr, L"                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|\n");
	fwprintf_s(stderr, L"                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|\n");
	fwprintf_s(stderr, L"                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|\n");
	fwprintf_s(stderr, L"                           CAA|TA|DLV|RESERVED\n");
	fwprintf_s(stderr, L"   -qc Classes       Specifie Query classes.\n");
	fwprintf_s(stderr, L"                     Query classes must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY\n");
	fwprintf_s(stderr, L"   -p ConfigurationParameter.ServiceType    Specifie UDP port/protocol(Sevice names).\n");
	fwprintf_s(stderr, L"                     UDP port must between 0x0001 - 0xFFFF/65535.\n");
	fwprintf_s(stderr, L"                     Protocol: TCPMUX|ECHO|DISCARD|SYSTAT|DAYTIME|NETSTAT|\n");
	fwprintf_s(stderr, L"                               QOTD|MSP|CHARGEN|FTP|SSH|TELNET|SMTP|\n");
	fwprintf_s(stderr, L"                               TIME|RAP|RLP|NAME|WHOIS|TACACS|DNS|XNSAUTH|MTP|\n");
	fwprintf_s(stderr, L"                               BOOTPS|BOOTPC|TFTP|RJE|FINGER|TTYLINK|SUPDUP|\n");
	fwprintf_s(stderr, L"                               SUNRPC|SQL|NTP|EPMAP|NETBIOSNS|NETBIOSDGM|\n");
	fwprintf_s(stderr, L"                               NETBIOSSSN|IMAP|BFTP|SGMP|SQLSRV|DMSP|SNMP|\n");
	fwprintf_s(stderr, L"                               SNMPTRAP|ATRTMP|ATHBP|QMTP|IPX|IMAP|IMAP3|\n");
	fwprintf_s(stderr, L"                               BGMP|TSP|IMMP|ODMR|RPC2PORTMAP|CLEARCASE|\n");
	fwprintf_s(stderr, L"                               HPALARMMGR|ARNS|AURP|LDAP|UPS|SLP|SNPP|\n");
	fwprintf_s(stderr, L"                               MICROSOFTDS|KPASSWD|TCPNETHASPSRV|RETROSPECT|\n");
	fwprintf_s(stderr, L"                               ISAKMP|BIFFUDP|WHOSERVER|SYSLOG|ROUTERSERVER|\n");
	fwprintf_s(stderr, L"                               NCP|COURIER|COMMERCE|RTSP|NNTP|HTTPRPCEPMAP|\n");
	fwprintf_s(stderr, L"                               IPP|LDAPS|MSDP|AODV|FTPSDATA|FTPS|NAS|TELNETS\n");
	fwprintf_s(stderr, L"   -rawdata RAW_Data Specifie Raw data to send.\n");
	fwprintf_s(stderr, L"                     RAW_Data is hex, but do not add \"0x\" before hex.\n");
	fwprintf_s(stderr, L"                     Length of RAW_Data must between 64 - 1500 bytes.\n");
	fwprintf_s(stderr, L"   -raw ConfigurationParameter.ServiceType  Specifie Raw socket type.\n");
	fwprintf_s(stderr, L"                     Service Name: HOPOPTS|ICMP|IGMP|GGP|IPV4|ST|TCP|CBT|EGP|\n");
	fwprintf_s(stderr, L"                                   IGP|BBNRCCMON|NVPII|PUP|ARGUS|EMCON|XNET|\n");
	fwprintf_s(stderr, L"                                   CHAOS|MUX|DCN|HMP|PRM|IDP|TRUNK_1|TRUNK_2\n");
	fwprintf_s(stderr, L"                                   LEAF_1|LEAF_2|RDP|IRTP|ISOTP4|MFE|MERIT|\n");
	fwprintf_s(stderr, L"                                   DCCP|3PC|IDPR|XTP|DDP|IDPRCMTP|TP++|IL|\n");
	fwprintf_s(stderr, L"                                   IPV6|SDRP|ROUTING|FRAGMENT|IDRP|RSVP|GRE|\n");
	fwprintf_s(stderr, L"                                   DSR|BNA|ESP|AH|NLSP|SWIPE|NARP|MOBILE|TLSP|\n");
	fwprintf_s(stderr, L"                                   SKIP|ICMPV6|NONE|DSTOPTS|AHI|CFTP|ALN|SAT|\n");
	fwprintf_s(stderr, L"                                   KRYPTOLAN|RVD|IPPC|ADF|SATMON|VISA|IPCV|\n");
	fwprintf_s(stderr, L"                                   CPNX|CPHB|WSN|PVP|BR|ND|ICLFXBM|WBEXPAK|\n");
	fwprintf_s(stderr, L"                                   ISO|VMTP|SVMTP|VINES|TTP|IPTM|NSFNET|DGP|\n");
	fwprintf_s(stderr, L"                                   TCF|EIGRP|SPRITE|LARP|MTP|AX25|IPIP|MICP|\n");
	fwprintf_s(stderr, L"                                   SCC|ETHERIP|ENCAP|APES|GMTP|IFMP|PNNI|PIM|\n");
	fwprintf_s(stderr, L"                                   ARIS|SCPS|QNX|AN|IPCOMP|SNP|COMPAQ|IPX|PGM|\n");
	fwprintf_s(stderr, L"                                   0HOP|L2TP|DDX|IATP|STP|SRP|UTI|SMP|SM|\n");
	fwprintf_s(stderr, L"                                   PTP|ISIS|FIRE|CRTP|CRUDP|SSCOPMCE|IPLT|\n");
	fwprintf_s(stderr, L"                                   SPS|PIPE|SCTP|FC|RSVPE2E|MOBILITY|UDPLITE|\n");
	fwprintf_s(stderr, L"                                   MPLS|MANET|HIP|SHIM6|WESP|ROHC|TEST-1|\n");
	fwprintf_s(stderr, L"                                   TEST-2|RAW\n");
	fwprintf_s(stderr, L"   -buf Size         Specifie receive buffer size.\n");
	fwprintf_s(stderr, L"                     Buffer size must between 512 - 4096 bytes.\n");
	fwprintf_s(stderr, L"   -dv               Disable packets validated.\n");
	fwprintf_s(stderr, L"   -show Response    Show result or data of responses.\n");
	fwprintf_s(stderr, L"                     Response: Result|Hex\n");
	fwprintf_s(stderr, L"   -of FileName      Output result to file.\n");
	fwprintf_s(stderr, L"                     FileName must less than 260 bytes.\n");
	fwprintf_s(stderr, L"   -6                Using IPv6.\n");
	fwprintf_s(stderr, L"   -4                Using IPv4.\n");
	fwprintf_s(stderr, L"   Test_DomainName   A domain name which will make requesting to send\n");
	fwprintf_s(stderr, L"                     to DNS server.\n");
	fwprintf_s(stderr, L"   Target            Target of DNSPing, support IPv4/IPv6 address and domain.\n");

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	fwprintf_s(stderr, L"\n");
#endif
	return;
}
