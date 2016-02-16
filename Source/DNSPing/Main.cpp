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


#include "Main.h"

//Main function of program
#if defined(PLATFORM_WIN)
int wmain(
	int argc, 
	wchar_t* argv[])
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
int main(
	int argc, 
	char *argv[])
#endif
{
//Main process
	if (argc <= 2)
	{
		PrintDescription();
	}
	else {
	//Initialization and read commands.
		if (ConfigurationInitialization() == EXIT_FAILURE)
		{
			return EXIT_FAILURE;
		}
		else if (ReadCommands(argc, argv) == EXIT_FAILURE)
		{
			WSACleanup();
			return EXIT_FAILURE;
		}

	//Check parameter reading.
		if (ConfigurationParameter.SockAddr.ss_family == AF_INET6) //IPv6
		{
			if (CheckEmptyBuffer(&((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_addr, sizeof(in6_addr)))
			{
				fwprintf_s(stderr, L"\nTarget is empty.\n");

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
			//Mark port.
				if (ConfigurationParameter.ServiceType == 0)
				{
					ConfigurationParameter.ServiceType = htons(IPPORT_DNS);
					((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_port = htons(IPPORT_DNS);
				}
				else {
					((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_port = ConfigurationParameter.ServiceType;
				}
			}
		}
		else { //IPv4
			if (((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_addr.s_addr == 0)
			{
				fwprintf_s(stderr, L"\nTarget is empty.\n");

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
			//Mark port.
				if (ConfigurationParameter.ServiceType == 0)
				{
					ConfigurationParameter.ServiceType = htons(IPPORT_DNS);
					((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_port = htons(IPPORT_DNS);
				}
				else {
					((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_port = ConfigurationParameter.ServiceType;
				}
			}
		}

	//Check parameter.
	//Minimum supported system of Windows Version Helpers is Windows Vista.
	#if defined(PLATFORM_WIN)
		#if defined(PLATFORM_WIN64)
			if (!IsWindows8OrGreater())
		#elif defined(PLATFORM_WIN32)
			if (IsLowerThanWin8())
		#endif
			{
				if (ConfigurationParameter.SocketTimeout > TIME_OUT_MIN)
					ConfigurationParameter.SocketTimeout -= 500;
				else if (ConfigurationParameter.SocketTimeout == TIME_OUT_MIN)
					ConfigurationParameter.SocketTimeout = 1;
			}
		ConfigurationParameter.MinTime = ConfigurationParameter.SocketTimeout;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		ConfigurationParameter.MinTime = ConfigurationParameter.SocketTimeout.tv_sec * SECOND_TO_MILLISECOND + ConfigurationParameter.SocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
	#endif

	//Convert multiple byte string to wide char string.
		std::wstring wTestDomain, wTargetDomainString;
	#if defined(PLATFORM_WIN)
		std::shared_ptr<wchar_t> wTargetStringPTR(new wchar_t[LARGE_PACKET_MAXSIZE]());
		wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
		MultiByteToWideChar(CP_ACP, 0, ConfigurationParameter.TargetString.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)ConfigurationParameter.TargetString.length());
		ConfigurationParameter.wTargetString = wTargetStringPTR.get();
		wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
		MultiByteToWideChar(CP_ACP, 0, ConfigurationParameter.TestDomain.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)ConfigurationParameter.TestDomain.length());
		wTestDomain = wTargetStringPTR.get();
		if (!ConfigurationParameter.TargetDomainString.empty())
		{
			wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
			MultiByteToWideChar(CP_ACP, 0, ConfigurationParameter.TargetDomainString.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)ConfigurationParameter.TargetDomainString.length());
			wTargetDomainString = wTargetStringPTR.get();
		}
		wTargetStringPTR.reset();
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		MBSToWCSString(ConfigurationParameter.wTargetString, ConfigurationParameter.TargetString.c_str());
		MBSToWCSString(wTestDomain, ConfigurationParameter.TestDomain.c_str());
		if (!ConfigurationParameter.TargetDomainString.empty())
			MBSToWCSString(wTargetDomainString, ConfigurationParameter.TargetDomainString.c_str());
	#endif

	//Check DNS header.
		if (ConfigurationParameter.HeaderParameter.Flags == 0)
			ConfigurationParameter.HeaderParameter.Flags = htons(DNS_STANDARD);
		if (ConfigurationParameter.HeaderParameter.Questions == 0)
			ConfigurationParameter.HeaderParameter.Questions = htons(U16_NUM_ONE);

	//Check DNS query.
		if (ConfigurationParameter.QueryParameter.Classes == 0)
			ConfigurationParameter.QueryParameter.Classes = htons(DNS_CLASS_IN);
		if (ConfigurationParameter.QueryParameter.Type == 0)
		{
			if (ConfigurationParameter.SockAddr.ss_family == AF_INET6) //IPv6
				ConfigurationParameter.QueryParameter.Type = htons(DNS_RECORD_AAAA);
			else //IPv4
				ConfigurationParameter.QueryParameter.Type = htons(DNS_RECORD_A);
		}

	//Check EDNS0 Label.
		if (ConfigurationParameter.DNSSEC)
			ConfigurationParameter.EDNS0 = true;
		if (ConfigurationParameter.EDNS0)
		{
			ConfigurationParameter.HeaderParameter.Additional = htons(U16_NUM_ONE);
			ConfigurationParameter.EDNS0Parameter.Type = htons(DNS_RECORD_OPT);
			if (ConfigurationParameter.EDNS0PayloadSize == 0)
				ConfigurationParameter.EDNS0Parameter.UDPPayloadSize = htons(EDNS0_MINSIZE);
			else 
				ConfigurationParameter.EDNS0Parameter.UDPPayloadSize = htons((uint16_t)ConfigurationParameter.EDNS0PayloadSize);
			if (ConfigurationParameter.DNSSEC)
			{
				ConfigurationParameter.HeaderParameter.FlagsBits.AD = ~ConfigurationParameter.HeaderParameter.FlagsBits.AD; //Local DNSSEC Server validate
				ConfigurationParameter.HeaderParameter.FlagsBits.CD = ~ConfigurationParameter.HeaderParameter.FlagsBits.CD; //Client validate
				ConfigurationParameter.EDNS0Parameter.Z_Bits.DO = ~ConfigurationParameter.EDNS0Parameter.Z_Bits.DO; //Accepts DNSSEC security RRs
			}
		}

	//Output result to file.
		SSIZE_T Result = 0;
		if (!ConfigurationParameter.wOutputFileName.empty())
		{
		#if defined(PLATFORM_WIN)
			Result = _wfopen_s(&ConfigurationParameter.OutputFile, ConfigurationParameter.wOutputFileName.c_str(), L"a,ccs=UTF-8");
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			ConfigurationParameter.OutputFile = fopen(ConfigurationParameter.OutputFileName.c_str(), ("a"));
		#endif
			if (ConfigurationParameter.OutputFile == nullptr)
			{
				fwprintf_s(stderr, L"Create output result file %ls error, error code is %d.\n", ConfigurationParameter.wOutputFileName.c_str(), (int)Result);

				WSACleanup();
				return EXIT_SUCCESS;
			}
			else {
				tm TimeStructure = {0};
				time_t TimeValues = 0;
				time(&TimeValues);
				localtime_s(&TimeStructure, &TimeValues);

				fwprintf_s(ConfigurationParameter.OutputFile, L"------------------------------ %d-%02d-%02d %02d:%02d:%02d ------------------------------\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
			}
		}

	//Print to screen before sending.
		fwprintf_s(stderr, L"\n");
		if (ConfigurationParameter.ReverseLookup)
		{
			if (wTargetDomainString.empty())
			{
				char FQDN[NI_MAXHOST + 1U] = {0};
				if (getnameinfo((PSOCKADDR)&ConfigurationParameter.SockAddr, sizeof(sockaddr_in), FQDN, NI_MAXHOST, nullptr, 0, NI_NUMERICSERV) != 0)
				{
					fwprintf_s(stderr, L"\nResolve addresses to host names error, error code is %d.\n", WSAGetLastError());
					fwprintf_s(stderr, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
					if (ConfigurationParameter.OutputFile != nullptr)
						fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
				}
				else {
					if (ConfigurationParameter.TargetString == FQDN)
					{
						fwprintf_s(stderr, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
						if (ConfigurationParameter.OutputFile != nullptr)
							fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
					}
					else {
						std::shared_ptr<wchar_t> wFQDN(new wchar_t[strnlen(FQDN, NI_MAXHOST) + 1U]());
						wmemset(wFQDN.get(), 0, strnlen(FQDN, NI_MAXHOST) + 1U);

					#if defined(PLATFORM_WIN)
						MultiByteToWideChar(CP_ACP, 0, FQDN, MBSTOWCS_NULLTERMINATE, wFQDN.get(), (int)strlen(FQDN));
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
						mbstowcs(wFQDN.get(), FQDN, strlen(FQDN));
					#endif

						fwprintf_s(stderr, L"DNSPing %ls:%u [%ls] with %ls:\n", wFQDN.get(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
						if (ConfigurationParameter.OutputFile != nullptr)
							fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wFQDN.get(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
					}
				}
			}
			else {
				fwprintf_s(stderr, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
			}
		}
		else {
			if (!ConfigurationParameter.TargetDomainString.empty())
			{
				fwprintf_s(stderr, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ConfigurationParameter.ServiceType), ConfigurationParameter.wTargetString.c_str(), wTestDomain.c_str());
			}
			else {
				fwprintf_s(stderr, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
				if (ConfigurationParameter.OutputFile != nullptr)
					fwprintf_s(ConfigurationParameter.OutputFile, L"DNSPing %ls:%u with %ls:\n", ConfigurationParameter.wTargetString.c_str(), ntohs(ConfigurationParameter.ServiceType), wTestDomain.c_str());
			}
		}

	//Send.
		if (ConfigurationParameter.SendNum == 0)
		{
			for (;;)
			{
				if (ConfigurationParameter.RealSendNum <= UINT16_MAX)
				{
					++ConfigurationParameter.RealSendNum;
					if (SendProcess(ConfigurationParameter.SockAddr, false) == EXIT_FAILURE)
					{
						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					fwprintf_s(stderr, L"\nStatistics is full.\n");
					if (ConfigurationParameter.OutputFile != nullptr)
						fwprintf_s(ConfigurationParameter.OutputFile, L"\nStatistics is full.\n");

					PrintProcess(true, true);
				//Close file handle.
					if (ConfigurationParameter.OutputFile != nullptr)
						fclose(ConfigurationParameter.OutputFile);

					WSACleanup();
					return EXIT_SUCCESS;
				}
			}
		}
		else {
			auto LastSend = false;
			for (size_t Index = 0;Index < ConfigurationParameter.SendNum;++Index)
			{
				++ConfigurationParameter.RealSendNum;
				if (Index == ConfigurationParameter.SendNum - 1U)
					LastSend = true;
				if (SendProcess(ConfigurationParameter.SockAddr, LastSend) == EXIT_FAILURE)
				{
				//Close file handle.
					if (ConfigurationParameter.OutputFile != nullptr)
						fclose(ConfigurationParameter.OutputFile);

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		}

	//Print to screen before finished.
		PrintProcess(true, true);

	//Close file handle.
		if (ConfigurationParameter.OutputFile != nullptr)
			fclose(ConfigurationParameter.OutputFile);
	}

	WSACleanup();
	return EXIT_SUCCESS;
}

//Configuration initialization process
size_t __fastcall ConfigurationInitialization(
	void)
{
//Initialization
#if defined(PLATFORM_WIN)
	memset(&ConfigurationParameter, 0, sizeof(ConfigurationTable) - (sizeof(std::string) * 3U + sizeof(std::wstring) * 2U + sizeof(std::shared_ptr<char>)));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	memset(&ConfigurationParameter, 0, sizeof(ConfigurationTable) - (sizeof(std::string) * 4U + sizeof(std::wstring) * 2U + sizeof(std::shared_ptr<char>)));
#endif

	ConfigurationParameter.SendNum = DEFAULT_SEND_TIMES;
	ConfigurationParameter.BufferSize = PACKET_MAXSIZE;
	ConfigurationParameter.Validate = true;
#if defined(PLATFORM_WIN)
	ConfigurationParameter.SocketTimeout = DEFAULT_TIME_OUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ConfigurationParameter.SocketTimeout.tv_sec = DEFAULT_TIME_OUT;
#endif

#if defined(PLATFORM_WIN)
//Handle the system signal.
	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == false)
	{
		fwprintf_s(stderr, L"\nSet console ctrl handler error, error code is %lu.\n", GetLastError());
		return EXIT_FAILURE;
	}

//Winsock initialization
	WSAData WSAInitialization = {0};
	if (WSAStartup(MAKEWORD(2, 2), &WSAInitialization) != 0 || LOBYTE(WSAInitialization.wVersion) != 2 || HIBYTE(WSAInitialization.wVersion) != 2)
	{
		fwprintf_s(stderr, L"\nWinsock initialization error, error code is %d.\n", WSAGetLastError());

		WSACleanup();
		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Handle the system signal.
	if (signal(SIGHUP, SIG_Handler) == SIG_ERR || signal(SIGINT, SIG_Handler) == SIG_ERR || signal(SIGQUIT, SIG_Handler) == SIG_ERR || signal(SIGTERM, SIG_Handler) == SIG_ERR)
	{
		fwprintf(stderr, L"Handle the system signal error, error code is %d.\n", errno);
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

//Read commands
#if defined(PLATFORM_WIN)
size_t __fastcall ReadCommands(
	int argc, 
	wchar_t* argv[])
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
size_t __fastcall ReadCommands(
	int argc, 
	char *argv[])
#endif
{
//Initialization
	std::wstring Parameter;
	SSIZE_T Result = 0;

//Read parameter
	for (size_t Index = 1U;Index < (size_t)argc;++Index)
	{
	#if defined(PLATFORM_WIN)
		Parameter = argv[Index];
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		MBSToWCSString(Parameter, argv[Index]);
	#endif
		Result = 0;

	//Description(Usage)
		if (Parameter.find(L"?") != std::string::npos || Parameter == L"-H" || Parameter == L"-h")
		{
			PrintDescription();
		}
	//Pings the specified host until stopped. To see statistics and continue type Control-Break. To stop type Control-C.
		else if (Parameter == L"-t")
		{
			ConfigurationParameter.SendNum = 0;
		}
	//Resolve addresses to host names.
		else if (Parameter == L"-a")
		{
			ConfigurationParameter.ReverseLookup = true;
		}
	//Set number of echo requests to send.
		else if (Parameter == L"-n")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.SendNum = Result;
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-n Count] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Set the "Don't Fragment" flag in outgoing packets.
	//All Non-SOCK_STREAM will set "Don't Fragment" flag(Linux).
	#if defined(PLATFORM_WIN)
		else if (Parameter == L"-f")
		{
			ConfigurationParameter.IPv4_DF = true;
		}
	#endif
	//Specifie a Time To Live for outgoing packets.
		else if (Parameter == L"-i")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT8_MAX)
				{
					ConfigurationParameter.IP_HopLimits = (int)Result;
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-i HopLimit/TTL] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Set a long wait periods (in milliseconds) for a response.
		else if (Parameter == L"-w")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result >= TIME_OUT_MIN && Result < UINT16_MAX)
				{
				#if defined(PLATFORM_WIN)
					ConfigurationParameter.SocketTimeout = (int)Result;
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					ConfigurationParameter.SocketTimeout.tv_sec = (time_t)(Result / SECOND_TO_MILLISECOND);
					ConfigurationParameter.SocketTimeout.tv_usec = (suseconds_t)(Result % MICROSECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND);
				#endif
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-w Timeout] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie DNS header ID.
		else if (Parameter == L"-ID" || Parameter == L"-id")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.HeaderParameter.ID = htons((uint16_t)Result);
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-id DNS_ID] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Set DNS header flag: QR
		else if (Parameter == L"-QR" || Parameter == L"-qr")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.QR = ~ConfigurationParameter.HeaderParameter.FlagsBits.QR;
		}
	//Specifie DNS header OPCode.
		else if (Parameter == L"-OPCode" || Parameter == L"-opcode")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT4_MAX)
				{
				#if __BYTE_ORDER == __LITTLE_ENDIAN
					auto TempFlags = (uint16_t)Result;
					TempFlags = htons(TempFlags << 11U);
					ConfigurationParameter.HeaderParameter.Flags = ConfigurationParameter.HeaderParameter.Flags | TempFlags;
				#else //Big-Endian
					auto TempFlags = (uint8_t)Result;
					TempFlags = TempFlags & 15;//0x00001111
					ConfigurationParameter.HeaderParameter.FlagsBits.OPCode = TempFlags;
				#endif
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-opcode OPCode] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Set DNS header flag: AA
		else if (Parameter == L"-AA" || Parameter == L"-aa")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.AA = ~ConfigurationParameter.HeaderParameter.FlagsBits.AA;
		}
	//Set DNS header flag: TC
		else if (Parameter == L"-TC" || Parameter == L"-tc")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.TC = ~ConfigurationParameter.HeaderParameter.FlagsBits.TC;
		}
	//Set DNS header flag: RD
		else if (Parameter == L"-RD" || Parameter == L"-rd")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.RD = ~ConfigurationParameter.HeaderParameter.FlagsBits.RD;
		}
	//Set DNS header flag: RA
		else if (Parameter == L"-RA" || Parameter == L"-ra")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.RA = ~ConfigurationParameter.HeaderParameter.FlagsBits.RA;
		}
	//Set DNS header flag: AD
		else if (Parameter == L"-AD" || Parameter == L"-ad")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.AD = ~ConfigurationParameter.HeaderParameter.FlagsBits.AD;
		}
	//Set DNS header flag: CD
		else if (Parameter == L"-CD" || Parameter == L"-cd")
		{
			ConfigurationParameter.HeaderParameter.FlagsBits.CD = ~ConfigurationParameter.HeaderParameter.FlagsBits.CD;
		}
	//Specifie DNS header RCode.
		else if (Parameter == L"-RCode" || Parameter == L"-rcode")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT4_MAX)
				{
				#if __BYTE_ORDER == __LITTLE_ENDIAN
					auto TempFlags = (uint16_t)Result;
					TempFlags = htons(TempFlags);
					ConfigurationParameter.HeaderParameter.Flags = ConfigurationParameter.HeaderParameter.Flags | TempFlags;
				#else //Big-Endian
					auto TempFlags = (uint8_t)Result;
					TempFlags = TempFlags & 15; //0x00001111
					ConfigurationParameter.HeaderParameter.FlagsBits.RCode = TempFlags;
				#endif
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-rcode RCode] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie DNS header question count.
		else if (Parameter == L"-QN" || Parameter == L"-qn")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.HeaderParameter.Questions = htons((uint16_t)Result);
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-qn Count] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie DNS header Answer count.
		else if (Parameter == L"-ANN" || Parameter == L"-ann")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.HeaderParameter.Answer = htons((uint16_t)Result);
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-ann Count] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie DNS header Authority count.
		else if (Parameter == L"-AUN" || Parameter == L"-aun")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.HeaderParameter.Authority = htons((uint16_t)Result);
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-aun Count] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie DNS header Additional count.
		else if (Parameter == L"-ADN" || Parameter == L"-adn")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > 0 && Result <= UINT16_MAX)
				{
					ConfigurationParameter.HeaderParameter.Additional = htons((uint16_t)Result);
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-adn Count] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie transmission interval time(in milliseconds).
		else if (Parameter == L"-Ti" || Parameter == L"-ti")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result >= 0)
				{
				#if defined(PLATFORM_WIN)
					ConfigurationParameter.TransmissionInterval = Result;
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					ConfigurationParameter.TransmissionInterval = Result * MICROSECOND_TO_MILLISECOND;
				#endif
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-ti IntervalTime] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Send with EDNS0 Label.
		else if (Parameter == L"-EDNS0" || Parameter == L"-edns0")
		{
			ConfigurationParameter.EDNS0 = true;
		}
	//Specifie EDNS0 Label UDP Payload length.
		else if (Parameter == L"-Payload" || Parameter == L"-payload")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result > OLD_DNS_MAXSIZE && Result <= UINT16_MAX)
				{
					ConfigurationParameter.EDNS0PayloadSize = Result;
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-payload Length] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}

			ConfigurationParameter.EDNS0 = true;
		}
	//Send with DNSSEC requesting.
		else if (Parameter == L"-DNSSEC" || Parameter == L"-dnssec")
		{
			ConfigurationParameter.EDNS0 = true;
			ConfigurationParameter.DNSSEC = true;
		}
	//Specifie Query Type.
		else if (Parameter == L"-QT" || Parameter == L"-qt")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

			//Type name
				Result = DNSTypeNameToHex(Parameter);
				if (Result == 0)
				{
			//Type number
					Result = wcstoul(Parameter.c_str(), nullptr, 0);
					if (Result > 0 && Result <= UINT16_MAX)
					{
						ConfigurationParameter.QueryParameter.Type = htons((uint16_t)Result);
					}
					else {
						fwprintf_s(stderr, L"\nParameter [-qt Type] error.\n");
						return EXIT_FAILURE;
					}
				}
				else {
					ConfigurationParameter.QueryParameter.Type = (uint16_t)Result;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie Query Classes.
		else if (Parameter == L"-QC" || Parameter == L"-qc")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

			//Classes name
				Result = DNSClassesNameToHex(Parameter);
				if (Result == 0)
				{
			//Classes number
					Result = wcstoul(Parameter.c_str(), nullptr, 0);
					if (Result > 0 && Result <= UINT16_MAX)
					{
						ConfigurationParameter.QueryParameter.Classes = htons((uint16_t)Result);
					}
					else {
						fwprintf_s(stderr, L"\nParameter [-qc Classes] error.\n");
						return EXIT_FAILURE;
					}
				}
				else {
					ConfigurationParameter.QueryParameter.Classes = (uint16_t)Result;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie requesting server name or port.
		else if (Parameter == L"-p")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

			//Server name
				Result = ServiceNameToPort(Parameter);
				if (Result == 0)
				{
				//Number port
					Result = wcstoul(Parameter.c_str(), nullptr, 0);
					if (Result > 0 && Result <= UINT16_MAX)
					{
						ConfigurationParameter.ServiceType = htons((uint16_t)Result);
					}
					else {
						fwprintf_s(stderr, L"\nParameter [-p ServiceType/Protocol] error.\n");
						return EXIT_FAILURE;
					}
				}
				else {
					ConfigurationParameter.ServiceType = (uint16_t)Result;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie Raw data to send.
		else if (Parameter == L"-RAWDATA" || Parameter == L"-rawdata")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

			//Initialization
				std::shared_ptr<char> RawDataStringPTR(new char[Parameter.length() + 1U]());
				memset(RawDataStringPTR.get(), 0, Parameter.length() + 1U);
			#if defined(PLATFORM_WIN)
				WideCharToMultiByte(CP_ACP, 0, Parameter.c_str(), (int)Parameter.length(), RawDataStringPTR.get(), (int)Parameter.length() + 1U, nullptr, nullptr);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				wcstombs(RawDataStringPTR.get(), Parameter.c_str(), Parameter.length());
			#endif
				std::string RawDataString(RawDataStringPTR.get());
				RawDataStringPTR.reset();

				if (RawDataString.length() < PACKET_MINSIZE && RawDataString.length() > PACKET_MAXSIZE)
				{
					fwprintf_s(stderr, L"\nParameter [-rawdata RAW_Data] error.\n");
					return EXIT_FAILURE;
				}
				std::shared_ptr<char> TempRawData(new char[PACKET_MAXSIZE]());
				memset(TempRawData.get(), 0, PACKET_MAXSIZE);
				ConfigurationParameter.RawData.swap(TempRawData);
				TempRawData.reset();
				char TempString[5U] = {0};
				TempString[0] = ASCII_ZERO;
				TempString[1U] = 120; //"x"

			//Read raw data.
				for (size_t InnerIndex = 0;InnerIndex < RawDataString.length();++InnerIndex)
				{
					TempString[2U] = RawDataString[InnerIndex];
					++InnerIndex;
					TempString[3U] = RawDataString[InnerIndex];
					Result = (SSIZE_T)strtoul(TempString, nullptr, 0);
					if (Result > 0 && Result <= UINT8_MAX)
					{
						ConfigurationParameter.RawData.get()[ConfigurationParameter.RawDataLen] = (char)Result;
						++ConfigurationParameter.RawDataLen;
					}
					else {
						fwprintf_s(stderr, L"\nParameter [-rawdata RAW_Data] error.\n");
						return EXIT_FAILURE;
					}
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Send RAW data with Raw Socket.
		else if (Parameter == L"-RAW" || Parameter == L"-raw")
		{
			if (Index + 1U < (size_t)argc)
			{
				ConfigurationParameter.RawSocket = true;
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

			//Protocol name
				Result = InternetProtocolNameToPort(Parameter);
				if (Result == 0)
				{
			//Protocol number
					Result = wcstoul(Parameter.c_str(), nullptr, 0);
					if (Result == IPPROTO_UDP)
					{
						ConfigurationParameter.RawSocket = false;
					}
					else if (Result > 0 && Result <= UINT4_MAX)
					{
						ConfigurationParameter.ServiceType = (uint8_t)Result;
					}
					else {
						fwprintf_s(stderr, L"\nParameter [-raw ServiceType] error.\n");
						return EXIT_FAILURE;
					}
				}
				else if (Result == IPPROTO_UDP)
				{
					ConfigurationParameter.RawSocket = false;
				}
				else {
					ConfigurationParameter.ServiceType = (uint8_t)Result;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Specifie buffer size.
		else if (Parameter == L"-Buf" || Parameter == L"-buf")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				Result = wcstoul(Parameter.c_str(), nullptr, 0);
				if (Result >= OLD_DNS_MAXSIZE && Result <= LARGE_PACKET_MAXSIZE)
				{
					ConfigurationParameter.BufferSize = Result;
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-show Response] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Disable packets validated.
		else if (Parameter == L"-DV" || Parameter == L"-dv")
		{
			ConfigurationParameter.Validate = false;
		}
	//Show response.
		else if (Parameter == L"-SHOW" || Parameter == L"-show")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				if (Parameter == L"Result" || Parameter == L"result")
				{
					ConfigurationParameter.ShowResponse = true;
				}
				else if (Parameter == L"Hex" || Parameter == L"hex")
				{
					ConfigurationParameter.ShowResponseHex = true;
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-buf Size] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Output result to file.
		else if (Parameter == L"-OF" || Parameter == L"-of")
		{
			if (Index + 1U < (size_t)argc)
			{
				++Index;
			#if defined(PLATFORM_WIN)
				Parameter = argv[Index];
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				MBSToWCSString(Parameter, argv[Index]);
			#endif

				if (Parameter.length() <= MAX_PATH)
				{
					ConfigurationParameter.wOutputFileName = Parameter;

				#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					std::shared_ptr<char> OutputFileNamePTR(new char[Parameter.length() + 1U]);
					memset(OutputFileNamePTR.get(), 0, Parameter.length() + 1U);
					wcstombs(OutputFileNamePTR.get(), Parameter.c_str(), Parameter.length());
					ConfigurationParameter.OutputFileName = OutputFileNamePTR.get();
				#endif
				}
				else {
					fwprintf_s(stderr, L"\nParameter [-of FileName] error.\n");
					return EXIT_FAILURE;
				}
			}
			else {
				fwprintf_s(stderr, L"\nNot enough parameters error.\n");
				return EXIT_FAILURE;
			}
		}
	//Using IPv6.
		else if (Parameter == L"-6")
		{
			ConfigurationParameter.Protocol = AF_INET6;
		}
	//Using IPv4.
		else if (Parameter == L"-4")
		{
			ConfigurationParameter.Protocol = AF_INET;
		}
	//Specifie Query Domain.
		else if (!ConfigurationParameter.RawData && ConfigurationParameter.TestDomain.empty() && Index == (size_t)(argc - 2))
		{
		//Check parameter.
			if (Parameter.length() <= DOMAIN_MINSIZE || Parameter.length() > DOMAIN_MAXSIZE)
			{
				fwprintf_s(stderr, L"\nTest domain length error.\n");
				return EXIT_FAILURE;
			}

			std::shared_ptr<char> TestDomainPTR(new char[Parameter.length() + 1U]());
			memset(TestDomainPTR.get(), 0, Parameter.length() + 1U);
		#if defined(PLATFORM_WIN)
			WideCharToMultiByte(CP_ACP, 0, Parameter.c_str(), (int)Parameter.length(), TestDomainPTR.get(), (int)(Parameter.length() + 1U), nullptr, nullptr);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			wcstombs(TestDomainPTR.get(), Parameter.c_str(), Parameter.length());
		#endif

			ConfigurationParameter.TestDomain = TestDomainPTR.get();
		}
	//Specifie target.
		else if (Index == (size_t)(argc - 1))
		{
		//Check parameter.
			if (Parameter.length() < DOMAIN_MINSIZE || Parameter.length() > DOMAIN_MAXSIZE)
			{
				fwprintf_s(stderr, L"\nTarget length error.\n");
				return EXIT_FAILURE;
			}

		//Initialization
			std::shared_ptr<char> ParameterPTR(new char[Parameter.length() + 1U]());
			memset(ParameterPTR.get(), 0, Parameter.length() + 1U);
		#if defined(PLATFORM_WIN)
			WideCharToMultiByte(CP_ACP, 0, Parameter.c_str(), (int)Parameter.length(), ParameterPTR.get(), (int)(Parameter.length() + 1U), nullptr, nullptr);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			wcstombs(ParameterPTR.get(), Parameter.c_str(), Parameter.length());
		#endif
			std::string ParameterString(ParameterPTR.get());
			ParameterPTR.reset();

		//IPv6 address
			if (ParameterString.find(ASCII_COLON) != std::string::npos)
			{
			//Check parameter.
				if (Parameter.length() < 2U || Parameter.length() > 40U) //IPv6 format
				{
					fwprintf_s(stderr, L"\nTarget length error.\n");
					return EXIT_FAILURE;
				}
				else if (ConfigurationParameter.Protocol == AF_INET)
				{
					fwprintf_s(stderr, L"\nTarget protocol error.\n");
					return EXIT_FAILURE;
				}

				ConfigurationParameter.Protocol = AF_INET6;
				ConfigurationParameter.SockAddr.ss_family = AF_INET6;
				if (AddressStringToBinary((PSTR)ParameterString.c_str(), &((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
				{
					fwprintf_s(stderr, L"\nTarget format error, error code is %d.\n", (int)Result);
					return EXIT_FAILURE;
				}

				ConfigurationParameter.TargetString.append("[");
				ConfigurationParameter.TargetString.append(ParameterString);
				ConfigurationParameter.TargetString.append("]");
			}
			else {
				for (auto StringIter = ParameterString.begin();StringIter != ParameterString.end();++StringIter)
				{
				//Domain
					if (*StringIter < ASCII_PERIOD || *StringIter == ASCII_SLASH || *StringIter > ASCII_NINE)
					{
					//Check parameter.
						if (Parameter.length() <= DOMAIN_MINSIZE)
						{
							fwprintf_s(stderr, L"\nTarget length error.\n");
							return EXIT_FAILURE;
						}

						ADDRINFOA AddrInfoHints = {0}, *AddrInfo = nullptr;
					//Try with IPv6.
						if (ConfigurationParameter.Protocol == 0)
							ConfigurationParameter.Protocol = AF_INET6;
						AddrInfoHints.ai_family = ConfigurationParameter.Protocol;
						ConfigurationParameter.SockAddr.ss_family = ConfigurationParameter.Protocol;

					//Get address.
						if (getaddrinfo(ParameterString.c_str(), nullptr, &AddrInfoHints, &AddrInfo) != 0)
						{
						//Retry with IPv4.
							ConfigurationParameter.Protocol = AF_INET;
							AddrInfoHints.ai_family = ConfigurationParameter.Protocol;
							ConfigurationParameter.SockAddr.ss_family = ConfigurationParameter.Protocol;
							if (getaddrinfo(ParameterString.c_str(), nullptr, &AddrInfoHints, &AddrInfo) != 0)
							{
								fwprintf_s(stderr, L"\nResolve domain name error, error code is %d.\n", WSAGetLastError());
								return EXIT_FAILURE;
							}
						}

					//Get address from PTR.
						if (AddrInfo != nullptr)
						{
							for (auto PTR = AddrInfo;PTR != nullptr;PTR = PTR->ai_next)
							{
							//IPv6
								if (PTR->ai_family == AF_INET6 && ConfigurationParameter.SockAddr.ss_family == AF_INET6 &&
									!IN6_IS_ADDR_LINKLOCAL((in6_addr *)(PTR->ai_addr)) && 
									!(((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_scope_id == 0)) //Get port from first(Main) IPv6 device
								{
									((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_addr = ((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_addr;

								//Get string of address.
									ConfigurationParameter.TargetDomainString = ParameterString;
									char Buffer[ADDR_STRING_MAXSIZE] = {0};

								//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
								#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
									DWORD BufferLength = ADDR_STRING_MAXSIZE;
									WSAAddressToStringA((PSOCKADDR)&ConfigurationParameter.SockAddr, sizeof(sockaddr_in6), nullptr, Buffer, &BufferLength);
								#else
									inet_ntop(AF_INET6, &((PSOCKADDR_IN6)&ConfigurationParameter.SockAddr)->sin6_addr, Buffer, ADDR_STRING_MAXSIZE);
								#endif
									CaseConvert(true, Buffer, strlen(Buffer));

									ConfigurationParameter.TargetString.append("[");
									ConfigurationParameter.TargetString.append(Buffer);
									ConfigurationParameter.TargetString.append("]");
									break;
								}
							//IPv4
								else if (PTR->ai_family == AF_INET && ConfigurationParameter.SockAddr.ss_family == AF_INET &&
									((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.s_addr != INADDR_LOOPBACK && 
									((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.s_addr != INADDR_BROADCAST)
								{
									((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_addr = ((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr;

								//Get string of address.
									ConfigurationParameter.TargetDomainString = ParameterString;
									char Buffer[ADDR_STRING_MAXSIZE] = {0};

								//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
								#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
									DWORD BufferLength = ADDR_STRING_MAXSIZE;
									WSAAddressToStringA((PSOCKADDR)&ConfigurationParameter.SockAddr, sizeof(sockaddr_in), nullptr, Buffer, &BufferLength);
								#else
									inet_ntop(AF_INET, &((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_addr, Buffer, ADDR_STRING_MAXSIZE);
								#endif

									ConfigurationParameter.TargetString = Buffer;
									break;
								}
							}

							freeaddrinfo(AddrInfo);
						}

						break;
					}

				//IPv4
					if (StringIter == ParameterString.end() - 1U)
					{
					//Check parameter.
						if (Parameter.length() < 7U || Parameter.length() > 15U) //IPv4 format
						{
							fwprintf_s(stderr, L"\nTarget length error.\n");
							return EXIT_FAILURE;
						}
						else if (ConfigurationParameter.Protocol == AF_INET6)
						{
							fwprintf_s(stderr, L"\nTarget protocol error.\n");
							return EXIT_FAILURE;
						}

						ConfigurationParameter.Protocol = AF_INET;
						ConfigurationParameter.SockAddr.ss_family = AF_INET;
						if (AddressStringToBinary((PSTR)ParameterString.c_str(), &((PSOCKADDR_IN)&ConfigurationParameter.SockAddr)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
						{
							fwprintf_s(stderr, L"\nTarget format error, error code is %d.\n", (int)Result);
							return EXIT_FAILURE;
						}

						ConfigurationParameter.TargetString = ParameterString;
					}
				}
			}
		}
	}

	return EXIT_SUCCESS;
}
