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
	int wmain(int argc, wchar_t* argv[])
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int main(int argc, char *argv[])
#endif
{
#if defined(PLATFORM_WIN)
//Handle the system signal.
	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == false)
	{
		wprintf_s(L"\nSet console ctrl handler error, error code is %lu.\n", GetLastError());
		return EXIT_FAILURE;
	}

//Winsock initialization
	WSAData WSAInitialization = {0};
	if (WSAStartup(MAKEWORD(2, 2), &WSAInitialization) != 0 || LOBYTE(WSAInitialization.wVersion) != 2 || HIBYTE(WSAInitialization.wVersion) != 2)
	{
		wprintf_s(L"\nWinsock initialization error, error code is %d.\n", WSAGetLastError());

		WSACleanup();
		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Handle the system signal.
	if (signal(SIGHUP, SIG_Handler) == SIG_ERR || signal(SIGINT, SIG_Handler) == SIG_ERR || signal(SIGQUIT, SIG_Handler) == SIG_ERR || signal(SIGTERM, SIG_Handler) == SIG_ERR)
	{
		wprintf(L"Handle the system signal error, error code is %d.\n", errno);
		return EXIT_FAILURE;
	}
#endif

//Main
	if (argc > 2)
	{
		std::wstring Parameter;
		SSIZE_T Result = 0;

	//Read parameter
		auto ReverseLookup = false;
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
				SendNum = 0;
			}
		//Resolve addresses to host names.
			else if (Parameter == L"-a")
			{
				ReverseLookup = true;
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
						SendNum = Result;
					}
					else {
						wprintf_s(L"\nParameter [-n Count] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Set the "Don't Fragment" flag in outgoing packets.
		// All Non-SOCK_STREAM will set "Don't Fragment" flag(Linux).
		#if defined(PLATFORM_WIN)
			else if (Parameter == L"-f")
			{
				IPv4_DF = true;
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
						IP_HopLimits = (int)Result;
					}
					else {
						wprintf_s(L"\nParameter [-i HopLimit/TTL] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						SocketTimeout = (int)Result;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
						SocketTimeout.tv_sec = (time_t)(Result / SECOND_TO_MILLISECOND);
						SocketTimeout.tv_usec = (suseconds_t)(Result % MICROSECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND);
					#endif
					}
					else {
						wprintf_s(L"\nParameter [-w Timeout] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						HeaderParameter.ID = htons((uint16_t)Result);
					}
					else {
						wprintf_s(L"\nParameter [-id DNS_ID] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Set DNS header flag: QR
			else if (Parameter == L"-QR" || Parameter == L"-qr")
			{
				HeaderParameter.FlagsBits.QR = ~HeaderParameter.FlagsBits.QR;
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
						HeaderParameter.Flags = HeaderParameter.Flags | TempFlags;
					#else //Big-Endian
						auto TempFlags = (uint8_t)Result;
						TempFlags = TempFlags & 15;//0x00001111
						HeaderParameter.FlagsBits.OPCode = TempFlags;
					#endif
					}
					else {
						wprintf_s(L"\nParameter [-opcode OPCode] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Set DNS header flag: AA
			else if (Parameter == L"-AA" || Parameter == L"-aa")
			{
				HeaderParameter.FlagsBits.AA = ~HeaderParameter.FlagsBits.AA;
			}
		//Set DNS header flag: TC
			else if (Parameter == L"-TC" || Parameter == L"-tc")
			{
				HeaderParameter.FlagsBits.TC = ~HeaderParameter.FlagsBits.TC;
			}
		//Set DNS header flag: RD
			else if (Parameter == L"-RD" || Parameter == L"-rd")
			{
				HeaderParameter.FlagsBits.RD = ~HeaderParameter.FlagsBits.RD;
			}
		//Set DNS header flag: RA
			else if (Parameter == L"-RA" || Parameter == L"-ra")
			{
				HeaderParameter.FlagsBits.RA = ~HeaderParameter.FlagsBits.RA;
			}
		//Set DNS header flag: AD
			else if (Parameter == L"-AD" || Parameter == L"-ad")
			{
				HeaderParameter.FlagsBits.AD = ~HeaderParameter.FlagsBits.AD;
			}
		//Set DNS header flag: CD
			else if (Parameter == L"-CD" || Parameter == L"-cd")
			{
				HeaderParameter.FlagsBits.CD = ~HeaderParameter.FlagsBits.CD;
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
						HeaderParameter.Flags = HeaderParameter.Flags | TempFlags;
					#else //Big-Endian
						auto TempFlags = (uint8_t)Result;
						TempFlags = TempFlags & 15; //0x00001111
						HeaderParameter.FlagsBits.RCode = TempFlags;
					#endif
					}
					else {
						wprintf_s(L"\nParameter [-rcode RCode] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						HeaderParameter.Questions = htons((uint16_t)Result);
					}
					else {
						wprintf_s(L"\nParameter [-qn Count] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						HeaderParameter.Answer = htons((uint16_t)Result);
					}
					else {
						wprintf_s(L"\nParameter [-ann Count] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						HeaderParameter.Authority = htons((uint16_t)Result);
					}
					else {
						wprintf_s(L"\nParameter [-aun Count] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						HeaderParameter.Additional = htons((uint16_t)Result);
					}
					else {
						wprintf_s(L"\nParameter [-adn Count] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						TransmissionInterval = Result;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
						TransmissionInterval = Result * MICROSECOND_TO_MILLISECOND;
					#endif
					}
					else {
						wprintf_s(L"\nParameter [-ti IntervalTime] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Send with EDNS0 Label.
			else if (Parameter == L"-EDNS0" || Parameter == L"-edns0")
			{
				EDNS0 = true;
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
						EDNS0PayloadSize = Result;
					}
					else {
						wprintf_s(L"\nParameter [-payload Length] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}

				EDNS0 = true;
			}
		//Send with DNSSEC requesting.
			else if (Parameter == L"-DNSSEC" || Parameter == L"-dnssec")
			{
				EDNS0 = true;
				DNSSEC = true;
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
							QueryParameter.Type = htons((uint16_t)Result);
						}
						else {
							wprintf_s(L"\nParameter [-qt Type] error.\n");

							WSACleanup();
							return EXIT_FAILURE;
						}
					}
					else {
						QueryParameter.Type = (uint16_t)Result;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
							QueryParameter.Classes = htons((uint16_t)Result);
						}
						else {
							wprintf_s(L"\nParameter [-qc Classes] error.\n");

							WSACleanup();
							return EXIT_FAILURE;
						}
					}
					else {
						QueryParameter.Classes = (uint16_t)Result;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
							ServiceType = htons((uint16_t)Result);
						}
						else {
							wprintf_s(L"\nParameter [-p ServiceType/Protocol] error.\n");

							WSACleanup();
							return EXIT_FAILURE;
						}
					}
					else {
						ServiceType = (uint16_t)Result;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						wprintf_s(L"\nParameter [-rawdata RAW_Data] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
					std::shared_ptr<char> TempRawData(new char[PACKET_MAXSIZE]());
					memset(TempRawData.get(), 0, PACKET_MAXSIZE);
					RawData.swap(TempRawData);
					TempRawData.reset();
					std::shared_ptr<char> TempString(new char[5U]());
					memset(TempString.get(), 0, 5U);
					TempString.get()[0] = ASCII_ZERO;
					TempString.get()[1U] = 120; //"x"

				//Read raw data.
					for (size_t InnerIndex = 0;InnerIndex < RawDataString.length();++InnerIndex)
					{
						TempString.get()[2U] = RawDataString[InnerIndex];
						++InnerIndex;
						TempString.get()[3U] = RawDataString[InnerIndex];
						Result = (SSIZE_T)strtoul(TempString.get(), nullptr, 0);
						if (Result > 0 && Result <= UINT8_MAX)
						{
							RawData.get()[RawDataLen] = (char)Result;
							++RawDataLen;
						}
						else {
							wprintf_s(L"\nParameter [-rawdata RAW_Data] error.\n");

							WSACleanup();
							return EXIT_FAILURE;
						}
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Send RAW data with Raw Socket.
			else if (Parameter == L"-RAW" || Parameter == L"-raw")
			{
				if (Index + 1U < (size_t)argc)
				{
					RawSocket = true;
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
							RawSocket = false;
						}
						else if (Result > 0 && Result <= UINT4_MAX)
						{
							ServiceType = (uint8_t)Result;
						}
						else {
							wprintf_s(L"\nParameter [-raw ServiceType] error.\n");

							WSACleanup();
							return EXIT_FAILURE;
						}
					}
					else if (Result == IPPROTO_UDP)
					{
						RawSocket = false;
					}
					else {
						ServiceType = (uint8_t)Result;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						BufferSize = Result;
					}
					else {
						wprintf_s(L"\nParameter [-show Response] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Disable packets validated.
			else if (Parameter == L"-DV" || Parameter == L"-dv")
			{
				Validate = false;
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
						ShowResponse = true;
					}
					else if (Parameter == L"Hex" || Parameter == L"hex")
					{
						ShowResponseHex = true;
					}
					else {
						wprintf_s(L"\nParameter [-buf Size] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
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
						wOutputFileName = Parameter;

					#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
						std::shared_ptr<char> OutputFileNamePTR(new char[Parameter.length() + 1U]);
						memset(OutputFileNamePTR.get(), 0, Parameter.length() + 1U);
						wcstombs(OutputFileNamePTR.get(), Parameter.c_str(), Parameter.length());
						OutputFileName = OutputFileNamePTR.get();
					#endif
					}
					else {
						wprintf_s(L"\nParameter [-of FileName] error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nNot enough parameters error.\n");

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		//Using IPv6.
			else if (Parameter == L"-6")
			{
				Protocol = AF_INET6;
			}
		//Using IPv4.
			else if (Parameter == L"-4")
			{
				Protocol = AF_INET;
			}
		//Specifie Query Domain.
			else if (!RawData && TestDomain.empty() && Index == (size_t)(argc - 2))
			{
			//Check parameter.
				if (Parameter.length() <= DOMAIN_MINSIZE || Parameter.length() > DOMAIN_MAXSIZE)
				{
					wprintf_s(L"\nTest domain length error.\n");
					return EXIT_FAILURE;
				}

				std::shared_ptr<char> TestDomainPTR(new char[Parameter.length() + 1U]());
				memset(TestDomainPTR.get(), 0, Parameter.length() + 1U);
			#if defined(PLATFORM_WIN)
				WideCharToMultiByte(CP_ACP, 0, Parameter.c_str(), (int)Parameter.length(), TestDomainPTR.get(), (int)(Parameter.length() + 1U), nullptr, nullptr);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				wcstombs(TestDomainPTR.get(), Parameter.c_str(), Parameter.length());
			#endif

				TestDomain = TestDomainPTR.get();
			}
		//Specifie target.
			else if (Index == (size_t)(argc - 1))
			{
			//Check parameter.
				if (Parameter.length() < DOMAIN_MINSIZE || Parameter.length() > DOMAIN_MAXSIZE)
				{
					wprintf_s(L"\nTarget length error.\n");
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
						wprintf_s(L"\nTarget length error.\n");
						return EXIT_FAILURE;
					}
					else if (Protocol == AF_INET)
					{
						wprintf_s(L"\nTarget protocol error.\n");

						WSACleanup();
						return EXIT_FAILURE;
					}

					Protocol = AF_INET6;
					SockAddr.ss_family = AF_INET6;
					if (AddressStringToBinary((PSTR)ParameterString.c_str(), &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, AF_INET6, Result) == EXIT_FAILURE)
					{
						wprintf_s(L"\nTarget format error, error code is %d.\n", (int)Result);

						WSACleanup();
						return EXIT_FAILURE;
					}

					TargetString.append("[");
					TargetString.append(ParameterString);
					TargetString.append("]");
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
								wprintf_s(L"\nTarget length error.\n");
								return EXIT_FAILURE;
							}

							ADDRINFOA AddrInfoHints = {0}, *AddrInfo = nullptr;
						//Try with IPv6.
							if (Protocol == 0)
								Protocol = AF_INET6;
							AddrInfoHints.ai_family = Protocol;
							SockAddr.ss_family = Protocol;

						//Get address.
							if (getaddrinfo(ParameterString.c_str(), nullptr, &AddrInfoHints, &AddrInfo) != 0)
							{
							//Retry with IPv4.
								Protocol = AF_INET;
								AddrInfoHints.ai_family = Protocol;
								SockAddr.ss_family = Protocol;

								if (getaddrinfo(ParameterString.c_str(), nullptr, &AddrInfoHints, &AddrInfo) != 0)
								{
									wprintf_s(L"\nResolve domain name error, error code is %d.\n", WSAGetLastError());

									WSACleanup();
									return EXIT_FAILURE;
								}
							}

						//Get address from PTR.
							if (AddrInfo != nullptr)
							{
								for (auto PTR = AddrInfo;PTR != nullptr;PTR = PTR->ai_next)
								{
								//IPv6
									if (PTR->ai_family == AF_INET6 && SockAddr.ss_family == AF_INET6 && 
										!IN6_IS_ADDR_LINKLOCAL((in6_addr *)(PTR->ai_addr)) && 
										!(((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_scope_id == 0)) //Get port from first(Main) IPv6 device
									{
										((PSOCKADDR_IN6)&SockAddr)->sin6_addr = ((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_addr;

									//Get string of address.
										TargetDomainString = ParameterString;
										std::shared_ptr<char> Buffer(new char[ADDR_STRING_MAXSIZE]());
										memset(Buffer.get(), 0, ADDR_STRING_MAXSIZE);

									//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
									#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
										DWORD BufferLength = ADDR_STRING_MAXSIZE;
										WSAAddressToStringA((PSOCKADDR)&SockAddr, sizeof(sockaddr_in6), nullptr, Buffer.get(), &BufferLength);
									#else
										inet_ntop(AF_INET6, &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, Buffer.get(), ADDR_STRING_MAXSIZE);
									#endif
										CaseConvert(true, Buffer.get(), strlen(Buffer.get()));

										TargetString.append("[");
										TargetString.append(Buffer.get());
										TargetString.append("]");
										break;
									}
								//IPv4
									else if (PTR->ai_family == AF_INET && SockAddr.ss_family == AF_INET && 
										((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.s_addr != INADDR_LOOPBACK && 
										((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.s_addr != INADDR_BROADCAST)
									{
										((PSOCKADDR_IN)&SockAddr)->sin_addr = ((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr;

									//Get string of address.
										TargetDomainString = ParameterString;
										std::shared_ptr<char> Buffer(new char[ADDR_STRING_MAXSIZE]());
										memset(Buffer.get(), 0, ADDR_STRING_MAXSIZE);

									//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
									#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
										DWORD BufferLength = ADDR_STRING_MAXSIZE;
										WSAAddressToStringA((PSOCKADDR)&SockAddr, sizeof(sockaddr_in), nullptr, Buffer.get(), &BufferLength);
									#else
										inet_ntop(AF_INET, &((PSOCKADDR_IN)&SockAddr)->sin_addr, Buffer.get(), ADDR_STRING_MAXSIZE);
									#endif

										TargetString = Buffer.get();
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
								wprintf_s(L"\nTarget length error.\n");
								return EXIT_FAILURE;
							}
							else if (Protocol == AF_INET6)
							{
								wprintf_s(L"\nTarget protocol error.\n");

								WSACleanup();
								return EXIT_FAILURE;
							}

							Protocol = AF_INET;
							SockAddr.ss_family = AF_INET;
							if (AddressStringToBinary((PSTR)ParameterString.c_str(), &((PSOCKADDR_IN)&SockAddr)->sin_addr, AF_INET, Result) == EXIT_FAILURE)
							{
								wprintf_s(L"\nTarget format error, error code is %d.\n", (int)Result);

								WSACleanup();
								return EXIT_FAILURE;
							}

							TargetString = ParameterString;
						}
					}
				}
			}
		}

	//Check parameter reading.
		if (SockAddr.ss_family == AF_INET6) //IPv6
		{
			if (CheckEmptyBuffer(&((PSOCKADDR_IN6)&SockAddr)->sin6_addr, sizeof(in6_addr)))
			{
				wprintf_s(L"\nTarget is empty.\n");

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
			//Mark port.
				if (ServiceType == 0)
				{
					ServiceType = htons(IPPORT_DNS);
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(IPPORT_DNS);
				}
				else {
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = ServiceType;
				}
			}
		}
		else { //IPv4
			if (((PSOCKADDR_IN)&SockAddr)->sin_addr.s_addr == 0)
			{
				wprintf_s(L"\nTarget is empty.\n");

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
			//Mark port.
				if (ServiceType == 0)
				{
					ServiceType = htons(IPPORT_DNS);
					((PSOCKADDR_IN)&SockAddr)->sin_port = htons(IPPORT_DNS);
				}
				else {
					((PSOCKADDR_IN)&SockAddr)->sin_port = ServiceType;
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
				if (SocketTimeout > TIME_OUT_MIN)
					SocketTimeout -= 500;
				else if (SocketTimeout == TIME_OUT_MIN)
					SocketTimeout = 1;
			}
		MinTime = SocketTimeout;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		MinTime = SocketTimeout.tv_sec * SECOND_TO_MILLISECOND + SocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
	#endif

	//Convert multiple byte string to wide char string.
		std::wstring wTestDomain, wTargetDomainString;
	#if defined(PLATFORM_WIN)
		std::shared_ptr<wchar_t> wTargetStringPTR(new wchar_t[LARGE_PACKET_MAXSIZE]());
		wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
		MultiByteToWideChar(CP_ACP, 0, TargetString.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)TargetString.length());
		wTargetString = wTargetStringPTR.get();
		wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
		MultiByteToWideChar(CP_ACP, 0, TestDomain.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)TestDomain.length());
		wTestDomain = wTargetStringPTR.get();
		if (!TargetDomainString.empty())
		{
			wmemset(wTargetStringPTR.get(), 0, LARGE_PACKET_MAXSIZE);
			MultiByteToWideChar(CP_ACP, 0, TargetDomainString.c_str(), MBSTOWCS_NULLTERMINATE, wTargetStringPTR.get(), (int)TargetDomainString.length());
			wTargetDomainString = wTargetStringPTR.get();
		}
		wTargetStringPTR.reset();
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		MBSToWCSString(wTargetString, TargetString.c_str());
		MBSToWCSString(wTestDomain, TestDomain.c_str());
		if (!TargetDomainString.empty())
			MBSToWCSString(wTargetDomainString, TargetDomainString.c_str());
	#endif

	//Check DNS header.
		if (HeaderParameter.Flags == 0)
			HeaderParameter.Flags = htons(DNS_STANDARD);
		if (HeaderParameter.Questions == 0)
			HeaderParameter.Questions = htons(U16_NUM_ONE);

	//Check DNS query.
		if (QueryParameter.Classes == 0)
			QueryParameter.Classes = htons(DNS_CLASS_IN);
		if (QueryParameter.Type == 0)
		{
			if (SockAddr.ss_family == AF_INET6) //IPv6
				QueryParameter.Type = htons(DNS_RECORD_AAAA);
			else //IPv4
				QueryParameter.Type = htons(DNS_RECORD_A);
		}

	//Check EDNS0 Label.
		if (DNSSEC)
			EDNS0 = true;
		if (EDNS0)
		{
			HeaderParameter.Additional = htons(U16_NUM_ONE);
			EDNS0Parameter.Type = htons(DNS_RECORD_OPT);
			if (EDNS0PayloadSize == 0)
				EDNS0Parameter.UDPPayloadSize = htons(EDNS0_MINSIZE);
			else 
				EDNS0Parameter.UDPPayloadSize = htons((uint16_t)EDNS0PayloadSize);
			if (DNSSEC)
			{
				HeaderParameter.FlagsBits.AD = ~HeaderParameter.FlagsBits.AD; //Local DNSSEC Server validate
				HeaderParameter.FlagsBits.CD = ~HeaderParameter.FlagsBits.CD; //Client validate
				EDNS0Parameter.Z_Bits.DO = ~EDNS0Parameter.Z_Bits.DO; //Accepts DNSSEC security RRs
			}
		}

	//Output result to file.
		if (!wOutputFileName.empty())
		{
		#if defined(PLATFORM_WIN)
			Result = _wfopen_s(&OutputFile, wOutputFileName.c_str(), L"a,ccs=UTF-8");
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputFile = fopen(OutputFileName.c_str(), ("a"));
		#endif
			if (OutputFile == nullptr)
			{
				wprintf_s(L"Create output result file %ls error, error code is %d.\n", wOutputFileName.c_str(), (int)Result);

				WSACleanup();
				return EXIT_SUCCESS;
			}
			else {
				std::shared_ptr<tm> TimeStructure(new tm());
				memset(TimeStructure.get(), 0, sizeof(tm));
				time_t TimeValues = 0;
				time(&TimeValues);
				localtime_s(TimeStructure.get(), &TimeValues);

				fwprintf_s(OutputFile, L"------------------------------ %d-%02d-%02d %02d:%02d:%02d ------------------------------\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
			}
		}

	//Print to screen before sending.
		wprintf_s(L"\n");
		if (ReverseLookup)
		{
			if (wTargetDomainString.empty())
			{
				std::shared_ptr<char> FQDN(new char[NI_MAXHOST + 1U]());
				memset(FQDN.get(), 0, NI_MAXHOST + 1U);
				if (getnameinfo((PSOCKADDR)&SockAddr, sizeof(sockaddr_in), FQDN.get(), NI_MAXHOST, nullptr, 0, NI_NUMERICSERV) != 0)
				{
					wprintf_s(L"\nResolve addresses to host names error, error code is %d.\n", WSAGetLastError());
					wprintf_s(L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
					if (OutputFile != nullptr)
						fwprintf_s(OutputFile, L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
				}
				else {
					if (TargetString == FQDN.get())
					{
						wprintf_s(L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
						if (OutputFile != nullptr)
							fwprintf_s(OutputFile, L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
					}
					else {
						std::shared_ptr<wchar_t> wFQDN(new wchar_t[strnlen(FQDN.get(), NI_MAXHOST) + 1U]());
						wmemset(wFQDN.get(), 0, strnlen(FQDN.get(), NI_MAXHOST) + 1U);

					#if defined(PLATFORM_WIN)
						MultiByteToWideChar(CP_ACP, 0, FQDN.get(), MBSTOWCS_NULLTERMINATE, wFQDN.get(), (int)strlen(FQDN.get()));
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
						mbstowcs(wFQDN.get(), FQDN.get(), strlen(FQDN.get()));
					#endif

						wprintf_s(L"DNSPing %ls:%u [%ls] with %ls:\n", wFQDN.get(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
						if (OutputFile != nullptr)
							fwprintf_s(OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wFQDN.get(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
					}
				}
			}
			else {
				wprintf_s(L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
			}
		}
		else {
			if (!TargetDomainString.empty())
			{
				wprintf_s(L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, L"DNSPing %ls:%u [%ls] with %ls:\n", wTargetDomainString.c_str(), ntohs(ServiceType), wTargetString.c_str(), wTestDomain.c_str());
			}
			else {
				wprintf_s(L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, L"DNSPing %ls:%u with %ls:\n", wTargetString.c_str(), ntohs(ServiceType), wTestDomain.c_str());
			}
		}

	//Send.
		if (SendNum == 0)
		{
			while (true)
			{
				if (RealSendNum <= UINT16_MAX)
				{
					++RealSendNum;
					if (SendProcess(SockAddr, false) == EXIT_FAILURE)
					{
						WSACleanup();
						return EXIT_FAILURE;
					}
				}
				else {
					wprintf_s(L"\nStatistics is full.\n");
					if (OutputFile != nullptr)
						fwprintf_s(OutputFile, L"\nStatistics is full.\n");

					PrintProcess(true, true);
				//Close file handle.
					if (OutputFile != nullptr)
						fclose(OutputFile);

					WSACleanup();
					return EXIT_SUCCESS;
				}
			}
		}
		else {
			auto LastSend = false;
			for (size_t Index = 0;Index < SendNum;++Index)
			{
				++RealSendNum;
				if (Index == SendNum - 1U)
					LastSend = true;
				if (SendProcess(SockAddr, LastSend) == EXIT_FAILURE)
				{
				//Close file handle.
					if (OutputFile != nullptr)
						fclose(OutputFile);

					WSACleanup();
					return EXIT_FAILURE;
				}
			}
		}

	//Print to screen before finished.
		PrintProcess(true, true);

	//Close file handle.
		if (OutputFile != nullptr)
			fclose(OutputFile);
	}
	else {
		PrintDescription();
	}

	WSACleanup();
	return EXIT_SUCCESS;
}
