// This code is part of DNSPing(Windows)
// DNSPing, Ping with DNS requesting.
// Copyright (C) 2014 Chengr28
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


#include "DNSPing.h"

extern std::string TestDomain;
extern std::wstring wTargetString;
extern long double TotalTime, MaxTime, MinTime;
extern size_t SendNum, RealSendNum, RecvNum, TransmissionInterval, BufferSize, RawDataLen;
extern uint16_t Protocol, ServiceName;
extern std::shared_ptr<char> RawData;
extern int SocketTimeout, IP_HopLimits;
extern bool RawSocket, IPv4_DF, EDNS0, DNSSEC, Validate, ShowResponse, ShowResponseHex;
extern dns_hdr HeaderParameter;
extern dns_qry QueryParameter;
extern dns_opt_record EDNS0Parameter;
extern FILE *OutputFile;

//Send DNS requesting process
size_t __fastcall SendProcess(const sockaddr_storage Target)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[BufferSize]()), RecvBuffer(new char[BufferSize]());
	SSIZE_T DataLength = 0;
	LARGE_INTEGER CPUFrequency = {0}, BeforeTime = {0}, AfterTime = {0};
	SOCKET Socket = 0;
	int AddrLen = 0;

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
			wprintf_s(L"Socket initialization error, error code is %d.\n", WSAGetLastError());

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
			wprintf_s(L"Socket initialization error, error code is %d.\n", WSAGetLastError());

			WSACleanup();
			return EXIT_FAILURE;
		}
	}

//Set socket timeout.
	if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&SocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&SocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		wprintf_s(L"Set UDP socket timeout error, error code is %d.\n", WSAGetLastError());
		return EXIT_FAILURE;
	}

//Set IP options.
	if (Protocol == AF_INET6) //IPv6
	{
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, (PSTR)&IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
		{
			wprintf_s(L"Set HopLimit/TTL flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	}
	else { //IPv4
		if (IP_HopLimits != 0 && setsockopt(Socket, IPPROTO_IP, IP_TTL, (PSTR)&IP_HopLimits, sizeof(int)) == SOCKET_ERROR)
		{
			wprintf_s(L"Set HopLimit/TTL flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}

	//Set "Don't Fragment" flag.
		int iIPv4_DF = 1;
		if (IPv4_DF && setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, (PSTR)&iIPv4_DF, sizeof(int)) == SOCKET_ERROR)
		{
			wprintf_s(L"Set \"Don't Fragment\" flag error, error code is %d.\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	}

	dns_hdr *pdns_hdr = nullptr;
//Make packet.
	if (!RawData)
	{
	//DNS requesting
		memcpy(Buffer.get() + DataLength, &HeaderParameter, sizeof(dns_hdr));
		if (HeaderParameter.ID == 0)
		{
			pdns_hdr = (dns_hdr *)(Buffer.get() + DataLength);
			pdns_hdr->ID = htons((uint16_t)GetCurrentProcessId());
		}
		DataLength += sizeof(dns_hdr);
		DataLength += CharToDNSQuery((PSTR)TestDomain.c_str(), Buffer.get() + DataLength);
		memcpy(Buffer.get() + DataLength, &QueryParameter, sizeof(dns_qry));
		DataLength += sizeof(dns_qry);
		if (EDNS0)
		{
			memcpy(Buffer.get() + DataLength, &EDNS0Parameter, sizeof(dns_opt_record));
			DataLength += sizeof(dns_opt_record);
		}
	}
	else {
		if (BufferSize >= RawDataLen)
		{
			memcpy(Buffer.get(), RawData.get(), RawDataLen);
			DataLength = RawDataLen;
		}
		else {
			memcpy(Buffer.get(), RawData.get(), BufferSize);
			DataLength = BufferSize;
		}
	}

//Send requesting.
	if (QueryPerformanceFrequency(&CPUFrequency) == 0 || QueryPerformanceCounter(&BeforeTime) == 0)
	{
		wprintf_s(L"Get current time form High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
		return EXIT_FAILURE;
	}
	sendto(Socket, Buffer.get(), (int)DataLength, NULL, (PSOCKADDR)&Target, AddrLen);

//Receive response.
	DataLength = recvfrom(Socket, RecvBuffer.get(), (int)BufferSize, NULL, (PSOCKADDR)&Target, &AddrLen);
	if (QueryPerformanceCounter(&AfterTime) == 0)
	{
		wprintf_s(L"Get current time form High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
		return EXIT_FAILURE;
	}

//Get waiting time.
	long double Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);

//Print to screen.
	if (DataLength > 0)
	{
	//Validate packet.
		if (Validate && pdns_hdr != nullptr && !ValidatePacket(RecvBuffer.get(), DataLength, pdns_hdr->ID))
		{
			wprintf_s(L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);

		//Try to waiting correct packet.
			while (true)
			{
			//Timeout
				if (Result >= SocketTimeout)
					break;

			//Receive.
				memset(RecvBuffer.get(), 0, BufferSize);
				DataLength = recvfrom(Socket, RecvBuffer.get(), (int)BufferSize, NULL, (PSOCKADDR)&Target, &AddrLen);
				if (QueryPerformanceCounter(&AfterTime) == 0)
				{
					wprintf_s(L"Get current time form High Precision Event Timer/HPET error, error code is %d.\n", (int)GetLastError());
					return EXIT_FAILURE;
				}

			//Get waiting time.
				Result = (long double)((AfterTime.QuadPart - BeforeTime.QuadPart) * (long double)MICROSECOND_TO_MILLISECOND / (long double)CPUFrequency.QuadPart);

			//SOCKET_ERROR
				if (DataLength <= 0)
					break;

			//Validate packet.
				if (!ValidatePacket(RecvBuffer.get(), DataLength, pdns_hdr->ID))
				{
					wprintf_s(L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
					if (OutputFile != nullptr)
						fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes but validate error, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				}
				else {
					break;
				}
			}

			if (DataLength <= 0)
			{
				wprintf_s(L"Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n", (int)DataLength, WSAGetLastError(), Result);
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, L"Receive error: %d(%d), waiting correct answers timeout(%lf ms).\n", (int)DataLength, WSAGetLastError(), Result);

				return EXIT_SUCCESS;
			}
			else {
				wprintf_s(L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
				if (OutputFile != nullptr)
					fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			}
		}
		else {
			wprintf_s(L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, L"Receive from %ls:%u -> %d bytes, waiting %lf ms.\n", wTargetString.c_str(), ntohs(ServiceName), (int)DataLength, Result);
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
		RecvNum++;

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
		wprintf_s(L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);

	//Output to file.
		if (OutputFile != nullptr)
			fwprintf_s(OutputFile, L"Receive error: %d(%d), waiting %lf ms.\n", (int)DataLength, WSAGetLastError(), Result);
	}

//Transmission interval
	if (TransmissionInterval != 0 && TransmissionInterval > Result)
		Sleep((DWORD)(TransmissionInterval - Result));
	else if (Result <= STANDARD_TIME_OUT)
		Sleep(STANDARD_TIME_OUT);

	return EXIT_SUCCESS;
}

//Print statistics to screen(and/or output result to file)
size_t __fastcall PrintProcess(const bool PacketStatistics, const bool TimeStatistics)
{
//Packet Statistics
	if (PacketStatistics)
	{
		wprintf_s(L"\nPacket statistics for pinging %ls:\n", wTargetString.c_str());
		wprintf_s(L"   Send: %lu\n", (ULONG)RealSendNum);
		wprintf_s(L"   Receive: %lu\n", (ULONG)RecvNum);

	//Output to file.
		if (OutputFile != nullptr)
		{
			fwprintf_s(OutputFile, L"\nPacket statistics for pinging %ls:\n", wTargetString.c_str());
			fwprintf_s(OutputFile, L"   Send: %lu\n", (ULONG)RealSendNum);
			fwprintf_s(OutputFile, L"   Receive: %lu\n", (ULONG)RecvNum);
		}

		if ((SSIZE_T)RealSendNum - (SSIZE_T)RecvNum >= 0)
		{
			wprintf_s(L"   Lost: %lu", (ULONG)(RealSendNum - RecvNum));
			if (RealSendNum > 0)
				wprintf_s(L" (%lu%%)\n", (ULONG)((RealSendNum - RecvNum) * 100 / RealSendNum));
			else  //Not any packets.
				wprintf_s(L"\n");

		//Output to file.
			if (OutputFile != nullptr)
			{
				fwprintf_s(OutputFile, L"   Lost: %lu", (ULONG)(RealSendNum - RecvNum));
				if (RealSendNum > 0)
					fwprintf_s(OutputFile, L" (%lu%%)\n", (ULONG)((RealSendNum - RecvNum) * 100 / RealSendNum));
				else  //Not any packets.
					fwprintf_s(OutputFile, L"\n");
			}
		}
		else {
			wprintf_s(L"   Lost: 0 (0%%)\n");

		//Output to file.
			if (OutputFile != nullptr)
				fwprintf_s(OutputFile, L"   Lost: 0 (0%%)\n");
		}
	}

//Time Statistics
	if (TimeStatistics && 
		RecvNum > 0 && MaxTime > 0 && MinTime > 0)
	{
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
	}

	wprintf_s(L"\n");
	if (OutputFile != nullptr)
		fwprintf_s(OutputFile, L"\n");
	return EXIT_SUCCESS;
}

//Print description to screen
void __fastcall PrintDescription(void)
{
	wprintf_s(L"\n");

//Description
	wprintf_s(L"--------------------------------------------------\n");
	wprintf_s(L"DNSPing v0.1 Beta(Windows)\n");
	wprintf_s(L"DNSPing, Ping with DNS requesting.\n");
	wprintf_s(L"Copyright (C) 2014 Chengr28\n");
	wprintf_s(L"--------------------------------------------------\n");

//Usage
	wprintf_s(L"\nUsage: DNSPing [-h] [-t] [-a] [-n Count] [-f] [-i HopLimit/TTL] [-w Timeout]\n");
	wprintf_s(L"               [-id DNS_ID] [-qr] [-opcode OPCode] [-aa] [-tc]\n");
	wprintf_s(L"               [-rd] [-ra] [-ad] [-cd] [-rcode RCode] [-qn Count]\n");
	wprintf_s(L"               [-ann Count] [-aun Count] [-adn Count] [-ti Time] [-edns0]\n");
	wprintf_s(L"               [-payload Length] [-dnssec] [-qt Type] [-qc Classes]\n");
	wprintf_s(L"               [-p ServiceName] [-rawdata RAW_Data] [-raw ServiceName]\n");
	wprintf_s(L"               [-buf Size] [-dv] [-show Response] [-of FileName]\n");
	wprintf_s(L"               Test_DomainName Target\n");

//Options
	wprintf_s(L"\nOptions:\n");
	wprintf_s(L"   N/A               Description.\n");
	wprintf_s(L"   ?                 Description.\n");
	wprintf_s(L"   -h                Description.\n");
	wprintf_s(L"   -t                Pings the specified host until stopped.\n                     To see statistics and continue type Control-Break.\n                     To stop type Control-C.\n");
	wprintf_s(L"   -a                Resolve addresses to host names.\n");
	wprintf_s(L"   -n Count          Set number of echo requests to send.\n                     Count must between 1 - 0xFFFF/65535.\n");
	wprintf_s(L"   -f                Set the \"Don't Fragment\" flag in outgoing packets(IPv4).\n");
	wprintf_s(L"   -i HopLimit/TTL   Specifie a Time To Live for outgoing packets.\n                     HopLimit/TTL must between 1 - 255.\n");
	wprintf_s(L"   -w Timeout        Set a long wait periods (in milliseconds) for a response.\n                     Timeout must between 500 - 0xFFFF/65535.\n");
	wprintf_s(L"   -id DNS_ID        Specifie DNS header ID.\n                     DNS ID must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"   -qr               Set DNS header QR flag.\n");
	wprintf_s(L"   -opcode OPCode    Specifie DNS header OPCode.\n                     OPCode must between 0x0000 - 0x00FF/255.\n");
	wprintf_s(L"   -aa               Set DNS header AA flag.\n");
	wprintf_s(L"   -tc               Set DNS header TC flag.\n");
	wprintf_s(L"   -rd               Set DNS header RD flag.\n");
	wprintf_s(L"   -ra               Set DNS header RA flag.\n");
	wprintf_s(L"   -ad               Set DNS header AD flag.\n");
	wprintf_s(L"   -cd               Set DNS header CD flag.\n");
	wprintf_s(L"   -rcode RCode      Specifie DNS header RCode.\n                     RCode must between 0x0000 - 0x00FF/255.\n");
	wprintf_s(L"   -qn Count         Specifie DNS header Question count.\n                     Question count must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"   -ann Count        Specifie DNS header Answer count.\n                     Answer count must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"   -aun Count        Specifie DNS header Authority count.\n                     Authority count must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"   -adn Count        Specifie DNS header Additional count.\n                     Additional count must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"   -ti IntervalTime  Specifie transmission interval time(in milliseconds).\n");
	wprintf_s(L"   -edns0            Send with EDNS0 Label.\n");
	wprintf_s(L"   -payload Length   Specifie EDNS0 Label UDP Payload length.\n                     Payload length must between 512 - 0xFFFF/65535.\n");
	wprintf_s(L"   -dnssec           Send with DNSSEC requesting.\n                     EDNS0 Label will enable when DNSSEC is enable.\n");
	wprintf_s(L"   -qt Type          Specifie Query type.\n                     Query type must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"                     Type: A|NS|MD|MF|CNAME|SOA|MB|MG|MR|NULL|WKS|PTR|HINFO|\n");
	wprintf_s(L"                           MINFO|MX|TXT|RP|AFSDB|X25|ISDN|RT|NSAP|NSAPPTR|\n");
	wprintf_s(L"                           SIG|KEY|PX|GPOS|AAAA|LOC|NXT|EID|NIMLOC|SRV|ATMA|\n");
	wprintf_s(L"                           NAPTR|KX|A6|CERT|DNAME|SINK|OPT|APL|DS|SSHFP|\n");
	wprintf_s(L"                           IPSECKEY|RRSIG|NSEC|DNSKEY|DHCID|NSEC3|NSEC3PARAM|\n");
	wprintf_s(L"                           TLSA|HIP|NINFO|RKEY|TALINK|CDS|CDNSKEY|OPENPGPKEY|\n");
	wprintf_s(L"                           SPF|UINFO|UID|GID|UNSPEC|NID|L32|L64|LP|EUI48|\n");
	wprintf_s(L"                           EUI64|TKEY|TSIG|IXFR|AXFR|MAILB|MAILA|ANY|URI|\n");
	wprintf_s(L"                           CAA|TA|DLV|RESERVED\n");
	wprintf_s(L"   -qc Classes       Specifie Query classes.\n                     Query classes must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"                     Classes: IN|CSNET|CHAOS|HESIOD|NONE|ALL|ANY\n");
	wprintf_s(L"   -p ServiceName    Specifie UDP port/protocol(Sevice names).\n                     UDP port must between 0x0001 - 0xFFFF/65535.\n");
	wprintf_s(L"                     Protocol: TCPMUX|ECHO|DISCARD|SYSTAT|DAYTIME|NETSTAT|\n");
	wprintf_s(L"                               QOTD|MSP|CHARGEN|FTP|SSH|TELNET|SMTP|\n");
	wprintf_s(L"                               TIME|RAP|RLP|NAME|WHOIS|TACACS|DNS|XNSAUTH|MTP|\n");
	wprintf_s(L"                               BOOTPS|BOOTPC|TFTP|RJE|FINGER|TTYLINK|SUPDUP|\n");
	wprintf_s(L"                               SUNRPC|SQL|NTP|EPMAP|NETBIOSNS|NETBIOSDGM|\n");
	wprintf_s(L"                               NETBIOSSSN|IMAP|BFTP|SGMP|SQLSRV|DMSP|SNMP|\n");
	wprintf_s(L"                               SNMPTRAP|ATRTMP|ATHBP|QMTP|IPX|IMAP|IMAP3|\n");
	wprintf_s(L"                               BGMP|TSP|IMMP|ODMR|RPC2PORTMAP|CLEARCASE|\n");
	wprintf_s(L"                               HPALARMMGR|ARNS|AURP|LDAP|UPS|SLP|SNPP|\n");
	wprintf_s(L"                               MICROSOFTDS|KPASSWD|TCPNETHASPSRV|RETROSPECT|\n");
	wprintf_s(L"                               ISAKMP|BIFFUDP|WHOSERVER|SYSLOG|ROUTERSERVER|\n");
	wprintf_s(L"                               NCP|COURIER|COMMERCE|RTSP|NNTP|HTTPRPCEPMAP|\n");
	wprintf_s(L"                               IPP|LDAPS|MSDP|AODV|FTPSDATA|FTPS|NAS|TELNETS\n");
	wprintf_s(L"   -rawdata RAW_Data Specifie Raw data to send.\n");
	wprintf_s(L"                     RAW_Data is hex, but do not add \"0x\" before hex.\n");
	wprintf_s(L"                     Length of RAW_Data must between 64 - 1512 bytes.\n");
	wprintf_s(L"   -raw ServiceName  Specifie Raw socket type.\n");
	wprintf_s(L"                     Service Name: HOPOPTS|ICMP|IGMP|GGP|IPV4|ST|TCP|CBT|EGP|\n");
	wprintf_s(L"                                   IGP|BBNRCCMON|NVPII|PUP|ARGUS|EMCON|XNET|\n");
	wprintf_s(L"                                   CHAOS|MUX|DCN|HMP|PRM|IDP|TRUNK_1|TRUNK_2\n");
	wprintf_s(L"                                   LEAF_1|LEAF_2|RDP|IRTP|ISOTP4|MFE|MERIT|\n");
	wprintf_s(L"                                   DCCP|3PC|IDPR|XTP|DDP|IDPRCMTP|TP++|IL|\n");
	wprintf_s(L"                                   IPV6|SDRP|ROUTING|FRAGMENT|IDRP|RSVP|GRE|\n");
	wprintf_s(L"                                   DSR|BNA|ESP|AH|NLSP|SWIPE|NARP|MOBILE|TLSP|\n");
	wprintf_s(L"                                   SKIP|ICMPV6|NONE|DSTOPTS|AHI|CFTP|ALN|SAT|\n");
	wprintf_s(L"                                   KRYPTOLAN|RVD|IPPC|ADF|SATMON|VISA|IPCV|\n");
	wprintf_s(L"                                   CPNX|CPHB|WSN|PVP|BR|ND|ICLFXBM|WBEXPAK|\n");
	wprintf_s(L"                                   ISO|VMTP|SVMTP|VINES|TTP|IPTM|NSFNET|DGP|\n");
	wprintf_s(L"                                   TCF|EIGRP|SPRITE|LARP|MTP|AX25|IPIP|MICP|\n");
	wprintf_s(L"                                   SCC|ETHERIP|ENCAP|APES|GMTP|IFMP|PNNI|PIM|\n");
	wprintf_s(L"                                   ARIS|SCPS|QNX|AN|IPCOMP|SNP|COMPAQ|IPX|PGM|\n");
	wprintf_s(L"                                   0HOP|L2TP|DDX|IATP|STP|SRP|UTI|SMP|SM|\n");
	wprintf_s(L"                                   PTP|ISIS|FIRE|CRTP|CRUDP|SSCOPMCE|IPLT|\n");
	wprintf_s(L"                                   SPS|PIPE|SCTP|FC|RSVPE2E|MOBILITY|UDPLITE|\n");
	wprintf_s(L"                                   MPLS|MANET|HIP|SHIM6|WESP|ROHC|TEST-1|\n");
	wprintf_s(L"                                   TEST-2|RAW\n");
	wprintf_s(L"   -buf Size         Specifie receive buffer size.\n                     Buffer size must between 512 - 4096 bytes.\n");
	wprintf_s(L"   -dv               Disable packets validated.\n");
	wprintf_s(L"   -show Response    Show result or data of responses.\n");
	wprintf_s(L"                     Response: Result|Hex\n");
	wprintf_s(L"   -of FileName      Output result to file.\n                     FileName must less than 260 bytes.\n");
	wprintf_s(L"   -6                Using IPv6.\n");
	wprintf_s(L"   -4                Using IPv4.\n");
	wprintf_s(L"   Test_DomainName   A domain name which will make requesting to send\n");
	wprintf_s(L"                     to DNS server.\n");
	wprintf_s(L"   Target            Target of DNSPing, support IPv4/IPv6 address and domain.\n");

	return;
}
