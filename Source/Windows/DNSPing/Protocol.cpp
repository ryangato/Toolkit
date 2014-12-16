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

extern bool EDNS0, DNSSEC;

//Minimum supported system of Windows Version Helpers is Windows Vista.
#ifdef _WIN64
#else //x86
//Check operation system which higher than Windows 7.
bool __fastcall IsLowerThanWin8(void)
{
	OSVERSIONINFOEX OSVI = {0};
	OSVI.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	BOOL bOsVersionInfoEx = GetVersionExW((OSVERSIONINFO *)&OSVI);

	if (bOsVersionInfoEx && OSVI.dwPlatformId == VER_PLATFORM_WIN32_NT && 
		(OSVI.dwMajorVersion < 6U || OSVI.dwMajorVersion == 6U && OSVI.dwMinorVersion < 2U))
			return true;

	return false;
}
#endif

//Check empty buffer
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length)
{
	if (Buffer == nullptr)
		return true;

	for (size_t Index = 0;Index < Length;Index++)
	{
		if (((uint8_t *)Buffer)[Index] != NULL)
			return false;
	}

	return true;
}

//Convert lowercase/uppercase word(s) to uppercase/lowercase word(s).
size_t __fastcall CaseConvert(bool LowerUpper, const PSTR Buffer, const size_t Length)
{
	for (size_t Index = 0;Index < Length;Index++)
	{
		if (LowerUpper) //Lowercase to uppercase
		{
			if (Buffer[Index] > ASCII_ACCENT && Buffer[Index] < ASCII_BRACES_LEAD)
				Buffer[Index] -= ASCII_LOWER_TO_UPPER;
		}
		else { //Uppercase to lowercase
			if (Buffer[Index] > ASCII_AT && Buffer[Index] < ASCII_BRACKETS_LEAD)
				Buffer[Index] += ASCII_UPPER_TO_LOWER;
		}
	}

	return EXIT_SUCCESS;
}

//Convert address strings to binary.
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *pAddr, const uint16_t Protocol, SSIZE_T &ErrorCode)
{
	SSIZE_T Result = 0;

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#ifdef _WIN64
#else //x86
	sockaddr_storage SockAddr = {0};
	int SockLength = 0;
#endif

//IPv6
	if (Protocol == AF_INET6)
	{
	//Check IPv6 addresses
		for (Result = 0;Result < (SSIZE_T)strlen(AddrString);Result++)
		{
			if (AddrString[Result] < ASCII_ZERO || AddrString[Result] > ASCII_COLON && AddrString[Result] < ASCII_UPPERCASE_A || AddrString[Result] > ASCII_UPPERCASE_F && AddrString[Result] < ASCII_LOWERCASE_A || AddrString[Result] > ASCII_LOWERCASE_F)
				break;
		}

		std::string sAddrString(AddrString);
	//Check abbreviation format.
		if (sAddrString.find(ASCII_COLON) == std::string::npos)
		{
			sAddrString.clear();
			sAddrString.append("::");
			sAddrString.append(AddrString);
		}
		else if (sAddrString.find(ASCII_COLON) == sAddrString.rfind(ASCII_COLON))
		{
			sAddrString.replace(sAddrString.find(ASCII_COLON), 1U, ("::"));
		}

	//Convert to binary.
	#ifdef _WIN64
		Result = inet_pton(AF_INET6, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET6, NULL, (LPSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(pAddr, &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, sizeof(in6_addr));
	#endif
	}
//IPv4
	else {
		size_t CommaNum = 0;
		for (Result = 0;Result < (SSIZE_T)strlen(AddrString);Result++)
		{
			if (AddrString[Result] != ASCII_PERIOD && AddrString[Result] < ASCII_ZERO || AddrString[Result] > ASCII_NINE)
				return EXIT_FAILURE;
			else if (AddrString[Result] == ASCII_PERIOD)
				CommaNum++;
		}

		std::string sAddrString(AddrString);
	//Delete zero(s) before whole data.
		while (sAddrString.length() > 1U && sAddrString[0] == ASCII_ZERO && sAddrString[1U] != ASCII_PERIOD)
			sAddrString.erase(0, 1U);

	//Check abbreviation format.
		if (CommaNum == 0)
		{
			sAddrString.clear();
			sAddrString.append("0.0.0.");
			sAddrString.append(AddrString);
		}
		else if (CommaNum == 1U)
		{
			sAddrString.replace(sAddrString.find(ASCII_PERIOD), 1U, (".0.0."));
		}
		else if (CommaNum == 2U)
		{
			sAddrString.replace(sAddrString.find(ASCII_PERIOD), 1U, (".0."));
		}

	//Delete zero(s) before data.
		while (sAddrString.find(".00") != std::string::npos)
			sAddrString.replace(sAddrString.find(".00"), 3U, ("."));
		while (sAddrString.find(".0") != std::string::npos)
			sAddrString.replace(sAddrString.find(".0"), 2U, ("."));
		while (sAddrString.find("..") != std::string::npos)
			sAddrString.replace(sAddrString.find(".."), 2U, (".0."));
		if (sAddrString[sAddrString.length() - 1U] == ASCII_PERIOD)
			sAddrString.append("0");

	//Convert to binary.
	#ifdef _WIN64
		Result = inet_pton(AF_INET, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET, NULL, (LPSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(pAddr, &((PSOCKADDR_IN)&SockAddr)->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Convert protocol name to hex
uint16_t __fastcall InternetProtocolNameToPort(const LPWSTR Buffer)
{
//Internet Protocol Number(Part 1)
	if (wcsstr(Buffer, (L"HOPOPTS")) != nullptr || wcsstr(Buffer, (L"hopopts")) != nullptr)
		return IPPROTO_HOPOPTS;
	else if (wcsstr(Buffer, (L"ICMP")) != nullptr || wcsstr(Buffer, (L"icmp")) != nullptr)
		return IPPROTO_ICMP;
	else if (wcsstr(Buffer, (L"IGMP")) != nullptr || wcsstr(Buffer, (L"igmp")) != nullptr)
		return IPPROTO_IGMP;
	else if (wcsstr(Buffer, (L"GGP")) != nullptr || wcsstr(Buffer, (L"ggp")) != nullptr)
		return IPPROTO_GGP;
	else if (wcsstr(Buffer, (L"IPV4")) != nullptr || wcsstr(Buffer, (L"ipv4")) != nullptr)
		return IPPROTO_IPV4;
	else if (wcsstr(Buffer, (L"ST")) != nullptr || wcsstr(Buffer, (L"st")) != nullptr)
		return IPPROTO_ST;
	else if (wcsstr(Buffer, (L"TCP")) != nullptr || wcsstr(Buffer, (L"tcp")) != nullptr)
		return IPPROTO_TCP;
	else if (wcsstr(Buffer, (L"CBT")) != nullptr || wcsstr(Buffer, (L"cbt")) != nullptr)
		return IPPROTO_CBT;
	else if (wcsstr(Buffer, (L"EGP")) != nullptr || wcsstr(Buffer, (L"egp")) != nullptr)
		return IPPROTO_EGP;
	else if (wcsstr(Buffer, (L"IGP")) != nullptr || wcsstr(Buffer, (L"igp")) != nullptr)
		return IPPROTO_IGP;
	else if (wcsstr(Buffer, (L"BBNRCCMON")) != nullptr || wcsstr(Buffer, (L"bbnrccmon")) != nullptr)
		return IPPROTO_BBN_RCC_MON;
	else if (wcsstr(Buffer, (L"NVPII")) != nullptr || wcsstr(Buffer, (L"nvpii")) != nullptr)
		return IPPROTO_NVP_II;
	else if (wcsstr(Buffer, (L"PUP")) != nullptr || wcsstr(Buffer, (L"pup")) != nullptr)
		return IPPROTO_PUP;
	else if (wcsstr(Buffer, (L"ARGUS")) != nullptr || wcsstr(Buffer, (L"argus")) != nullptr)
		return IPPROTO_ARGUS;
	else if (wcsstr(Buffer, (L"EMCON")) != nullptr || wcsstr(Buffer, (L"emcon")) != nullptr)
		return IPPROTO_EMCON;
	else if (wcsstr(Buffer, (L"XNET")) != nullptr || wcsstr(Buffer, (L"xnet")) != nullptr)
		return IPPROTO_XNET;
	else if (wcsstr(Buffer, (L"CHAOS")) != nullptr || wcsstr(Buffer, (L"chaos")) != nullptr)
		return IPPROTO_CHAOS;
	else if (wcsstr(Buffer, (L"UDP")) != nullptr || wcsstr(Buffer, (L"udp")) != nullptr)
		return IPPROTO_UDP;
	else if (wcsstr(Buffer, (L"MUX")) != nullptr || wcsstr(Buffer, (L"mux")) != nullptr)
		return IPPROTO_MUX;
	else if (wcsstr(Buffer, (L"DCN")) != nullptr || wcsstr(Buffer, (L"dcn")) != nullptr)
		return IPPROTO_DCN;
	else if (wcsstr(Buffer, (L"HMP")) != nullptr || wcsstr(Buffer, (L"hmp")) != nullptr)
		return IPPROTO_HMP;
	else if (wcsstr(Buffer, (L"PRM")) != nullptr || wcsstr(Buffer, (L"prm")) != nullptr)
		return IPPROTO_PRM;
	else if (wcsstr(Buffer, (L"IDP")) != nullptr || wcsstr(Buffer, (L"idp")) != nullptr)
		return IPPROTO_IDP;
	else if (wcsstr(Buffer, (L"TRUNK-1")) != nullptr || wcsstr(Buffer, (L"trunk-1")) != nullptr)
		return IPPROTO_TRUNK_1;
	else if (wcsstr(Buffer, (L"TRUNK-2")) != nullptr || wcsstr(Buffer, (L"trunk-2")) != nullptr)
		return IPPROTO_TRUNK_2;
	else if (wcsstr(Buffer, (L"LEAF-1")) != nullptr || wcsstr(Buffer, (L"leaf-1")) != nullptr)
		return IPPROTO_LEAF_1;
	else if (wcsstr(Buffer, (L"LEAF")) != nullptr || wcsstr(Buffer, (L"leaf-2")) != nullptr)
		return IPPROTO_LEAF_2;
	else if (wcsstr(Buffer, (L"RDP")) != nullptr || wcsstr(Buffer, (L"rdp")) != nullptr)
		return IPPROTO_RDP;
	else if (wcsstr(Buffer, (L"IRTP")) != nullptr || wcsstr(Buffer, (L"irtp")) != nullptr)
		return IPPROTO_IRTP;
	else if (wcsstr(Buffer, (L"ISOTP4")) != nullptr || wcsstr(Buffer, (L"isotp4")) != nullptr)
		return IPPROTO_ISO_TP4;
	else if (wcsstr(Buffer, (L"NETBLT")) != nullptr || wcsstr(Buffer, (L"netblt")) != nullptr)
		return IPPROTO_NETBLT;
	else if (wcsstr(Buffer, (L"MFE")) != nullptr || wcsstr(Buffer, (L"mfe")) != nullptr)
		return IPPROTO_MFE;
	else if (wcsstr(Buffer, (L"MERIT")) != nullptr || wcsstr(Buffer, (L"merit")) != nullptr)
		return IPPROTO_MERIT;
	else if (wcsstr(Buffer, (L"DCCP")) != nullptr || wcsstr(Buffer, (L"dccp")) != nullptr)
		return IPPROTO_DCCP;
	else if (wcsstr(Buffer, (L"3PC")) != nullptr || wcsstr(Buffer, (L"3pc")) != nullptr)
		return IPPROTO_3PC;
	else if (wcsstr(Buffer, (L"IDPR")) != nullptr || wcsstr(Buffer, (L"idpr")) != nullptr)
		return IPPROTO_IDPR;
	else if (wcsstr(Buffer, (L"XTP")) != nullptr || wcsstr(Buffer, (L"xtp")) != nullptr)
		return IPPROTO_XTP;
	else if (wcsstr(Buffer, (L"DDP")) != nullptr || wcsstr(Buffer, (L"ddp")) != nullptr)
		return IPPROTO_DDP;
	else if (wcsstr(Buffer, (L"IDPRCMTP")) != nullptr || wcsstr(Buffer, (L"idrpcmtp")) != nullptr)
		return IPPROTO_IDPR_CMTP;
	else if (wcsstr(Buffer, (L"TP++")) != nullptr || wcsstr(Buffer, (L"tp++")) != nullptr)
		return IPPROTO_TPPLUS;
	else if (wcsstr(Buffer, (L"IL")) != nullptr || wcsstr(Buffer, (L"il")) != nullptr)
		return IPPROTO_IL;
	else if (wcsstr(Buffer, (L"IPV6")) != nullptr || wcsstr(Buffer, (L"ipv6")) != nullptr)
		return IPPROTO_IPV6;
	else if (wcsstr(Buffer, (L"SDRP")) != nullptr || wcsstr(Buffer, (L"sdrp")) != nullptr)
		return IPPROTO_SDRP;
	else if (wcsstr(Buffer, (L"ROUTING")) != nullptr || wcsstr(Buffer, (L"routing")) != nullptr)
		return IPPROTO_ROUTING;
	else if (wcsstr(Buffer, (L"FRAGMENT")) != nullptr || wcsstr(Buffer, (L"fragment")) != nullptr)
		return IPPROTO_FRAGMENT;
	else if (wcsstr(Buffer, (L"IDRP")) != nullptr || wcsstr(Buffer, (L"idrp")) != nullptr)
		return IPPROTO_IDRP;
	else if (wcsstr(Buffer, (L"RSVP")) != nullptr || wcsstr(Buffer, (L"rsvp")) != nullptr)
		return IPPROTO_RSVP;
	else if (wcsstr(Buffer, (L"GRE")) != nullptr || wcsstr(Buffer, (L"gre")) != nullptr)
		return IPPROTO_GRE;
	else if (wcsstr(Buffer, (L"DSR")) != nullptr || wcsstr(Buffer, (L"dsr")) != nullptr)
		return IPPROTO_DSR;
	else if (wcsstr(Buffer, (L"BNA")) != nullptr || wcsstr(Buffer, (L"bna")) != nullptr)
		return IPPROTO_BNA;
	else if (wcsstr(Buffer, (L"ESP")) != nullptr || wcsstr(Buffer, (L"esp")) != nullptr)
		return IPPROTO_ESP;
	else if (wcsstr(Buffer, (L"AH")) != nullptr || wcsstr(Buffer, (L"ah")) != nullptr)
		return IPPROTO_AH;
	else if (wcsstr(Buffer, (L"NLSP")) != nullptr || wcsstr(Buffer, (L"nlsp")) != nullptr)
		return IPPROTO_NLSP;
	else if (wcsstr(Buffer, (L"SWIPE")) != nullptr || wcsstr(Buffer, (L"swipe")) != nullptr)
		return IPPROTO_SWIPE;
	else if (wcsstr(Buffer, (L"NARP")) != nullptr || wcsstr(Buffer, (L"narp")) != nullptr)
		return IPPROTO_NARP;
	else if (wcsstr(Buffer, (L"MOBILE")) != nullptr || wcsstr(Buffer, (L"mobile")) != nullptr)
		return IPPROTO_MOBILE;
	else if (wcsstr(Buffer, (L"TLSP")) != nullptr || wcsstr(Buffer, (L"tlsp")) != nullptr)
		return IPPROTO_TLSP;
	else if (wcsstr(Buffer, (L"SKIP")) != nullptr || wcsstr(Buffer, (L"skip")) != nullptr)
		return IPPROTO_SKIP;
	else if (wcsstr(Buffer, (L"ICMPV6")) != nullptr || wcsstr(Buffer, (L"icmpv6")) != nullptr)
		return IPPROTO_ICMPV6;
	else if (wcsstr(Buffer, (L"NONE")) != nullptr || wcsstr(Buffer, (L"none")) != nullptr)
		return IPPROTO_NONE;
	else if (wcsstr(Buffer, (L"DSTOPTS")) != nullptr || wcsstr(Buffer, (L"dstopts")) != nullptr)
		return IPPROTO_DSTOPTS;
	else if (wcsstr(Buffer, (L"AHI")) != nullptr || wcsstr(Buffer, (L"ahi")) != nullptr)
		return IPPROTO_AHI;
	else if (wcsstr(Buffer, (L"CFTP")) != nullptr || wcsstr(Buffer, (L"cftp")) != nullptr)
		return IPPROTO_CFTP;
	else if (wcsstr(Buffer, (L"ALN")) != nullptr || wcsstr(Buffer, (L"aln")) != nullptr)
		return IPPROTO_ALN;
	else if (wcsstr(Buffer, (L"SAT")) != nullptr || wcsstr(Buffer, (L"sat")) != nullptr)
		return IPPROTO_SAT;
	else if (wcsstr(Buffer, (L"KRYPTOLAN")) != nullptr || wcsstr(Buffer, (L"kryptolan")) != nullptr)
		return IPPROTO_KRYPTOLAN;
	else if (wcsstr(Buffer, (L"RVD")) != nullptr || wcsstr(Buffer, (L"rvd")) != nullptr)
		return IPPROTO_RVD;
	else if (wcsstr(Buffer, (L"IPPC")) != nullptr || wcsstr(Buffer, (L"ippc")) != nullptr)
		return IPPROTO_IPPC;
	else if (wcsstr(Buffer, (L"ADF")) != nullptr || wcsstr(Buffer, (L"adf")) != nullptr)
		return IPPROTO_ADF;
	else if (wcsstr(Buffer, (L"SATMON")) != nullptr || wcsstr(Buffer, (L"satmon")) != nullptr)
		return IPPROTO_SAT_MON;
	else if (wcsstr(Buffer, (L"VISA")) != nullptr || wcsstr(Buffer, (L"visa")) != nullptr)
		return IPPROTO_VISA;
	else if (wcsstr(Buffer, (L"IPCV")) != nullptr || wcsstr(Buffer, (L"ipcv")) != nullptr)
		return IPPROTO_IPCV;
	else if (wcsstr(Buffer, (L"CPNX")) != nullptr || wcsstr(Buffer, (L"cpnx")) != nullptr)
		return IPPROTO_CPNX;
	else if (wcsstr(Buffer, (L"CPHB")) != nullptr || wcsstr(Buffer, (L"cphb")) != nullptr)
		return IPPROTO_CPHB;
	else if (wcsstr(Buffer, (L"WSN")) != nullptr || wcsstr(Buffer, (L"wsn")) != nullptr)
		return IPPROTO_WSN;
	else if (wcsstr(Buffer, (L"PVP")) != nullptr || wcsstr(Buffer, (L"pvp")) != nullptr)
		return IPPROTO_PVP;
	else if (wcsstr(Buffer, (L"BR")) != nullptr || wcsstr(Buffer, (L"br")) != nullptr)
		return IPPROTO_BR;
	else if (wcsstr(Buffer, (L"ND")) != nullptr || wcsstr(Buffer, (L"nd")) != nullptr)
		return IPPROTO_ND;
	else if (wcsstr(Buffer, (L"ICLFXBM")) != nullptr || wcsstr(Buffer, (L"iclfxbm")) != nullptr)
		return IPPROTO_ICLFXBM;
	else if (wcsstr(Buffer, (L"WBEXPAK")) != nullptr || wcsstr(Buffer, (L"wbexpak")) != nullptr)
		return IPPROTO_WBEXPAK;
	else if (wcsstr(Buffer, (L"ISO")) != nullptr || wcsstr(Buffer, (L"iso")) != nullptr)
		return IPPROTO_ISO;
	else if (wcsstr(Buffer, (L"VMTP")) != nullptr || wcsstr(Buffer, (L"vmtp")) != nullptr)
		return IPPROTO_VMTP;
	else if (wcsstr(Buffer, (L"SVMTP")) != nullptr || wcsstr(Buffer, (L"svmtp")) != nullptr)
		return IPPROTO_SVMTP;
	else if (wcsstr(Buffer, (L"VINES")) != nullptr || wcsstr(Buffer, (L"vines")) != nullptr)
		return IPPROTO_VINES;
	else if (wcsstr(Buffer, (L"TTP")) != nullptr || wcsstr(Buffer, (L"ttp")) != nullptr)
		return IPPROTO_TTP;
	else if (wcsstr(Buffer, (L"IPTM")) != nullptr || wcsstr(Buffer, (L"iptm")) != nullptr)
		return IPPROTO_IPTM;
	else if (wcsstr(Buffer, (L"NSFNET")) != nullptr || wcsstr(Buffer, (L"nsfnet")) != nullptr)
		return IPPROTO_NSFNET;
	else if (wcsstr(Buffer, (L"DGP")) != nullptr || wcsstr(Buffer, (L"dgp")) != nullptr)
		return IPPROTO_DGP;
	else if (wcsstr(Buffer, (L"TCF")) != nullptr || wcsstr(Buffer, (L"tcf")) != nullptr)
		return IPPROTO_TCF;
	else if (wcsstr(Buffer, (L"EIGRP")) != nullptr || wcsstr(Buffer, (L"eigrp")) != nullptr)
		return IPPROTO_EIGRP;
	else if (wcsstr(Buffer, (L"SPRITE")) != nullptr || wcsstr(Buffer, (L"sprite")) != nullptr)
		return IPPROTO_SPRITE;
	else if (wcsstr(Buffer, (L"LARP")) != nullptr || wcsstr(Buffer, (L"larp")) != nullptr)
		return IPPROTO_LARP;
	else if (wcsstr(Buffer, (L"MTP")) != nullptr || wcsstr(Buffer, (L"mtp")) != nullptr)
		return IPPROTO_MTP;
	else if (wcsstr(Buffer, (L"AX25")) != nullptr || wcsstr(Buffer, (L"ax25")) != nullptr)
		return IPPROTO_AX25;
	else if (wcsstr(Buffer, (L"IPIP")) != nullptr || wcsstr(Buffer, (L"ipip")) != nullptr)
		return IPPROTO_IPIP;
	else if (wcsstr(Buffer, (L"MICP")) != nullptr || wcsstr(Buffer, (L"micp")) != nullptr)
		return IPPROTO_MICP;
	else if (wcsstr(Buffer, (L"SCC")) != nullptr || wcsstr(Buffer, (L"scc")) != nullptr)
		return IPPROTO_SCC;
	else if (wcsstr(Buffer, (L"ETHERIP")) != nullptr || wcsstr(Buffer, (L"etherip")) != nullptr)
		return IPPROTO_ETHERIP;
	else if (wcsstr(Buffer, (L"ENCAP")) != nullptr || wcsstr(Buffer, (L"encap")) != nullptr)
		return IPPROTO_ENCAP;
	else if (wcsstr(Buffer, (L"APES")) != nullptr || wcsstr(Buffer, (L"apes")) != nullptr)
		return IPPROTO_APES;
	else if (wcsstr(Buffer, (L"GMTP")) != nullptr || wcsstr(Buffer, (L"gmtp")) != nullptr)
		return IPPROTO_GMTP;
	else if (wcsstr(Buffer, (L"IFMP")) != nullptr || wcsstr(Buffer, (L"ifmp")) != nullptr)
		return IPPROTO_IFMP;
	else if (wcsstr(Buffer, (L"PIM")) != nullptr || wcsstr(Buffer, (L"pim")) != nullptr)
		return IPPROTO_PIM;
	else if (wcsstr(Buffer, (L"PNNI")) != nullptr || wcsstr(Buffer, (L"pnni")) != nullptr)
		return IPPROTO_PNNI;
	else if (wcsstr(Buffer, (L"ARIS")) != nullptr || wcsstr(Buffer, (L"aris")) != nullptr)
		return IPPROTO_ARIS;
	else if (wcsstr(Buffer, (L"SCPS")) != nullptr || wcsstr(Buffer, (L"scps")) != nullptr)
		return IPPROTO_SCPS;
	else if (wcsstr(Buffer, (L"QNX")) != nullptr || wcsstr(Buffer, (L"qnx")) != nullptr)
		return IPPROTO_QNX;
	else if (wcsstr(Buffer, (L"AN")) != nullptr || wcsstr(Buffer, (L"an")) != nullptr)
		return IPPROTO_AN;
	else if (wcsstr(Buffer, (L"IPCOMP")) != nullptr || wcsstr(Buffer, (L"ipcomp")) != nullptr)
		return IPPROTO_IPCOMP;
	else if (wcsstr(Buffer, (L"SNP")) != nullptr || wcsstr(Buffer, (L"snp")) != nullptr)
		return IPPROTO_SNP;
	else if (wcsstr(Buffer, (L"COMPAQ")) != nullptr || wcsstr(Buffer, (L"compaq")) != nullptr)
		return IPPROTO_COMPAQ;
	else if (wcsstr(Buffer, (L"IPX")) != nullptr || wcsstr(Buffer, (L"ipx")) != nullptr)
		return IPPROTO_IPX;
	else if (wcsstr(Buffer, (L"PGM")) != nullptr || wcsstr(Buffer, (L"pgm")) != nullptr)
		return IPPROTO_PGM;
	else if (wcsstr(Buffer, (L"0HOP")) != nullptr || wcsstr(Buffer, (L"0hop")) != nullptr)
		return IPPROTO_0HOP;
	else if (wcsstr(Buffer, (L"L2TP")) != nullptr || wcsstr(Buffer, (L"l2tp")) != nullptr)
		return IPPROTO_L2TP;
	else if (wcsstr(Buffer, (L"DDX")) != nullptr || wcsstr(Buffer, (L"ddx")) != nullptr)
		return IPPROTO_DDX;
	else if (wcsstr(Buffer, (L"IATP")) != nullptr || wcsstr(Buffer, (L"iatp")) != nullptr)
		return IPPROTO_IATP;
	else if (wcsstr(Buffer, (L"STP")) != nullptr || wcsstr(Buffer, (L"stp")) != nullptr)
		return IPPROTO_STP;
	else if (wcsstr(Buffer, (L"SRP")) != nullptr || wcsstr(Buffer, (L"srp")) != nullptr)
		return IPPROTO_SRP;
	else if (wcsstr(Buffer, (L"UTI")) != nullptr || wcsstr(Buffer, (L"uti")) != nullptr)
		return IPPROTO_UTI;
	else if (wcsstr(Buffer, (L"SMP")) != nullptr || wcsstr(Buffer, (L"smp")) != nullptr)
		return IPPROTO_SMP;
	else if (wcsstr(Buffer, (L"SM")) != nullptr || wcsstr(Buffer, (L"sm")) != nullptr)
		return IPPROTO_SM;
	else if (wcsstr(Buffer, (L"PTP")) != nullptr || wcsstr(Buffer, (L"ptp")) != nullptr)
		return IPPROTO_PTP;

//Internet Protocol Number(Part 2)
	if (wcsstr(Buffer, (L"ISIS")) != nullptr || wcsstr(Buffer, (L"isis")) != nullptr)
		return IPPROTO_ISIS;
	else if (wcsstr(Buffer, (L"FIRE")) != nullptr || wcsstr(Buffer, (L"fire")) != nullptr)
		return IPPROTO_FIRE;
	else if (wcsstr(Buffer, (L"CRTP")) != nullptr || wcsstr(Buffer, (L"crtp")) != nullptr)
		return IPPROTO_CRTP;
	else if (wcsstr(Buffer, (L"CRUDP")) != nullptr || wcsstr(Buffer, (L"crudp")) != nullptr)
		return IPPROTO_CRUDP;
	else if (wcsstr(Buffer, (L"SSCOPMCE")) != nullptr || wcsstr(Buffer, (L"sscopmce")) != nullptr)
		return IPPROTO_SSCOPMCE;
	else if (wcsstr(Buffer, (L"IPLT")) != nullptr || wcsstr(Buffer, (L"iplt")) != nullptr)
		return IPPROTO_IPLT;
	else if (wcsstr(Buffer, (L"SPS")) != nullptr || wcsstr(Buffer, (L"sps")) != nullptr)
		return IPPROTO_SPS;
	else if (wcsstr(Buffer, (L"PIPE")) != nullptr || wcsstr(Buffer, (L"pipe")) != nullptr)
		return IPPROTO_PIPE;
	else if (wcsstr(Buffer, (L"SCTP")) != nullptr || wcsstr(Buffer, (L"sctp")) != nullptr)
		return IPPROTO_SCTP;
	else if (wcsstr(Buffer, (L"FC")) != nullptr || wcsstr(Buffer, (L"fc")) != nullptr)
		return IPPROTO_FC;
	else if (wcsstr(Buffer, (L"RSVPE2E")) != nullptr || wcsstr(Buffer, (L"rsvpe2e")) != nullptr)
		return IPPROTO_RSVP_E2E;
	else if (wcsstr(Buffer, (L"MOBILITY")) != nullptr || wcsstr(Buffer, (L"mobility")) != nullptr)
		return IPPROTO_MOBILITY;
	else if (wcsstr(Buffer, (L"UDPLITE")) != nullptr || wcsstr(Buffer, (L"udplite")) != nullptr)
		return IPPROTO_UDPLITE;
	else if (wcsstr(Buffer, (L"MPLS")) != nullptr || wcsstr(Buffer, (L"mpls")) != nullptr)
		return IPPROTO_MPLS;
	else if (wcsstr(Buffer, (L"MANET")) != nullptr || wcsstr(Buffer, (L"manet")) != nullptr)
		return IPPROTO_MANET;
	else if (wcsstr(Buffer, (L"HIP")) != nullptr || wcsstr(Buffer, (L"hip")) != nullptr)
		return IPPROTO_HIP;
	else if (wcsstr(Buffer, (L"SHIM6")) != nullptr || wcsstr(Buffer, (L"shim6")) != nullptr)
		return IPPROTO_SHIM6;
	else if (wcsstr(Buffer, (L"WESP")) != nullptr || wcsstr(Buffer, (L"wesp")) != nullptr)
		return IPPROTO_WESP;
	else if (wcsstr(Buffer, (L"ROHC")) != nullptr || wcsstr(Buffer, (L"rohc")) != nullptr)
		return IPPROTO_ROHC;
	else if (wcsstr(Buffer, (L"TEST-1")) != nullptr || wcsstr(Buffer, (L"test-1")) != nullptr)
		return IPPROTO_TEST_1;
	else if (wcsstr(Buffer, (L"TEST-2")) != nullptr || wcsstr(Buffer, (L"test-2")) != nullptr)
		return IPPROTO_TEST_2;
	else if (wcsstr(Buffer, (L"RAW")) != nullptr || wcsstr(Buffer, (L"raw")) != nullptr)
		return IPPROTO_RAW;

//No match.
	return 0;
}

//Convert service name to port
uint16_t __fastcall ServiceNameToPort(const LPWSTR Buffer)
{
//Server name
	if (wcsstr(Buffer, (L"TCPMUX")) != nullptr || wcsstr(Buffer, (L"tcpmux")) != nullptr)
		return htons(IPPORT_TCPMUX);
	else if (wcsstr(Buffer, (L"ECHO")) != nullptr || wcsstr(Buffer, (L"echo")) != nullptr)
		return htons(IPPORT_ECHO);
	else if (wcsstr(Buffer, (L"DISCARD")) != nullptr || wcsstr(Buffer, (L"discard")) != nullptr)
		return htons(IPPORT_DISCARD);
	else if (wcsstr(Buffer, (L"SYSTAT")) != nullptr || wcsstr(Buffer, (L"systat")) != nullptr)
		return htons(IPPORT_SYSTAT);
	else if (wcsstr(Buffer, (L"DAYTIME")) != nullptr || wcsstr(Buffer, (L"daytime")) != nullptr)
		return htons(IPPORT_DAYTIME);
	else if (wcsstr(Buffer, (L"NETSTAT")) != nullptr || wcsstr(Buffer, (L"netstat")) != nullptr)
		return htons(IPPORT_NETSTAT);
	else if (wcsstr(Buffer, (L"QOTD")) != nullptr || wcsstr(Buffer, (L"qotd")) != nullptr)
		return htons(IPPORT_QOTD);
	else if (wcsstr(Buffer, (L"MSP")) != nullptr || wcsstr(Buffer, (L"msp")) != nullptr)
		return htons(IPPORT_MSP);
	else if (wcsstr(Buffer, (L"CHARGEN")) != nullptr || wcsstr(Buffer, (L"chargen")) != nullptr)
		return htons(IPPORT_CHARGEN);
	else if (wcsstr(Buffer, (L"FTPDATA")) != nullptr || wcsstr(Buffer, (L"ftpdata")) != nullptr)
		return htons(IPPORT_FTP_DATA);
	else if (wcsstr(Buffer, (L"FTP")) != nullptr || wcsstr(Buffer, (L"ftp")) != nullptr)
		return htons(IPPORT_FTP);
	else if (wcsstr(Buffer, (L"SSH")) != nullptr || wcsstr(Buffer, (L"ssh")) != nullptr)
		return htons(IPPORT_SSH);
	else if (wcsstr(Buffer, (L"TELNET")) != nullptr || wcsstr(Buffer, (L"telnet")) != nullptr)
		return htons(IPPORT_TELNET);
	else if (wcsstr(Buffer, (L"SMTP")) != nullptr || wcsstr(Buffer, (L"smtp")) != nullptr)
		return htons(IPPORT_SMTP);
	else if (wcsstr(Buffer, (L"TIME")) != nullptr || wcsstr(Buffer, (L"time")) != nullptr)
		return htons(IPPORT_TIMESERVER);
	else if (wcsstr(Buffer, (L"RAP")) != nullptr || wcsstr(Buffer, (L"rap")) != nullptr)
		return htons(IPPORT_RAP);
	else if (wcsstr(Buffer, (L"RLP")) != nullptr || wcsstr(Buffer, (L"rlp")) != nullptr)
		return htons(IPPORT_RLP);
	else if (wcsstr(Buffer, (L"NAME")) != nullptr || wcsstr(Buffer, (L"name")) != nullptr)
		return htons(IPPORT_NAMESERVER);
	else if (wcsstr(Buffer, (L"WHOIS")) != nullptr || wcsstr(Buffer, (L"whois")) != nullptr)
		return htons(IPPORT_WHOIS);
	else if (wcsstr(Buffer, (L"TACACS")) != nullptr || wcsstr(Buffer, (L"tacacs")) != nullptr)
		return htons(IPPORT_TACACS);
	else if (wcsstr(Buffer, (L"DNS")) != nullptr || wcsstr(Buffer, (L"dns")) != nullptr)
		return htons(IPPORT_DNS);
	else if (wcsstr(Buffer, (L"XNSAUTH")) != nullptr || wcsstr(Buffer, (L"xnsauth")) != nullptr)
		return htons(IPPORT_XNSAUTH);
	else if (wcsstr(Buffer, (L"MTP")) != nullptr || wcsstr(Buffer, (L"mtp")) != nullptr)
		return htons(IPPORT_MTP);
	else if (wcsstr(Buffer, (L"BOOTPS")) != nullptr || wcsstr(Buffer, (L"bootps")) != nullptr)
		return htons(IPPORT_BOOTPS);
	else if (wcsstr(Buffer, (L"BOOTPC")) != nullptr || wcsstr(Buffer, (L"bootpc")) != nullptr)
		return htons(IPPORT_BOOTPC);
	else if (wcsstr(Buffer, (L"TFTP")) != nullptr || wcsstr(Buffer, (L"tftp")) != nullptr)
		return htons(IPPORT_TFTP);
	else if (wcsstr(Buffer, (L"RJE")) != nullptr || wcsstr(Buffer, (L"rje")) != nullptr)
		return htons(IPPORT_RJE);
	else if (wcsstr(Buffer, (L"FINGER")) != nullptr || wcsstr(Buffer, (L"finger")) != nullptr)
		return htons(IPPORT_FINGER);
	else if (wcsstr(Buffer, (L"HTTP")) != nullptr || wcsstr(Buffer, (L"http")) != nullptr)
		return htons(IPPORT_HTTP);
	else if (wcsstr(Buffer, (L"HTTPBACKUP")) != nullptr || wcsstr(Buffer, (L"httpbackup")) != nullptr)
		return htons(IPPORT_HTTPBACKUP);
	else if (wcsstr(Buffer, (L"TTYLINK")) != nullptr || wcsstr(Buffer, (L"ttylink")) != nullptr)
		return htons(IPPORT_TTYLINK);
	else if (wcsstr(Buffer, (L"SUPDUP")) != nullptr || wcsstr(Buffer, (L"supdup")) != nullptr)
		return htons(IPPORT_SUPDUP);
	else if (wcsstr(Buffer, (L"POP3")) != nullptr || wcsstr(Buffer, (L"pop3")) != nullptr)
		return htons(IPPORT_POP3);
	else if (wcsstr(Buffer, (L"SUNRPC")) != nullptr || wcsstr(Buffer, (L"sunrpc")) != nullptr)
		return htons(IPPORT_SUNRPC);
	else if (wcsstr(Buffer, (L"SQL")) != nullptr || wcsstr(Buffer, (L"sql")) != nullptr)
		return htons(IPPORT_SQL);
	else if (wcsstr(Buffer, (L"NTP")) != nullptr || wcsstr(Buffer, (L"ntp")) != nullptr)
		return htons(IPPORT_NTP);
	else if (wcsstr(Buffer, (L"EPMAP")) != nullptr || wcsstr(Buffer, (L"epmap")) != nullptr)
		return htons(IPPORT_EPMAP);
	else if (wcsstr(Buffer, (L"NETBIOSNS")) != nullptr || wcsstr(Buffer, (L"netbiosns")) != nullptr)
		return htons(IPPORT_NETBIOS_NS);
	else if (wcsstr(Buffer, (L"NETBIOSDGM")) != nullptr || wcsstr(Buffer, (L"netbiosdgm")) != nullptr)
		return htons(IPPORT_NETBIOS_DGM);
	else if (wcsstr(Buffer, (L"NETBIOSSSN")) != nullptr || wcsstr(Buffer, (L"netbiosssn")) != nullptr)
		return htons(IPPORT_NETBIOS_SSN);
	else if (wcsstr(Buffer, (L"IMAP")) != nullptr || wcsstr(Buffer, (L"imap")) != nullptr)
		return htons(IPPORT_IMAP);
	else if (wcsstr(Buffer, (L"BFTP")) != nullptr || wcsstr(Buffer, (L"bftp")) != nullptr)
		return htons(IPPORT_BFTP);
	else if (wcsstr(Buffer, (L"SGMP")) != nullptr || wcsstr(Buffer, (L"sgmp")) != nullptr)
		return htons(IPPORT_SGMP);
	else if (wcsstr(Buffer, (L"SQLSRV")) != nullptr || wcsstr(Buffer, (L"sqlsrv")) != nullptr)
		return htons(IPPORT_SQLSRV);
	else if (wcsstr(Buffer, (L"DMSP")) != nullptr || wcsstr(Buffer, (L"dmsp")) != nullptr)
		return htons(IPPORT_DMSP);
	else if (wcsstr(Buffer, (L"SNMP")) != nullptr || wcsstr(Buffer, (L"snmp")) != nullptr)
		return htons(IPPORT_SNMP);
	else if (wcsstr(Buffer, (L"SNMPTRAP")) != nullptr || wcsstr(Buffer, (L"snmptrap")) != nullptr)
		return htons(IPPORT_SNMP_TRAP);
	else if (wcsstr(Buffer, (L"ATRTMP")) != nullptr || wcsstr(Buffer, (L"atrtmp")) != nullptr)
		return htons(IPPORT_ATRTMP);
	else if (wcsstr(Buffer, (L"ATHBP")) != nullptr || wcsstr(Buffer, (L"athbp")) != nullptr)
		return htons(IPPORT_ATHBP);
	else if (wcsstr(Buffer, (L"QMTP")) != nullptr || wcsstr(Buffer, (L"qmtp")) != nullptr)
		return htons(IPPORT_QMTP);
	else if (wcsstr(Buffer, (L"IPX")) != nullptr || wcsstr(Buffer, (L"ipx")) != nullptr)
		return htons(IPPORT_IPX);
	else if (wcsstr(Buffer, (L"IMAP3")) != nullptr || wcsstr(Buffer, (L"imap3")) != nullptr)
		return htons(IPPORT_IMAP3);
	else if (wcsstr(Buffer, (L"BGMP")) != nullptr || wcsstr(Buffer, (L"bgmp")) != nullptr)
		return htons(IPPORT_BGMP);
	else if (wcsstr(Buffer, (L"TSP")) != nullptr || wcsstr(Buffer, (L"tsp")) != nullptr)
		return htons(IPPORT_TSP);
	else if (wcsstr(Buffer, (L"IMMP")) != nullptr || wcsstr(Buffer, (L"immp")) != nullptr)
		return htons(IPPORT_IMMP);
	else if (wcsstr(Buffer, (L"ODMR")) != nullptr || wcsstr(Buffer, (L"odmr")) != nullptr)
		return htons(IPPORT_ODMR);
	else if (wcsstr(Buffer, (L"RPC2PORTMAP")) != nullptr || wcsstr(Buffer, (L"rpc2portmap")) != nullptr)
		return htons(IPPORT_RPC2PORTMAP);
	else if (wcsstr(Buffer, (L"CLEARCASE")) != nullptr || wcsstr(Buffer, (L"clearcase")) != nullptr)
		return htons(IPPORT_CLEARCASE);
	else if (wcsstr(Buffer, (L"HPALARMMGR")) != nullptr || wcsstr(Buffer, (L"hpalarmmgr")) != nullptr)
		return htons(IPPORT_HPALARMMGR);
	else if (wcsstr(Buffer, (L"ARNS")) != nullptr || wcsstr(Buffer, (L"arns")) != nullptr)
		return htons(IPPORT_ARNS);
	else if (wcsstr(Buffer, (L"AURP")) != nullptr || wcsstr(Buffer, (L"aurp")) != nullptr)
		return htons(IPPORT_AURP);
	else if (wcsstr(Buffer, (L"LDAP")) != nullptr || wcsstr(Buffer, (L"ldap")) != nullptr)
		return htons(IPPORT_LDAP);
	else if (wcsstr(Buffer, (L"UPS")) != nullptr || wcsstr(Buffer, (L"ups")) != nullptr)
		return htons(IPPORT_UPS);
	else if (wcsstr(Buffer, (L"SLP")) != nullptr || wcsstr(Buffer, (L"slp")) != nullptr)
		return htons(IPPORT_SLP);
	else if (wcsstr(Buffer, (L"HTTPS")) != nullptr || wcsstr(Buffer, (L"https")) != nullptr)
		return htons(IPPORT_HTTPS);
	else if (wcsstr(Buffer, (L"SNPP")) != nullptr || wcsstr(Buffer, (L"snpp")) != nullptr)
		return htons(IPPORT_SNPP);
	else if (wcsstr(Buffer, (L"MICROSOFTDS")) != nullptr || wcsstr(Buffer, (L"microsoftds")) != nullptr)
		return htons(IPPORT_MICROSOFT_DS);
	else if (wcsstr(Buffer, (L"KPASSWD")) != nullptr || wcsstr(Buffer, (L"kpasswd")) != nullptr)
		return htons(IPPORT_KPASSWD);
	else if (wcsstr(Buffer, (L"TCPNETHASPSRV")) != nullptr || wcsstr(Buffer, (L"tcpnethaspsrv")) != nullptr)
		return htons(IPPORT_TCPNETHASPSRV);
	else if (wcsstr(Buffer, (L"RETROSPECT")) != nullptr || wcsstr(Buffer, (L"retrospect")) != nullptr)
		return htons(IPPORT_RETROSPECT);
	else if (wcsstr(Buffer, (L"ISAKMP")) != nullptr || wcsstr(Buffer, (L"isakmp")) != nullptr)
		return htons(IPPORT_ISAKMP);
	else if (wcsstr(Buffer, (L"BIFFUDP")) != nullptr || wcsstr(Buffer, (L"biffudp")) != nullptr)
		return htons(IPPORT_BIFFUDP);
	else if (wcsstr(Buffer, (L"WHOSERVER")) != nullptr || wcsstr(Buffer, (L"whoserver")) != nullptr)
		return htons(IPPORT_WHOSERVER);
	else if (wcsstr(Buffer, (L"SYSLOG")) != nullptr || wcsstr(Buffer, (L"syslog")) != nullptr)
		return htons(IPPORT_SYSLOG);
	else if (wcsstr(Buffer, (L"ROUTERSERVER")) != nullptr || wcsstr(Buffer, (L"routerserver")) != nullptr)
		return htons(IPPORT_ROUTESERVER);
	else if (wcsstr(Buffer, (L"NCP")) != nullptr || wcsstr(Buffer, (L"ncp")) != nullptr)
		return htons(IPPORT_NCP);
	else if (wcsstr(Buffer, (L"COURIER")) != nullptr || wcsstr(Buffer, (L"courier")) != nullptr)
		return htons(IPPORT_COURIER);
	else if (wcsstr(Buffer, (L"COMMERCE")) != nullptr || wcsstr(Buffer, (L"commerce")) != nullptr)
		return htons(IPPORT_COMMERCE);
	else if (wcsstr(Buffer, (L"RTSP")) != nullptr || wcsstr(Buffer, (L"rtsp")) != nullptr)
		return htons(IPPORT_RTSP);
	else if (wcsstr(Buffer, (L"NNTP")) != nullptr || wcsstr(Buffer, (L"nntp")) != nullptr)
		return htons(IPPORT_NNTP);
	else if (wcsstr(Buffer, (L"HTTPRPCEPMAP")) != nullptr || wcsstr(Buffer, (L"httprpcepmap")) != nullptr)
		return htons(IPPORT_HTTPRPCEPMAP);
	else if (wcsstr(Buffer, (L"IPP")) != nullptr || wcsstr(Buffer, (L"ipp")) != nullptr)
		return htons(IPPORT_IPP);
	else if (wcsstr(Buffer, (L"LDAPS")) != nullptr || wcsstr(Buffer, (L"ldaps")) != nullptr)
		return htons(IPPORT_LDAPS);
	else if (wcsstr(Buffer, (L"MSDP")) != nullptr || wcsstr(Buffer, (L"msdp")) != nullptr)
		return htons(IPPORT_MSDP);
	else if (wcsstr(Buffer, (L"AODV")) != nullptr || wcsstr(Buffer, (L"aodv")) != nullptr)
		return htons(IPPORT_AODV);
	else if (wcsstr(Buffer, (L"FTPSDATA")) != nullptr || wcsstr(Buffer, (L"ftpsdata")) != nullptr)
		return htons(IPPORT_FTPSDATA);
	else if (wcsstr(Buffer, (L"FTPS")) != nullptr || wcsstr(Buffer, (L"ftps")) != nullptr)
		return htons(IPPORT_FTPS);
	else if (wcsstr(Buffer, (L"NAS")) != nullptr || wcsstr(Buffer, (L"nas")) != nullptr)
		return htons(IPPORT_NAS);
	else if (wcsstr(Buffer, (L"TELNETS")) != nullptr || wcsstr(Buffer, (L"telnets")) != nullptr)
		return htons(IPPORT_TELNETS);
//No match.
	return 0;
}

//Convert DNS classes name to hex
uint16_t __fastcall DNSClassesNameToHex(const LPWSTR Buffer)
{
//DNS classes name
	if (wcsstr(Buffer, (L"INTERNET")) != nullptr || wcsstr(Buffer, (L"internet")) != nullptr || wcsstr(Buffer, (L"IN")) != nullptr || wcsstr(Buffer, (L"in")) != nullptr)
		return htons(DNS_CLASS_IN);
	else if (wcsstr(Buffer, (L"CSNET")) != nullptr || wcsstr(Buffer, (L"csnet")) != nullptr)
		return htons(DNS_CLASS_CSNET);
	else if (wcsstr(Buffer, (L"CHAOS")) != nullptr || wcsstr(Buffer, (L"chaos")) != nullptr)
		return htons(DNS_CLASS_CHAOS);
	else if (wcsstr(Buffer, (L"HESIOD")) != nullptr || wcsstr(Buffer, (L"hesiod")) != nullptr)
		return htons(DNS_CLASS_HESIOD);
	else if (wcsstr(Buffer, (L"NONE")) != nullptr || wcsstr(Buffer, (L"none")) != nullptr)
		return htons(DNS_CLASS_NONE);
	else if (wcsstr(Buffer, (L"ALL")) != nullptr || wcsstr(Buffer, (L"all")) != nullptr)
		return htons(DNS_CLASS_ALL);
	else if (wcsstr(Buffer, (L"ANY")) != nullptr || wcsstr(Buffer, (L"any")) != nullptr)
		return htons(DNS_CLASS_ANY);
//No match.
	return 0;
}

//Convert DNS type name to hex
uint16_t __fastcall DNSTypeNameToHex(const LPWSTR Buffer)
{
//DNS type name
	if (wcsstr(Buffer, (L"A")) != nullptr || wcsstr(Buffer, (L"a")) != nullptr)
		return htons(DNS_RECORD_A);
	else if (wcsstr(Buffer, (L"NS")) != nullptr || wcsstr(Buffer, (L"ns")) != nullptr)
		return htons(DNS_RECORD_NS);
	else if (wcsstr(Buffer, (L"MD")) != nullptr || wcsstr(Buffer, (L"md")) != nullptr)
		return htons(DNS_RECORD_MD);
	else if (wcsstr(Buffer, (L"MF")) != nullptr || wcsstr(Buffer, (L"mf")) != nullptr)
		return htons(DNS_RECORD_MF);
	else if (wcsstr(Buffer, (L"CNAME")) != nullptr || wcsstr(Buffer, (L"cname")) != nullptr)
		return htons(DNS_RECORD_CNAME);
	else if (wcsstr(Buffer, (L"SOA")) != nullptr || wcsstr(Buffer, (L"soa")) != nullptr)
		return htons(DNS_RECORD_SOA);
	else if (wcsstr(Buffer, (L"MB")) != nullptr || wcsstr(Buffer, (L"mb")) != nullptr)
		return htons(DNS_RECORD_MB);
	else if (wcsstr(Buffer, (L"MG")) != nullptr || wcsstr(Buffer, (L"mg")) != nullptr)
		return htons(DNS_RECORD_MG);
	else if (wcsstr(Buffer, (L"MR")) != nullptr || wcsstr(Buffer, (L"mr")) != nullptr)
		return htons(DNS_RECORD_MR);
	else if (wcsstr(Buffer, (L"PTR")) != nullptr || wcsstr(Buffer, (L"ptr")) != nullptr)
		return htons(DNS_RECORD_PTR);
	else if (wcsstr(Buffer, (L"NULL")) != nullptr || wcsstr(Buffer, (L"null")) != nullptr)
		return htons(DNS_RECORD_NULL);
	else if (wcsstr(Buffer, (L"WKS")) != nullptr || wcsstr(Buffer, (L"wks")) != nullptr)
		return htons(DNS_RECORD_WKS);
	else if (wcsstr(Buffer, (L"HINFO")) != nullptr || wcsstr(Buffer, (L"hinfo")) != nullptr)
		return htons(DNS_RECORD_HINFO);
	else if (wcsstr(Buffer, (L"MINFO")) != nullptr || wcsstr(Buffer, (L"minfo")) != nullptr)
		return htons(DNS_RECORD_MINFO);
	else if (wcsstr(Buffer, (L"MX")) != nullptr || wcsstr(Buffer, (L"mx")) != nullptr)
		return htons(DNS_RECORD_MX);
	else if (wcsstr(Buffer, (L"TXT")) != nullptr || wcsstr(Buffer, (L"txt")) != nullptr)
		return htons(DNS_RECORD_TXT);
	else if (wcsstr(Buffer, (L"RP")) != nullptr || wcsstr(Buffer, (L"rp")) != nullptr)
		return htons(DNS_RECORD_RP);
	else if (wcsstr(Buffer, (L"SIG")) != nullptr || wcsstr(Buffer, (L"sig")) != nullptr)
		return htons(DNS_RECORD_SIG);
	else if (wcsstr(Buffer, (L"AFSDB")) != nullptr || wcsstr(Buffer, (L"afsdb")) != nullptr)
		return htons(DNS_RECORD_AFSDB);
	else if (wcsstr(Buffer, (L"X25")) != nullptr || wcsstr(Buffer, (L"x25")) != nullptr)
		return htons(DNS_RECORD_X25);
	else if (wcsstr(Buffer, (L"ISDN")) != nullptr || wcsstr(Buffer, (L"isdn")) != nullptr)
		return htons(DNS_RECORD_ISDN);
	else if (wcsstr(Buffer, (L"RT")) != nullptr || wcsstr(Buffer, (L"rt")) != nullptr)
		return htons(DNS_RECORD_RT);
	else if (wcsstr(Buffer, (L"NSAP")) != nullptr || wcsstr(Buffer, (L"nsap")) != nullptr)
		return htons(DNS_RECORD_NSAP);
	else if (wcsstr(Buffer, (L"NSAPPTR")) != nullptr || wcsstr(Buffer, (L"nsapptr")) != nullptr)
		return htons(DNS_RECORD_NSAP_PTR);
	else if (wcsstr(Buffer, (L"SIG")) != nullptr || wcsstr(Buffer, (L"sig")) != nullptr)
		return htons(DNS_RECORD_SIG);
	else if (wcsstr(Buffer, (L"KEY")) != nullptr || wcsstr(Buffer, (L"key")) != nullptr)
		return htons(DNS_RECORD_KEY);
	else if (wcsstr(Buffer, (L"AAAA")) != nullptr || wcsstr(Buffer, (L"aaaa")) != nullptr)
		return htons(DNS_RECORD_AAAA);
	else if (wcsstr(Buffer, (L"PX")) != nullptr || wcsstr(Buffer, (L"px")) != nullptr)
		return htons(DNS_RECORD_PX);
	else if (wcsstr(Buffer, (L"GPOS")) != nullptr || wcsstr(Buffer, (L"gpos")) != nullptr)
		return htons(DNS_RECORD_GPOS);
	else if (wcsstr(Buffer, (L"LOC")) != nullptr || wcsstr(Buffer, (L"loc")) != nullptr)
		return htons(DNS_RECORD_LOC);
	else if (wcsstr(Buffer, (L"NXT")) != nullptr || wcsstr(Buffer, (L"nxt")) != nullptr)
		return htons(DNS_RECORD_NXT);
	else if (wcsstr(Buffer, (L"EID")) != nullptr || wcsstr(Buffer, (L"eid")) != nullptr)
		return htons(DNS_RECORD_EID);
	else if (wcsstr(Buffer, (L"NIMLOC")) != nullptr || wcsstr(Buffer, (L"nimloc")) != nullptr)
		return htons(DNS_RECORD_NIMLOC);
	else if (wcsstr(Buffer, (L"SRV")) != nullptr || wcsstr(Buffer, (L"srv")) != nullptr)
		return htons(DNS_RECORD_SRV);
	else if (wcsstr(Buffer, (L"ATMA")) != nullptr || wcsstr(Buffer, (L"atma")) != nullptr)
		return htons(DNS_RECORD_ATMA);
	else if (wcsstr(Buffer, (L"NAPTR")) != nullptr || wcsstr(Buffer, (L"naptr")) != nullptr)
		return htons(DNS_RECORD_NAPTR);
	else if (wcsstr(Buffer, (L"KX")) != nullptr || wcsstr(Buffer, (L"kx")) != nullptr)
		return htons(DNS_RECORD_KX);
	else if (wcsstr(Buffer, (L"CERT")) != nullptr || wcsstr(Buffer, (L"cert")) != nullptr)
		return htons(DNS_RECORD_CERT);
	else if (wcsstr(Buffer, (L"A6")) != nullptr || wcsstr(Buffer, (L"a6")) != nullptr)
		return htons(DNS_RECORD_A6);
	else if (wcsstr(Buffer, (L"DNAME")) != nullptr || wcsstr(Buffer, (L"dname")) != nullptr)
		return htons(DNS_RECORD_DNAME);
	else if (wcsstr(Buffer, (L"SINK")) != nullptr || wcsstr(Buffer, (L"sink")) != nullptr)
		return htons(DNS_RECORD_SINK);
	else if (wcsstr(Buffer, (L"OPT")) != nullptr || wcsstr(Buffer, (L"opt")) != nullptr)
		return htons(DNS_RECORD_OPT);
	else if (wcsstr(Buffer, (L"APL")) != nullptr || wcsstr(Buffer, (L"apl")) != nullptr)
		return htons(DNS_RECORD_APL);
	else if (wcsstr(Buffer, (L"DS")) != nullptr || wcsstr(Buffer, (L"ds")) != nullptr)
		return htons(DNS_RECORD_DS);
	else if (wcsstr(Buffer, (L"SSHFP")) != nullptr || wcsstr(Buffer, (L"sshfp")) != nullptr)
		return htons(DNS_RECORD_SSHFP);
	else if (wcsstr(Buffer, (L"IPSECKEY")) != nullptr || wcsstr(Buffer, (L"ipseckey")) != nullptr)
		return htons(DNS_RECORD_IPSECKEY);
	else if (wcsstr(Buffer, (L"RRSIG")) != nullptr || wcsstr(Buffer, (L"rrsig")) != nullptr)
		return htons(DNS_RECORD_RRSIG);
	else if (wcsstr(Buffer, (L"NSEC")) != nullptr || wcsstr(Buffer, (L"nsec")) != nullptr)
		return htons(DNS_RECORD_NSEC);
	else if (wcsstr(Buffer, (L"DNSKEY")) != nullptr || wcsstr(Buffer, (L"dnskey")) != nullptr)
		return htons(DNS_RECORD_DNSKEY);
	else if (wcsstr(Buffer, (L"DHCID")) != nullptr || wcsstr(Buffer, (L"dhcid")) != nullptr)
		return htons(DNS_RECORD_DHCID);
	else if (wcsstr(Buffer, (L"NSEC3")) != nullptr || wcsstr(Buffer, (L"nsec3")) != nullptr)
		return htons(DNS_RECORD_NSEC3);
	else if (wcsstr(Buffer, (L"NSEC3PARAM")) != nullptr || wcsstr(Buffer, (L"nsec3param")) != nullptr)
		return htons(DNS_RECORD_NSEC3PARAM);
	else if (wcsstr(Buffer, (L"TLSA")) != nullptr || wcsstr(Buffer, (L"tlsa")) != nullptr)
		return htons(DNS_RECORD_TLSA);
	else if (wcsstr(Buffer, (L"HIP")) != nullptr || wcsstr(Buffer, (L"hip")) != nullptr)
		return htons(DNS_RECORD_HIP);
	else if (wcsstr(Buffer, (L"HINFO")) != nullptr || wcsstr(Buffer, (L"hinfo")) != nullptr)
		return htons(DNS_RECORD_HINFO);
	else if (wcsstr(Buffer, (L"RKEY")) != nullptr || wcsstr(Buffer, (L"rkey")) != nullptr)
		return htons(DNS_RECORD_RKEY);
	else if (wcsstr(Buffer, (L"TALINK")) != nullptr || wcsstr(Buffer, (L"talink")) != nullptr)
		return htons(DNS_RECORD_TALINK);
	else if (wcsstr(Buffer, (L"CDS")) != nullptr || wcsstr(Buffer, (L"cds")) != nullptr)
		return htons(DNS_RECORD_CDS);
	else if (wcsstr(Buffer, (L"CDNSKEY")) != nullptr || wcsstr(Buffer, (L"cdnskey")) != nullptr)
		return htons(DNS_RECORD_CDNSKEY);
	else if (wcsstr(Buffer, (L"OPENPGPKEY")) != nullptr || wcsstr(Buffer, (L"openpgpkey")) != nullptr)
		return htons(DNS_RECORD_OPENPGPKEY);
	else if (wcsstr(Buffer, (L"SPF")) != nullptr || wcsstr(Buffer, (L"spf")) != nullptr)
		return htons(DNS_RECORD_SPF);
	else if (wcsstr(Buffer, (L"UINFO")) != nullptr || wcsstr(Buffer, (L"uinfo")) != nullptr)
		return htons(DNS_RECORD_UINFO);
	else if (wcsstr(Buffer, (L"UID")) != nullptr || wcsstr(Buffer, (L"uid")) != nullptr)
		return htons(DNS_RECORD_UID);
	else if (wcsstr(Buffer, (L"GID")) != nullptr || wcsstr(Buffer, (L"gid")) != nullptr)
		return htons(DNS_RECORD_GID);
	else if (wcsstr(Buffer, (L"UNSPEC")) != nullptr || wcsstr(Buffer, (L"unspec")) != nullptr)
		return htons(DNS_RECORD_UNSPEC);
	else if (wcsstr(Buffer, (L"NID")) != nullptr || wcsstr(Buffer, (L"nid")) != nullptr)
		return htons(DNS_RECORD_NID);
	else if (wcsstr(Buffer, (L"L32")) != nullptr || wcsstr(Buffer, (L"l32")) != nullptr)
		return htons(DNS_RECORD_L32);
	else if (wcsstr(Buffer, (L"L64")) != nullptr || wcsstr(Buffer, (L"l64")) != nullptr)
		return htons(DNS_RECORD_L64);
	else if (wcsstr(Buffer, (L"LP")) != nullptr || wcsstr(Buffer, (L"lp")) != nullptr)
		return htons(DNS_RECORD_LP);
	else if (wcsstr(Buffer, (L"EUI48")) != nullptr || wcsstr(Buffer, (L"eui48")) != nullptr)
		return htons(DNS_RECORD_EUI48);
	else if (wcsstr(Buffer, (L"EUI64")) != nullptr || wcsstr(Buffer, (L"eui64")) != nullptr)
		return htons(DNS_RECORD_EUI64);
	else if (wcsstr(Buffer, (L"TKEY")) != nullptr || wcsstr(Buffer, (L"tkey")) != nullptr)
		return htons(DNS_RECORD_TKEY);
	else if (wcsstr(Buffer, (L"TSIG")) != nullptr || wcsstr(Buffer, (L"tsig")) != nullptr)
		return htons(DNS_RECORD_TSIG);
	else if (wcsstr(Buffer, (L"IXFR")) != nullptr || wcsstr(Buffer, (L"ixfr")) != nullptr)
		return htons(DNS_RECORD_IXFR);
	else if (wcsstr(Buffer, (L"AXFR")) != nullptr || wcsstr(Buffer, (L"axfr")) != nullptr)
		return htons(DNS_RECORD_AXFR);
	else if (wcsstr(Buffer, (L"MAILB")) != nullptr || wcsstr(Buffer, (L"mailb")) != nullptr)
		return htons(DNS_RECORD_MAILB);
	else if (wcsstr(Buffer, (L"MAILA")) != nullptr || wcsstr(Buffer, (L"maila")) != nullptr)
		return htons(DNS_RECORD_MAILA);
	else if (wcsstr(Buffer, (L"ANY")) != nullptr || wcsstr(Buffer, (L"any")) != nullptr)
		return htons(DNS_RECORD_ANY);
	else if (wcsstr(Buffer, (L"URI")) != nullptr || wcsstr(Buffer, (L"uri")) != nullptr)
		return htons(DNS_RECORD_URI);
	else if (wcsstr(Buffer, (L"CAA")) != nullptr || wcsstr(Buffer, (L"caa")) != nullptr)
		return htons(DNS_RECORD_CAA);
	else if (wcsstr(Buffer, (L"TA")) != nullptr || wcsstr(Buffer, (L"ta")) != nullptr)
		return htons(DNS_RECORD_TA);
	else if (wcsstr(Buffer, (L"DLV")) != nullptr || wcsstr(Buffer, (L"dlv")) != nullptr)
		return htons(DNS_RECORD_DLV);
	else if (wcsstr(Buffer, (L"RESERVED")) != nullptr || wcsstr(Buffer, (L"reserved")) != nullptr)
		return htons(DNS_RECORD_RESERVED);
//No match.
	return 0;
}

//Convert data from char(s) to DNS query
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName)
{
	int Index[] = {(int)strlen(FName) - 1, 0, 0};
	Index[2U] = Index[0] + 1;
	TName[Index[0] + 2] = 0;

	for (;Index[0] >= 0;Index[0]--,Index[2U]--)
	{
		if (FName[Index[0]] == ASCII_PERIOD)
		{
			TName[Index[2U]] = (char)Index[1U];
			Index[1U] = 0;
		}
		else
		{
			TName[Index[2U]] = FName[Index[0]];
			Index[1U]++;
		}
	}
	TName[Index[2U]] = (char)Index[1U];

	return strlen(TName) + 1U;
}

//Convert data from DNS query to char(s)
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName, uint16_t &Truncated)
{
//Initialization
	size_t uIndex = 0;
	int Index[] = {0, 0};

//Convert domain.
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;uIndex++)
	{
	//Pointer
		if ((UCHAR)TName[uIndex] >= 0xC0)
		{
			Truncated = (UCHAR)(TName[uIndex] & 0x3F);
			Truncated = Truncated << sizeof(char) * BYTES_TO_BITS;
			Truncated += (UCHAR)TName[uIndex + 1U];
			return uIndex + sizeof(uint16_t);
		}
		else if (uIndex == 0)
		{
			Index[0] = TName[uIndex];
		}
		else if (uIndex == Index[0] + Index[1U] + 1U)
		{
			Index[0] = TName[uIndex];
			if (Index[0] == 0)
				break;
			Index[1U] = (int)uIndex;

			FName[uIndex - 1U] = ASCII_PERIOD;
		}
		else {
			FName[uIndex - 1U] = TName[uIndex];
		}
	}

	Truncated = 0;
	return uIndex;
}

//Validate packets
bool __fastcall ValidatePacket(const PSTR Buffer, const size_t Length, const uint16_t DNS_ID)
{
	auto pdns_hdr = (dns_hdr *)Buffer;

//DNS ID and Questions check
	if (pdns_hdr->ID != DNS_ID || pdns_hdr->Questions == 0)
		return false;

//EDNS0 Lable check
	if (EDNS0)
	{
		if (pdns_hdr->Additional == 0)
		{
			return false;
		}
		else if (pdns_hdr->Additional == 1U)
		{
			if (Length > sizeof(dns_opt_record))
			{
				auto pdns_opt_record = (dns_opt_record *)(Buffer + Length - sizeof(dns_opt_record));

			//UDP Payload Size and Z Field of DNSSEC check
				if (pdns_opt_record->UDPPayloadSize == 0 || DNSSEC && pdns_opt_record->Z_Field == 0)
					return false;
			}
			else {
				return false;
			}
		}
	}

	return true;
}

//Print date from seconds
void __fastcall PrintSecondsInDateTime(const time_t Seconds)
{
//Less than 1 minute
	if (Seconds < SECONDS_IN_MINUTE)
		return;

//Initialization
	auto Before = false;
	time_t DateTime = Seconds;
	wprintf_s(L"(");

//Years
	if (DateTime / SECONDS_IN_YEAR > 0)
	{
		wprintf_s(L"%u year", (UINT)(DateTime / SECONDS_IN_YEAR));
		if (DateTime / SECONDS_IN_YEAR > 1U)
			wprintf_s(L"s");
		DateTime %= SECONDS_IN_YEAR;
		Before = true;
	}
//Months
	if (DateTime / SECONDS_IN_MONTH > 0)
	{
		if (Before)
			wprintf_s(L" ");
		wprintf_s(L"%u month", (UINT)(DateTime / SECONDS_IN_MONTH));
		if (DateTime / SECONDS_IN_MONTH > 1U)
			wprintf_s(L"s");
		DateTime %= SECONDS_IN_MONTH;
		Before = true;
	}
//Days
	if (DateTime / SECONDS_IN_DAY > 0)
	{
		if (Before)
			wprintf_s(L" ");
		wprintf_s(L"%u day", (UINT)(DateTime / SECONDS_IN_DAY));
		if (DateTime / SECONDS_IN_DAY > 1U)
			wprintf_s(L"s");
		DateTime %= SECONDS_IN_DAY;
		Before = true;
	}
//Hours
	if (DateTime / SECONDS_IN_HOUR > 0)
	{
		if (Before)
			wprintf_s(L" ");
		wprintf_s(L"%u hour", (UINT)(DateTime / SECONDS_IN_HOUR));
		if (DateTime / SECONDS_IN_HOUR > 1U)
			wprintf_s(L"s");
		DateTime %= SECONDS_IN_HOUR;
		Before = true;
	}
//Minutes
	if (DateTime / SECONDS_IN_MINUTE > 0)
	{
		if (Before)
			wprintf_s(L" ");
		wprintf_s(L"%u minute", (UINT)(DateTime / SECONDS_IN_MINUTE));
		if (DateTime / SECONDS_IN_MINUTE > 1U)
			wprintf_s(L"s");
		DateTime %= SECONDS_IN_MINUTE;
		Before = true;
	}
//Seconds
	if (DateTime > 0)
	{
		if (Before)
			wprintf_s(L" ");
		wprintf_s(L"%u second", (UINT)(DateTime));
		if (DateTime > 1U)
			wprintf_s(L"s");
	}

	wprintf_s(L")");
	return;
}

//Print date from seconds to file
void __fastcall PrintSecondsInDateTime(const time_t Seconds, FILE *OutputFile)
{
//Less than 1 minute
	if (Seconds < SECONDS_IN_MINUTE)
		return;

//Initialization
	auto Before = false;
	time_t DateTime = Seconds;
	fwprintf_s(OutputFile, L"(");

//Years
	if (DateTime / SECONDS_IN_YEAR > 0)
	{
		fwprintf_s(OutputFile, L"%u year", (UINT)(DateTime / SECONDS_IN_YEAR));
		if (DateTime / SECONDS_IN_YEAR > 1U)
			fwprintf_s(OutputFile, L"s");
		DateTime %= SECONDS_IN_YEAR;
		Before = true;
	}
//Months
	if (DateTime / SECONDS_IN_MONTH > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, L" ");
		fwprintf_s(OutputFile, L"%u month", (UINT)(DateTime / SECONDS_IN_MONTH));
		if (DateTime / SECONDS_IN_MONTH > 1U)
			fwprintf_s(OutputFile, L"s");
		DateTime %= SECONDS_IN_MONTH;
		Before = true;
	}
//Days
	if (DateTime / SECONDS_IN_DAY > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, L" ");
		fwprintf_s(OutputFile, L"%u day", (UINT)(DateTime / SECONDS_IN_DAY));
		if (DateTime / SECONDS_IN_DAY > 1U)
			fwprintf_s(OutputFile, L"s");
		DateTime %= SECONDS_IN_DAY;
		Before = true;
	}
//Hours
	if (DateTime / SECONDS_IN_HOUR > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, L" ");
		fwprintf_s(OutputFile, L"%u hour", (UINT)(DateTime / SECONDS_IN_HOUR));
		if (DateTime / SECONDS_IN_HOUR > 1U)
			fwprintf_s(OutputFile, L"s");
		DateTime %= SECONDS_IN_HOUR;
		Before = true;
	}
//Minutes
	if (DateTime / SECONDS_IN_MINUTE > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, L" ");
		fwprintf_s(OutputFile, L"%u minute", (UINT)(DateTime / SECONDS_IN_MINUTE));
		if (DateTime / SECONDS_IN_MINUTE > 1U)
			fwprintf_s(OutputFile, L"s");
		DateTime %= SECONDS_IN_MINUTE;
		Before = true;
	}
//Seconds
	if (DateTime > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, L" ");
		fwprintf_s(OutputFile, L"%u second", (UINT)(DateTime));
		if (DateTime > 1U)
			fwprintf_s(OutputFile, L"s");
	}

	fwprintf_s(OutputFile, L")");
	return;
}

//Print Date and Time with UNIX time
void __fastcall PrintDateTime(const time_t Time)
{
	std::shared_ptr<tm> TimeStructure(new tm());
	localtime_s(TimeStructure.get(), &Time);
	wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);

	return;
}

//Print Date and Time with UNIX time to file
void __fastcall PrintDateTime(const time_t Time, FILE *OutputFile)
{
	std::shared_ptr<tm> TimeStructure(new tm());
	localtime_s(TimeStructure.get(), &Time);
	fwprintf_s(OutputFile, L"%d-%02d-%02d %02d:%02d:%02d", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);

	return;
}
