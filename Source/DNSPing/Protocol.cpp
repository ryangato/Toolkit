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


#include "Protocol.h"

//Minimum supported system of Windows Version Helpers is Windows Vista.
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
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

	for (size_t Index = 0;Index < Length;++Index)
	{
		if (((uint8_t *)Buffer)[Index] != 0)
			return false;
	}

	return true;
}

//Convert lowercase/uppercase word(s) to uppercase/lowercase word(s).
size_t __fastcall CaseConvert(const bool IsLowerUpper, const PSTR Buffer, const size_t Length)
{
	for (size_t Index = 0;Index < Length;++Index)
	{
		if (IsLowerUpper) //Lowercase to uppercase
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
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *pAddr, const uint16_t Protocol, SSIZE_T &ErrCode)
{
	SSIZE_T Result = 0;

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
	sockaddr_storage SockAddr = {0};
	int SockLength = 0;
#endif

//IPv6
	if (Protocol == AF_INET6)
	{
	//Check IPv6 addresses
		for (Result = 0;Result < (SSIZE_T)strlen(AddrString);++Result)
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
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET6, nullptr, (PSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#else 
		Result = inet_pton(AF_INET6, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#endif
		{
			ErrCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		memcpy_s(pAddr, sizeof(in6_addr), &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, sizeof(in6_addr));
	#endif
	}
//IPv4
	else {
		size_t CommaNum = 0;
		for (Result = 0;Result < (SSIZE_T)strlen(AddrString);++Result)
		{
			if (AddrString[Result] != ASCII_PERIOD && AddrString[Result] < ASCII_ZERO || AddrString[Result] > ASCII_NINE)
				return EXIT_FAILURE;
			else if (AddrString[Result] == ASCII_PERIOD)
				++CommaNum;
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
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET, nullptr, (PSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#else 
		Result = inet_pton(AF_INET, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#endif
		{
			ErrCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		memcpy_s(pAddr, sizeof(in_addr), &((PSOCKADDR_IN)&SockAddr)->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Convert protocol name to hex
#if defined(PLATFORM_WIN)
uint16_t __fastcall InternetProtocolNameToPort(const std::wstring &Buffer)
#elif defined(PLATFORM_LINUX)
uint16_t __fastcall InternetProtocolNameToPort(const std::string &Buffer)
#endif
{
//Internet Protocol Number(Part 1)
	if (Buffer == _T("HOPOPTS") || Buffer == _T("hopopts"))
		return IPPROTO_HOPOPTS;
	else if (Buffer == _T("ICMP") || Buffer == _T("icmp"))
		return IPPROTO_ICMP;
	else if (Buffer == _T("IGMP") || Buffer == _T("igmp"))
		return IPPROTO_IGMP;
	else if (Buffer == _T("GGP") || Buffer == _T("ggp"))
		return IPPROTO_GGP;
	else if (Buffer == _T("IPV4") || Buffer == _T("ipv4"))
		return IPPROTO_IPV4;
	else if (Buffer == _T("ST") || Buffer == _T("st"))
		return IPPROTO_ST;
	else if (Buffer == _T("TCP") || Buffer == _T("tcp"))
		return IPPROTO_TCP;
	else if (Buffer == _T("CBT") || Buffer == _T("cbt"))
		return IPPROTO_CBT;
	else if (Buffer == _T("EGP") || Buffer == _T("egp"))
		return IPPROTO_EGP;
	else if (Buffer == _T("IGP") || Buffer == _T("igp"))
		return IPPROTO_IGP;
	else if (Buffer == _T("BBNRCCMON") || Buffer == _T("bbnrccmon"))
		return IPPROTO_BBN_RCC_MON;
	else if (Buffer == _T("NVPII") || Buffer == _T("nvpii"))
		return IPPROTO_NVP_II;
	else if (Buffer == _T("PUP") || Buffer == _T("pup"))
		return IPPROTO_PUP;
	else if (Buffer == _T("ARGUS") || Buffer == _T("argus"))
		return IPPROTO_ARGUS;
	else if (Buffer == _T("EMCON") || Buffer == _T("emcon"))
		return IPPROTO_EMCON;
	else if (Buffer == _T("XNET") || Buffer == _T("xnet"))
		return IPPROTO_XNET;
	else if (Buffer == _T("CHAOS") || Buffer == _T("chaos"))
		return IPPROTO_CHAOS;
	else if (Buffer == _T("UDP") || Buffer == _T("udp"))
		return IPPROTO_UDP;
	else if (Buffer == _T("MUX") || Buffer == _T("mux"))
		return IPPROTO_MUX;
	else if (Buffer == _T("DCN") || Buffer == _T("dcn"))
		return IPPROTO_DCN;
	else if (Buffer == _T("HMP") || Buffer == _T("hmp"))
		return IPPROTO_HMP;
	else if (Buffer == _T("PRM") || Buffer == _T("prm"))
		return IPPROTO_PRM;
	else if (Buffer == _T("IDP") || Buffer == _T("idp"))
		return IPPROTO_IDP;
	else if (Buffer == _T("TRUNK-1") || Buffer == _T("trunk-1"))
		return IPPROTO_TRUNK_1;
	else if (Buffer == _T("TRUNK-2") || Buffer == _T("trunk-2"))
		return IPPROTO_TRUNK_2;
	else if (Buffer == _T("LEAF-1") || Buffer == _T("leaf-1"))
		return IPPROTO_LEAF_1;
	else if (Buffer == _T("LEAF") || Buffer == _T("leaf-2"))
		return IPPROTO_LEAF_2;
	else if (Buffer == _T("RDP") || Buffer == _T("rdp"))
		return IPPROTO_RDP;
	else if (Buffer == _T("IRTP") || Buffer == _T("irtp"))
		return IPPROTO_IRTP;
	else if (Buffer == _T("ISOTP4") || Buffer == _T("isotp4"))
		return IPPROTO_ISO_TP4;
	else if (Buffer == _T("NETBLT") || Buffer == _T("netblt"))
		return IPPROTO_NETBLT;
	else if (Buffer == _T("MFE") || Buffer == _T("mfe"))
		return IPPROTO_MFE;
	else if (Buffer == _T("MERIT") || Buffer == _T("merit"))
		return IPPROTO_MERIT;
	else if (Buffer == _T("DCCP") || Buffer == _T("dccp"))
		return IPPROTO_DCCP;
	else if (Buffer == _T("3PC") || Buffer == _T("3pc"))
		return IPPROTO_3PC;
	else if (Buffer == _T("IDPR") || Buffer == _T("idpr"))
		return IPPROTO_IDPR;
	else if (Buffer == _T("XTP") || Buffer == _T("xtp"))
		return IPPROTO_XTP;
	else if (Buffer == _T("DDP") || Buffer == _T("ddp"))
		return IPPROTO_DDP;
	else if (Buffer == _T("IDPRCMTP") || Buffer == _T("idrpcmtp"))
		return IPPROTO_IDPR_CMTP;
	else if (Buffer == _T("TP++") || Buffer == _T("tp++"))
		return IPPROTO_TPPLUS;
	else if (Buffer == _T("I_T(") || Buffer == _T("il"))
		return IPPROTO_IL;
	else if (Buffer == _T("IPV6") || Buffer == _T("ipv6"))
		return IPPROTO_IPV6;
	else if (Buffer == _T("SDRP") || Buffer == _T("sdrp"))
		return IPPROTO_SDRP;
	else if (Buffer == _T("ROUTING") || Buffer == _T("routing"))
		return IPPROTO_ROUTING;
	else if (Buffer == _T("FRAGMENT") || Buffer == _T("fragment"))
		return IPPROTO_FRAGMENT;
	else if (Buffer == _T("IDRP") || Buffer == _T("idrp"))
		return IPPROTO_IDRP;
	else if (Buffer == _T("RSVP") || Buffer == _T("rsvp"))
		return IPPROTO_RSVP;
	else if (Buffer == _T("GRE") || Buffer == _T("gre"))
		return IPPROTO_GRE;
	else if (Buffer == _T("DSR") || Buffer == _T("dsr"))
		return IPPROTO_DSR;
	else if (Buffer == _T("BNA") || Buffer == _T("bna"))
		return IPPROTO_BNA;
	else if (Buffer == _T("ESP") || Buffer == _T("esp"))
		return IPPROTO_ESP;
	else if (Buffer == _T("AH") || Buffer == _T("ah"))
		return IPPROTO_AH;
	else if (Buffer == _T("NLSP") || Buffer == _T("nlsp"))
		return IPPROTO_NLSP;
	else if (Buffer == _T("SWIPE") || Buffer == _T("swipe"))
		return IPPROTO_SWIPE;
	else if (Buffer == _T("NARP") || Buffer == _T("narp"))
		return IPPROTO_NARP;
	else if (Buffer == _T("MOBILE") || Buffer == _T("mobile"))
		return IPPROTO_MOBILE;
	else if (Buffer == _T("TLSP") || Buffer == _T("tlsp"))
		return IPPROTO_TLSP;
	else if (Buffer == _T("SKIP") || Buffer == _T("skip"))
		return IPPROTO_SKIP;
	else if (Buffer == _T("ICMPV6") || Buffer == _T("icmpv6"))
		return IPPROTO_ICMPV6;
	else if (Buffer == _T("NONE") || Buffer == _T("none"))
		return IPPROTO_NONE;
	else if (Buffer == _T("DSTOPTS") || Buffer == _T("dstopts"))
		return IPPROTO_DSTOPTS;
	else if (Buffer == _T("AHI") || Buffer == _T("ahi"))
		return IPPROTO_AHI;
	else if (Buffer == _T("CFTP") || Buffer == _T("cftp"))
		return IPPROTO_CFTP;
	else if (Buffer == _T("ALN") || Buffer == _T("aln"))
		return IPPROTO_ALN;
	else if (Buffer == _T("SAT") || Buffer == _T("sat"))
		return IPPROTO_SAT;
	else if (Buffer == _T("KRYPTOLAN") || Buffer == _T("kryptolan"))
		return IPPROTO_KRYPTOLAN;
	else if (Buffer == _T("RVD") || Buffer == _T("rvd"))
		return IPPROTO_RVD;
	else if (Buffer == _T("IPPC") || Buffer == _T("ippc"))
		return IPPROTO_IPPC;
	else if (Buffer == _T("ADF") || Buffer == _T("adf"))
		return IPPROTO_ADF;
	else if (Buffer == _T("SATMON") || Buffer == _T("satmon"))
		return IPPROTO_SAT_MON;
	else if (Buffer == _T("VISA") || Buffer == _T("visa"))
		return IPPROTO_VISA;
	else if (Buffer == _T("IPCV") || Buffer == _T("ipcv"))
		return IPPROTO_IPCV;
	else if (Buffer == _T("CPNX") || Buffer == _T("cpnx"))
		return IPPROTO_CPNX;
	else if (Buffer == _T("CPHB") || Buffer == _T("cphb"))
		return IPPROTO_CPHB;
	else if (Buffer == _T("WSN") || Buffer == _T("wsn"))
		return IPPROTO_WSN;
	else if (Buffer == _T("PVP") || Buffer == _T("pvp"))
		return IPPROTO_PVP;
	else if (Buffer == _T("BR") || Buffer == _T("br"))
		return IPPROTO_BR;
	else if (Buffer == _T("ND") || Buffer == _T("nd"))
		return IPPROTO_ND;
	else if (Buffer == _T("ICLFXBM") || Buffer == _T("iclfxbm"))
		return IPPROTO_ICLFXBM;
	else if (Buffer == _T("WBEXPAK") || Buffer == _T("wbexpak"))
		return IPPROTO_WBEXPAK;
	else if (Buffer == _T("ISO") || Buffer == _T("iso"))
		return IPPROTO_ISO;
	else if (Buffer == _T("VMTP") || Buffer == _T("vmtp"))
		return IPPROTO_VMTP;
	else if (Buffer == _T("SVMTP") || Buffer == _T("svmtp"))
		return IPPROTO_SVMTP;
	else if (Buffer == _T("VINES") || Buffer == _T("vines"))
		return IPPROTO_VINES;
	else if (Buffer == _T("TTP") || Buffer == _T("ttp"))
		return IPPROTO_TTP;
	else if (Buffer == _T("IPTM") || Buffer == _T("iptm"))
		return IPPROTO_IPTM;
	else if (Buffer == _T("NSFNET") || Buffer == _T("nsfnet"))
		return IPPROTO_NSFNET;
	else if (Buffer == _T("DGP") || Buffer == _T("dgp"))
		return IPPROTO_DGP;
	else if (Buffer == _T("TCF") || Buffer == _T("tcf"))
		return IPPROTO_TCF;
	else if (Buffer == _T("EIGRP") || Buffer == _T("eigrp"))
		return IPPROTO_EIGRP;
	else if (Buffer == _T("SPRITE") || Buffer == _T("sprite"))
		return IPPROTO_SPRITE;
	else if (Buffer == _T("LARP") || Buffer == _T("larp"))
		return IPPROTO_LARP;
	else if (Buffer == _T("MTP") || Buffer == _T("mtp"))
		return IPPROTO_MTP;
	else if (Buffer == _T("AX25") || Buffer == _T("ax25"))
		return IPPROTO_AX25;
	else if (Buffer == _T("IPIP") || Buffer == _T("ipip"))
		return IPPROTO_IPIP;
	else if (Buffer == _T("MICP") || Buffer == _T("micp"))
		return IPPROTO_MICP;
	else if (Buffer == _T("SCC") || Buffer == _T("scc"))
		return IPPROTO_SCC;
	else if (Buffer == _T("ETHERIP") || Buffer == _T("etherip"))
		return IPPROTO_ETHERIP;
	else if (Buffer == _T("ENCAP") || Buffer == _T("encap"))
		return IPPROTO_ENCAP;
	else if (Buffer == _T("APES") || Buffer == _T("apes"))
		return IPPROTO_APES;
	else if (Buffer == _T("GMTP") || Buffer == _T("gmtp"))
		return IPPROTO_GMTP;
	else if (Buffer == _T("IFMP") || Buffer == _T("ifmp"))
		return IPPROTO_IFMP;
	else if (Buffer == _T("PIM") || Buffer == _T("pim"))
		return IPPROTO_PIM;
	else if (Buffer == _T("PNNI") || Buffer == _T("pnni"))
		return IPPROTO_PNNI;
	else if (Buffer == _T("ARIS") || Buffer == _T("aris"))
		return IPPROTO_ARIS;
	else if (Buffer == _T("SCPS") || Buffer == _T("scps"))
		return IPPROTO_SCPS;
	else if (Buffer == _T("QNX") || Buffer == _T("qnx"))
		return IPPROTO_QNX;
	else if (Buffer == _T("AN") || Buffer == _T("an"))
		return IPPROTO_AN;
	else if (Buffer == _T("IPCOMP") || Buffer == _T("ipcomp"))
		return IPPROTO_IPCOMP;
	else if (Buffer == _T("SNP") || Buffer == _T("snp"))
		return IPPROTO_SNP;
	else if (Buffer == _T("COMPAQ") || Buffer == _T("compaq"))
		return IPPROTO_COMPAQ;
	else if (Buffer == _T("IPX") || Buffer == _T("ipx"))
		return IPPROTO_IPX;
	else if (Buffer == _T("PGM") || Buffer == _T("pgm"))
		return IPPROTO_PGM;
	else if (Buffer == _T("0HOP") || Buffer == _T("0hop"))
		return IPPROTO_0HOP;
	else if (Buffer == _T("L2TP") || Buffer == _T("l2tp"))
		return IPPROTO_L2TP;
	else if (Buffer == _T("DDX") || Buffer == _T("ddx"))
		return IPPROTO_DDX;
	else if (Buffer == _T("IATP") || Buffer == _T("iatp"))
		return IPPROTO_IATP;
	else if (Buffer == _T("STP") || Buffer == _T("stp"))
		return IPPROTO_STP;
	else if (Buffer == _T("SRP") || Buffer == _T("srp"))
		return IPPROTO_SRP;
	else if (Buffer == _T("UTI") || Buffer == _T("uti"))
		return IPPROTO_UTI;
	else if (Buffer == _T("SMP") || Buffer == _T("smp"))
		return IPPROTO_SMP;
	else if (Buffer == _T("SM") || Buffer == _T("sm"))
		return IPPROTO_SM;
	else if (Buffer == _T("PTP") || Buffer == _T("ptp"))
		return IPPROTO_PTP;

//Internet Protocol Number(Part 2)
	if (Buffer == _T("ISIS") || Buffer == _T("isis"))
		return IPPROTO_ISIS;
	else if (Buffer == _T("FIRE") || Buffer == _T("fire"))
		return IPPROTO_FIRE;
	else if (Buffer == _T("CRTP") || Buffer == _T("crtp"))
		return IPPROTO_CRTP;
	else if (Buffer == _T("CRUDP") || Buffer == _T("crudp"))
		return IPPROTO_CRUDP;
	else if (Buffer == _T("SSCOPMCE") || Buffer == _T("sscopmce"))
		return IPPROTO_SSCOPMCE;
	else if (Buffer == _T("IPLT") || Buffer == _T("iplt"))
		return IPPROTO_IPLT;
	else if (Buffer == _T("SPS") || Buffer == _T("sps"))
		return IPPROTO_SPS;
	else if (Buffer == _T("PIPE") || Buffer == _T("pipe"))
		return IPPROTO_PIPE;
	else if (Buffer == _T("SCTP") || Buffer == _T("sctp"))
		return IPPROTO_SCTP;
	else if (Buffer == _T("FC") || Buffer == _T("fc"))
		return IPPROTO_FC;
	else if (Buffer == _T("RSVPE2E") || Buffer == _T("rsvpe2e"))
		return IPPROTO_RSVP_E2E;
	else if (Buffer == _T("MOBILITY") || Buffer == _T("mobility"))
		return IPPROTO_MOBILITY;
	else if (Buffer == _T("UDPLITE") || Buffer == _T("udplite"))
		return IPPROTO_UDPLITE;
	else if (Buffer == _T("MPLS") || Buffer == _T("mpls"))
		return IPPROTO_MPLS;
	else if (Buffer == _T("MANET") || Buffer == _T("manet"))
		return IPPROTO_MANET;
	else if (Buffer == _T("HIP") || Buffer == _T("hip"))
		return IPPROTO_HIP;
	else if (Buffer == _T("SHIM6") || Buffer == _T("shim6"))
		return IPPROTO_SHIM6;
	else if (Buffer == _T("WESP") || Buffer == _T("wesp"))
		return IPPROTO_WESP;
	else if (Buffer == _T("ROHC") || Buffer == _T("rohc"))
		return IPPROTO_ROHC;
	else if (Buffer == _T("TEST-1") || Buffer == _T("test-1"))
		return IPPROTO_TEST_1;
	else if (Buffer == _T("TEST-2") || Buffer == _T("test-2"))
		return IPPROTO_TEST_2;
	else if (Buffer == _T("RAW") || Buffer == _T("raw"))
		return IPPROTO_RAW;

//No match.
	return 0;
}

//Convert service name to port
#if defined(PLATFORM_WIN)
uint16_t __fastcall ServiceNameToPort(const std::wstring &Buffer)
#elif defined(PLATFORM_LINUX)
uint16_t __fastcall ServiceNameToPort(const std::string &Buffer)
#endif
{
//Server name
	if (Buffer == _T("TCPMUX") || Buffer == _T("tcpmux"))
		return htons(IPPORT_TCPMUX);
	else if (Buffer == _T("ECHO") || Buffer == _T("echo"))
		return htons(IPPORT_ECHO);
	else if (Buffer == _T("DISCARD") || Buffer == _T("discard"))
		return htons(IPPORT_DISCARD);
	else if (Buffer == _T("SYSTAT") || Buffer == _T("systat"))
		return htons(IPPORT_SYSTAT);
	else if (Buffer == _T("DAYTIME") || Buffer == _T("daytime"))
		return htons(IPPORT_DAYTIME);
	else if (Buffer == _T("NETSTAT") || Buffer == _T("netstat"))
		return htons(IPPORT_NETSTAT);
	else if (Buffer == _T("QOTD") || Buffer == _T("qotd"))
		return htons(IPPORT_QOTD);
	else if (Buffer == _T("MSP") || Buffer == _T("msp"))
		return htons(IPPORT_MSP);
	else if (Buffer == _T("CHARGEN") || Buffer == _T("chargen"))
		return htons(IPPORT_CHARGEN);
	else if (Buffer == _T("FTPDATA") || Buffer == _T("ftpdata"))
		return htons(IPPORT_FTP_DATA);
	else if (Buffer == _T("FTP") || Buffer == _T("ftp"))
		return htons(IPPORT_FTP);
	else if (Buffer == _T("SSH") || Buffer == _T("ssh"))
		return htons(IPPORT_SSH);
	else if (Buffer == _T("TELNET") || Buffer == _T("telnet"))
		return htons(IPPORT_TELNET);
	else if (Buffer == _T("SMTP") || Buffer == _T("smtp"))
		return htons(IPPORT_SMTP);
	else if (Buffer == _T("TIME") || Buffer == _T("time"))
		return htons(IPPORT_TIMESERVER);
	else if (Buffer == _T("RAP") || Buffer == _T("rap"))
		return htons(IPPORT_RAP);
	else if (Buffer == _T("RLP") || Buffer == _T("rlp"))
		return htons(IPPORT_RLP);
	else if (Buffer == _T("NAME") || Buffer == _T("name"))
		return htons(IPPORT_NAMESERVER);
	else if (Buffer == _T("WHOIS") || Buffer == _T("whois"))
		return htons(IPPORT_WHOIS);
	else if (Buffer == _T("TACACS") || Buffer == _T("tacacs"))
		return htons(IPPORT_TACACS);
	else if (Buffer == _T("DNS") || Buffer == _T("dns"))
		return htons(IPPORT_DNS);
	else if (Buffer == _T("XNSAUTH") || Buffer == _T("xnsauth"))
		return htons(IPPORT_XNSAUTH);
	else if (Buffer == _T("MTP") || Buffer == _T("mtp"))
		return htons(IPPORT_MTP);
	else if (Buffer == _T("BOOTPS") || Buffer == _T("bootps"))
		return htons(IPPORT_BOOTPS);
	else if (Buffer == _T("BOOTPC") || Buffer == _T("bootpc"))
		return htons(IPPORT_BOOTPC);
	else if (Buffer == _T("TFTP") || Buffer == _T("tftp"))
		return htons(IPPORT_TFTP);
	else if (Buffer == _T("RJE") || Buffer == _T("rje"))
		return htons(IPPORT_RJE);
	else if (Buffer == _T("FINGER") || Buffer == _T("finger"))
		return htons(IPPORT_FINGER);
	else if (Buffer == _T("HTTP") || Buffer == _T("http"))
		return htons(IPPORT_HTTP);
	else if (Buffer == _T("HTTPBACKUP") || Buffer == _T("httpbackup"))
		return htons(IPPORT_HTTPBACKUP);
	else if (Buffer == _T("TTYLINK") || Buffer == _T("ttylink"))
		return htons(IPPORT_TTYLINK);
	else if (Buffer == _T("SUPDUP") || Buffer == _T("supdup"))
		return htons(IPPORT_SUPDUP);
	else if (Buffer == _T("POP3") || Buffer == _T("pop3"))
		return htons(IPPORT_POP3);
	else if (Buffer == _T("SUNRPC") || Buffer == _T("sunrpc"))
		return htons(IPPORT_SUNRPC);
	else if (Buffer == _T("SQ_T(") || Buffer == _T("sql"))
		return htons(IPPORT_SQL);
	else if (Buffer == _T("NTP") || Buffer == _T("ntp"))
		return htons(IPPORT_NTP);
	else if (Buffer == _T("EPMAP") || Buffer == _T("epmap"))
		return htons(IPPORT_EPMAP);
	else if (Buffer == _T("NETBIOSNS") || Buffer == _T("netbiosns"))
		return htons(IPPORT_NETBIOS_NS);
	else if (Buffer == _T("NETBIOSDGM") || Buffer == _T("netbiosdgm"))
		return htons(IPPORT_NETBIOS_DGM);
	else if (Buffer == _T("NETBIOSSSN") || Buffer == _T("netbiosssn"))
		return htons(IPPORT_NETBIOS_SSN);
	else if (Buffer == _T("IMAP") || Buffer == _T("imap"))
		return htons(IPPORT_IMAP);
	else if (Buffer == _T("BFTP") || Buffer == _T("bftp"))
		return htons(IPPORT_BFTP);
	else if (Buffer == _T("SGMP") || Buffer == _T("sgmp"))
		return htons(IPPORT_SGMP);
	else if (Buffer == _T("SQLSRV") || Buffer == _T("sqlsrv"))
		return htons(IPPORT_SQLSRV);
	else if (Buffer == _T("DMSP") || Buffer == _T("dmsp"))
		return htons(IPPORT_DMSP);
	else if (Buffer == _T("SNMP") || Buffer == _T("snmp"))
		return htons(IPPORT_SNMP);
	else if (Buffer == _T("SNMPTRAP") || Buffer == _T("snmptrap"))
		return htons(IPPORT_SNMP_TRAP);
	else if (Buffer == _T("ATRTMP") || Buffer == _T("atrtmp"))
		return htons(IPPORT_ATRTMP);
	else if (Buffer == _T("ATHBP") || Buffer == _T("athbp"))
		return htons(IPPORT_ATHBP);
	else if (Buffer == _T("QMTP") || Buffer == _T("qmtp"))
		return htons(IPPORT_QMTP);
	else if (Buffer == _T("IPX") || Buffer == _T("ipx"))
		return htons(IPPORT_IPX);
	else if (Buffer == _T("IMAP3") || Buffer == _T("imap3"))
		return htons(IPPORT_IMAP3);
	else if (Buffer == _T("BGMP") || Buffer == _T("bgmp"))
		return htons(IPPORT_BGMP);
	else if (Buffer == _T("TSP") || Buffer == _T("tsp"))
		return htons(IPPORT_TSP);
	else if (Buffer == _T("IMMP") || Buffer == _T("immp"))
		return htons(IPPORT_IMMP);
	else if (Buffer == _T("ODMR") || Buffer == _T("odmr"))
		return htons(IPPORT_ODMR);
	else if (Buffer == _T("RPC2PORTMAP") || Buffer == _T("rpc2portmap"))
		return htons(IPPORT_RPC2PORTMAP);
	else if (Buffer == _T("CLEARCASE") || Buffer == _T("clearcase"))
		return htons(IPPORT_CLEARCASE);
	else if (Buffer == _T("HPALARMMGR") || Buffer == _T("hpalarmmgr"))
		return htons(IPPORT_HPALARMMGR);
	else if (Buffer == _T("ARNS") || Buffer == _T("arns"))
		return htons(IPPORT_ARNS);
	else if (Buffer == _T("AURP") || Buffer == _T("aurp"))
		return htons(IPPORT_AURP);
	else if (Buffer == _T("LDAP") || Buffer == _T("ldap"))
		return htons(IPPORT_LDAP);
	else if (Buffer == _T("UPS") || Buffer == _T("ups"))
		return htons(IPPORT_UPS);
	else if (Buffer == _T("SLP") || Buffer == _T("slp"))
		return htons(IPPORT_SLP);
	else if (Buffer == _T("HTTPS") || Buffer == _T("https"))
		return htons(IPPORT_HTTPS);
	else if (Buffer == _T("SNPP") || Buffer == _T("snpp"))
		return htons(IPPORT_SNPP);
	else if (Buffer == _T("MICROSOFTDS") || Buffer == _T("microsoftds"))
		return htons(IPPORT_MICROSOFT_DS);
	else if (Buffer == _T("KPASSWD") || Buffer == _T("kpasswd"))
		return htons(IPPORT_KPASSWD);
	else if (Buffer == _T("TCPNETHASPSRV") || Buffer == _T("tcpnethaspsrv"))
		return htons(IPPORT_TCPNETHASPSRV);
	else if (Buffer == _T("RETROSPECT") || Buffer == _T("retrospect"))
		return htons(IPPORT_RETROSPECT);
	else if (Buffer == _T("ISAKMP") || Buffer == _T("isakmp"))
		return htons(IPPORT_ISAKMP);
	else if (Buffer == _T("BIFFUDP") || Buffer == _T("biffudp"))
		return htons(IPPORT_BIFFUDP);
	else if (Buffer == _T("WHOSERVER") || Buffer == _T("whoserver"))
		return htons(IPPORT_WHOSERVER);
	else if (Buffer == _T("SYSLOG") || Buffer == _T("syslog"))
		return htons(IPPORT_SYSLOG);
	else if (Buffer == _T("ROUTERSERVER") || Buffer == _T("routerserver"))
		return htons(IPPORT_ROUTESERVER);
	else if (Buffer == _T("NCP") || Buffer == _T("ncp"))
		return htons(IPPORT_NCP);
	else if (Buffer == _T("COURIER") || Buffer == _T("courier"))
		return htons(IPPORT_COURIER);
	else if (Buffer == _T("COMMERCE") || Buffer == _T("commerce"))
		return htons(IPPORT_COMMERCE);
	else if (Buffer == _T("RTSP") || Buffer == _T("rtsp"))
		return htons(IPPORT_RTSP);
	else if (Buffer == _T("NNTP") || Buffer == _T("nntp"))
		return htons(IPPORT_NNTP);
	else if (Buffer == _T("HTTPRPCEPMAP") || Buffer == _T("httprpcepmap"))
		return htons(IPPORT_HTTPRPCEPMAP);
	else if (Buffer == _T("IPP") || Buffer == _T("ipp"))
		return htons(IPPORT_IPP);
	else if (Buffer == _T("LDAPS") || Buffer == _T("ldaps"))
		return htons(IPPORT_LDAPS);
	else if (Buffer == _T("MSDP") || Buffer == _T("msdp"))
		return htons(IPPORT_MSDP);
	else if (Buffer == _T("AODV") || Buffer == _T("aodv"))
		return htons(IPPORT_AODV);
	else if (Buffer == _T("FTPSDATA") || Buffer == _T("ftpsdata"))
		return htons(IPPORT_FTPSDATA);
	else if (Buffer == _T("FTPS") || Buffer == _T("ftps"))
		return htons(IPPORT_FTPS);
	else if (Buffer == _T("NAS") || Buffer == _T("nas"))
		return htons(IPPORT_NAS);
	else if (Buffer == _T("TELNETS") || Buffer == _T("telnets"))
		return htons(IPPORT_TELNETS);
//No match.
	return 0;
}

//Convert DNS classes name to hex
#if defined(PLATFORM_WIN)
uint16_t __fastcall DNSClassesNameToHex(const std::wstring &Buffer)
#elif defined(PLATFORM_LINUX)
uint16_t __fastcall DNSClassesNameToHex(const std::string &Buffer)
#endif
{
//DNS classes name
	if (Buffer == _T("INTERNET") || Buffer == _T("internet") || Buffer == _T("IN") || Buffer == _T("in"))
		return htons(DNS_CLASS_IN);
	else if (Buffer == _T("CSNET") || Buffer == _T("csnet"))
		return htons(DNS_CLASS_CSNET);
	else if (Buffer == _T("CHAOS") || Buffer == _T("chaos"))
		return htons(DNS_CLASS_CHAOS);
	else if (Buffer == _T("HESIOD") || Buffer == _T("hesiod"))
		return htons(DNS_CLASS_HESIOD);
	else if (Buffer == _T("NONE") || Buffer == _T("none"))
		return htons(DNS_CLASS_NONE);
	else if (Buffer == _T("AL_T(") || Buffer == _T("all"))
		return htons(DNS_CLASS_ALL);
	else if (Buffer == _T("ANY") || Buffer == _T("any"))
		return htons(DNS_CLASS_ANY);
//No match.
	return 0;
}

//Convert DNS type name to hex
#if defined(PLATFORM_WIN)
uint16_t __fastcall DNSTypeNameToHex(const std::wstring &Buffer)
#elif defined(PLATFORM_LINUX)
uint16_t __fastcall DNSTypeNameToHex(const std::string &Buffer)
#endif
{
//DNS type name
	if (Buffer == _T("A") || Buffer == _T("a"))
		return htons(DNS_RECORD_A);
	else if (Buffer == _T("NS") || Buffer == _T("ns"))
		return htons(DNS_RECORD_NS);
	else if (Buffer == _T("MD") || Buffer == _T("md"))
		return htons(DNS_RECORD_MD);
	else if (Buffer == _T("MF") || Buffer == _T("mf"))
		return htons(DNS_RECORD_MF);
	else if (Buffer == _T("CNAME") || Buffer == _T("cname"))
		return htons(DNS_RECORD_CNAME);
	else if (Buffer == _T("SOA") || Buffer == _T("soa"))
		return htons(DNS_RECORD_SOA);
	else if (Buffer == _T("MB") || Buffer == _T("mb"))
		return htons(DNS_RECORD_MB);
	else if (Buffer == _T("MG") || Buffer == _T("mg"))
		return htons(DNS_RECORD_MG);
	else if (Buffer == _T("MR") || Buffer == _T("mr"))
		return htons(DNS_RECORD_MR);
	else if (Buffer == _T("PTR") || Buffer == _T("ptr"))
		return htons(DNS_RECORD_PTR);
	else if (Buffer == _T("NUL_T(") || Buffer == _T("null"))
		return htons(DNS_RECORD_NULL);
	else if (Buffer == _T("WKS") || Buffer == _T("wks"))
		return htons(DNS_RECORD_WKS);
	else if (Buffer == _T("HINFO") || Buffer == _T("hinfo"))
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == _T("MINFO") || Buffer == _T("minfo"))
		return htons(DNS_RECORD_MINFO);
	else if (Buffer == _T("MX") || Buffer == _T("mx"))
		return htons(DNS_RECORD_MX);
	else if (Buffer == _T("TXT") || Buffer == _T("txt"))
		return htons(DNS_RECORD_TXT);
	else if (Buffer == _T("RP") || Buffer == _T("rp"))
		return htons(DNS_RECORD_RP);
	else if (Buffer == _T("SIG") || Buffer == _T("sig"))
		return htons(DNS_RECORD_SIG);
	else if (Buffer == _T("AFSDB") || Buffer == _T("afsdb"))
		return htons(DNS_RECORD_AFSDB);
	else if (Buffer == _T("X25") || Buffer == _T("x25"))
		return htons(DNS_RECORD_X25);
	else if (Buffer == _T("ISDN") || Buffer == _T("isdn"))
		return htons(DNS_RECORD_ISDN);
	else if (Buffer == _T("RT") || Buffer == _T("rt"))
		return htons(DNS_RECORD_RT);
	else if (Buffer == _T("NSAP") || Buffer == _T("nsap"))
		return htons(DNS_RECORD_NSAP);
	else if (Buffer == _T("NSAPPTR") || Buffer == _T("nsapptr"))
		return htons(DNS_RECORD_NSAP_PTR);
	else if (Buffer == _T("SIG") || Buffer == _T("sig"))
		return htons(DNS_RECORD_SIG);
	else if (Buffer == _T("KEY") || Buffer == _T("key"))
		return htons(DNS_RECORD_KEY);
	else if (Buffer == _T("AAAA") || Buffer == _T("aaaa"))
		return htons(DNS_RECORD_AAAA);
	else if (Buffer == _T("PX") || Buffer == _T("px"))
		return htons(DNS_RECORD_PX);
	else if (Buffer == _T("GPOS") || Buffer == _T("gpos"))
		return htons(DNS_RECORD_GPOS);
	else if (Buffer == _T("LOC") || Buffer == _T("loc"))
		return htons(DNS_RECORD_LOC);
	else if (Buffer == _T("NXT") || Buffer == _T("nxt"))
		return htons(DNS_RECORD_NXT);
	else if (Buffer == _T("EID") || Buffer == _T("eid"))
		return htons(DNS_RECORD_EID);
	else if (Buffer == _T("NIMLOC") || Buffer == _T("nimloc"))
		return htons(DNS_RECORD_NIMLOC);
	else if (Buffer == _T("SRV") || Buffer == _T("srv"))
		return htons(DNS_RECORD_SRV);
	else if (Buffer == _T("ATMA") || Buffer == _T("atma"))
		return htons(DNS_RECORD_ATMA);
	else if (Buffer == _T("NAPTR") || Buffer == _T("naptr"))
		return htons(DNS_RECORD_NAPTR);
	else if (Buffer == _T("KX") || Buffer == _T("kx"))
		return htons(DNS_RECORD_KX);
	else if (Buffer == _T("CERT") || Buffer == _T("cert"))
		return htons(DNS_RECORD_CERT);
	else if (Buffer == _T("A6") || Buffer == _T("a6"))
		return htons(DNS_RECORD_A6);
	else if (Buffer == _T("DNAME") || Buffer == _T("dname"))
		return htons(DNS_RECORD_DNAME);
	else if (Buffer == _T("SINK") || Buffer == _T("sink"))
		return htons(DNS_RECORD_SINK);
	else if (Buffer == _T("OPT") || Buffer == _T("opt"))
		return htons(DNS_RECORD_OPT);
	else if (Buffer == _T("AP_T(") || Buffer == _T("apl"))
		return htons(DNS_RECORD_APL);
	else if (Buffer == _T("DS") || Buffer == _T("ds"))
		return htons(DNS_RECORD_DS);
	else if (Buffer == _T("SSHFP") || Buffer == _T("sshfp"))
		return htons(DNS_RECORD_SSHFP);
	else if (Buffer == _T("IPSECKEY") || Buffer == _T("ipseckey"))
		return htons(DNS_RECORD_IPSECKEY);
	else if (Buffer == _T("RRSIG") || Buffer == _T("rrsig"))
		return htons(DNS_RECORD_RRSIG);
	else if (Buffer == _T("NSEC") || Buffer == _T("nsec"))
		return htons(DNS_RECORD_NSEC);
	else if (Buffer == _T("DNSKEY") || Buffer == _T("dnskey"))
		return htons(DNS_RECORD_DNSKEY);
	else if (Buffer == _T("DHCID") || Buffer == _T("dhcid"))
		return htons(DNS_RECORD_DHCID);
	else if (Buffer == _T("NSEC3") || Buffer == _T("nsec3"))
		return htons(DNS_RECORD_NSEC3);
	else if (Buffer == _T("NSEC3PARAM") || Buffer == _T("nsec3param"))
		return htons(DNS_RECORD_NSEC3PARAM);
	else if (Buffer == _T("TLSA") || Buffer == _T("tlsa"))
		return htons(DNS_RECORD_TLSA);
	else if (Buffer == _T("HIP") || Buffer == _T("hip"))
		return htons(DNS_RECORD_HIP);
	else if (Buffer == _T("HINFO") || Buffer == _T("hinfo"))
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == _T("RKEY") || Buffer == _T("rkey"))
		return htons(DNS_RECORD_RKEY);
	else if (Buffer == _T("TALINK") || Buffer == _T("talink"))
		return htons(DNS_RECORD_TALINK);
	else if (Buffer == _T("CDS") || Buffer == _T("cds"))
		return htons(DNS_RECORD_CDS);
	else if (Buffer == _T("CDNSKEY") || Buffer == _T("cdnskey"))
		return htons(DNS_RECORD_CDNSKEY);
	else if (Buffer == _T("OPENPGPKEY") || Buffer == _T("openpgpkey"))
		return htons(DNS_RECORD_OPENPGPKEY);
	else if (Buffer == _T("SPF") || Buffer == _T("spf"))
		return htons(DNS_RECORD_SPF);
	else if (Buffer == _T("UINFO") || Buffer == _T("uinfo"))
		return htons(DNS_RECORD_UINFO);
	else if (Buffer == _T("UID") || Buffer == _T("uid"))
		return htons(DNS_RECORD_UID);
	else if (Buffer == _T("GID") || Buffer == _T("gid"))
		return htons(DNS_RECORD_GID);
	else if (Buffer == _T("UNSPEC") || Buffer == _T("unspec"))
		return htons(DNS_RECORD_UNSPEC);
	else if (Buffer == _T("NID") || Buffer == _T("nid"))
		return htons(DNS_RECORD_NID);
	else if (Buffer == _T("L32") || Buffer == _T("l32"))
		return htons(DNS_RECORD_L32);
	else if (Buffer == _T("L64") || Buffer == _T("l64"))
		return htons(DNS_RECORD_L64);
	else if (Buffer == _T("LP") || Buffer == _T("lp"))
		return htons(DNS_RECORD_LP);
	else if (Buffer == _T("EUI48") || Buffer == _T("eui48"))
		return htons(DNS_RECORD_EUI48);
	else if (Buffer == _T("EUI64") || Buffer == _T("eui64"))
		return htons(DNS_RECORD_EUI64);
	else if (Buffer == _T("TKEY") || Buffer == _T("tkey"))
		return htons(DNS_RECORD_TKEY);
	else if (Buffer == _T("TSIG") || Buffer == _T("tsig"))
		return htons(DNS_RECORD_TSIG);
	else if (Buffer == _T("IXFR") || Buffer == _T("ixfr"))
		return htons(DNS_RECORD_IXFR);
	else if (Buffer == _T("AXFR") || Buffer == _T("axfr"))
		return htons(DNS_RECORD_AXFR);
	else if (Buffer == _T("MAILB") || Buffer == _T("mailb"))
		return htons(DNS_RECORD_MAILB);
	else if (Buffer == _T("MAILA") || Buffer == _T("maila"))
		return htons(DNS_RECORD_MAILA);
	else if (Buffer == _T("ANY") || Buffer == _T("any"))
		return htons(DNS_RECORD_ANY);
	else if (Buffer == _T("URI") || Buffer == _T("uri"))
		return htons(DNS_RECORD_URI);
	else if (Buffer == _T("CAA") || Buffer == _T("caa"))
		return htons(DNS_RECORD_CAA);
	else if (Buffer == _T("TA") || Buffer == _T("ta"))
		return htons(DNS_RECORD_TA);
	else if (Buffer == _T("DLV") || Buffer == _T("dlv"))
		return htons(DNS_RECORD_DLV);
	else if (Buffer == _T("RESERVED") || Buffer == _T("reserved"))
		return htons(DNS_RECORD_RESERVED);
//No match.
	return 0;
}

//Convert data from char(s) to DNS query
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName)
{
	int Index[] = {(int)strnlen_s(FName, DOMAIN_MAXSIZE) - 1, 0, 0};
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
			++Index[1U];
		}
	}

	TName[Index[2U]] = (char)Index[1U];
	return strnlen_s(TName, DOMAIN_MAXSIZE - 1U) + 1U;
}

//Convert data from DNS query to char(s)
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName, uint16_t &Truncated)
{
//Initialization
	size_t uIndex = 0;
	int Index[] = {0, 0};

//Convert domain.
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;++uIndex)
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
	auto DateTime = Seconds;
	wprintf_s(_T("("));

//Years
	if (DateTime / SECONDS_IN_YEAR > 0)
	{
		wprintf_s(_T("%u year"), (UINT)(DateTime / SECONDS_IN_YEAR));
		if (DateTime / SECONDS_IN_YEAR > 1U)
			wprintf_s(_T("s"));
		DateTime %= SECONDS_IN_YEAR;
		Before = true;
	}
//Months
	if (DateTime / SECONDS_IN_MONTH > 0)
	{
		if (Before)
			wprintf_s(_T(" "));
		wprintf_s(_T("%u month"), (UINT)(DateTime / SECONDS_IN_MONTH));
		if (DateTime / SECONDS_IN_MONTH > 1U)
			wprintf_s(_T("s"));
		DateTime %= SECONDS_IN_MONTH;
		Before = true;
	}
//Days
	if (DateTime / SECONDS_IN_DAY > 0)
	{
		if (Before)
			wprintf_s(_T(" "));
		wprintf_s(_T("%u day"), (UINT)(DateTime / SECONDS_IN_DAY));
		if (DateTime / SECONDS_IN_DAY > 1U)
			wprintf_s(_T("s"));
		DateTime %= SECONDS_IN_DAY;
		Before = true;
	}
//Hours
	if (DateTime / SECONDS_IN_HOUR > 0)
	{
		if (Before)
			wprintf_s(_T(" "));
		wprintf_s(_T("%u hour"), (UINT)(DateTime / SECONDS_IN_HOUR));
		if (DateTime / SECONDS_IN_HOUR > 1U)
			wprintf_s(_T("s"));
		DateTime %= SECONDS_IN_HOUR;
		Before = true;
	}
//Minutes
	if (DateTime / SECONDS_IN_MINUTE > 0)
	{
		if (Before)
			wprintf_s(_T(" "));
		wprintf_s(_T("%u minute"), (UINT)(DateTime / SECONDS_IN_MINUTE));
		if (DateTime / SECONDS_IN_MINUTE > 1U)
			wprintf_s(_T("s"));
		DateTime %= SECONDS_IN_MINUTE;
		Before = true;
	}
//Seconds
	if (DateTime > 0)
	{
		if (Before)
			wprintf_s(_T(" "));
		wprintf_s(_T("%u second"), (UINT)(DateTime));
		if (DateTime > 1U)
			wprintf_s(_T("s"));
	}

	wprintf_s(_T("))"));
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
	auto DateTime = Seconds;
	fwprintf_s(OutputFile, _T("("));

//Years
	if (DateTime / SECONDS_IN_YEAR > 0)
	{
		fwprintf_s(OutputFile, _T("%u year"), (UINT)(DateTime / SECONDS_IN_YEAR));
		if (DateTime / SECONDS_IN_YEAR > 1U)
			fwprintf_s(OutputFile, _T("s"));
		DateTime %= SECONDS_IN_YEAR;
		Before = true;
	}
//Months
	if (DateTime / SECONDS_IN_MONTH > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, _T(" "));
		fwprintf_s(OutputFile, _T("%u month"), (UINT)(DateTime / SECONDS_IN_MONTH));
		if (DateTime / SECONDS_IN_MONTH > 1U)
			fwprintf_s(OutputFile, _T("s"));
		DateTime %= SECONDS_IN_MONTH;
		Before = true;
	}
//Days
	if (DateTime / SECONDS_IN_DAY > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, _T(" "));
		fwprintf_s(OutputFile, _T("%u day"), (UINT)(DateTime / SECONDS_IN_DAY));
		if (DateTime / SECONDS_IN_DAY > 1U)
			fwprintf_s(OutputFile, _T("s"));
		DateTime %= SECONDS_IN_DAY;
		Before = true;
	}
//Hours
	if (DateTime / SECONDS_IN_HOUR > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, _T(" "));
		fwprintf_s(OutputFile, _T("%u hour"), (UINT)(DateTime / SECONDS_IN_HOUR));
		if (DateTime / SECONDS_IN_HOUR > 1U)
			fwprintf_s(OutputFile, _T("s"));
		DateTime %= SECONDS_IN_HOUR;
		Before = true;
	}
//Minutes
	if (DateTime / SECONDS_IN_MINUTE > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, _T(" "));
		fwprintf_s(OutputFile, _T("%u minute"), (UINT)(DateTime / SECONDS_IN_MINUTE));
		if (DateTime / SECONDS_IN_MINUTE > 1U)
			fwprintf_s(OutputFile, _T("s"));
		DateTime %= SECONDS_IN_MINUTE;
		Before = true;
	}
//Seconds
	if (DateTime > 0)
	{
		if (Before)
			fwprintf_s(OutputFile, _T(" "));
		fwprintf_s(OutputFile, _T("%u second"), (UINT)(DateTime));
		if (DateTime > 1U)
			fwprintf_s(OutputFile, _T("s"));
	}

	fwprintf_s(OutputFile, _T("))"));
	return;
}

//Print Date and Time with UNIX time
void __fastcall PrintDateTime(const time_t Time)
{
	std::shared_ptr<tm> TimeStructure(new tm());
	localtime_s(TimeStructure.get(), &Time);
	wprintf_s(_T("%d-%02d-%02d %02d:%02d:%02d"), TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);

	return;
}

//Print Date and Time with UNIX time to file
void __fastcall PrintDateTime(const time_t Time, FILE *OutputFile)
{
	std::shared_ptr<tm> TimeStructure(new tm());
	localtime_s(TimeStructure.get(), &Time);
	fwprintf_s(OutputFile, _T("%d-%02d-%02d %02d:%02d:%02d"), TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);

	return;
}
