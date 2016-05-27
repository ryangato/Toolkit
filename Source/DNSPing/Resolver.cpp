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


#include "Resolver.h"

//Print response hex format data
void __fastcall PrintResponseHex(
	const char *Buffer, 
	const size_t Length, 
	FILE *FileHandle)
{
//Initialization and print header.
	size_t Index = 0;
	fwprintf_s(FileHandle, L"------------------------------ Response Hex ------------------------------\n");

//Print hex format data(Part 1).
	for (Index = 0;Index < Length;++Index)
	{
		if (Index == 0)
		{
			fwprintf_s(FileHandle, L"0000  %02x ", (UCHAR)Buffer[Index]);
		}
		else if (Index % NUM_HEX + 1U == NUM_HEX)
		{
			fwprintf_s(FileHandle, L"%02x   ", (UCHAR)Buffer[Index]);
			for (size_t InnerIndex = Index - (NUM_HEX - 1U);InnerIndex < Index + 1U;++InnerIndex)
			{
				if (InnerIndex != Index - (NUM_HEX - 1U) && InnerIndex % (NUM_HEX / 2U) == 0)
					fwprintf_s(FileHandle, L" ");
				if ((UCHAR)Buffer[InnerIndex] >= ASCII_SPACE && (UCHAR)Buffer[InnerIndex] <= ASCII_TILDE)
					fwprintf_s(FileHandle, L"%c", (UCHAR)Buffer[InnerIndex]);
				else
					fwprintf_s(FileHandle, L".");
			}
			if (Index + 1U < Length)
			{
				fwprintf_s(FileHandle, L"\n%04x  ", (UINT)(Index + 1U));
			}
		}
		else {
			if (Index % (NUM_HEX / 2U) == 0 && Index % NUM_HEX != 0)
				fwprintf_s(FileHandle, L" ");
			fwprintf_s(FileHandle, L"%02x ", (UCHAR)Buffer[Index]);
		}
	}

//Print spaces.
	if (NUM_HEX - Length % NUM_HEX < NUM_HEX)
	{
		for (Index = 0;Index < NUM_HEX - Length % NUM_HEX;++Index)
			fwprintf_s(FileHandle, L"   ");
	}

//Print hex format data(Part 2).
	if (Length % NUM_HEX > 0)
	{
		fwprintf_s(FileHandle, L"   ");
		for (Index = Length - Length % NUM_HEX;Index < Length;++Index)
		{
			if ((UCHAR)Buffer[Index] >= ASCII_SPACE && (UCHAR)Buffer[Index] <= ASCII_TILDE)
				fwprintf_s(FileHandle, L"%c", (UCHAR)Buffer[Index]);
			else
				fwprintf_s(FileHandle, L".");
		}
	}
	fwprintf_s(FileHandle, L"\n");

//End.
	fwprintf_s(FileHandle, L"------------------------------ Response Hex ------------------------------\n");
	return;
}

//Print response result or data to file
void __fastcall PrintResponse(
	const char *Buffer, 
	const size_t Length, 
	FILE *FileHandle)
{
//Initialization and print header.
	size_t Index = 0, CurrentLength = sizeof(dns_hdr);
	auto pdns_hdr = (dns_hdr *)Buffer;
	fwprintf_s(FileHandle, L"-------------------------------- Response --------------------------------\n");

//Print DNS header.
	fwprintf_s(FileHandle, L"ID: 0x%04x\n", ntohs(pdns_hdr->ID));
	fwprintf_s(FileHandle, L"Flags: 0x%04x", ntohs(pdns_hdr->Flags));
	PrintFlags(pdns_hdr->Flags, FileHandle);
	fwprintf_s(FileHandle, L"Questions RR Count: %u\n", ntohs(pdns_hdr->Questions));
	fwprintf_s(FileHandle, L"Answer RR Count: %u\n", ntohs(pdns_hdr->Answer));
	fwprintf_s(FileHandle, L"Authority RR Count: %u\n", ntohs(pdns_hdr->Authority));
	fwprintf_s(FileHandle, L"Additional RR Count: %u\n", ntohs(pdns_hdr->Additional));

//Print Questions RRs.
	if (ntohs(pdns_hdr->Questions) > 0)
	{
		fwprintf_s(FileHandle, L"Questions RR:\n   Name: ");
		dns_qry *pdns_qry = nullptr;
		for (Index = 0;Index < ntohs(pdns_hdr->Questions);++Index)
		{
		//Print Name.
			PrintDomainName(Buffer, CurrentLength, FileHandle);
			fwprintf_s(FileHandle, L"\n");
			CurrentLength += strnlen_s(Buffer + CurrentLength, Length - CurrentLength) + 1U;

		//Print Type and Classes.
			pdns_qry = (dns_qry *)(Buffer + CurrentLength);
			fwprintf_s(FileHandle, L"   Type: 0x%04x", ntohs(pdns_qry->Type));
			PrintTypeClassesName(pdns_qry->Type, 0, FileHandle);
			fwprintf_s(FileHandle, L"   Classes: 0x%04x", ntohs(pdns_qry->Classes));
			PrintTypeClassesName(0, pdns_qry->Classes, FileHandle);
			CurrentLength += sizeof(dns_qry);
		}
	}

//Print Answer RRs.
	dns_standard_record *pdns_standard_record = nullptr;
	if (ntohs(pdns_hdr->Answer) > 0)
	{
		fwprintf_s(FileHandle, L"Answer RR:\n");
		for (Index = 0;Index < ntohs(pdns_hdr->Answer);++Index)
		{
		//Print Name.
			fwprintf_s(FileHandle, L" RR(%u)\n   Name: ", (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, FileHandle);
			fwprintf_s(FileHandle, L"\n");

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(FileHandle, L"   Type: 0x%04x", ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, FileHandle);
			fwprintf_s(FileHandle, L"   Classes: 0x%04x", ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes, FileHandle);
			fwprintf_s(FileHandle, L"   TTL: %u", ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL), FileHandle);
			fwprintf_s(FileHandle, L"\n");
			fwprintf_s(FileHandle, L"   Length: %u", ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, FileHandle);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Authority RR.
	if (ntohs(pdns_hdr->Authority) > 0)
	{
		fwprintf_s(FileHandle, L"Authority RR:\n");
		for (Index = 0;Index < ntohs(pdns_hdr->Authority);++Index)
		{
		//Print Name.
			fwprintf_s(FileHandle, L" RR(%u)\n   Name: ", (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, FileHandle);
			fwprintf_s(FileHandle, L"\n");

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(FileHandle, L"   Type: 0x%04x", ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, FileHandle);
			fwprintf_s(FileHandle, L"   Classes: 0x%04x", ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes, FileHandle);
			fwprintf_s(FileHandle, L"   TTL: %u", ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL), FileHandle);
			fwprintf_s(FileHandle, L"\n");
			fwprintf_s(FileHandle, L"   Length: %u", ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, FileHandle);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Additional RR.
	if (ntohs(pdns_hdr->Additional) > 0)
	{
		fwprintf_s(FileHandle, L"Additional RR:\n");
		for (Index = 0;Index < ntohs(pdns_hdr->Additional);++Index)
		{
		//Print Name.
			fwprintf_s(FileHandle, L" RR(%u)\n   Name: ", (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, FileHandle);
			fwprintf_s(FileHandle, L"\n");

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(FileHandle, L"   Type: 0x%04x", ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, FileHandle);
			if (pdns_standard_record->Type == htons(DNS_RECORD_OPT)) //EDNS Label
			{
				PrintResourseData(Buffer, CurrentLength - 1U, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, FileHandle);
				CurrentLength += sizeof(dns_standard_record) + ntohs(pdns_standard_record->Length);
			}
			else {
				fwprintf_s(FileHandle, L"   Classes: 0x%04x", ntohs(pdns_standard_record->Classes));
				PrintTypeClassesName(0, pdns_standard_record->Classes, FileHandle);
				fwprintf_s(FileHandle, L"   TTL: %u", ntohl(pdns_standard_record->TTL));
				PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL), FileHandle);
				fwprintf_s(FileHandle, L"\n");
				fwprintf_s(FileHandle, L"   Length: %u", ntohs(pdns_standard_record->Length));
				CurrentLength += sizeof(dns_standard_record);
				PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, FileHandle);
				CurrentLength += ntohs(pdns_standard_record->Length);
			}
		}
	}

//End.
	fwprintf_s(FileHandle, L"-------------------------------- Response --------------------------------\n");
	return;
}

//Print Header Flags to file
void __fastcall PrintFlags(
	const uint16_t Flags, 
	FILE *FileHandle)
{
//Print Flags
	if (Flags > 0)
	{
		auto FlagsBits = ntohs(Flags);

	//Print OPCode
		fwprintf_s(FileHandle, L"(OPCode: ");
		FlagsBits = FlagsBits & HIGHEST_BIT_U16;
		FlagsBits = FlagsBits >> 11U;
		if (FlagsBits == DNS_OPCODE_QUERY)
			fwprintf_s(FileHandle, L"Query");
		else if (FlagsBits == DNS_OPCODE_IQUERY)
			fwprintf_s(FileHandle, L"Inverse Query");
		else if (FlagsBits == DNS_OPCODE_STATUS)
			fwprintf_s(FileHandle, L"Status");
		else if (FlagsBits == DNS_OPCODE_NOTIFY)
			fwprintf_s(FileHandle, L"Notify");
		else if (FlagsBits == DNS_OPCODE_UPDATE)
			fwprintf_s(FileHandle, L"Update");
		else
			fwprintf_s(FileHandle, L"%x", FlagsBits);

	//Print RCode.
		fwprintf_s(FileHandle, L"/RCode: ");
		FlagsBits = ntohs(Flags);
		FlagsBits = FlagsBits & UINT4_MAX;
		if (FlagsBits == DNS_RCODE_NOERROR)
			fwprintf_s(FileHandle, L"No Error");
		else if (FlagsBits == DNS_RCODE_FORMERR)
			fwprintf_s(FileHandle, L"Format Error");
		else if (FlagsBits == DNS_RCODE_SERVFAIL)
			fwprintf_s(FileHandle, L"Server Failure");
		else if (FlagsBits == DNS_RCODE_NXDOMAIN)
			fwprintf_s(FileHandle, L"Non-Existent Domain");
		else if (FlagsBits == DNS_RCODE_NOTIMP)
			fwprintf_s(FileHandle, L"Not Implemented");
		else if (FlagsBits == DNS_RCODE_REFUSED)
			fwprintf_s(FileHandle, L"Query Refused");
		else if (FlagsBits == DNS_RCODE_YXDOMAIN)
			fwprintf_s(FileHandle, L"Name Exists when it should not");
		else if (FlagsBits == DNS_RCODE_YXRRSET)
			fwprintf_s(FileHandle, L"RR Set Exists when it should not");
		else if (FlagsBits == DNS_RCODE_NXRRSET)
			fwprintf_s(FileHandle, L"RR Set that should exist does not");
		else if (FlagsBits == DNS_RCODE_NOTAUTH)
			fwprintf_s(FileHandle, L"Server Not Authoritative for zone/Not Authorized");
		else if (FlagsBits == DNS_RCODE_NOTZONE)
			fwprintf_s(FileHandle, L"Name not contained in zone");
		else if (FlagsBits == DNS_RCODE_BADVERS)
			fwprintf_s(FileHandle, L"Bad OPT Version/TSIG Signature Failure");
		else if (FlagsBits == DNS_RCODE_BADKEY)
			fwprintf_s(FileHandle, L"Key not recognized");
		else if (FlagsBits == DNS_RCODE_BADTIME)
			fwprintf_s(FileHandle, L"Signature out of time window");
		else if (FlagsBits == DNS_RCODE_BADMODE)
			fwprintf_s(FileHandle, L"Bad TKEY Mode");
		else if (FlagsBits == DNS_RCODE_BADNAME)
			fwprintf_s(FileHandle, L"Duplicate key name");
		else if (FlagsBits == DNS_RCODE_BADALG)
			fwprintf_s(FileHandle, L"Algorithm not supported");
		else if (FlagsBits == DNS_RCODE_BADTRUNC)
			fwprintf_s(FileHandle, L"Bad Truncation");
		else if (FlagsBits >= DNS_RCODE_PRIVATE_A && FlagsBits <= DNS_RCODE_PRIVATE_B)
			fwprintf_s(FileHandle, L"Reserved Private use");
		else if (FlagsBits == DNS_OPCODE_RESERVED)
			fwprintf_s(FileHandle, L"Reserved");
		else
			fwprintf_s(FileHandle, L"%x", FlagsBits);
		fwprintf_s(FileHandle, L")");
	}

	fwprintf_s(FileHandle, L"\n");
	return;
}

//Print Type and Classes name to file
void __fastcall PrintTypeClassesName(
	const uint16_t Type, 
	const uint16_t Classes, 
	FILE *FileHandle)
{
//Print Classes.
	if (Classes > 0)
	{
	//Cache flush check
		auto HighBitSet = false;
		auto ClassesTemp = ntohs(Classes);
		if (ClassesTemp >> HIGHEST_MOVE_BIT_U16 > 0)
		{
			HighBitSet = true;
			ClassesTemp = ntohs(Classes);
			ClassesTemp = ClassesTemp & HIGHEST_BIT_U16;
		}

	//Classes check
		if (ClassesTemp == DNS_CLASS_IN)
		{
			fwprintf_s(FileHandle, L"(Class IN");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_CSNET)
		{
			fwprintf_s(FileHandle, L"(Class CSNET");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_CHAOS)
		{
			fwprintf_s(FileHandle, L"(Class CHAOS");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_HESIOD)
		{
			fwprintf_s(FileHandle, L"(Class HESIOD");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_NONE)
		{
			fwprintf_s(FileHandle, L"(Class NONE");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_ALL)
		{
			fwprintf_s(FileHandle, L"(Class ALL");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
		else if (ClassesTemp == DNS_CLASS_ANY)
		{
			fwprintf_s(FileHandle, L"(Class ANY");
			if (HighBitSet)
				fwprintf_s(FileHandle, L"/Unicast Queries or Cache Flush");
			fwprintf_s(FileHandle, L")");
		}
	}
//Print Type.
	else {
		if (Type == htons(DNS_RECORD_A))
			fwprintf_s(FileHandle, L"(A Record)");
		else if (Type == htons(DNS_RECORD_NS))
			fwprintf_s(FileHandle, L"(NS Record)");
		else if (Type == htons(DNS_RECORD_MD))
			fwprintf_s(FileHandle, L"(MD Record)");
		else if (Type == htons(DNS_RECORD_MF))
			fwprintf_s(FileHandle, L"(MF Record)");
		else if (Type == htons(DNS_RECORD_CNAME))
			fwprintf_s(FileHandle, L"(CNAME Record)");
		else if (Type == htons(DNS_RECORD_SOA))
			fwprintf_s(FileHandle, L"(SOA Record)");
		else if (Type == htons(DNS_RECORD_MB))
			fwprintf_s(FileHandle, L"(MB Record)");
		else if (Type == htons(DNS_RECORD_MG))
			fwprintf_s(FileHandle, L"(MG Record)");
		else if (Type == htons(DNS_RECORD_MR))
			fwprintf_s(FileHandle, L"(MR Record)");
		else if (Type == htons(DNS_RECORD_NULL))
			fwprintf_s(FileHandle, L"(NULL Record)");
		else if (Type == htons(DNS_RECORD_WKS))
			fwprintf_s(FileHandle, L"(WKS Record)");
		else if (Type == htons(DNS_RECORD_PTR))
			fwprintf_s(FileHandle, L"(PTR Record)");
		else if (Type == htons(DNS_RECORD_HINFO))
			fwprintf_s(FileHandle, L"(HINFO Record)");
		else if (Type == htons(DNS_RECORD_MINFO))
			fwprintf_s(FileHandle, L"(MINFO Record)");
		else if (Type == htons(DNS_RECORD_MX))
			fwprintf_s(FileHandle, L"(MX Record)");
		else if (Type == htons(DNS_RECORD_TXT))
			fwprintf_s(FileHandle, L"(TXT Record)");
		else if (Type == htons(DNS_RECORD_RP))
			fwprintf_s(FileHandle, L"(RP Record)");
		else if (Type == htons(DNS_RECORD_RP))
			fwprintf_s(FileHandle, L"(RP Record)");
		else if (Type == htons(DNS_RECORD_AFSDB))
			fwprintf_s(FileHandle, L"(AFSDB Record)");
		else if (Type == htons(DNS_RECORD_X25))
			fwprintf_s(FileHandle, L"(X25 Record)");
		else if (Type == htons(DNS_RECORD_ISDN))
			fwprintf_s(FileHandle, L"(ISDN Record)");
		else if (Type == htons(DNS_RECORD_RT))
			fwprintf_s(FileHandle, L"(RT Record)");
		else if (Type == htons(DNS_RECORD_NSAP))
			fwprintf_s(FileHandle, L"(NSAP Record)");
		else if (Type == htons(DNS_RECORD_NSAP_PTR))
			fwprintf_s(FileHandle, L"(NSAP PTR Record)");
		else if (Type == htons(DNS_RECORD_SIG))
			fwprintf_s(FileHandle, L"(SIG Record)");
		else if (Type == htons(DNS_RECORD_KEY))
			fwprintf_s(FileHandle, L"(KEY Record)");
		else if (Type == htons(DNS_RECORD_PX))
			fwprintf_s(FileHandle, L"(PX Record)");
		else if (Type == htons(DNS_RECORD_GPOS))
			fwprintf_s(FileHandle, L"(GPOS Record)");
		else if (Type == htons(DNS_RECORD_AAAA))
			fwprintf_s(FileHandle, L"(AAAA Record)");
		else if (Type == htons(DNS_RECORD_LOC))
			fwprintf_s(FileHandle, L"(LOC Record)");
		else if (Type == htons(DNS_RECORD_NXT))
			fwprintf_s(FileHandle, L"(NXT Record)");
		else if (Type == htons(DNS_RECORD_EID))
			fwprintf_s(FileHandle, L"(EID Record)");
		else if (Type == htons(DNS_RECORD_NIMLOC))
			fwprintf_s(FileHandle, L"(NIMLOC Record)");
		else if (Type == htons(DNS_RECORD_SRV))
			fwprintf_s(FileHandle, L"(SRV Record)");
		else if (Type == htons(DNS_RECORD_ATMA))
			fwprintf_s(FileHandle, L"(ATMA Record)");
		else if (Type == htons(DNS_RECORD_NAPTR))
			fwprintf_s(FileHandle, L"(NAPTR Record)");
		else if (Type == htons(DNS_RECORD_KX))
			fwprintf_s(FileHandle, L"(KX Record)");
		else if (Type == htons(DNS_RECORD_CERT))
			fwprintf_s(FileHandle, L"(CERT Record)");
		else if (Type == htons(DNS_RECORD_DNAME))
			fwprintf_s(FileHandle, L"(DNAME Record)");
		else if (Type == htons(DNS_RECORD_SINK))
			fwprintf_s(FileHandle, L"(SINK Record)");
		else if (Type == htons(DNS_RECORD_OPT))
			fwprintf_s(FileHandle, L"(OPT/EDNS Record)");
		else if (Type == htons(DNS_RECORD_APL))
			fwprintf_s(FileHandle, L"(APL Record)");
		else if (Type == htons(DNS_RECORD_DS))
			fwprintf_s(FileHandle, L"(DS Record)");
		else if (Type == htons(DNS_RECORD_SSHFP))
			fwprintf_s(FileHandle, L"(SSHFP Record)");
		else if (Type == htons(DNS_RECORD_IPSECKEY))
			fwprintf_s(FileHandle, L"(IPSECKEY Record)");
		else if (Type == htons(DNS_RECORD_RRSIG))
			fwprintf_s(FileHandle, L"(RRSIG Record)");
		else if (Type == htons(DNS_RECORD_NSEC))
			fwprintf_s(FileHandle, L"(NSEC Record)");
		else if (Type == htons(DNS_RECORD_DNSKEY))
			fwprintf_s(FileHandle, L"(DNSKEY Record)");
		else if (Type == htons(DNS_RECORD_DHCID))
			fwprintf_s(FileHandle, L"(DHCID Record)");
		else if (Type == htons(DNS_RECORD_NSEC3))
			fwprintf_s(FileHandle, L"(NSEC3 Record)");
		else if (Type == htons(DNS_RECORD_NSEC3PARAM))
			fwprintf_s(FileHandle, L"(NSEC3PARAM Record)");
		else if (Type == htons(DNS_RECORD_TLSA))
			fwprintf_s(FileHandle, L"(TLSA Record)");
		else if (Type == htons(DNS_RECORD_HIP))
			fwprintf_s(FileHandle, L"(HIP Record)");
		else if (Type == htons(DNS_RECORD_NINFO))
			fwprintf_s(FileHandle, L"(NINFO Record)");
		else if (Type == htons(DNS_RECORD_RKEY))
			fwprintf_s(FileHandle, L"(RKEY Record)");
		else if (Type == htons(DNS_RECORD_TALINK))
			fwprintf_s(FileHandle, L"(TALINK Record)");
		else if (Type == htons(DNS_RECORD_CDS))
			fwprintf_s(FileHandle, L"(CDS Record)");
		else if (Type == htons(DNS_RECORD_CDNSKEY))
			fwprintf_s(FileHandle, L"(CDNSKEY Record)");
		else if (Type == htons(DNS_RECORD_OPENPGPKEY))
			fwprintf_s(FileHandle, L"(OPENPGPKEY Record)");
		else if (Type == htons(DNS_RECORD_SPF))
			fwprintf_s(FileHandle, L"(SPF Record)");
		else if (Type == htons(DNS_RECORD_UID))
			fwprintf_s(FileHandle, L"(UID Record)");
		else if (Type == htons(DNS_RECORD_GID))
			fwprintf_s(FileHandle, L"(GID Record)");
		else if (Type == htons(DNS_RECORD_UNSPEC))
			fwprintf_s(FileHandle, L"(UNSPEC Record)");
		else if (Type == htons(DNS_RECORD_NID))
			fwprintf_s(FileHandle, L"(NID Record)");
		else if (Type == htons(DNS_RECORD_L32))
			fwprintf_s(FileHandle, L"(L32 Record)");
		else if (Type == htons(DNS_RECORD_L64))
			fwprintf_s(FileHandle, L"(L64 Record)");
		else if (Type == htons(DNS_RECORD_LP))
			fwprintf_s(FileHandle, L"(LP Record)");
		else if (Type == htons(DNS_RECORD_EUI48))
			fwprintf_s(FileHandle, L"(EUI48 Record)");
		else if (Type == htons(DNS_RECORD_EUI64))
			fwprintf_s(FileHandle, L"(EUI64 Record)");
		else if (Type == htons(DNS_RECORD_TKEY))
			fwprintf_s(FileHandle, L"(TKEY Record)");
		else if (Type == htons(DNS_RECORD_TSIG))
			fwprintf_s(FileHandle, L"(TSIG Record)");
		else if (Type == htons(DNS_RECORD_IXFR))
			fwprintf_s(FileHandle, L"(IXFR Record)");
		else if (Type == htons(DNS_RECORD_AXFR))
			fwprintf_s(FileHandle, L"(AXFR Record)");
		else if (Type == htons(DNS_RECORD_MAILB))
			fwprintf_s(FileHandle, L"(MAILB Record)");
		else if (Type == htons(DNS_RECORD_MAILA))
			fwprintf_s(FileHandle, L"(MAILA Record)");
		else if (Type == htons(DNS_RECORD_ANY))
			fwprintf_s(FileHandle, L"(ANY Record)");
		else if (Type == htons(DNS_RECORD_URI))
			fwprintf_s(FileHandle, L"(URI Record)");
		else if (Type == htons(DNS_RECORD_CAA))
			fwprintf_s(FileHandle, L"(CAA Record)");
		else if (Type == htons(DNS_RECORD_TA))
			fwprintf_s(FileHandle, L"(TA Record)");
		else if (Type == htons(DNS_RECORD_DLV))
			fwprintf_s(FileHandle, L"(DLV Record)");
		else if (ntohs(Type) >= DNS_RECORD_PRIVATE_A && ntohs(Type) <= DNS_RECORD_PRIVATE_B)
			fwprintf_s(FileHandle, L"(Reserved Private use Record)");
		else if (Type == htons(DNS_RECORD_RESERVED))
			fwprintf_s(FileHandle, L"(Reserved Record)");
	}

	fwprintf_s(FileHandle, L"\n");
	return;
}

//Print Domain Name in response to file
size_t __fastcall PrintDomainName(
	const char *Buffer, 
	const size_t Location, 
	FILE *FileHandle)
{
//Root check
	if (Buffer[Location] == 0)
	{
		fwprintf_s(FileHandle, L"<Root>");
		return sizeof(char);
	}

//Initialization
	std::shared_ptr<char> BufferTemp(new char[PACKET_MAXSIZE]());
	memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
	size_t Index = 0, Result = 0;
	uint16_t Truncated = 0;
	auto MultiplePTR = false;

//Convert.
	Result = DNSQueryToChar(Buffer + Location, BufferTemp.get(), Truncated);
	if (Truncated > 0)
	{
	//Print once when pointer is not at first.
		if (Result > sizeof(uint16_t))
		{
			for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
				fwprintf_s(FileHandle, L"%c", BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			fwprintf_s(FileHandle, L".");
		}

	//Get pointer.
		while (Truncated > 0)
		{
			if (MultiplePTR)
				fwprintf_s(FileHandle, L".");
			DNSQueryToChar(Buffer + Truncated, BufferTemp.get(), Truncated);
			for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
				fwprintf_s(FileHandle, L"%c", BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			MultiplePTR = true;
		}
	}
	else {
		++Result;
	}

//Print last.
	for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
		fwprintf_s(FileHandle, L"%c", BufferTemp.get()[Index]);
	return Result;
}

//Print Resourse data to file
void __fastcall PrintResourseData(
	const char *Buffer, 
	const size_t Location, 
	const uint16_t Length, 
	const uint16_t Type, 
	const uint16_t Classes, 
	FILE *FileHandle)
{
//Length and Type check
	if ((Length == 0 && Type != htons(DNS_RECORD_OPT)) || Classes == 0)
		return;
	size_t Index = 0, CurrentLength = 0;

//A Record(IPv4 address)
	if (Type == htons(DNS_RECORD_A) && Length == sizeof(in_addr))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");
		auto Addr = (in_addr *)(Buffer + Location);
		fwprintf_s(FileHandle, L"%u.%u.%u.%u", Addr->s_net, Addr->s_host, Addr->s_lh, Addr->s_impno);
	}
//NS Record(Authoritative Name Server) and CNAME Record(Canonical Name)
	else if (Type == htons(DNS_RECORD_NS) || Type == htons(DNS_RECORD_CNAME))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");
		PrintDomainName(Buffer, Location, FileHandle);
	}
//SOA Record(Start Of a zone of Authority)
	else if (Type == htons(DNS_RECORD_SOA))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		fwprintf_s(FileHandle, L"Primary Name Server: ");
		CurrentLength = PrintDomainName(Buffer, Location, FileHandle);
		fwprintf_s(FileHandle, L"\n         Responsible authority's mailbox: ");
		CurrentLength += PrintDomainName(Buffer, Location + CurrentLength, FileHandle);
		auto pdns_soa_record = (dns_soa_record *)(Buffer + Location + CurrentLength);
		fwprintf_s(FileHandle, L"\n         Serial Number: %u", ntohl(pdns_soa_record->Serial));
		fwprintf_s(FileHandle, L"\n         Refresh Interval: %u", ntohl(pdns_soa_record->RefreshInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RefreshInterval), FileHandle);
		fwprintf_s(FileHandle, L"\n         Retry Interval: %u", ntohl(pdns_soa_record->RetryInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RetryInterval), FileHandle);
		fwprintf_s(FileHandle, L"\n         Expire Limit: %u", ntohl(pdns_soa_record->ExpireLimit));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->ExpireLimit), FileHandle);
		fwprintf_s(FileHandle, L"\n         Minimum TTL: %u", ntohl(pdns_soa_record->MinimumTTL));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->MinimumTTL), FileHandle);
	}
//PTR Record(domain name PoinTeR)
	else if (Type == htons(DNS_RECORD_PTR))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");
		PrintDomainName(Buffer, Location, FileHandle);
	}
//MX Record(Mail eXchange)
	else if (Type == htons(DNS_RECORD_MX))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		auto pdns_mx_record = (dns_mx_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"Preference: %u", ntohs(pdns_mx_record->Preference));
		fwprintf_s(FileHandle, L"\n         Mail Exchange: ");
		PrintDomainName(Buffer, Location + sizeof(dns_mx_record), FileHandle);
	}
//TXT Record(Text strings)
	else if (Type == htons(DNS_RECORD_TXT))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		auto pdns_txt_record = (dns_txt_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"Length: %u", pdns_txt_record->Length);
		fwprintf_s(FileHandle, L"\n         TXT: \"");
		for (Index = Location + sizeof(dns_txt_record);Index < Location + Length;++Index)
			fwprintf_s(FileHandle, L"%c", Buffer[Index]);
		fwprintf_s(FileHandle, L"\"");
	}
//AAAA Record(IPv6 address)
	else if (Type == htons(DNS_RECORD_AAAA) && Length == sizeof(in6_addr))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		char BufferTemp[ADDR_STRING_MAXSIZE];
		memset(BufferTemp, 0, ADDR_STRING_MAXSIZE);
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		DWORD BufferLength = ADDR_STRING_MAXSIZE;
		sockaddr_storage SockAddr;
		memset(&SockAddr, 0, sizeof(sockaddr_storage));
		SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = *(in6_addr *)(Buffer + Location);
		WSAAddressToStringA((PSOCKADDR)&SockAddr, sizeof(sockaddr_in6), nullptr, BufferTemp, &BufferLength);
	#else
		inet_ntop(AF_INET6, (char *)(Buffer + Location), BufferTemp, ADDR_STRING_MAXSIZE);
	#endif
		CaseConvert(true, BufferTemp, strnlen_s(BufferTemp, ADDR_STRING_MAXSIZE));

		for (Index = 0;Index < strnlen_s(BufferTemp, ADDR_STRING_MAXSIZE);++Index)
			fwprintf_s(FileHandle, L"%c", BufferTemp[Index]);
	}
//SRV Record(Server Selection)
	else if (Type == htons(DNS_RECORD_SRV))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		auto pdns_srv_record = (dns_srv_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"Priority: %x", ntohs(pdns_srv_record->Priority));
		fwprintf_s(FileHandle, L"\n         Weight: %u", ntohs(pdns_srv_record->Weight));
		fwprintf_s(FileHandle, L"\n         Port: %u", ntohs(pdns_srv_record->Port));
		fwprintf_s(FileHandle, L"\n         Target: ");
		PrintDomainName(Buffer, Location + sizeof(dns_srv_record), FileHandle);
	}
//OPT/EDNS Record(Extension Mechanisms for Domain Name System)
	else if (Type == htons(DNS_RECORD_OPT))
	{
		fwprintf_s(FileHandle, L"   Data: ");

		auto pdns_opt_record = (dns_opt_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"UDP Playload Size: %u", ntohs(pdns_opt_record->UDPPayloadSize));
		fwprintf_s(FileHandle, L"\n         Extended RCode: %x", pdns_opt_record->Extended_RCode);
		fwprintf_s(FileHandle, L"\n         EDNS Version: %u", pdns_opt_record->Version);
		if (ntohs(pdns_opt_record->Z_Field) >> HIGHEST_MOVE_BIT_U16 == 0)
			fwprintf_s(FileHandle, L"\n         Server cannot handle DNSSEC security RRs.");
		else
			fwprintf_s(FileHandle, L"\n         Server can handle DNSSEC security RRs.");

	//EDNS Option
		if (Length >= sizeof(dns_edns0_option))
		{
			auto pdns_edns0_option = (dns_edns0_option *)(Buffer + Location + sizeof(dns_opt_record));
			fwprintf_s(FileHandle, L"\n         EDNS Option:\n                         Code: ");
			if (pdns_edns0_option->Code == htons(EDNS0_CODE_LLQ))
				fwprintf_s(FileHandle, L"LLQ");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_UL))
				fwprintf_s(FileHandle, L"LLQ");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_NSID))
				fwprintf_s(FileHandle, L"");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_OWNER))
				fwprintf_s(FileHandle, L"OWNER");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DAU))
				fwprintf_s(FileHandle, L"DAU");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DHU))
				fwprintf_s(FileHandle, L"DHU");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_N3U))
				fwprintf_s(FileHandle, L"N3U");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET))
				fwprintf_s(FileHandle, L"CLIENT_SUBNET");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_EDNS_EXPIRE))
				fwprintf_s(FileHandle, L"EDNS_EXPIRE");
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET_EXP))
				fwprintf_s(FileHandle, L"CLIENT_SUBNET_EXP");
			else
				fwprintf_s(FileHandle, L"%x", ntohs(pdns_edns0_option->Code));
			fwprintf_s(FileHandle, L"\n                         Length: %x", ntohs(pdns_edns0_option->Length));
		}
	}
//RRSIG Record(Resource Record digital SIGnature)
	else if (Type == htons(DNS_RECORD_RRSIG))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		auto pdns_rrsig_record = (dns_rrsig_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"Type Covered: 0x%04x", ntohs(pdns_rrsig_record->TypeCovered));
		PrintTypeClassesName(pdns_rrsig_record->TypeCovered, 0, FileHandle);
		fwprintf_s(FileHandle, L"         Algorithm: ");
		if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_MD5)
			fwprintf_s(FileHandle, L"RSA/MD5");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DH)
			fwprintf_s(FileHandle, L"DH");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA)
			fwprintf_s(FileHandle, L"DSA");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC)
			fwprintf_s(FileHandle, L"ECC");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1)
			fwprintf_s(FileHandle, L"RSA/SHA-1");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA_NSEC3_SHA1)
			fwprintf_s(FileHandle, L"DSA/NSEC3/SHA-1");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1)
			fwprintf_s(FileHandle, L"RSA/SHA-1/NSEC3/SHA-1");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA256)
			fwprintf_s(FileHandle, L"RSA/SHA-256");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA512)
			fwprintf_s(FileHandle, L"RSA/SHA-512");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC_GOST)
			fwprintf_s(FileHandle, L"ECC/GOST");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P256_SHA256)
			fwprintf_s(FileHandle, L"ECDSA P256/SHA-256");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P386_SHA386)
			fwprintf_s(FileHandle, L"ECDSA P386/SHA-386");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_HMAC_MD5)
			fwprintf_s(FileHandle, L"HMAC/MD5");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_INDIRECT)
			fwprintf_s(FileHandle, L"Indirect");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_DNS)
			fwprintf_s(FileHandle, L"Private DNS");
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_OID)
			fwprintf_s(FileHandle, L"Private OID");
		else 
			fwprintf_s(FileHandle, L"%u", pdns_rrsig_record->Algorithm);
		fwprintf_s(FileHandle, L"\n         Labels: %u", pdns_rrsig_record->Labels);
		fwprintf_s(FileHandle, L"\n         Original TTL: %u", ntohl(pdns_rrsig_record->TTL));
		PrintSecondsInDateTime(ntohl(pdns_rrsig_record->TTL), FileHandle);
		fwprintf_s(FileHandle, L"\n         Signature Expiration: ");
		PrintDateTime(ntohl(pdns_rrsig_record->Expiration), FileHandle);
		fwprintf_s(FileHandle, L"\n         Signature Inception: ");
		PrintDateTime(ntohl(pdns_rrsig_record->Inception), FileHandle);
		fwprintf_s(FileHandle, L"\n         Key Tag: %u", ntohs(pdns_rrsig_record->KeyTag));
		fwprintf_s(FileHandle, L"\n         Signer's name: ");
		CurrentLength = PrintDomainName(Buffer, Location + sizeof(dns_rrsig_record), FileHandle) + 1U;
		CurrentLength += sizeof(dns_rrsig_record);
		fwprintf_s(FileHandle, L"\n         Signature: ");
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			fwprintf_s(FileHandle, L"%02x", (UCHAR)Buffer[Index]);
	}
//NSEC Record(Next-SECure)
	else if (Type == htons(DNS_RECORD_NSEC))
	{
		fwprintf_s(FileHandle, L"\n   Data: ");

		fwprintf_s(FileHandle, L"Next Domain Name: ");
		CurrentLength = PrintDomainName(Buffer, Location, FileHandle);
		fwprintf_s(FileHandle, L"\n         List of Type Bit Map: ");
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			fwprintf_s(FileHandle, L"%x", (UCHAR)Buffer[Index]);
	}
//CAA Record(Certification Authority Authorization)
	else if (Type == htons(DNS_RECORD_CAA))
	{
		fwprintf_s(FileHandle, L"   Data: ");

		auto pdns_caa_record = (dns_caa_record *)(Buffer + Location);
		fwprintf_s(FileHandle, L"Flags: %x", pdns_caa_record->Flags);
		fwprintf_s(FileHandle, L"\n         Length: %u", pdns_caa_record->Length);
		fwprintf_s(FileHandle, L"\n         Tag: \"");
		for (Index = Location + sizeof(dns_caa_record);Index < Location + sizeof(dns_caa_record) + pdns_caa_record->Length;++Index)
			fwprintf_s(FileHandle, L"%c", Buffer[Index]);
		fwprintf_s(FileHandle, L"\"");
		fwprintf_s(FileHandle, L"\n         Value: \"");
		for (Index = Location + sizeof(dns_caa_record) + pdns_caa_record->Length;Index < Location + Length;++Index)
			fwprintf_s(FileHandle, L"%c", Buffer[Index]);
		fwprintf_s(FileHandle, L"\"");
	}

	fwprintf_s(FileHandle, L"\n");
	return;
}
