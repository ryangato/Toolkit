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


#include "Resolver.h"

//Print response hexs
void __fastcall PrintResponseHex(const PSTR Buffer, const size_t Length)
{
//Initialization
	size_t Index = 0;

//Start.
	wprintf_s(_T("------------------------------ Response Hex ------------------------------\n"));

//Print hexs.
	for (Index = 0;Index < Length;++Index)
	{
		if (Index == 0)
		{
			wprintf_s(_T("0000  %02x "), (UCHAR)Buffer[Index]);
		}
		else if (Index % NUM_HEX + 1U == NUM_HEX)
		{
			wprintf_s(_T("%02x   "), (UCHAR)Buffer[Index]);
			for (size_t InnerIndex = Index - (NUM_HEX - 1U);InnerIndex < Index + 1U;++InnerIndex)
			{
				if (InnerIndex != Index - (NUM_HEX - 1U) && InnerIndex % (NUM_HEX / 2U) == 0)
					wprintf_s(_T(" "));
				if ((UCHAR)Buffer[InnerIndex] >= ASCII_SPACE && (UCHAR)Buffer[InnerIndex] <= ASCII_TILDE)
					wprintf_s(_T("%c"), (UCHAR)Buffer[InnerIndex]);
				else 
					wprintf_s(_T("."));
			}
			if (Index + 1U < Length)
			{
				wprintf_s(_T("\n%04x  "), (UINT)(Index + 1U));
			}
		}
		else {
			if (Index % (NUM_HEX / 2U) == 0 && Index % NUM_HEX != 0)
				wprintf_s(_T(" "));
			wprintf_s(_T("%02x "), (UCHAR)Buffer[Index]);
		}
	}
	if (NUM_HEX - Length % NUM_HEX < NUM_HEX)
	{
		for (Index = 0;Index < NUM_HEX - Length % NUM_HEX;++Index)
			wprintf_s(_T("   "));
	}
	if (Length % NUM_HEX > 0)
	{
		wprintf_s(_T("   "));
		for (Index = Length - Length % NUM_HEX;Index < Length;++Index)
		{
			if ((UCHAR)Buffer[Index] >= ASCII_SPACE && (UCHAR)Buffer[Index] <= ASCII_TILDE)
				wprintf_s(_T("%c"), (UCHAR)Buffer[Index]);
			else
				wprintf_s(_T("."));
		}
	}
	wprintf_s(_T("\n"));

//End.
	wprintf_s(_T("------------------------------ Response Hex ------------------------------\n"));
	return;
}

//Print response hexs to file
void __fastcall PrintResponseHex(const PSTR Buffer, const size_t Length, FILE *OutputFile)
{
//Initialization
	size_t Index = 0;

//Start.
	fwprintf_s(OutputFile, _T("------------------------------ Response Hex ------------------------------\n"));

//Print hexs.
	for (Index = 0;Index < Length;++Index)
	{
		if (Index == 0)
		{
			fwprintf_s(OutputFile, _T("0000  %02x "), (UCHAR)Buffer[Index]);
		}
		else if (Index % NUM_HEX + 1U == NUM_HEX)
		{
			fwprintf_s(OutputFile, _T("%02x   "), (UCHAR)Buffer[Index]);
			for (size_t InnerIndex = Index - (NUM_HEX - 1U);InnerIndex < Index + 1U;++InnerIndex)
			{
				if (InnerIndex != Index - (NUM_HEX - 1U) && InnerIndex % (NUM_HEX / 2U) == 0)
					fwprintf_s(OutputFile, _T(" "));
				if ((UCHAR)Buffer[InnerIndex] >= ASCII_SPACE && (UCHAR)Buffer[InnerIndex] <= ASCII_TILDE)
					fwprintf_s(OutputFile, _T("%c"), (UCHAR)Buffer[InnerIndex]);
				else
					fwprintf_s(OutputFile, _T("."));
			}
			if (Index + 1U < Length)
			{
				fwprintf_s(OutputFile, _T("\n%04x  "), (UINT)(Index + 1U));
			}
		}
		else {
			if (Index % (NUM_HEX / 2U) == 0 && Index % NUM_HEX != 0)
				fwprintf_s(OutputFile, _T(" "));
			fwprintf_s(OutputFile, _T("%02x "), (UCHAR)Buffer[Index]);
		}
	}
	if (NUM_HEX - Length % NUM_HEX < NUM_HEX)
	{
		for (Index = 0;Index < NUM_HEX - Length % NUM_HEX;++Index)
			fwprintf_s(OutputFile, _T("   "));
	}
	if (Length % NUM_HEX > 0)
	{
		fwprintf_s(OutputFile, _T("   "));
		for (Index = Length - Length % NUM_HEX;Index < Length;++Index)
		{
			if ((UCHAR)Buffer[Index] >= ASCII_SPACE && (UCHAR)Buffer[Index] <= ASCII_TILDE)
				fwprintf_s(OutputFile, _T("%c"), (UCHAR)Buffer[Index]);
			else
				fwprintf_s(OutputFile, _T("."));
		}
	}
	fwprintf_s(OutputFile, _T("\n"));

//End.
	fwprintf_s(OutputFile, _T("------------------------------ Response Hex ------------------------------\n"));
	return;
}

//Print response result or data
void __fastcall PrintResponse(const PSTR Buffer, const size_t Length)
{
//Initialization
	size_t Index = 0, CurrentLength = sizeof(dns_hdr);
	auto pdns_hdr = (dns_hdr *)Buffer;

//Start.
	wprintf_s(_T("-------------------------------- Response --------------------------------\n"));

//Print DNS header.
	wprintf_s(_T("ID: 0x%04x\n"), ntohs(pdns_hdr->ID));
	wprintf_s(_T("Flags: 0x%04x"), ntohs(pdns_hdr->Flags));
	PrintFlags(pdns_hdr->Flags);
	wprintf_s(_T("Questions RR Count: %u\n"), ntohs(pdns_hdr->Questions));
	wprintf_s(_T("Answer RR Count: %u\n"), ntohs(pdns_hdr->Answer));
	wprintf_s(_T("Authority RR Count: %u\n"), ntohs(pdns_hdr->Authority));
	wprintf_s(_T("Additional RR Count: %u\n"), ntohs(pdns_hdr->Additional));

//Print Questions RR.
	if (ntohs(pdns_hdr->Questions) > 0)
	{
		wprintf_s(_T("Questions RR:\n   Name: "));
		dns_qry *pdns_qry = nullptr;
		for (Index = 0;Index < ntohs(pdns_hdr->Questions);++Index)
		{
		//Print Name.
			PrintDomainName(Buffer, CurrentLength);
			wprintf_s(_T("\n"));
			CurrentLength += strnlen_s(Buffer + CurrentLength, Length - CurrentLength) + 1U;

		//Print Type and Classes.
			pdns_qry = (dns_qry *)(Buffer + CurrentLength);
			wprintf_s(_T("   Type: 0x%04x"), ntohs(pdns_qry->Type));
			PrintTypeClassesName(pdns_qry->Type, 0);
			wprintf_s(_T("   Classes: 0x%04x"), ntohs(pdns_qry->Classes));
			PrintTypeClassesName(0, pdns_qry->Classes);
			CurrentLength += sizeof(dns_qry);
		}
	}

	dns_standard_record *pdns_standard_record = nullptr;
//Print Answer RR.
	if (ntohs(pdns_hdr->Answer) > 0)
	{
		wprintf_s(_T("Answer RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Answer);++Index)
		{
		//Print Name.
			wprintf_s(_T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength);
			wprintf_s(_T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			wprintf_s(_T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0);
			wprintf_s(_T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes);
			wprintf_s(_T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
			wprintf_s(_T("\n"));
			wprintf_s(_T("   Length: %u"), ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Authority RR.
	if (ntohs(pdns_hdr->Authority) > 0)
	{
		wprintf_s(_T("Authority RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Authority);++Index)
		{
		//Print Name.
			wprintf_s(_T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength);
			wprintf_s(_T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			wprintf_s(_T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0);
			wprintf_s(_T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes);
			wprintf_s(_T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
			wprintf_s(_T("\n"));
			wprintf_s(_T("   Length: %u"), ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Additional RR.
	if (ntohs(pdns_hdr->Additional) > 0)
	{
		wprintf_s(_T("Additional RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Additional);++Index)
		{
		//Print Name.
			wprintf_s(_T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength);
			wprintf_s(_T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			wprintf_s(_T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0);
			if (pdns_standard_record->Type == htons(DNS_RECORD_OPT)) //EDNS0 Label
			{
				PrintResourseData(Buffer, CurrentLength - 1U, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes);
				CurrentLength += sizeof(dns_standard_record) + ntohs(pdns_standard_record->Length);
			}
			else {
				wprintf_s(_T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
				PrintTypeClassesName(0, pdns_standard_record->Classes);
				wprintf_s(_T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
				PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
				wprintf_s(_T("\n"));
				wprintf_s(_T("   Length: %u"), ntohs(pdns_standard_record->Length));
				CurrentLength += sizeof(dns_standard_record);
				PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes);
				CurrentLength += ntohs(pdns_standard_record->Length);
			}
		}
	}

//End.
	wprintf_s(_T("-------------------------------- Response --------------------------------\n"));
	return;
}

//Print response result or data to file
void __fastcall PrintResponse(const PSTR Buffer, const size_t Length, FILE *OutputFile)
{
//Initialization
	size_t Index = 0, CurrentLength = sizeof(dns_hdr);
	auto pdns_hdr = (dns_hdr *)Buffer;

//Start.
	fwprintf_s(OutputFile, _T("-------------------------------- Response --------------------------------\n"));

//Print DNS header.
	fwprintf_s(OutputFile, _T("ID: 0x%04x\n"), ntohs(pdns_hdr->ID));
	fwprintf_s(OutputFile, _T("Flags: 0x%04x"), ntohs(pdns_hdr->Flags));
	PrintFlags(pdns_hdr->Flags, OutputFile);
	fwprintf_s(OutputFile, _T("Questions RR Count: %u\n"), ntohs(pdns_hdr->Questions));
	fwprintf_s(OutputFile, _T("Answer RR Count: %u\n"), ntohs(pdns_hdr->Answer));
	fwprintf_s(OutputFile, _T("Authority RR Count: %u\n"), ntohs(pdns_hdr->Authority));
	fwprintf_s(OutputFile, _T("Additional RR Count: %u\n"), ntohs(pdns_hdr->Additional));

//Print Questions RR.
	if (ntohs(pdns_hdr->Questions) > 0)
	{
		fwprintf_s(OutputFile, _T("Questions RR:\n   Name: "));
		dns_qry *pdns_qry = nullptr;
		for (Index = 0;Index < ntohs(pdns_hdr->Questions);++Index)
		{
		//Print Name.
			PrintDomainName(Buffer, CurrentLength, OutputFile);
			fwprintf_s(OutputFile, _T("\n"));
			CurrentLength += strnlen_s(Buffer + CurrentLength, Length - CurrentLength) + 1U;

		//Print Type and Classes.
			pdns_qry = (dns_qry *)(Buffer + CurrentLength);
			fwprintf_s(OutputFile, _T("   Type: 0x%04x"), ntohs(pdns_qry->Type));
			PrintTypeClassesName(pdns_qry->Type, 0, OutputFile);
			fwprintf_s(OutputFile, _T("   Classes: 0x%04x"), ntohs(pdns_qry->Classes));
			PrintTypeClassesName(0, pdns_qry->Classes, OutputFile);
			CurrentLength += sizeof(dns_qry);
		}
	}

	dns_standard_record *pdns_standard_record = nullptr;
//Print Answer RR.
	if (ntohs(pdns_hdr->Answer) > 0)
	{
		fwprintf_s(OutputFile, _T("Answer RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Answer);++Index)
		{
		//Print Name.
			fwprintf_s(OutputFile, _T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, OutputFile);
			fwprintf_s(OutputFile, _T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(OutputFile, _T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, OutputFile);
			fwprintf_s(OutputFile, _T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes, OutputFile);
			fwprintf_s(OutputFile, _T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
			fwprintf_s(OutputFile, _T("\n"));
			fwprintf_s(OutputFile, _T("   Length: %u"), ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, OutputFile);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Authority RR.
	if (ntohs(pdns_hdr->Authority) > 0)
	{
		fwprintf_s(OutputFile, _T("Authority RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Authority);++Index)
		{
		//Print Name.
			fwprintf_s(OutputFile, _T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, OutputFile);
			fwprintf_s(OutputFile, _T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(OutputFile, _T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, OutputFile);
			fwprintf_s(OutputFile, _T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
			PrintTypeClassesName(0, pdns_standard_record->Classes, OutputFile);
			fwprintf_s(OutputFile, _T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
			PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
			fwprintf_s(OutputFile, _T("\n"));
			fwprintf_s(OutputFile, _T("   Length: %u"), ntohs(pdns_standard_record->Length));
			CurrentLength += sizeof(dns_standard_record);
			PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, OutputFile);
			CurrentLength += ntohs(pdns_standard_record->Length);
		}
	}

//Print Additional RR.
	if (ntohs(pdns_hdr->Additional) > 0)
	{
		fwprintf_s(OutputFile, _T("Additional RR:\n"));
		for (Index = 0;Index < ntohs(pdns_hdr->Additional);++Index)
		{
		//Print Name.
			fwprintf_s(OutputFile, _T(" RR(%u)\n   Name: "), (UINT)(Index + 1U));
			CurrentLength += PrintDomainName(Buffer, CurrentLength, OutputFile);
			fwprintf_s(OutputFile, _T("\n"));

		//Print Type, Classes, TTL and Length.
			pdns_standard_record = (dns_standard_record *)(Buffer + CurrentLength);
			fwprintf_s(OutputFile, _T("   Type: 0x%04x"), ntohs(pdns_standard_record->Type));
			PrintTypeClassesName(pdns_standard_record->Type, 0, OutputFile);
			if (pdns_standard_record->Type == htons(DNS_RECORD_OPT)) //EDNS0 Label
			{
				PrintResourseData(Buffer, CurrentLength - 1U, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, OutputFile);
				CurrentLength += sizeof(dns_standard_record) + ntohs(pdns_standard_record->Length);
			}
			else {
				fwprintf_s(OutputFile, _T("   Classes: 0x%04x"), ntohs(pdns_standard_record->Classes));
				PrintTypeClassesName(0, pdns_standard_record->Classes, OutputFile);
				fwprintf_s(OutputFile, _T("   TTL: %u"), ntohl(pdns_standard_record->TTL));
				PrintSecondsInDateTime(ntohl(pdns_standard_record->TTL));
				fwprintf_s(OutputFile, _T("\n"));
				fwprintf_s(OutputFile, _T("   Length: %u"), ntohs(pdns_standard_record->Length));
				CurrentLength += sizeof(dns_standard_record);
				PrintResourseData(Buffer, CurrentLength, ntohs(pdns_standard_record->Length), pdns_standard_record->Type, pdns_standard_record->Classes, OutputFile);
				CurrentLength += ntohs(pdns_standard_record->Length);
			}
		}
	}

//End.
	fwprintf_s(OutputFile, _T("-------------------------------- Response --------------------------------\n"));
	return;
}

//Print Header Flags
void __fastcall PrintFlags(const uint16_t Flags)
{
//Print Flags
	if (Flags > 0)
	{
		auto FlagsBits = ntohs(Flags);

	//Print OPCode
		wprintf_s(_T("(OPCode: "));
		FlagsBits = FlagsBits & HIGHEST_BIT_U16;
		FlagsBits = FlagsBits >> 11U;
		if (FlagsBits == DNS_OPCODE_QUERY)
			wprintf_s(_T("Query"));
		else if (FlagsBits == DNS_OPCODE_IQUERY)
			wprintf_s(_T("Inverse Query"));
		else if (FlagsBits == DNS_OPCODE_STATUS)
			wprintf_s(_T("Status"));
		else if (FlagsBits == DNS_OPCODE_NOTIFY)
			wprintf_s(_T("Notify"));
		else if (FlagsBits == DNS_OPCODE_UPDATE)
			wprintf_s(_T("Update"));
		else
			wprintf_s(_T("%x"), FlagsBits);

	//Print RCode.
		wprintf_s(_T("/RCode: "));
		FlagsBits = ntohs(Flags);
		FlagsBits = FlagsBits & UINT4_MAX;
		if (FlagsBits == DNS_RCODE_NOERROR)
			wprintf_s(_T("No Error"));
		else if (FlagsBits == DNS_RCODE_FORMERR)
			wprintf_s(_T("Format Error"));
		else if (FlagsBits == DNS_RCODE_SERVFAIL)
			wprintf_s(_T("Server Failure"));
		else if (FlagsBits == DNS_RCODE_NXDOMAIN)
			wprintf_s(_T("Non-Existent Domain"));
		else if (FlagsBits == DNS_RCODE_NOTIMP)
			wprintf_s(_T("Not Implemented"));
		else if (FlagsBits == DNS_RCODE_REFUSED)
			wprintf_s(_T("Query Refused"));
		else if (FlagsBits == DNS_RCODE_YXDOMAIN)
			wprintf_s(_T("Name Exists when it should not"));
		else if (FlagsBits == DNS_RCODE_YXRRSET)
			wprintf_s(_T("RR Set Exists when it should not"));
		else if (FlagsBits == DNS_RCODE_NXRRSET)
			wprintf_s(_T("RR Set that should exist does not"));
		else if (FlagsBits == DNS_RCODE_NOTAUTH)
			wprintf_s(_T("Server Not Authoritative for zone/Not Authorized"));
		else if (FlagsBits == DNS_RCODE_NOTZONE)
			wprintf_s(_T("Name not contained in zone"));
		else if (FlagsBits == DNS_RCODE_BADVERS)
			wprintf_s(_T("Bad OPT Version/TSIG Signature Failure"));
		else if (FlagsBits == DNS_RCODE_BADKEY)
			wprintf_s(_T("Key not recognized"));
		else if (FlagsBits == DNS_RCODE_BADTIME)
			wprintf_s(_T("Signature out of time window"));
		else if (FlagsBits == DNS_RCODE_BADMODE)
			wprintf_s(_T("Bad TKEY Mode"));
		else if (FlagsBits == DNS_RCODE_BADNAME)
			wprintf_s(_T("Duplicate key name"));
		else if (FlagsBits == DNS_RCODE_BADALG)
			wprintf_s(_T("Algorithm not supported"));
		else if (FlagsBits == DNS_RCODE_BADTRUNC)
			wprintf_s(_T("Bad Truncation"));
		else if (FlagsBits >= DNS_RCODE_PRIVATE_A && FlagsBits <= DNS_RCODE_PRIVATE_B)
			wprintf_s(_T("Reserved Private use"));
		else if (FlagsBits == DNS_OPCODE_RESERVED)
			wprintf_s(_T("Reserved"));
		else
			wprintf_s(_T("%x"), FlagsBits);
		wprintf_s(_T("))"));
	}

	wprintf_s(_T("\n"));
	return;
}

//Print Header Flags to file
void __fastcall PrintFlags(const uint16_t Flags, FILE *OutputFile)
{
//Print Flags
	if (Flags > 0)
	{
		auto FlagsBits = ntohs(Flags);

	//Print OPCode
		fwprintf_s(OutputFile, _T("(OPCode: "));
		FlagsBits = FlagsBits & HIGHEST_BIT_U16;
		FlagsBits = FlagsBits >> 11U;
		if (FlagsBits == DNS_OPCODE_QUERY)
			fwprintf_s(OutputFile, _T("Query"));
		else if (FlagsBits == DNS_OPCODE_IQUERY)
			fwprintf_s(OutputFile, _T("Inverse Query"));
		else if (FlagsBits == DNS_OPCODE_STATUS)
			fwprintf_s(OutputFile, _T("Status"));
		else if (FlagsBits == DNS_OPCODE_NOTIFY)
			fwprintf_s(OutputFile, _T("Notify"));
		else if (FlagsBits == DNS_OPCODE_UPDATE)
			fwprintf_s(OutputFile, _T("Update"));
		else
			fwprintf_s(OutputFile, _T("%x"), FlagsBits);

	//Print RCode.
		fwprintf_s(OutputFile, _T("/RCode: "));
		FlagsBits = ntohs(Flags);
		FlagsBits = FlagsBits & UINT4_MAX;
		if (FlagsBits == DNS_RCODE_NOERROR)
			fwprintf_s(OutputFile, _T("No Error"));
		else if (FlagsBits == DNS_RCODE_FORMERR)
			fwprintf_s(OutputFile, _T("Format Error"));
		else if (FlagsBits == DNS_RCODE_SERVFAIL)
			fwprintf_s(OutputFile, _T("Server Failure"));
		else if (FlagsBits == DNS_RCODE_NXDOMAIN)
			fwprintf_s(OutputFile, _T("Non-Existent Domain"));
		else if (FlagsBits == DNS_RCODE_NOTIMP)
			fwprintf_s(OutputFile, _T("Not Implemented"));
		else if (FlagsBits == DNS_RCODE_REFUSED)
			fwprintf_s(OutputFile, _T("Query Refused"));
		else if (FlagsBits == DNS_RCODE_YXDOMAIN)
			fwprintf_s(OutputFile, _T("Name Exists when it should not"));
		else if (FlagsBits == DNS_RCODE_YXRRSET)
			fwprintf_s(OutputFile, _T("RR Set Exists when it should not"));
		else if (FlagsBits == DNS_RCODE_NXRRSET)
			fwprintf_s(OutputFile, _T("RR Set that should exist does not"));
		else if (FlagsBits == DNS_RCODE_NOTAUTH)
			fwprintf_s(OutputFile, _T("Server Not Authoritative for zone/Not Authorized"));
		else if (FlagsBits == DNS_RCODE_NOTZONE)
			fwprintf_s(OutputFile, _T("Name not contained in zone"));
		else if (FlagsBits == DNS_RCODE_BADVERS)
			fwprintf_s(OutputFile, _T("Bad OPT Version/TSIG Signature Failure"));
		else if (FlagsBits == DNS_RCODE_BADKEY)
			fwprintf_s(OutputFile, _T("Key not recognized"));
		else if (FlagsBits == DNS_RCODE_BADTIME)
			fwprintf_s(OutputFile, _T("Signature out of time window"));
		else if (FlagsBits == DNS_RCODE_BADMODE)
			fwprintf_s(OutputFile, _T("Bad TKEY Mode"));
		else if (FlagsBits == DNS_RCODE_BADNAME)
			fwprintf_s(OutputFile, _T("Duplicate key name"));
		else if (FlagsBits == DNS_RCODE_BADALG)
			fwprintf_s(OutputFile, _T("Algorithm not supported"));
		else if (FlagsBits == DNS_RCODE_BADTRUNC)
			fwprintf_s(OutputFile, _T("Bad Truncation"));
		else if (FlagsBits >= DNS_RCODE_PRIVATE_A && FlagsBits <= DNS_RCODE_PRIVATE_B)
			fwprintf_s(OutputFile, _T("Reserved Private use"));
		else if (FlagsBits == DNS_OPCODE_RESERVED)
			fwprintf_s(OutputFile, _T("Reserved"));
		else
			fwprintf_s(OutputFile, _T("%x"), FlagsBits);
		fwprintf_s(OutputFile, _T("))"));
	}

	fwprintf_s(OutputFile, _T("\n"));
	return;
}

//Print Type and Classes name
void __fastcall PrintTypeClassesName(const uint16_t Type, const uint16_t Classes)
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
			wprintf_s(_T("(Class IN"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_CSNET)
		{
			wprintf_s(_T("(Class CSNET"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_CHAOS)
		{
			wprintf_s(_T("(Class CHAOS"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_HESIOD)
		{
			wprintf_s(_T("(Class HESIOD"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_NONE)
		{
			wprintf_s(_T("(Class NONE"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_ALL)
		{
			wprintf_s(_T("(Class AL_T("));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_ANY)
		{
			wprintf_s(_T("(Class ANY"));
			if (HighBitSet)
				wprintf_s(_T("/Unicast Queries or Cache Flush"));
			wprintf_s(_T("))"));
		}
	}
//Print Type.
	else {
		if (Type == htons(DNS_RECORD_A))
			wprintf_s(_T("(A Record)"));
		else if (Type == htons(DNS_RECORD_NS))
			wprintf_s(_T("(NS Record)"));
		else if (Type == htons(DNS_RECORD_MD))
			wprintf_s(_T("(MD Record)"));
		else if (Type == htons(DNS_RECORD_MF))
			wprintf_s(_T("(MF Record)"));
		else if (Type == htons(DNS_RECORD_CNAME))
			wprintf_s(_T("(CNAME Record)"));
		else if (Type == htons(DNS_RECORD_SOA))
			wprintf_s(_T("(SOA Record)"));
		else if (Type == htons(DNS_RECORD_MB))
			wprintf_s(_T("(MB Record)"));
		else if (Type == htons(DNS_RECORD_MG))
			wprintf_s(_T("(MG Record)"));
		else if (Type == htons(DNS_RECORD_MR))
			wprintf_s(_T("(MR Record)"));
		else if (Type == htons(DNS_RECORD_NULL))
			wprintf_s(_T("(NULL Record)"));
		else if (Type == htons(DNS_RECORD_WKS))
			wprintf_s(_T("(WKS Record)"));
		else if (Type == htons(DNS_RECORD_PTR))
			wprintf_s(_T("(PTR Record)"));
		else if (Type == htons(DNS_RECORD_HINFO))
			wprintf_s(_T("(HINFO Record)"));
		else if (Type == htons(DNS_RECORD_MINFO))
			wprintf_s(_T("(MINFO Record)"));
		else if (Type == htons(DNS_RECORD_MX))
			wprintf_s(_T("(MX Record)"));
		else if (Type == htons(DNS_RECORD_TXT))
			wprintf_s(_T("(TXT Record)"));
		else if (Type == htons(DNS_RECORD_RP))
			wprintf_s(_T("(RP Record)"));
		else if (Type == htons(DNS_RECORD_RP))
			wprintf_s(_T("(RP Record)"));
		else if (Type == htons(DNS_RECORD_AFSDB))
			wprintf_s(_T("(AFSDB Record)"));
		else if (Type == htons(DNS_RECORD_X25))
			wprintf_s(_T("(X25 Record)"));
		else if (Type == htons(DNS_RECORD_ISDN))
			wprintf_s(_T("(ISDN Record)"));
		else if (Type == htons(DNS_RECORD_RT))
			wprintf_s(_T("(RT Record)"));
		else if (Type == htons(DNS_RECORD_NSAP))
			wprintf_s(_T("(NSAP Record)"));
		else if (Type == htons(DNS_RECORD_NSAP_PTR))
			wprintf_s(_T("(NSAP PTR Record)"));
		else if (Type == htons(DNS_RECORD_SIG))
			wprintf_s(_T("(SIG Record)"));
		else if (Type == htons(DNS_RECORD_KEY))
			wprintf_s(_T("(KEY Record)"));
		else if (Type == htons(DNS_RECORD_PX))
			wprintf_s(_T("(PX Record)"));
		else if (Type == htons(DNS_RECORD_GPOS))
			wprintf_s(_T("(GPOS Record)"));
		else if (Type == htons(DNS_RECORD_AAAA))
			wprintf_s(_T("(AAAA Record)"));
		else if (Type == htons(DNS_RECORD_LOC))
			wprintf_s(_T("(LOC Record)"));
		else if (Type == htons(DNS_RECORD_NXT))
			wprintf_s(_T("(NXT Record)"));
		else if (Type == htons(DNS_RECORD_EID))
			wprintf_s(_T("(EID Record)"));
		else if (Type == htons(DNS_RECORD_NIMLOC))
			wprintf_s(_T("(NIMLOC Record)"));
		else if (Type == htons(DNS_RECORD_SRV))
			wprintf_s(_T("(SRV Record)"));
		else if (Type == htons(DNS_RECORD_ATMA))
			wprintf_s(_T("(ATMA Record)"));
		else if (Type == htons(DNS_RECORD_NAPTR))
			wprintf_s(_T("(NAPTR Record)"));
		else if (Type == htons(DNS_RECORD_KX))
			wprintf_s(_T("(KX Record)"));
		else if (Type == htons(DNS_RECORD_CERT))
			wprintf_s(_T("(CERT Record)"));
		else if (Type == htons(DNS_RECORD_DNAME))
			wprintf_s(_T("(DNAME Record)"));
		else if (Type == htons(DNS_RECORD_SINK))
			wprintf_s(_T("(SINK Record)"));
		else if (Type == htons(DNS_RECORD_OPT))
			wprintf_s(_T("(OPT/EDNS0 Record)"));
		else if (Type == htons(DNS_RECORD_APL))
			wprintf_s(_T("(APL Record)"));
		else if (Type == htons(DNS_RECORD_DS))
			wprintf_s(_T("(DS Record)"));
		else if (Type == htons(DNS_RECORD_SSHFP))
			wprintf_s(_T("(SSHFP Record)"));
		else if (Type == htons(DNS_RECORD_IPSECKEY))
			wprintf_s(_T("(IPSECKEY Record)"));
		else if (Type == htons(DNS_RECORD_RRSIG))
			wprintf_s(_T("(RRSIG Record)"));
		else if (Type == htons(DNS_RECORD_NSEC))
			wprintf_s(_T("(NSEC Record)"));
		else if (Type == htons(DNS_RECORD_DNSKEY))
			wprintf_s(_T("(DNSKEY Record)"));
		else if (Type == htons(DNS_RECORD_DHCID))
			wprintf_s(_T("(DHCID Record)"));
		else if (Type == htons(DNS_RECORD_NSEC3))
			wprintf_s(_T("(NSEC3 Record)"));
		else if (Type == htons(DNS_RECORD_NSEC3PARAM))
			wprintf_s(_T("(NSEC3PARAM Record)"));
		else if (Type == htons(DNS_RECORD_TLSA))
			wprintf_s(_T("(TLSA Record)"));
		else if (Type == htons(DNS_RECORD_HIP))
			wprintf_s(_T("(HIP Record)"));
		else if (Type == htons(DNS_RECORD_NINFO))
			wprintf_s(_T("(NINFO Record)"));
		else if (Type == htons(DNS_RECORD_RKEY))
			wprintf_s(_T("(RKEY Record)"));
		else if (Type == htons(DNS_RECORD_TALINK))
			wprintf_s(_T("(TALINK Record)"));
		else if (Type == htons(DNS_RECORD_CDS))
			wprintf_s(_T("(CDS Record)"));
		else if (Type == htons(DNS_RECORD_CDNSKEY))
			wprintf_s(_T("(CDNSKEY Record)"));
		else if (Type == htons(DNS_RECORD_OPENPGPKEY))
			wprintf_s(_T("(OPENPGPKEY Record)"));
		else if (Type == htons(DNS_RECORD_SPF))
			wprintf_s(_T("(SPF Record)"));
		else if (Type == htons(DNS_RECORD_UID))
			wprintf_s(_T("(UID Record)"));
		else if (Type == htons(DNS_RECORD_GID))
			wprintf_s(_T("(GID Record)"));
		else if (Type == htons(DNS_RECORD_UNSPEC))
			wprintf_s(_T("(UNSPEC Record)"));
		else if (Type == htons(DNS_RECORD_NID))
			wprintf_s(_T("(NID Record)"));
		else if (Type == htons(DNS_RECORD_L32))
			wprintf_s(_T("(L32 Record)"));
		else if (Type == htons(DNS_RECORD_L64))
			wprintf_s(_T("(L64 Record)"));
		else if (Type == htons(DNS_RECORD_LP))
			wprintf_s(_T("(LP Record)"));
		else if (Type == htons(DNS_RECORD_EUI48))
			wprintf_s(_T("(EUI48 Record)"));
		else if (Type == htons(DNS_RECORD_EUI64))
			wprintf_s(_T("(EUI64 Record)"));
		else if (Type == htons(DNS_RECORD_TKEY))
			wprintf_s(_T("(TKEY Record)"));
		else if (Type == htons(DNS_RECORD_TSIG))
			wprintf_s(_T("(TSIG Record)"));
		else if (Type == htons(DNS_RECORD_IXFR))
			wprintf_s(_T("(IXFR Record)"));
		else if (Type == htons(DNS_RECORD_AXFR))
			wprintf_s(_T("(AXFR Record)"));
		else if (Type == htons(DNS_RECORD_MAILB))
			wprintf_s(_T("(MAILB Record)"));
		else if (Type == htons(DNS_RECORD_MAILA))
			wprintf_s(_T("(MAILA Record)"));
		else if (Type == htons(DNS_RECORD_ANY))
			wprintf_s(_T("(ANY Record)"));
		else if (Type == htons(DNS_RECORD_URI))
			wprintf_s(_T("(URI Record)"));
		else if (Type == htons(DNS_RECORD_CAA))
			wprintf_s(_T("(CAA Record)"));
		else if (Type == htons(DNS_RECORD_TA))
			wprintf_s(_T("(TA Record)"));
		else if (Type == htons(DNS_RECORD_DLV))
			wprintf_s(_T("(DLV Record)"));
		else if (ntohs(Type) >= DNS_RECORD_PRIVATE_A && ntohs(Type) <= DNS_RECORD_PRIVATE_B)
			wprintf_s(_T("(Reserved Private use Record)"));
		else if (Type == htons(DNS_RECORD_RESERVED))
			wprintf_s(_T("(Reserved Record)"));
	}

	wprintf_s(_T("\n"));
	return;
}

//Print Type and Classes name to file
void __fastcall PrintTypeClassesName(const uint16_t Type, const uint16_t Classes, FILE *OutputFile)
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
			fwprintf_s(OutputFile, _T("(Class IN"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_CSNET)
		{
			fwprintf_s(OutputFile, _T("(Class CSNET"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_CHAOS)
		{
			fwprintf_s(OutputFile, _T("(Class CHAOS"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_HESIOD)
		{
			fwprintf_s(OutputFile, _T("(Class HESIOD"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_NONE)
		{
			fwprintf_s(OutputFile, _T("(Class NONE"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_ALL)
		{
			fwprintf_s(OutputFile, _T("(Class AL_T("));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
		else if (ClassesTemp == DNS_CLASS_ANY)
		{
			fwprintf_s(OutputFile, _T("(Class ANY"));
			if (HighBitSet)
				fwprintf_s(OutputFile, _T("/Unicast Queries or Cache Flush"));
			fwprintf_s(OutputFile, _T("))"));
		}
	}
//Print Type.
	else {
		if (Type == htons(DNS_RECORD_A))
			fwprintf_s(OutputFile, _T("(A Record)"));
		else if (Type == htons(DNS_RECORD_NS))
			fwprintf_s(OutputFile, _T("(NS Record)"));
		else if (Type == htons(DNS_RECORD_MD))
			fwprintf_s(OutputFile, _T("(MD Record)"));
		else if (Type == htons(DNS_RECORD_MF))
			fwprintf_s(OutputFile, _T("(MF Record)"));
		else if (Type == htons(DNS_RECORD_CNAME))
			fwprintf_s(OutputFile, _T("(CNAME Record)"));
		else if (Type == htons(DNS_RECORD_SOA))
			fwprintf_s(OutputFile, _T("(SOA Record)"));
		else if (Type == htons(DNS_RECORD_MB))
			fwprintf_s(OutputFile, _T("(MB Record)"));
		else if (Type == htons(DNS_RECORD_MG))
			fwprintf_s(OutputFile, _T("(MG Record)"));
		else if (Type == htons(DNS_RECORD_MR))
			fwprintf_s(OutputFile, _T("(MR Record)"));
		else if (Type == htons(DNS_RECORD_NULL))
			fwprintf_s(OutputFile, _T("(NULL Record)"));
		else if (Type == htons(DNS_RECORD_WKS))
			fwprintf_s(OutputFile, _T("(WKS Record)"));
		else if (Type == htons(DNS_RECORD_PTR))
			fwprintf_s(OutputFile, _T("(PTR Record)"));
		else if (Type == htons(DNS_RECORD_HINFO))
			fwprintf_s(OutputFile, _T("(HINFO Record)"));
		else if (Type == htons(DNS_RECORD_MINFO))
			fwprintf_s(OutputFile, _T("(MINFO Record)"));
		else if (Type == htons(DNS_RECORD_MX))
			fwprintf_s(OutputFile, _T("(MX Record)"));
		else if (Type == htons(DNS_RECORD_TXT))
			fwprintf_s(OutputFile, _T("(TXT Record)"));
		else if (Type == htons(DNS_RECORD_RP))
			fwprintf_s(OutputFile, _T("(RP Record)"));
		else if (Type == htons(DNS_RECORD_RP))
			fwprintf_s(OutputFile, _T("(RP Record)"));
		else if (Type == htons(DNS_RECORD_AFSDB))
			fwprintf_s(OutputFile, _T("(AFSDB Record)"));
		else if (Type == htons(DNS_RECORD_X25))
			fwprintf_s(OutputFile, _T("(X25 Record)"));
		else if (Type == htons(DNS_RECORD_ISDN))
			fwprintf_s(OutputFile, _T("(ISDN Record)"));
		else if (Type == htons(DNS_RECORD_RT))
			fwprintf_s(OutputFile, _T("(RT Record)"));
		else if (Type == htons(DNS_RECORD_NSAP))
			fwprintf_s(OutputFile, _T("(NSAP Record)"));
		else if (Type == htons(DNS_RECORD_NSAP_PTR))
			fwprintf_s(OutputFile, _T("(NSAP PTR Record)"));
		else if (Type == htons(DNS_RECORD_SIG))
			fwprintf_s(OutputFile, _T("(SIG Record)"));
		else if (Type == htons(DNS_RECORD_KEY))
			fwprintf_s(OutputFile, _T("(KEY Record)"));
		else if (Type == htons(DNS_RECORD_PX))
			fwprintf_s(OutputFile, _T("(PX Record)"));
		else if (Type == htons(DNS_RECORD_GPOS))
			fwprintf_s(OutputFile, _T("(GPOS Record)"));
		else if (Type == htons(DNS_RECORD_AAAA))
			fwprintf_s(OutputFile, _T("(AAAA Record)"));
		else if (Type == htons(DNS_RECORD_LOC))
			fwprintf_s(OutputFile, _T("(LOC Record)"));
		else if (Type == htons(DNS_RECORD_NXT))
			fwprintf_s(OutputFile, _T("(NXT Record)"));
		else if (Type == htons(DNS_RECORD_EID))
			fwprintf_s(OutputFile, _T("(EID Record)"));
		else if (Type == htons(DNS_RECORD_NIMLOC))
			fwprintf_s(OutputFile, _T("(NIMLOC Record)"));
		else if (Type == htons(DNS_RECORD_SRV))
			fwprintf_s(OutputFile, _T("(SRV Record)"));
		else if (Type == htons(DNS_RECORD_ATMA))
			fwprintf_s(OutputFile, _T("(ATMA Record)"));
		else if (Type == htons(DNS_RECORD_NAPTR))
			fwprintf_s(OutputFile, _T("(NAPTR Record)"));
		else if (Type == htons(DNS_RECORD_KX))
			fwprintf_s(OutputFile, _T("(KX Record)"));
		else if (Type == htons(DNS_RECORD_CERT))
			fwprintf_s(OutputFile, _T("(CERT Record)"));
		else if (Type == htons(DNS_RECORD_DNAME))
			fwprintf_s(OutputFile, _T("(DNAME Record)"));
		else if (Type == htons(DNS_RECORD_SINK))
			fwprintf_s(OutputFile, _T("(SINK Record)"));
		else if (Type == htons(DNS_RECORD_OPT))
			fwprintf_s(OutputFile, _T("(OPT/EDNS0 Record)"));
		else if (Type == htons(DNS_RECORD_APL))
			fwprintf_s(OutputFile, _T("(APL Record)"));
		else if (Type == htons(DNS_RECORD_DS))
			fwprintf_s(OutputFile, _T("(DS Record)"));
		else if (Type == htons(DNS_RECORD_SSHFP))
			fwprintf_s(OutputFile, _T("(SSHFP Record)"));
		else if (Type == htons(DNS_RECORD_IPSECKEY))
			fwprintf_s(OutputFile, _T("(IPSECKEY Record)"));
		else if (Type == htons(DNS_RECORD_RRSIG))
			fwprintf_s(OutputFile, _T("(RRSIG Record)"));
		else if (Type == htons(DNS_RECORD_NSEC))
			fwprintf_s(OutputFile, _T("(NSEC Record)"));
		else if (Type == htons(DNS_RECORD_DNSKEY))
			fwprintf_s(OutputFile, _T("(DNSKEY Record)"));
		else if (Type == htons(DNS_RECORD_DHCID))
			fwprintf_s(OutputFile, _T("(DHCID Record)"));
		else if (Type == htons(DNS_RECORD_NSEC3))
			fwprintf_s(OutputFile, _T("(NSEC3 Record)"));
		else if (Type == htons(DNS_RECORD_NSEC3PARAM))
			fwprintf_s(OutputFile, _T("(NSEC3PARAM Record)"));
		else if (Type == htons(DNS_RECORD_TLSA))
			fwprintf_s(OutputFile, _T("(TLSA Record)"));
		else if (Type == htons(DNS_RECORD_HIP))
			fwprintf_s(OutputFile, _T("(HIP Record)"));
		else if (Type == htons(DNS_RECORD_NINFO))
			fwprintf_s(OutputFile, _T("(NINFO Record)"));
		else if (Type == htons(DNS_RECORD_RKEY))
			fwprintf_s(OutputFile, _T("(RKEY Record)"));
		else if (Type == htons(DNS_RECORD_TALINK))
			fwprintf_s(OutputFile, _T("(TALINK Record)"));
		else if (Type == htons(DNS_RECORD_CDS))
			fwprintf_s(OutputFile, _T("(CDS Record)"));
		else if (Type == htons(DNS_RECORD_CDNSKEY))
			fwprintf_s(OutputFile, _T("(CDNSKEY Record)"));
		else if (Type == htons(DNS_RECORD_OPENPGPKEY))
			fwprintf_s(OutputFile, _T("(OPENPGPKEY Record)"));
		else if (Type == htons(DNS_RECORD_SPF))
			fwprintf_s(OutputFile, _T("(SPF Record)"));
		else if (Type == htons(DNS_RECORD_UID))
			fwprintf_s(OutputFile, _T("(UID Record)"));
		else if (Type == htons(DNS_RECORD_GID))
			fwprintf_s(OutputFile, _T("(GID Record)"));
		else if (Type == htons(DNS_RECORD_UNSPEC))
			fwprintf_s(OutputFile, _T("(UNSPEC Record)"));
		else if (Type == htons(DNS_RECORD_NID))
			fwprintf_s(OutputFile, _T("(NID Record)"));
		else if (Type == htons(DNS_RECORD_L32))
			fwprintf_s(OutputFile, _T("(L32 Record)"));
		else if (Type == htons(DNS_RECORD_L64))
			fwprintf_s(OutputFile, _T("(L64 Record)"));
		else if (Type == htons(DNS_RECORD_LP))
			fwprintf_s(OutputFile, _T("(LP Record)"));
		else if (Type == htons(DNS_RECORD_EUI48))
			fwprintf_s(OutputFile, _T("(EUI48 Record)"));
		else if (Type == htons(DNS_RECORD_EUI64))
			fwprintf_s(OutputFile, _T("(EUI64 Record)"));
		else if (Type == htons(DNS_RECORD_TKEY))
			fwprintf_s(OutputFile, _T("(TKEY Record)"));
		else if (Type == htons(DNS_RECORD_TSIG))
			fwprintf_s(OutputFile, _T("(TSIG Record)"));
		else if (Type == htons(DNS_RECORD_IXFR))
			fwprintf_s(OutputFile, _T("(IXFR Record)"));
		else if (Type == htons(DNS_RECORD_AXFR))
			fwprintf_s(OutputFile, _T("(AXFR Record)"));
		else if (Type == htons(DNS_RECORD_MAILB))
			fwprintf_s(OutputFile, _T("(MAILB Record)"));
		else if (Type == htons(DNS_RECORD_MAILA))
			fwprintf_s(OutputFile, _T("(MAILA Record)"));
		else if (Type == htons(DNS_RECORD_ANY))
			fwprintf_s(OutputFile, _T("(ANY Record)"));
		else if (Type == htons(DNS_RECORD_URI))
			fwprintf_s(OutputFile, _T("(URI Record)"));
		else if (Type == htons(DNS_RECORD_CAA))
			fwprintf_s(OutputFile, _T("(CAA Record)"));
		else if (Type == htons(DNS_RECORD_TA))
			fwprintf_s(OutputFile, _T("(TA Record)"));
		else if (Type == htons(DNS_RECORD_DLV))
			fwprintf_s(OutputFile, _T("(DLV Record)"));
		else if (ntohs(Type) >= DNS_RECORD_PRIVATE_A && ntohs(Type) <= DNS_RECORD_PRIVATE_B)
			fwprintf_s(OutputFile, _T("(Reserved Private use Record)"));
		else if (Type == htons(DNS_RECORD_RESERVED))
			fwprintf_s(OutputFile, _T("(Reserved Record)"));
	}

	fwprintf_s(OutputFile, _T("\n"));
	return;
}

//Print Domain Name in response
size_t __fastcall PrintDomainName(const PSTR Buffer, const size_t Location)
{
//Root check
	if (Buffer[Location] == 0)
	{
		wprintf_s(_T("<Root>"));
		return sizeof(char);
	}

//Initialization
	std::shared_ptr<char> BufferTemp(new char[PACKET_MAXSIZE]());
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
				wprintf_s(_T("%c"), BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			wprintf_s(_T("."));
		}

	//Get pointer.
		while (Truncated > 0)
		{
			if (MultiplePTR)
				wprintf_s(_T("."));
			DNSQueryToChar(Buffer + Truncated, BufferTemp.get(), Truncated);
			for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
				wprintf_s(_T("%c"), BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			MultiplePTR = true;
		}
	}
	else {
		++Result;
	}

//Print last.
	for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
		wprintf_s(_T("%c"), BufferTemp.get()[Index]);
	return Result;
}

//Print Domain Name in response to file
size_t __fastcall PrintDomainName(const PSTR Buffer, const size_t Location, FILE *OutputFile)
{
//Root check
	if (Buffer[Location] == 0)
	{
		fwprintf_s(OutputFile, _T("<Root>"));
		return sizeof(char);
	}

//Initialization
	std::shared_ptr<char> BufferTemp(new char[PACKET_MAXSIZE]());
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
				fwprintf_s(OutputFile, _T("%c"), BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			fwprintf_s(OutputFile, _T("."));
		}

	//Get pointer.
		while (Truncated > 0)
		{
			if (MultiplePTR)
				fwprintf_s(OutputFile, _T("."));
			DNSQueryToChar(Buffer + Truncated, BufferTemp.get(), Truncated);
			for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
				fwprintf_s(OutputFile, _T("%c"), BufferTemp.get()[Index]);
			memset(BufferTemp.get(), 0, PACKET_MAXSIZE);
			MultiplePTR = true;
		}
	}
	else {
		++Result;
	}

//Print last.
	for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
		fwprintf_s(OutputFile, _T("%c"), BufferTemp.get()[Index]);
	return Result;
}

//Print Resourse data
void __fastcall PrintResourseData(const PSTR Buffer, const size_t Location, const uint16_t Length, const uint16_t Type, const uint16_t Classes)
{
//Length and Type check
	if (Length == 0 && Type != htons(DNS_RECORD_OPT))
		return;

//Initialization
	size_t Index = 0, CurrentLength = 0;

//A Record(IPv4 address)
	if (Type == htons(DNS_RECORD_A) && Length == sizeof(in_addr))
	{
		wprintf_s(_T("\n   Data: "));

		auto Addr = (in_addr *)(Buffer + Location);
		wprintf_s(_T("%u.%u.%u.%u"), Addr->s_net, Addr->s_host, Addr->s_lh, Addr->s_impno);
	}
//NS Record(Authoritative Name Server)
	else if (Type == htons(DNS_RECORD_NS))
	{
		wprintf_s(_T("\n   Data: "));

		PrintDomainName(Buffer, Location);
	}
//CNAME Record(Canonical Name)
	else if (Type == htons(DNS_RECORD_CNAME))
	{
		wprintf_s(_T("\n   Data: "));

		PrintDomainName(Buffer, Location);
	}
//SOA Record(Start Of a zone of Authority)
	else if (Type == htons(DNS_RECORD_SOA))
	{
		wprintf_s(_T("\n   Data: "));

		wprintf_s(_T("Primary Name Server: "));
		CurrentLength = PrintDomainName(Buffer, Location);
		wprintf_s(_T("\n         Responsible authority's mailbox: "));
		CurrentLength += PrintDomainName(Buffer, Location + CurrentLength);
		auto pdns_soa_record = (dns_soa_record *)(Buffer + Location + CurrentLength);
		wprintf_s(_T("\n         Serial Number: %u"), ntohl(pdns_soa_record->Serial));
		wprintf_s(_T("\n         Refresh Interval: %u"), ntohl(pdns_soa_record->RefreshInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RefreshInterval));
		wprintf_s(_T("\n         Retry Interval: %u"), ntohl(pdns_soa_record->RetryInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RetryInterval));
		wprintf_s(_T("\n         Expire Limit: %u"), ntohl(pdns_soa_record->ExpireLimit));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->ExpireLimit));
		wprintf_s(_T("\n         Minimum TTL: %u"), ntohl(pdns_soa_record->MinimumTTL));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->MinimumTTL));
	}
//PTR Record(domain name PoinTeR)
	else if (Type == htons(DNS_RECORD_PTR))
	{
		wprintf_s(_T("\n   Data: "));

		PrintDomainName(Buffer, Location);
	}
//MX Record(Mail eXchange)
	else if (Type == htons(DNS_RECORD_MX))
	{
		wprintf_s(_T("\n   Data: "));

		auto pdns_mx_record = (dns_mx_record *)(Buffer + Location);
		wprintf_s(_T("Preference: %u"), ntohs(pdns_mx_record->Preference));
		wprintf_s(_T("\n         Mail Exchange: "));
		PrintDomainName(Buffer, Location + sizeof(dns_mx_record));
	}
//TXT Record(Text strings)
	else if (Type == htons(DNS_RECORD_TXT))
	{
		wprintf_s(_T("\n   Data: "));

		auto pdns_txt_record = (dns_txt_record *)(Buffer + Location);
		wprintf_s(_T("Length: %u"), pdns_txt_record->Length);
		wprintf_s(_T("\n         TXT: \""));
		for (Index = Location + sizeof(dns_txt_record);Index < Location + Length;++Index)
			wprintf_s(_T("%c"), Buffer[Index]);
		wprintf_s(_T("\""));
	}
//AAAA Record(IPv6 address)
	else if (Type == htons(DNS_RECORD_AAAA) && Length == sizeof(in6_addr))
	{
		wprintf_s(_T("\n   Data: "));

		std::shared_ptr<char> BufferTemp(new char[ADDR_STRING_MAXSIZE]());
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		DWORD BufferLength = ADDR_STRING_MAXSIZE;
		std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
		SockAddr->ss_family = AF_INET6;
		((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = *(in6_addr *)(Buffer + Location);
		WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, BufferTemp.get(), &BufferLength);
	#else
		inet_ntop(AF_INET6, Buffer + Location, BufferTemp.get(), ADDR_STRING_MAXSIZE);
	#endif
		CaseConvert(true, BufferTemp.get(), strnlen_s(BufferTemp.get(), PACKET_MAXSIZE));

		for (Index = 0;Index < strnlen_s(BufferTemp.get(), PACKET_MAXSIZE);++Index)
			wprintf_s(_T("%c"), BufferTemp.get()[Index]);
	}
//SRV Record(Server Selection)
	else if (Type == htons(DNS_RECORD_SRV))
	{
		wprintf_s(_T("\n   Data: "));

		auto pdns_srv_record = (dns_srv_record *)(Buffer + Location);
		wprintf_s(_T("Priority: %x"), ntohs(pdns_srv_record->Priority));
		wprintf_s(_T("\n         Weight: %u"), ntohs(pdns_srv_record->Weight));
		wprintf_s(_T("\n         Port: %u"), ntohs(pdns_srv_record->Port));
		wprintf_s(_T("\n         Target: "));
		PrintDomainName(Buffer, Location + sizeof(dns_srv_record));
	}
//OPT/EDNS0 Record(Extension Mechanisms for Domain Name System)
	else if (Type == htons(DNS_RECORD_OPT))
	{
		wprintf_s(_T("   Data: "));

		auto pdns_opt_record = (dns_opt_record *)(Buffer + Location);
		wprintf_s(_T("UDP Playload Size: %u"), ntohs(pdns_opt_record->UDPPayloadSize));
		wprintf_s(_T("\n         Extended RCode: %x"), pdns_opt_record->Extended_RCode);
		wprintf_s(_T("\n         EDNS0 Version: %u"), pdns_opt_record->Version);
		if (ntohs(pdns_opt_record->Z_Field) >> HIGHEST_MOVE_BIT_U16 == 0)
			wprintf_s(_T("\n         Server cannot handle DNSSEC security RRs."));
		else 
			wprintf_s(_T("\n         Server can handle DNSSEC security RRs."));

	//EDNS0 Option
		if (Length >= sizeof(dns_edns0_option))
		{
			auto pdns_edns0_option = (dns_edns0_option *)(Buffer + Location + sizeof(dns_opt_record));
			wprintf_s(_T("\n         EDNS0 Option:\n                         Code: "));
			if (pdns_edns0_option->Code == htons(EDNS0_CODE_LLQ))
				wprintf_s(_T("LLQ"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_UL))
				wprintf_s(_T("LLQ"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_NSID))
				wprintf_s(_T(""));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_OWNER))
				wprintf_s(_T("OWNER"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DAU))
				wprintf_s(_T("DAU"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DHU))
				wprintf_s(_T("DHU"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_N3U))
				wprintf_s(_T("N3U"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET))
				wprintf_s(_T("CLIENT_SUBNET"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_EDNS_EXPIRE))
				wprintf_s(_T("EDNS_EXPIRE"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET_EXP))
				wprintf_s(_T("CLIENT_SUBNET_EXP"));
			else 
				wprintf_s(_T("%x"), ntohs(pdns_edns0_option->Code));
			wprintf_s(_T("\n                         Length: %x"), ntohs(pdns_edns0_option->Length));
		}
	}
//DS Record(Delegation Signer)
	else if (Type == htons(DNS_RECORD_DS))
	{
		wprintf_s(_T("\n   Data: "));


	}
//RRSIG Record(Resource Record digital SIGnature)
	else if (Type == htons(DNS_RECORD_RRSIG))
	{
		wprintf_s(_T("\n   Data: "));

		auto pdns_rrsig_record = (dns_rrsig_record *)(Buffer + Location);
		wprintf_s(_T("Type Covered: 0x%04x"), ntohs(pdns_rrsig_record->TypeCovered));
		PrintTypeClassesName(pdns_rrsig_record->TypeCovered, 0);
		wprintf_s(_T("         Algorithm: "));
		if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_MD5)
			wprintf_s(_T("RSA/MD5"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DH)
			wprintf_s(_T("DH"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA)
			wprintf_s(_T("DSA"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC)
			wprintf_s(_T("ECC"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1)
			wprintf_s(_T("RSA/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA_NSEC3_SHA1)
			wprintf_s(_T("DSA/NSEC3/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1)
			wprintf_s(_T("RSA/SHA-1/NSEC3/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA256)
			wprintf_s(_T("RSA/SHA-256"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA512)
			wprintf_s(_T("RSA/SHA-512"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC_GOST)
			wprintf_s(_T("ECC/GOST"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P256_SHA256)
			wprintf_s(_T("ECDSA P256/SHA-256"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P386_SHA386)
			wprintf_s(_T("ECDSA P386/SHA-386"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_HMAC_MD5)
			wprintf_s(_T("HMAC/MD5"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_INDIRECT)
			wprintf_s(_T("Indirect"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_DNS)
			wprintf_s(_T("Private DNS"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_OID)
			wprintf_s(_T("Private OID"));
		else 
			wprintf_s(_T("%u"), pdns_rrsig_record->Algorithm);
		wprintf_s(_T("\n         Labels: %u"), pdns_rrsig_record->Labels);
		wprintf_s(_T("\n         Original TTL: %u"), ntohl(pdns_rrsig_record->TTL));
		PrintSecondsInDateTime(ntohl(pdns_rrsig_record->TTL));
		wprintf_s(_T("\n         Signature Expiration: "));
		PrintDateTime(ntohl(pdns_rrsig_record->Expiration));
		wprintf_s(_T("\n         Signature Inception: "));
		PrintDateTime(ntohl(pdns_rrsig_record->Inception));
		wprintf_s(_T("\n         Key Tag: %u"), ntohs(pdns_rrsig_record->KeyTag));
		wprintf_s(_T("\n         Signer's name: "));
		CurrentLength = PrintDomainName(Buffer, Location + sizeof(dns_rrsig_record)) + 1U;
		CurrentLength += sizeof(dns_rrsig_record);
		wprintf_s(_T("\n         Signature: "));
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			wprintf_s(_T("%02x"), (UCHAR)Buffer[Index]);
	}
//NSEC Record(Next-SECure)
	else if (Type == htons(DNS_RECORD_NSEC))
	{
		wprintf_s(_T("\n   Data: "));

		wprintf_s(_T("Next Domain Name: "));
		CurrentLength = PrintDomainName(Buffer, Location);
		wprintf_s(_T("\n         List of Type Bit Map: "));
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			wprintf_s(_T("%x"), (UCHAR)Buffer[Index]);
	}
//DNSKEY Record(DNS public KEY)
	else if (Type == htons(DNS_RECORD_DNSKEY))
	{
		wprintf_s(_T("\n   Data: "));


	}
//CAA Record(Certification Authority Authorization)
	else if (Type == htons(DNS_RECORD_CAA))
	{
		wprintf_s(_T("   Data: "));

		auto pdns_caa_record = (dns_caa_record *)(Buffer + Location);
		wprintf_s(_T("Flags: %x"), pdns_caa_record->Flags);
		wprintf_s(_T("\n         Length: %u"), pdns_caa_record->Length);
		wprintf_s(_T("\n         Tag: \""));
		for (Index = Location + sizeof(dns_caa_record);Index < Location + sizeof(dns_caa_record) + pdns_caa_record->Length;++Index)
			wprintf_s(_T("%c"), Buffer[Index]);
		wprintf_s(_T("\""));
		wprintf_s(_T("\n         Value: \""));
		for (Index = Location + sizeof(dns_caa_record) + pdns_caa_record->Length;Index < Location + Length;++Index)
			wprintf_s(_T("%c"), Buffer[Index]);
		wprintf_s(_T("\""));
	}

	wprintf_s(_T("\n"));
	return;
}

//Print Resourse data to file
void __fastcall PrintResourseData(const PSTR Buffer, const size_t Location, const uint16_t Length, const uint16_t Type, const uint16_t Classes, FILE *OutputFile)
{
//Length and Type check
	if (Length == 0 && Type != htons(DNS_RECORD_OPT))
		return;
	size_t Index = 0, CurrentLength = 0;

//A Record(IPv4 address)
	if (Type == htons(DNS_RECORD_A) && Length == sizeof(in_addr))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));
		auto Addr = (in_addr *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("%u.%u.%u.%u"), Addr->s_net, Addr->s_host, Addr->s_lh, Addr->s_impno);
	}
//NS Record(Authoritative Name Server) and CNAME Record(Canonical Name)
	else if (Type == htons(DNS_RECORD_NS) || Type == htons(DNS_RECORD_CNAME))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));
		PrintDomainName(Buffer, Location, OutputFile);
	}
//SOA Record(Start Of a zone of Authority)
	else if (Type == htons(DNS_RECORD_SOA))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		fwprintf_s(OutputFile, _T("Primary Name Server: "));
		CurrentLength = PrintDomainName(Buffer, Location, OutputFile);
		fwprintf_s(OutputFile, _T("\n         Responsible authority's mailbox: "));
		CurrentLength += PrintDomainName(Buffer, Location + CurrentLength, OutputFile);
		auto pdns_soa_record = (dns_soa_record *)(Buffer + Location + CurrentLength);
		fwprintf_s(OutputFile, _T("\n         Serial Number: %u"), ntohl(pdns_soa_record->Serial));
		fwprintf_s(OutputFile, _T("\n         Refresh Interval: %u"), ntohl(pdns_soa_record->RefreshInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RefreshInterval));
		fwprintf_s(OutputFile, _T("\n         Retry Interval: %u"), ntohl(pdns_soa_record->RetryInterval));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->RetryInterval));
		fwprintf_s(OutputFile, _T("\n         Expire Limit: %u"), ntohl(pdns_soa_record->ExpireLimit));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->ExpireLimit));
		fwprintf_s(OutputFile, _T("\n         Minimum TTL: %u"), ntohl(pdns_soa_record->MinimumTTL));
		PrintSecondsInDateTime(ntohl(pdns_soa_record->MinimumTTL));
	}
//PTR Record(domain name PoinTeR)
	else if (Type == htons(DNS_RECORD_PTR))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));
		PrintDomainName(Buffer, Location, OutputFile);
	}
//MX Record(Mail eXchange)
	else if (Type == htons(DNS_RECORD_MX))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		auto pdns_mx_record = (dns_mx_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("Preference: %u"), ntohs(pdns_mx_record->Preference));
		fwprintf_s(OutputFile, _T("\n         Mail Exchange: "));
		PrintDomainName(Buffer, Location + sizeof(dns_mx_record), OutputFile);
	}
//TXT Record(Text strings)
	else if (Type == htons(DNS_RECORD_TXT))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		auto pdns_txt_record = (dns_txt_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("Length: %u"), pdns_txt_record->Length);
		fwprintf_s(OutputFile, _T("\n         TXT: \""));
		for (Index = Location + sizeof(dns_txt_record);Index < Location + Length;++Index)
			fwprintf_s(OutputFile, _T("%c"), Buffer[Index]);
		fwprintf_s(OutputFile, _T("\""));
	}
//AAAA Record(IPv6 address)
	else if (Type == htons(DNS_RECORD_AAAA) && Length == sizeof(in6_addr))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		std::shared_ptr<char> BufferTemp(new char[ADDR_STRING_MAXSIZE]());
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //x86
		DWORD BufferLength = ADDR_STRING_MAXSIZE;
		std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
		SockAddr->ss_family = AF_INET6;
		((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = *(in6_addr *)(Buffer + Location);
		WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, BufferTemp.get(), &BufferLength);
	#else
		inet_ntop(AF_INET6, Buffer + Location, BufferTemp.get(), ADDR_STRING_MAXSIZE);
	#endif
		CaseConvert(true, BufferTemp.get(), strnlen_s(BufferTemp.get(), ADDR_STRING_MAXSIZE));

		for (Index = 0;Index < strnlen_s(BufferTemp.get(), ADDR_STRING_MAXSIZE);++Index)
			fwprintf_s(OutputFile, _T("%c"), BufferTemp.get()[Index]);
	}
//SRV Record(Server Selection)
	else if (Type == htons(DNS_RECORD_SRV))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		auto pdns_srv_record = (dns_srv_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("Priority: %x"), ntohs(pdns_srv_record->Priority));
		fwprintf_s(OutputFile, _T("\n         Weight: %u"), ntohs(pdns_srv_record->Weight));
		fwprintf_s(OutputFile, _T("\n         Port: %u"), ntohs(pdns_srv_record->Port));
		fwprintf_s(OutputFile, _T("\n         Target: "));
		PrintDomainName(Buffer, Location + sizeof(dns_srv_record), OutputFile);
	}
//OPT/EDNS0 Record(Extension Mechanisms for Domain Name System)
	else if (Type == htons(DNS_RECORD_OPT))
	{
		fwprintf_s(OutputFile, _T("   Data: "));

		auto pdns_opt_record = (dns_opt_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("UDP Playload Size: %u"), ntohs(pdns_opt_record->UDPPayloadSize));
		fwprintf_s(OutputFile, _T("\n         Extended RCode: %x"), pdns_opt_record->Extended_RCode);
		fwprintf_s(OutputFile, _T("\n         EDNS0 Version: %u"), pdns_opt_record->Version);
		if (ntohs(pdns_opt_record->Z_Field) >> HIGHEST_MOVE_BIT_U16 == 0)
			fwprintf_s(OutputFile, _T("\n         Server cannot handle DNSSEC security RRs."));
		else
			fwprintf_s(OutputFile, _T("\n         Server can handle DNSSEC security RRs."));

	//EDNS0 Option
		if (Length >= sizeof(dns_edns0_option))
		{
			auto pdns_edns0_option = (dns_edns0_option *)(Buffer + Location + sizeof(dns_opt_record));
			fwprintf_s(OutputFile, _T("\n         EDNS0 Option:\n                         Code: "));
			if (pdns_edns0_option->Code == htons(EDNS0_CODE_LLQ))
				fwprintf_s(OutputFile, _T("LLQ"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_UL))
				fwprintf_s(OutputFile, _T("LLQ"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_NSID))
				fwprintf_s(OutputFile, _T(""));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_OWNER))
				fwprintf_s(OutputFile, _T("OWNER"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DAU))
				fwprintf_s(OutputFile, _T("DAU"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_DHU))
				fwprintf_s(OutputFile, _T("DHU"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_N3U))
				fwprintf_s(OutputFile, _T("N3U"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET))
				fwprintf_s(OutputFile, _T("CLIENT_SUBNET"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_EDNS_EXPIRE))
				fwprintf_s(OutputFile, _T("EDNS_EXPIRE"));
			else if (pdns_edns0_option->Code == htons(EDNS0_CODE_CLIENT_SUBNET_EXP))
				fwprintf_s(OutputFile, _T("CLIENT_SUBNET_EXP"));
			else
				fwprintf_s(OutputFile, _T("%x"), ntohs(pdns_edns0_option->Code));
			fwprintf_s(OutputFile, _T("\n                         Length: %x"), ntohs(pdns_edns0_option->Length));
		}
	}
//RRSIG Record(Resource Record digital SIGnature)
	else if (Type == htons(DNS_RECORD_RRSIG))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		auto pdns_rrsig_record = (dns_rrsig_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("Type Covered: 0x%04x"), ntohs(pdns_rrsig_record->TypeCovered));
		PrintTypeClassesName(pdns_rrsig_record->TypeCovered, 0);
		fwprintf_s(OutputFile, _T("         Algorithm: "));
		if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_MD5)
			fwprintf_s(OutputFile, _T("RSA/MD5"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DH)
			fwprintf_s(OutputFile, _T("DH"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA)
			fwprintf_s(OutputFile, _T("DSA"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC)
			fwprintf_s(OutputFile, _T("ECC"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1)
			fwprintf_s(OutputFile, _T("RSA/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_DSA_NSEC3_SHA1)
			fwprintf_s(OutputFile, _T("DSA/NSEC3/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1)
			fwprintf_s(OutputFile, _T("RSA/SHA-1/NSEC3/SHA-1"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA256)
			fwprintf_s(OutputFile, _T("RSA/SHA-256"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_RSA_SHA512)
			fwprintf_s(OutputFile, _T("RSA/SHA-512"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECC_GOST)
			fwprintf_s(OutputFile, _T("ECC/GOST"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P256_SHA256)
			fwprintf_s(OutputFile, _T("ECDSA P256/SHA-256"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_ECDSA_P386_SHA386)
			fwprintf_s(OutputFile, _T("ECDSA P386/SHA-386"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_HMAC_MD5)
			fwprintf_s(OutputFile, _T("HMAC/MD5"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_INDIRECT)
			fwprintf_s(OutputFile, _T("Indirect"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_DNS)
			fwprintf_s(OutputFile, _T("Private DNS"));
		else if (pdns_rrsig_record->Algorithm == DNSSEC_AlGORITHM_PRIVATE_OID)
			fwprintf_s(OutputFile, _T("Private OID"));
		else 
			fwprintf_s(OutputFile, _T("%u"), pdns_rrsig_record->Algorithm);
		fwprintf_s(OutputFile, _T("\n         Labels: %u"), pdns_rrsig_record->Labels);
		fwprintf_s(OutputFile, _T("\n         Original TTL: %u"), ntohl(pdns_rrsig_record->TTL));
		PrintSecondsInDateTime(ntohl(pdns_rrsig_record->TTL));
		fwprintf_s(OutputFile, _T("\n         Signature Expiration: "));
		PrintDateTime(ntohl(pdns_rrsig_record->Expiration));
		fwprintf_s(OutputFile, _T("\n         Signature Inception: "));
		PrintDateTime(ntohl(pdns_rrsig_record->Inception));
		fwprintf_s(OutputFile, _T("\n         Key Tag: %u"), ntohs(pdns_rrsig_record->KeyTag));
		fwprintf_s(OutputFile, _T("\n         Signer's name: "));
		CurrentLength = PrintDomainName(Buffer, Location + sizeof(dns_rrsig_record), OutputFile) + 1U;
		CurrentLength += sizeof(dns_rrsig_record);
		fwprintf_s(OutputFile, _T("\n         Signature: "));
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			fwprintf_s(OutputFile, _T("%02x"), (UCHAR)Buffer[Index]);
	}
//NSEC Record(Next-SECure)
	else if (Type == htons(DNS_RECORD_NSEC))
	{
		fwprintf_s(OutputFile, _T("\n   Data: "));

		fwprintf_s(OutputFile, _T("Next Domain Name: "));
		CurrentLength = PrintDomainName(Buffer, Location, OutputFile);
		fwprintf_s(OutputFile, _T("\n         List of Type Bit Map: "));
		for (Index = Location + CurrentLength;Index < Location + Length;++Index)
			fwprintf_s(OutputFile, _T("%x"), (UCHAR)Buffer[Index]);
	}
//CAA Record(Certification Authority Authorization)
	else if (Type == htons(DNS_RECORD_CAA))
	{
		fwprintf_s(OutputFile, _T("   Data: "));

		auto pdns_caa_record = (dns_caa_record *)(Buffer + Location);
		fwprintf_s(OutputFile, _T("Flags: %x"), pdns_caa_record->Flags);
		fwprintf_s(OutputFile, _T("\n         Length: %u"), pdns_caa_record->Length);
		fwprintf_s(OutputFile, _T("\n         Tag: \""));
		for (Index = Location + sizeof(dns_caa_record);Index < Location + sizeof(dns_caa_record) + pdns_caa_record->Length;++Index)
			fwprintf_s(OutputFile, _T("%c"), Buffer[Index]);
		fwprintf_s(OutputFile, _T("\""));
		fwprintf_s(OutputFile, _T("\n         Value: \""));
		for (Index = Location + sizeof(dns_caa_record) + pdns_caa_record->Length;Index < Location + Length;++Index)
			fwprintf_s(OutputFile, _T("%c"), Buffer[Index]);
		fwprintf_s(OutputFile, _T("\""));
	}

	fwprintf_s(OutputFile, _T("\n"));
	return;
}
