// This code is part of Toolkit(FileHash)
// A useful and powerful toolkit(FileHash)
// Copyright (C) 2012-2016 Chengr28
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


#include "FileHash.h"

//Check empty buffer
bool __fastcall CheckEmptyBuffer(
	const void *Buffer, 
	const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
		return false;

//Scan all data.
	for (size_t Index = 0;Index < Length;++Index)
	{
		if (((uint8_t *)Buffer)[Index] != 0)
			return false;
	}

	return true;
}

//Convert host values to network byte order with 64 bits
uint64_t __fastcall hton64(
	const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)htonl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | (uint32_t)htonl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}

/* Redirect to hton64.
//Convert network byte order to host values with 64 bits
uint64_t __fastcall ntoh64(const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)ntohl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | (uint32_t)ntohl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}
*/

//Convert multiple bytes to wide char string
bool __fastcall MBSToWCSString(
	const char *Buffer, 
	const size_t MaxLen, 
	std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	size_t Length = strnlen_s(Buffer, MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, Length))
		return false;

//Convert string.
	std::shared_ptr<wchar_t> TargetPTR(new wchar_t[Length + 1U]());
	wmemset(TargetPTR.get(), 0, Length + 1U);
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(CP_ACP, 0, Buffer, MBSTOWCS_NULLTERMINATE, TargetPTR.get(), (int)(Length + 1U)) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (mbstowcs(TargetPTR.get(), Buffer, Length + 1U) == (size_t)RETURN_ERROR)
#endif
	{
		return false;
	}
	else {
		Target = TargetPTR.get();
		if (Target.empty())
			return false;
	}

	return true;
}

#if defined(PLATFORM_WIN)
//Convert lowercase/uppercase words to uppercase/lowercase words(C++ wide string version)
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	std::wstring &Buffer)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = (char)toupper(StringIter);
	//Uppercase to lowercase
		else 
			StringIter = (char)tolower(StringIter);
	}

	return;
}
#endif

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ string version)
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	std::string &Buffer)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = (char)toupper(StringIter);
	//Uppercase to lowercase
		else 
			StringIter = (char)tolower(StringIter);
	}

	return;
}

//Derived from original code by CodesInChaos(LibSodium)
char *sodium_bin2hex(
	char *const hex, 
	const size_t hex_maxlen, 
	const unsigned char *const bin, 
	const size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        abort(); /* LCOV_EXCL_LINE */
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 | 
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0U;

    return hex;
}
