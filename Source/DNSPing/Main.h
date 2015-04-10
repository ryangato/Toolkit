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


#include "Base.h"

#if defined(PLATFORM_WIN)
	std::string TargetString, TestDomain, TargetDomainString;
	std::wstring wTargetString, OutputFileName;
#elif defined(PLATFORM_LINUX)
	std::string TargetString, TestDomain, TargetDomainString, OutputFileName;
#endif
long double TotalTime = 0, MaxTime = 0, MinTime = 0;
size_t SendNum = DEFAULT_SEND_TIMES, RealSendNum = 0, RecvNum = 0, TransmissionInterval = 0, BufferSize = PACKET_MAXSIZE, RawDataLen = 0, EDNS0PayloadSize = 0;
sockaddr_storage SockAddr = {0};
uint16_t Protocol = 0, ServiceName = 0;
std::shared_ptr<char> RawData;
int IP_HopLimits = 0;
#if defined(PLATFORM_WIN)
	int SocketTimeout = DEFAULT_TIME_OUT;
	auto RawSocket = false, IPv4_DF = false, EDNS0 = false, DNSSEC = false, Validate = true, ShowResponse = false, ShowResponseHex = false;
#elif defined(PLATFORM_LINUX)
	timeval SocketTimeout = {DEFAULT_TIME_OUT, 0};
	auto RawSocket = false, /* IPv4_DF = false, */ EDNS0 = false, DNSSEC = false, Validate = true, ShowResponse = false, ShowResponseHex = false;
#endif
dns_hdr HeaderParameter = {0};
dns_qry QueryParameter = {0};
dns_opt_record EDNS0Parameter = {0};
FILE *OutputFile = nullptr;
