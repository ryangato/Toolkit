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

extern std::string TestDomain;
extern std::wstring wTargetString;
extern long double TotalTime, MaxTime, MinTime;
extern size_t SendNum, RealSendNum, RecvNum, TransmissionInterval, BufferSize, RawDataLen;
extern uint16_t Protocol, ServiceType;
extern std::shared_ptr<char> RawData;
extern bool RawSocket, EDNS0, DNSSEC, Validate, ShowResponse, ShowResponseHex;
extern int IP_HopLimits;
#if defined(PLATFORM_WIN)
	extern int SocketTimeout;
	extern bool IPv4_DF;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	extern timeval SocketTimeout;
#endif
extern dns_hdr HeaderParameter;
extern dns_qry QueryParameter;
extern dns_opt_record EDNS0Parameter;
extern FILE *OutputFile;
