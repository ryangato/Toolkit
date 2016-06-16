// This code is part of Toolkit(DNSPing)
// A useful and powerful toolkit(DNSPing)
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


#include "Base.h"

//GlobalStatus class constructor
ConfigurationTable::ConfigurationTable(
	void)
{
#if defined(PLATFORM_WIN)
	memset(this, 0, sizeof(ConfigurationTable) - (sizeof(std::string) * 5U + sizeof(std::wstring) * 3U + sizeof(std::shared_ptr<char>)));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	memset(this, 0, sizeof(ConfigurationTable) - (sizeof(std::string) * 6U + sizeof(std::wstring) * 3U + sizeof(std::shared_ptr<char>)));
#endif

	Statistics_Send = DEFAULT_SEND_TIMES;
	BufferSize = PACKET_MAXSIZE;
	Validate = true;
#if defined(PLATFORM_WIN)
	SocketTimeout = DEFAULT_TIME_OUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SocketTimeout.tv_sec = DEFAULT_TIME_OUT;
#endif

	return;
}

//GlobalStatus class destructor
ConfigurationTable::~ConfigurationTable(
	void)
{
//Close all file and network handles.
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	_fcloseall();
	#if defined(PLATFORM_WIN)
		if (Initialization_WinSock)
			WSACleanup();
	#endif
#endif

	return;
}
