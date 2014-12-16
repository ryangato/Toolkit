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

extern FILE *OutputFile;

//Catch Control-C exception from keyboard.
BOOL __fastcall CtrlHandler(const DWORD fdwCtrlType)
{
	switch(fdwCtrlType)
	{
	//Handle the CTRL-C signal.
		case CTRL_C_EVENT:
		{
			wprintf_s(L"Get Control-C.\n");
			PrintProcess(true, true);

		//Close file handle.
			if (OutputFile != nullptr)
				fclose(OutputFile);

			WSACleanup();
			return FALSE;
		}
	//Handle the CTRL-Break signal.
		case CTRL_BREAK_EVENT:
		{
			wprintf_s(L"Get Control-Break.\n");
			PrintProcess(true, true);

			WSACleanup();
			return TRUE;
		}
	//Handle the Closing program signal.
		case CTRL_CLOSE_EVENT:
		{
			PrintProcess(true, true);

		//Close file handle.
			if (OutputFile != nullptr)
				fclose(OutputFile);

			WSACleanup();
			return FALSE;
		}
	//Handle the Closing program signal.
		case CTRL_LOGOFF_EVENT:
		{
			PrintProcess(true, true);

		//Close file handle.
			if (OutputFile != nullptr)
				fclose(OutputFile);

			WSACleanup();
			return FALSE;
		}
	//Handle the shutdown signal.
		case CTRL_SHUTDOWN_EVENT:
		{
			PrintProcess(true, true);

		//Close file handle.
			if (OutputFile != nullptr)
				fclose(OutputFile);

			WSACleanup();
			return FALSE;
		}
		default:
		{
			PrintProcess(true, true);

		//Close file handle.
			if (OutputFile != nullptr)
				fclose(OutputFile);

			WSACleanup();
			return FALSE;
		}
	}
}
