# This code is part of DNSPing
# Ping with DNS requesting.
# Copyright (C) 2014-2015 Chengr28
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


cmake_minimum_required(VERSION 3.0.2)

project(DNSPing)

set(CMAKE_BUILD_TYPE "Release")

set(SRC_FILES
		"Base.h"
		"Main.h"
		"Process.h"
		"Protocol.h"
		"Resolver.h"
		"Terminal.h"
		"Main.cpp"
		"Process.cpp"
		"Protocol.cpp"
		"Resolver.cpp"
		"Terminal.cpp")

add_definitions(-std=c++11 -fpic)

add_executable(DNSPing ${SRC_FILES})
