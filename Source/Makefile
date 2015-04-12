# This code is part of DNSPing
# DNSPing, Ping with DNS requesting.
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


#Preparing
CC = g++
COM_FLAGS = -std=c++11 -O3 -fpic -static -static-libgcc -static-libstdc++ -L ./ -c
LNK_FLAGS = -std=c++11 -O3 -fpic -static-libgcc -static-libstdc++ -L ./ -lpthread -Xlinker
SRC_DIR = ./DNSPing/
OBJ_DIR = ./Object/
BIN_DIR = ./Release/
Target_Name = $(BIN_DIR)DNSPing

all : Directory Target Clean_OBJ
Directory : 
		@echo 
		@echo Creating directories of object files.
		@-mkdir $(OBJ_DIR)
		@-mkdir $(BIN_DIR)

#Compiling
Target : Terminal.o Protocol.o Resolver.o Process.o Main.o
		@echo Linking all object files...
		@$(CC) $(LNK_FLAGS) $(OBJ_DIR)*.o -o $(Target_Name)
Terminal.o : $(SRC_DIR)Terminal.cpp
		@echo Compiling Terminal module...
		@$(CC) $(COM_FLAGS) $(SRC_DIR)Terminal.cpp -o $(OBJ_DIR)Terminal.o
Protocol.o : $(SRC_DIR)Protocol.cpp
		@echo Compiling Protocol module...
		@$(CC) $(COM_FLAGS) $(SRC_DIR)Protocol.cpp -o $(OBJ_DIR)Protocol.o
Resolver.o : $(SRC_DIR)Resolver.cpp
		@echo Compiling Resolver module...
		@$(CC) $(COM_FLAGS) $(SRC_DIR)Resolver.cpp -o $(OBJ_DIR)Resolver.o
Process.o : $(SRC_DIR)Process.cpp
		@echo Compiling Process module...
		@$(CC) $(COM_FLAGS) $(SRC_DIR)Process.cpp -o $(OBJ_DIR)Process.o
Main.o : $(SRC_DIR)Main.cpp
		@echo Compiling Main module...
		@$(CC) $(COM_FLAGS) $(SRC_DIR)Main.cpp -o $(OBJ_DIR)Main.o

#Cleanup
Clean_OBJ : 
		@echo Cleaning...
		@echo All processes are finished, the binary is in Release directory.
		@echo 
		@-rm -f -r ./Object

.PHONY : clean
clean : 
		@echo Cleaning...
		@echo 
		@-rm -f -r ./Object
		@-rm -f -r ./Release
