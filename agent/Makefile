default: agclient agserve
CC=gcc
ifeq ($(OS),Windows_NT)
DEBUG=-g
INC=-I C:/WpdPack/Include
CFLAGS=-std=c99 -DWIN32 $(INC) $(DEBUG)
LIBS=-L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32 
EXE=.exe
else
DEBUG=-g
EXE=
LIBS=-lpcap
INC=-I /usr/local/include
CFLAGS=-std=c99 $(INC) $(DEBUG)
endif
INCFILES=common.h jsmn.h monocypher.h

agclient.o: agclient.c $(INCFILES)

agserve.o: agserve.c $(INCFILES)

common.o: common.c $(INCFILES)

agclient: agclient.o monocypher.o common.o
	gcc -o agclient$(EXE) agclient.o monocypher.o common.o $(LIBS)

agserve: agserve.o monocypher.o common.o
	gcc -o agserve$(EXE) agserve.o monocypher.o common.o $(LIBS)
