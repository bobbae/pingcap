default: capture sendpack
CC=gcc
ifeq ($(OS),Windows_NT)
DEBUG=-g
INC=-I C:/WpdPack/Include
CFLAGS=-std=c99 -DWINNT $(INC) $(DEBUG)
LIBS=-L C:/Win10pcap/x64 -lwpcap -lws2_32
EXE=.exe
else
DEBUG=
EXE=
LIBS=-lpcap
INC=-I /usr/local/include
CFLAGS=-std=c99 $(INC) $(DEBUG)
endif



capture: capture.c
	gcc $(INC) -o capture$(EXE) capture.c $(LIBS)

sendpack: sendpack.c
	gcc $(INC) -o sendpack$(EXE) sendpack.c $(LIBS)
