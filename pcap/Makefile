default: capture sendpack
CC=gcc
ifeq ($(OS),Windows_NT)
CFLAGS=-std=c99 -DWINNT -g
LIBS=-L C:/Win10pcap/x64 -lwpcap -lws2_32
EXE=.exe
else
LIBS=-lpcap
EXE=
CFLAGS=-std=c99
endif
INC=-I C:/WpdPack/Include

capture: capture.c
	gcc $(INC) -o capture$(EXE) capture.c $(LIBS)

sendpack: sendpack.c
	gcc $(INC) -o sendpack$(EXE) sendpack.c $(LIBS)
