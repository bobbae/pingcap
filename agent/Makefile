default: agclient 

all: agclient dumqtt agserve

CC=gcc
ifeq ($(OS),Windows_NT)
DEBUG=-g
INC=-I C:/WpdPack/Include -I.
CFLAGS=-std=c99 -DWIN32 $(INC) $(DEBUG)
LIBS=-L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32 
EXE=.exe
else
ifeq ($(shell uname),Linux)
DEBUG=-g
EXE=
LIBS=-lpcap
INC=-I /usr/local/include -I.
CFLAGS=-std=c99 -DLINUX $(INC) $(DEBUG)
endif
endif

INCFILES=common.h jsmn.h monocypher.h

agclient.o: agclient.c $(INCFILES)

common.o: common.c $(INCFILES)

agclient: agclient.o monocypher.o common.o b64.o
	gcc -o agclient$(EXE) $^  $(LIBS)

.PHONY: agserve
agserve: 
	cd agserve; go build -a

test: test.o common.o monocypher.o
	gcc -o test$(EXE) $^ $(LIBS)

dumqtt: dumqtt.o mqtt.o mqtt_pal.o
	gcc  $(CFLAGS) -o dumqtt$(EXE) $^  $(LIBS)
