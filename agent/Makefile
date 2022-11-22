default: agclient agserve
CC=gcc
ifeq ($(OS),Windows_NT)
DEBUG=-g
INC=-I C:/WpdPack/Include
CFLAGS=-std=c99 -DWIN32 $(INC) $(DEBUG)
LIBS=-L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32 
EXE=.exe
else
ifeq ($(shell uname),Linux)
DEBUG=-g
EXE=
LIBS=-lpcap
INC=-I /usr/local/include
CFLAGS=-std=c99 -DLINUX $(INC) $(DEBUG)
endif
endif

INCFILES=common.h jsmn.h monocypher.h

agclient.o: agclient.c $(INCFILES)

common.o: common.c $(INCFILES)

agclient: agclient.o monocypher.o common.o
	gcc -o agclient$(EXE) agclient.o monocypher.o common.o $(LIBS)

.PHONY:
agserve: agrelay.c $(INCFILES)  agserve/agserv_linux.go agserve/agserv_windows.go
	cd agserve; go build -a

test: test.o common.o
	gcc -o test$(EXE) test.o monocypher.o common.o $(LIBS)

OBJ1=dumqtt.o mqtt.o mqtt_pal.o

dumqtt: $(OBJ1)
	gcc  $(CFLAGS) -o dumqtt$(EXE) $(OBJ1)  $(LIBS)
