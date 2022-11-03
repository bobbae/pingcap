default: agclient agserve
CC=gcc
ifeq ($(OS),Windows_NT)
CFLAGS=-std=c99 -DWINNT -g
LIBS=-lws2_32
EXE=.exe
else
EXE=
LIBS=
CFLAGS=
endif
INC=common.h jsmn.h monocypher.h

agclient.o: agclient.c $(INC)

agserve.o: agserve.c $(INC)

common.o: common.c $(INC)

agclient: agclient.o monocypher.o common.o
	gcc -o agclient$(EXE) agclient.o monocypher.o common.o $(LIBS)

agserve: agserve.o monocypher.o common.o
	gcc -o agserve$(EXE) agserve.o monocypher.o common.o $(LIBS)
