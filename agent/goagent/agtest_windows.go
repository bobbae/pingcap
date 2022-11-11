// +build windows
package main

/*
#cgo CFLAGS: -I.. -I. -g -std=c99 -DWIN32 -I C:/WpdPack/Include
#cgo LDFLAGS: -L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32
#include "common.c"
#include "monocypher.c"
*/
import "C"

func main() {
    C.show_devs()
}
