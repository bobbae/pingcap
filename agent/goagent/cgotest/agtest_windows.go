// +build windows
package main

/*
#cgo CFLAGS: -I../.. -I. -g -std=c99 -DWIN32 -I C:/WpdPack/Include
#cgo LDFLAGS: -L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32
#include "common.c"
#include "monocypher.c"
*/
import "C"
import (
	"unsafe"
)

func main() {
	/*
		var cstr *C.char = C.get_dev()
		fmt.Printf("%s\n", C.GoString(cstr))
	*/
	defer C.free(unsafe.Pointer(cstr))
	C.show_devs()
}
