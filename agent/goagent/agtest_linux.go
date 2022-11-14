// +build linux
package main

/*
#cgo CFLAGS: -I.. -I. -g -std=c99 -DCGO -DLINUX -I /usr/local/include
#cgo LDFLAGS: -lpcap
#include "common.c"
#include "monocypher.c"
*/
import "C"

func main() {
	C.show_devs()
}
