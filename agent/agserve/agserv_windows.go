// +build windows
package main

/*
#cgo CFLAGS: -I.. -I. -g -std=c99 -DWIN32 -DCGO -I C:/WpdPack/Include
#cgo LDFLAGS: -L C:/Win10pcap/x64 -lwpcap -liphlpapi -lws2_32
#include "common.c"
#include "monocypher.c"
#include "agrelay.c"
*/
import "C"
import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

type Message struct {
	Type          string `json:"type"`
	Id            string `json:"id"`
	MyEthAddr     string `json:"myEthAddr"`
	PeerPublicKey string `json:"peerPublicKey"`
	SrcEthAddr    string `json:"srcEthAddr"`
	EtherType     string `json:"etherType"`
	PlainText     string `json:"plainText"`
	Extra         string `json:"extra"`
}

var wg sync.WaitGroup

var devList = sync.Map{}

func main() {
	port := flag.Int("p", 28080, "port")
	devNum := flag.Int("d", -1, "device number")
	listDev := flag.Bool("l", false, "list devices")
	address := flag.String("a", "localhost", "udp server")
	flag.Parse()
	if *listDev {
		C.show_devs()
		os.Exit(0)
	}
	if *devNum == -1 {
		fmt.Println("error: device number required.")
		os.Exit(1)
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		udpAddr := *address + ":" + strconv.Itoa(*port)
		sock, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Println("error: can't listen to UDP socket")
			os.Exit(1)
		}
		defer sock.Close()
		fmt.Println("listening UDP at ", udpAddr)
		buffer := make([]byte, 10000)
		for {
			//fmt.Println("Waiting for UDP input")
			rlen, _, err := sock.ReadFrom(buffer)
			if err != nil {
				fmt.Println("error: UDP read error", err)
				continue
			}
			//fmt.Println("UDP read bytes", rlen, "from", addr, "message", string(buffer[:rlen]))

			var message Message

			if err := json.Unmarshal(buffer[:rlen], &message); err != nil {
				fmt.Println("error: can't parse json message", string(buffer[:rlen]))
				continue
			}
			//fmt.Println("message", message)
			devList.Store(message.Id, message)
		}
	}()

	go func() {
		defer wg.Done()
		var cstr *C.char = C.CString(*address)

		//fmt.Println("Calling C relay")

		C.run_relay(C.int(*port), C.int(*devNum), cstr)

		//fmt.Println("Finished C relay. Should not happen!")
		defer C.free(unsafe.Pointer(cstr))
	}()

	ticker := time.NewTicker(5000 * time.Millisecond)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			case t := <-ticker.C:

				var dstaddr *C.char = C.CString("ff:ff:ff:ff:ff:ff")
				var msgtype *C.char = C.CString("scan")
				var plainText *C.char = C.CString("send hello") // XXXCMD
				var extra *C.char = C.CString("extra msg in scan")

				fmt.Println("sending plain text", t)
				C.plain_send(dstaddr, msgtype, plainText, extra)

				defer C.free(unsafe.Pointer(dstaddr))
				defer C.free(unsafe.Pointer(msgtype))
				defer C.free(unsafe.Pointer(plainText))
				defer C.free(unsafe.Pointer(extra))
				/*

				   // send ping to each known client that
				   // has sent us a hello in the past
				   devList.Range(func(k, v interface{}) bool {
				       //fmt.Println(k, v)
				       sendPing(v.(Message))
				       return true
				   })
				*/
			}
		}
	}()

	wg.Wait()

	ticker.Stop()
	done <- true

	fmt.Println("exit")
}

func sendPing(m Message) {
	//fmt.Println("sendPing")

	var myaddr *C.char = C.CString(m.MyEthAddr)
	var peerPub *C.char = C.CString(m.PeerPublicKey)
	var dstaddr *C.char = C.CString(m.SrcEthAddr)
	var msgtype *C.char = C.CString("ping")
	var plainText *C.char = C.CString("send info") // XXXCMD
	var extra *C.char = C.CString("extra msg in ping")

	C.encrypt_send(myaddr, dstaddr, peerPub, msgtype, plainText, extra)

	defer C.free(unsafe.Pointer(myaddr))
	defer C.free(unsafe.Pointer(peerPub))
	defer C.free(unsafe.Pointer(dstaddr))
	defer C.free(unsafe.Pointer(msgtype))
	defer C.free(unsafe.Pointer(plainText))
	defer C.free(unsafe.Pointer(extra))
}
