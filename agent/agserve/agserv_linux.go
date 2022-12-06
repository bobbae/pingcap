// +build linux
package main

/*
#cgo CFLAGS: -I.. -I. -g -std=c99 -DCGO -DLINUX -I /usr/local/include
#cgo LDFLAGS: -lpcap
#include "common.c"
#include "monocypher.c"
#include "agrelay.c"
*/
import "C"
import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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


var cmdChan chan string

func main() {
	var wg sync.WaitGroup
	var devList = sync.Map{}

	port := flag.Int("p", 28080, "port")
	devNum := flag.Int("d", -1, "device number")
	listDev := flag.Bool("l", false, "list devices")
	address := flag.String("a", "localhost", "udp server")
	delay := flag.Int("t", 5, "time delay")
	flag.Parse()
	if *listDev {
		C.show_devs()
		os.Exit(0)
	}
	if *devNum == -1 {
		fmt.Println("error: device number required.")
		os.Exit(1)
	}
	cmdChan = make(chan string, 10)
	wg.Add(1)

	//get forwarded frame from C via UDP socket
	go func() {

		defer wg.Done()
		udpAddr := *address + ":" + strconv.Itoa(*port)
		sock, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Println("error: can't listen to UDP socket")
			os.Exit(1)
		}
		defer sock.Close()
        fmt.Println("debug: listening UDP at ", udpAddr)
		buffer := make([]byte, 10000)
		for {
            //fmt.Println("debug: Waiting for UDP input")
			rlen, _, err := sock.ReadFrom(buffer)
			if err != nil {
				fmt.Println("error: UDP read error", err)
				continue
			}
            fmt.Println("debug: UDP read bytes", rlen, string(buffer[:rlen]))

			var message Message

			if err := json.Unmarshal(buffer[:rlen], &message); err != nil {
				fmt.Println("error: can't parse json message", string(buffer[:rlen]))
				continue
			}
            //fmt.Println("debug: add to devList message", message)
			devList.Store(message.PeerPublicKey, message) // XXX pretender with stolen ID may inject a message?
		}
	}()

	wg.Add(1)

	//run C relay
	go func() {

		defer wg.Done()
		var cstr *C.char = C.CString(*address)

        fmt.Println("debug: Calling C relay")

		C.run_relay(C.int(*port), C.int(*devNum), cstr)

        fmt.Println("debug: Finished C relay. Should not happen!")
		defer C.free(unsafe.Pointer(cstr))
	}()

	ticker := time.NewTicker(time.Duration(*delay * 1000) * time.Millisecond)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
                fmt.Println("debug: timed sender done")
				return
			case <-ticker.C:
				//fmt.Println("debug: ticker")
				// XXX do some book keeping TODO
			case inCmd := <-cmdChan:
				numSent := 0
				fmt.Println("inCmd",inCmd)
				// send ping to each known client that
				// has sent us a hello in the past
				devList.Range(func(k, v interface{}) bool {
                    //fmt.Println("debug: devList kv", k, v)
					numSent++
					if inCmd != "" {
						fmt.Println("debug: inCmd", inCmd)
					}
					if inCmd == "ping" {
						sendMessage(v.(Message), "ping", "send info", "some extra")
						return true
					}
					if inCmd == "hello" {
						sendHello()
						return true
					}
					if strings.HasPrefix(inCmd, "!")  {
						inCmd = inCmd[1:]
						sEnc := base64.StdEncoding.EncodeToString([]byte(inCmd))
                        fmt.Println("debug: sEnc", sEnc)
						sendMessage(v.(Message), "cmd", sEnc, "some extra")
						return true
					} 
					return true
				})
                //fmt.Println("debug: numSent",numSent)
			}
		}
	}()

	wg.Add(1)

	// send CLI command from HTTP user
	go func() {

		defer wg.Done()
		//  form POST to  get user command to send to agent
		http.HandleFunc("/cli", handleCommand)
		address := ":9090"
        fmt.Println("info: HTTP serving at", address)

		err := http.ListenAndServe(address, nil) // setting listening port
		if err != nil {
			fmt.Println("error: HTTP ListenAndServe", err)
		}
	}()

	wg.Wait()

	ticker.Stop()
	done <- true

    fmt.Println("info: program exit")
}

func handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		command := r.Form["command"]
		cmdLine := strings.Join(command, " ")
		if len(cmdLine) >= 128 {
			fmt.Println("error: cmdLine too long", len(cmdLine), cmdLine)
			return
		}
		cmdChan <- cmdLine
        fmt.Println("debug: handling POST command", cmdLine)
	}

	t, _ := template.ParseFiles("cli.template")
	t.Execute(w, nil)
}

func sendMessage(m Message, mtype string, msg string, exmsg string) {
    fmt.Println("debug: sending message", mtype, msg, exmsg)
	var myaddr *C.char = C.CString(m.MyEthAddr)
	var peerPub *C.char = C.CString(m.PeerPublicKey)
	var dstaddr *C.char = C.CString(m.SrcEthAddr)
	var msgtype *C.char = C.CString(mtype)
	var plainText *C.char = C.CString(msg) // XXXCMD
	var extra *C.char = C.CString(exmsg)

	C.encrypt_send(myaddr, dstaddr, peerPub, msgtype, plainText, extra)

	defer C.free(unsafe.Pointer(myaddr))
	defer C.free(unsafe.Pointer(peerPub))
	defer C.free(unsafe.Pointer(dstaddr))
	defer C.free(unsafe.Pointer(msgtype))
	defer C.free(unsafe.Pointer(plainText))
	defer C.free(unsafe.Pointer(extra))
}

func sendHello() {
    fmt.Println("debug: send hello")
	var dstaddr *C.char = C.CString("ff:ff:ff:ff:ff:ff")
	var msgtype *C.char = C.CString("scan")
	var plainText *C.char = C.CString("send hello") // XXXCMD
	var extra *C.char = C.CString("extra msg in scan")

	C.plain_send(dstaddr, msgtype, plainText, extra)

	defer C.free(unsafe.Pointer(dstaddr))
	defer C.free(unsafe.Pointer(msgtype))
	defer C.free(unsafe.Pointer(plainText))
	defer C.free(unsafe.Pointer(extra))
}

