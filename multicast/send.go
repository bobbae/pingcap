package main

import (
	"log"
	"net"
	"time"
)

const (
	srvAddr         = "224.1.1.1:5004"
	maxDatagramSize = 8192
)

func main() {
	ping(srvAddr)
}

func ping(a string) {
	addr, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		log.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, addr)
	for {
		c.Write([]byte("hello, world\n"))
		time.Sleep(1 * time.Second)
	}
}

