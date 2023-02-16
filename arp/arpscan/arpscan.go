// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// arpscan implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   - Generating and sending packet data
//   - Reading in packet data and interpreting it
//   - Use of the 'pcap' subpackage for reading/writing
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/qeof/q"
)

type Device struct {
	IpAddr    net.IP           `json:"ipaddr"`
	HwAddr    net.HardwareAddr `json:"hwaddr"`
	Timestamp string           `json:"timestamp"`
	RespCount int              `json:"respcount"`
}

var Devices map[string]Device

func init() {
	q.O = "stderr"
	q.P = ".*"
	Devices = make(map[string]Device)
}

func main() {
	delay := flag.Int("d", 5, "seconds between ARP requests")
	timeout := flag.Int("t", 30, "seconds to wait")
	flag.StringVar(&q.O, "O", "stderr", "debug log output")
	flag.StringVar(&q.P, "P", ".*", "debug log pattern")
	flag.Parse()

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		if SkipIf(iface) {
			continue
		}
		wg.Add(1)

		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface, *delay, *timeout); err != nil {
				q.Q(iface, err)
			}
			q.Q(Devices, len(Devices))
		}(iface)
	}

	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()

	q.Q("scan complete")
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface, delay int, timeout int) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	q.Q(iface.Name)
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	q.Q(addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)

	timeoutChan := time.After(time.Duration(timeout) * time.Second)
	tickChan := time.Tick(time.Duration(delay) * time.Second)
	for {
		select {
		case <-timeoutChan:
			return nil
		case <-tickChan:
			if err := writeARP(handle, iface, addr); err != nil {
				q.Q(iface.Name, err)
				return err
			}
		}
	}
	return nil
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	var packet gopacket.Packet
	for {
		select {
		case <-stop:
			return
		case packet = <-in:
			if packet == nil {
				continue
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			ipaddr := net.IP(arp.SourceProtAddress)
			hwaddr := net.HardwareAddr(arp.SourceHwAddress)
			key := hwaddr.String()
			dev, ok := Devices[key]
			if !ok {
				q.Q("new device", ipaddr.String(), hwaddr.String())
				dev = Device{
					IpAddr:    ipaddr,
					HwAddr:    hwaddr,
					Timestamp: time.Now().Format(time.RFC3339),
				}
			}
			dev.RespCount++
			Devices[key] = dev
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

func BogusIf(name string, description string) bool {
	if name == "lo" || name == "bluetooth-monitor" || name == "nflog" ||
		name == "nfqueue" || name == "\\Device\\NPF_Loopback" ||
		strings.HasPrefix(name, "docker") ||
		strings.HasPrefix(name, "br-") ||
		strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(description, "Hyper-V") ||
		strings.HasPrefix(description, "Bluetooth") ||
		strings.HasPrefix(description, "Leaf Networks") ||
		strings.HasPrefix(description, "VMware") ||
		strings.HasPrefix(description, "Microsoft Wi-Fi Direct") ||
		strings.HasPrefix(description, "WireGuard") ||
		strings.HasPrefix(description, "WAN Miniport") {
		return true
	}
	return false
}

func SkipIf(iface net.Interface) bool {
	if BogusIf(iface.Name, "") {
		return true
	}
	if iface.Flags&net.FlagUp == 0 {
		return true
	}
	if iface.Flags&net.FlagBroadcast == 0 {
		return true
	}
	return false
}
