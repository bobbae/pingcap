package pingscan

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/miekg/pcap"
	"github.com/poofyleek/glog"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	SrcIPAddr  string
	SrcMACAddr string
	SrcVendor  string
}

type PingScanResult struct {
	Type string
	Scan ScanResult
}

func pingAll(CIDR string, ch chan *PingScanResult) {
	ip, ipnet, err := net.ParseCIDR(CIDR)
	if err != nil {
		glog.Fatal(err)
	}
	targets := make([]string, 0)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		glog.V(4).Infof("adding %v", ip)
		targets = append(targets, ip.String())
	}
	var wg sync.WaitGroup
	for _, ip := range targets {
		wg.Add(1)
		go func(ipa string) {
			ping(ipa)
			psRes := PingScanResult{}
			psRes.Type = "ping"
			ch <- &psRes
			wg.Done()
		}(ip)
	}
	wg.Wait()
}

// From Russ Cox
// http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func PingScan(CIDR, OUIFile, dev string, ch chan *PingScanResult) error {
	h, err := pcap.OpenLive(dev, 256, true, 500)
	if err != nil {
		return err
	}
	defer h.Close()
	err = h.SetFilter("icmp")
	if err != nil {
		return err
	}
	go func() {
		pingAll(CIDR, ch)
	}()
	ouiDB := make(map[string]string)
	ouiFileExists := true
	f, err := os.OpenFile(OUIFile, os.O_RDONLY, 0666)
	if err != nil {
		ouiFileExists = false
	}
	defer f.Close()
	if ouiFileExists {
		fc, err := ioutil.ReadFile(OUIFile)
		if err == nil {
			lines := strings.Split(string(fc), "\n")
			for _, line := range lines {
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				ouiDB[fields[0]] = strings.Join(fields[1:], " ")
			}
		}
	}
	sres := []ScanResult{}
	// REDFLAG: cannot put this loop in goroutine because of
	// runtime.sigpanic from pkg/runtime/os_linux.c:222
	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			continue
		}
		pkt.Decode()
		srcVend := "?"
		destVend := "?"
		if len(ouiDB) > 0 {
			srcVend = fmt.Sprintf("%02X%02X%02X",
				pkt.SrcMac&0xff0000000000>>40,
				pkt.SrcMac&0xff00000000>>32,
				pkt.SrcMac&0xff000000>>24)
			srcVend = ouiDB[srcVend]
			destVend = fmt.Sprintf("%02X%02X%02X",
				pkt.DestMac&0xff0000000000>>40,
				pkt.DestMac&0xff00000000>>32,
				pkt.DestMac&0xff000000>>24)
			destVend = ouiDB[destVend]
		}
		glog.V(2).Infof("pkt: ether[%02X:%012X(%s):%012X(%s)] %v",
			pkt.Type, pkt.DestMac, destVend, pkt.SrcMac, srcVend, pkt)
		sr := ScanResult{}
		sr.SrcMACAddr = fmt.Sprintf("%012X", pkt.SrcMac)
		sr.SrcVendor = srcVend
		sr.SrcIPAddr = ""
		var ip *pcap.Iphdr
		for _, h := range pkt.Headers {
			glog.Infof("%v", reflect.TypeOf(h))
			if reflect.TypeOf(h) == reflect.TypeOf(ip) {
				ip = h.(*pcap.Iphdr)
				sr.SrcIPAddr = ip.SrcAddr()
			}
		}
		sres = append(sres, sr)
		psRes := PingScanResult{}
		psRes.Type = "scan"
		psRes.Scan = sr
		ch <- &psRes
	}
	//not reached
	glog.V(2).Infof("exiting pcap capture. %v", h.Geterror())
	return nil
}

// icmpMessage represents an ICMP message.
type icmpMessage struct {
	Type     int             // type
	Code     int             // code
	Checksum int             // checksum
	Body     icmpMessageBody // body
}

// icmpMessageBody represents an ICMP message body.
type icmpMessageBody interface {
	Len() int
	Marshal() ([]byte, error)
}

type icmpEcho struct {
	ID   int    // identifier
	Seq  int    // sequence number
	Data []byte // data
}

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

func ping(ip string) error {
	c, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		panic(err)
	}
	glog.V(4).Infof("icmp to %s\n", ip)
	c.SetDeadline(time.Now().Add(time.Second))
	defer c.Close()
	typ := icmpv4EchoRequest
	xid := os.Getpid() & 0xffff
	xseq := 1
	wb, err := (&icmpMessage{Type: typ, Code: 0, Body: &icmpEcho{ID: xid, Seq: xseq, Data: bytes.Repeat([]byte("Go ping"), 10)}}).Marshal()
	if err != nil {
		return err
	}
	if _, err := c.Write(wb); err != nil {
		return err
	}
	rb := make([]byte, 20+len(wb))
	var m *icmpMessage
	for {
		if _, err := c.Read(rb); err != nil {
			if strings.HasSuffix(err.Error(), "i/o timeout") {
				return fmt.Errorf("timeout: %v", err)
			} else {
				return (err)
			}
		}
		rb = ipv4Payload(rb)
		if m, err = parseICMPMessage(rb); err != nil {
			return (err)
		}
		switch m.Type {
		case icmpv4EchoRequest:
			continue
		}
		break
	}
	switch p := m.Body.(type) {
	case *icmpEcho:
		if p.ID != xid || p.Seq != xseq {
			fmt.Printf("bad xid %d != %d seq %d != %d\n", p.ID, xid, p.Seq, xseq)
			return fmt.Errorf("bad xid")
		}
	default:
		return fmt.Errorf("bad type")
	}
	glog.V(2).Infof("got %v", m)
	return nil
}

func ipv4Payload(b []byte) []byte {
	if len(b) < 20 {
		return b
	}
	hdrlen := int(b[0]&0xf) << 2
	return b[hdrlen:]
}

func parseICMPEcho(b []byte) (*icmpEcho, error) {
	bodylen := len(b)
	p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

func parseICMPMessage(b []byte) (*icmpMessage, error) {
	msglen := len(b)
	if msglen < 4 {
		return nil, errors.New("message too short")
	}
	m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
	if msglen > 4 {
		var err error
		switch m.Type {
		case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
			m.Body, err = parseICMPEcho(b[4:])
			if err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

func (p *icmpEcho) Len() int {
	if p == nil {
		return 0
	}
	return 4 + len(p.Data)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message body p.
func (p *icmpEcho) Marshal() ([]byte, error) {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = byte(p.ID>>8), byte(p.ID)
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq)
	copy(b[4:], p.Data)
	return b, nil
}

func (m *icmpMessage) Marshal() ([]byte, error) {
	b := []byte{byte(m.Type), byte(m.Code), 0, 0}
	if m.Body != nil && m.Body.Len() != 0 {
		mb, err := m.Body.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, mb...)
	}
	switch m.Type {
	case icmpv6EchoRequest, icmpv6EchoReply:
		return b, nil
	}
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	// Place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero.
	b[2] ^= byte(^s)
	b[3] ^= byte(^s >> 8)
	return b, nil
}
