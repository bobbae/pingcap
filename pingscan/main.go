package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/bobbae/glog"
	"github.com/bobbae/pingscan"
	"os"
	"time"
)

func main() {
	var CIDR, dev, OUIFile string
	var timeout int64
	JSON := false
	flag.BoolVar(&JSON, "json", false, "output JSON")
	flag.StringVar(&CIDR, "cidr", "", "CIDR to scan")
	flag.StringVar(&OUIFile, "ouifile", "ieee-oui.txt", "IEEE OUI database text file")
	flag.StringVar(&dev, "dev", "", "net device to use")
	flag.Int64Var(&timeout, "timeout", 5, "seconds to timeout")
	flag.Parse()
	if dev == "" || CIDR == "" {
		flag.Usage()
		os.Exit(1)
	}
	ch := make(chan *pingscan.PingScanResult, 1)
	startTime := time.Now().Unix()
	go func() {
		for {
			time.Sleep(time.Second)
			if (time.Now().Unix() - startTime) > timeout {
				glog.V(2).Infof("stopping after %d seconds.", timeout)
				os.Exit(1)
			}
		}
	}()
	go func() {
		for {
			res := <-ch
			if res.Type == "scan" {
				if JSON {
					jstr, err := json.Marshal(res.Scan)
					if err != nil {
						glog.Errorf("marshalling error: %v", err)
						continue
					}
					fmt.Println(string(jstr))
				} else {
					fmt.Println(res.Scan)
				}
			}
		}
	}()
	err := pingscan.PingScan(CIDR, OUIFile, dev, ch)
	if err != nil {
		panic(err)
	}
}
