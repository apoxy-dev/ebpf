package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/rlimit"

	"github.com/apoxy-dev/ebpf/dns"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	if err := dns.TrackDNS(); err != nil {
		fmt.Printf("TrackDNS error: %v\n\n", err)
	}
}
