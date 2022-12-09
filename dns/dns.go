package dns

import (
	"encoding/json"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/ebpf/rawsocket"
	"github.com/apoxy-dev/ebpf/util"
)

type DNSEvent struct {
	Response bool // false = request.
	To       string
	From     string
	Query    string
	Domain   string
	Answer   string
	TTL      uint32
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event_t dns dns.c -- -I../headers

// pkt_type definitions:
// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
var pktTypeNames = []string{
	"HOST",
	"BROADCAST",
	"MULTICAST",
	"OTHERHOST",
	"OUTGOING",
	"LOOPBACK",
	"USER",
	"KERNEL",
}

// List taken from:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
var qTypeNames = map[uint]string{
	1:     "A",
	2:     "NS",
	3:     "MD",
	4:     "MF",
	5:     "CNAME",
	6:     "SOA",
	7:     "MB",
	8:     "MG",
	9:     "MR",
	10:    "NULL",
	11:    "WKS",
	12:    "PTR",
	13:    "HINFO",
	14:    "MINFO",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	19:    "X25",
	20:    "ISDN",
	21:    "RT",
	22:    "NSAP",
	23:    "NSAP-PTR",
	24:    "SIG",
	25:    "KEY",
	26:    "PX",
	27:    "GPOS",
	28:    "AAAA",
	29:    "LOC",
	30:    "NXT",
	31:    "EID",
	32:    "NIMLOC",
	33:    "SRV",
	34:    "ATMA",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	38:    "A6",
	39:    "DNAME",
	40:    "SINK",
	41:    "OPT",
	42:    "APL",
	43:    "DS",
	44:    "SSHFP",
	45:    "IPSECKEY",
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",
	55:    "HIP",
	56:    "NINFO",
	57:    "RKEY",
	58:    "TALINK",
	59:    "CDS",
	60:    "CDNSKEY",
	61:    "OPENPGPKEY",
	62:    "CSYNC",
	63:    "ZONEMD",
	64:    "SVCB",
	65:    "HTTPS",
	99:    "SPF",
	100:   "UINFO",
	101:   "UID",
	102:   "GID",
	103:   "UNSPEC",
	104:   "NID",
	105:   "L32",
	106:   "L64",
	107:   "LP",
	108:   "EUI48",
	109:   "EUI64",
	249:   "TKEY",
	250:   "TSIG",
	251:   "IXFR",
	252:   "AXFR",
	253:   "MAILB",
	254:   "MAILA",
	255:   "*",
	256:   "URI",
	257:   "CAA",
	258:   "AVC",
	259:   "DOA",
	260:   "AMTRELAY",
	32768: "TA",
	32769: "DLV",
}

const MaxDNSName = int(unsafe.Sizeof(dnsEventT{}.Name))

// parseLabelSequence parses a label sequence into a string with dots.
// See https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
func parseLabelSequence(sample []byte) (ret string) {
	sampleBounded := make([]byte, MaxDNSName)
	copy(sampleBounded, sample)

	for i := 0; i < MaxDNSName; i++ {
		length := int(sampleBounded[i])
		if length == 0 {
			break
		}
		if i+1+length < MaxDNSName {
			ret += string(sampleBounded[i+1:i+1+length]) + "."
		}
		i += length
	}
	return ret
}

func TrackDNS() error {
	objs := dnsObjects{}
	if err := loadDnsObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	log.Printf("opening raw socket...\n")
	sock, err := rawsocket.OpenRawSock(0)
	if err != nil {
		return fmt.Errorf("error opening raw socket: %v", err)
	}

	log.Printf("attaching BPF program...\n")
	if err = syscall.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.IgTraceDns.FD()); err != nil {
		return fmt.Errorf("error attaching probe: %v", err)
	}

	log.Printf("awaiting events...\n")
	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		return err
	}
	defer rd.Close()

	for {
		d, err := rd.Read()
		if err != nil {
			return err
		}
		bpfEvent := (*dnsEventT)(unsafe.Pointer(&d.RawSample[0]))

		e := &DNSEvent{
			Response: bpfEvent.Qr == 1,
			Domain:   parseLabelSequence(d.RawSample[unsafe.Offsetof(bpfEvent.Name):]),
		}

		if bpfEvent.Af == syscall.AF_INET {
			e.From = util.IPStringFromBytes(bpfEvent.SaddrV6, 4)
			e.To = util.IPStringFromBytes(bpfEvent.DaddrV6, 4)
		} else if bpfEvent.Af == syscall.AF_INET6 {
			e.From = util.IPStringFromBytes(bpfEvent.SaddrV6, 6)
			e.To = util.IPStringFromBytes(bpfEvent.DaddrV6, 6)
		}

		queryType, ok := qTypeNames[uint(bpfEvent.Qtype)]
		if !ok {
			queryType = "UNKNOWN"
		}
		e.Query = queryType

		if bpfEvent.AnswerCount > 0 {
			if bpfEvent.Af == syscall.AF_INET6 || queryType == "AAAA" {
				e.Answer = util.IPStringFromBytes(bpfEvent.AnsAddrV6, 6)
			} else if bpfEvent.Af == syscall.AF_INET {
				e.Answer = util.IPStringFromBytes(bpfEvent.AnsAddrV6, 4)
			}
			e.TTL = bpfEvent.AnsTtl
		}

		o, err := json.Marshal(e)
		if err != nil {
			log.Printf("error marshalling event: %v", err)
			continue
		}
		fmt.Printf("%s\n", string(o))
	}

	return nil
}
