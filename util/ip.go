package util

import "net/netip"

func IPStringFromBytes(ipBytes [16]byte, ipType int) string {
	switch ipType {
	case 4:
		return netip.AddrFrom4(*(*[4]byte)(ipBytes[0:4])).String()
	case 6:
		return netip.AddrFrom16(ipBytes).String()
	default:
		return ""
	}
}
