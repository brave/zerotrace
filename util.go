package zerotrace

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errInvalidIPHeader = errors.New("invalid IP header")
)

func extractTTL(ipPkt []byte) (uint8, error) {
	// At the very least, we expect an IP header.
	if len(ipPkt) < 20 {
		return 0, errInvalidIPHeader
	}

	// Try decoding the packet, to see if the header is well-formed.
	ip := layers.IPv4{}
	if err := ip.DecodeFromBytes(ipPkt, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	return uint8(ipPkt[8]), nil
}

// extractIPID parses the given IP header, extracts its IP ID, and returns it.
func extractIPID(ipPkt []byte) (uint16, error) {
	// At the very least, we expect an IP header.
	if len(ipPkt) < 20 {
		return 0, errInvalidIPHeader
	}

	// Try decoding the packet, to see if the header is well-formed.
	ip := layers.IPv4{}
	if err := ip.DecodeFromBytes(ipPkt, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	return uint16(ipPkt[4])<<8 | uint16(ipPkt[5]), nil
}
