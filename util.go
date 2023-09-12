package zerotrace

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	errInvalidIPHeader = errors.New("invalid IP header")
)

// extractRemoteIP extracts the remote IP address from the given net.Conn.
func extractRemoteIP(c net.Conn) (net.IP, error) {
	s := c.RemoteAddr().String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(host), nil
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

// openPcap returns a new pcap handle that listens for ICMP packets.
func openPcap(iface string, snapLen int32, timeout time.Duration) (*pcap.Handle, error) {
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(
		iface,
		snapLen,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	if err = pcapHdl.SetBPFFilter("icmp"); err != nil {
		return nil, err
	}
	return pcapHdl, nil
}
