package zerotrace

import (
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

const (
	// The payload that our trace packets carry.
	tcpPayload  = "trace packet"
	ipv4Version = uint8(4)
)

// createPkt creates and returns a trace packet for the given net.Conn object.
// Importantly, the function only returns the TCP header and the application
// payload.  The function assembles a TCP segment that resembles the given
// net.Conn and has a small dummy payload.  The returned byte slice is ready to
// be written to the wire when combined with an IP header.
func createPkt(conn net.Conn) ([]byte, error) {
	// Extract hosts and ports from our net.Conn object.
	srcIP, strSrcPort, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dstIP, strDstPort, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	// Convert ports from string to int.
	srcPort, err := strconv.ParseUint(strSrcPort, 10, 16)
	if err != nil {
		return nil, err
	}
	dstPort, err := strconv.ParseUint(strDstPort, 10, 16)
	if err != nil {
		return nil, err
	}

	// Compose the pseudo header that's necessary for computing the TCP header
	// checksum.
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Length:   uint16(20 + 20 + len(tcpPayload)),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window:  500,
		PSH:     true,
		ACK:     true,
		Seq:     0,
		Ack:     0,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	// Serialize our packet.
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(
		buf,
		options,
		tcpLayer,
		gopacket.Payload([]byte(tcpPayload)),
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// createRawIpConn returns a new raw IPv4 connection.  We (ab)use
// net.ListenPacket to get a raw socket.  We only care about sending packets and
// not about receiving them, so we use ip4:89 (OSPF) to "receive" packets that
// we are unlikely to encounter.
func createRawIpConn() (*ipv4.RawConn, error) {
	c, err := net.ListenPacket("ip4:89", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// newIpv4Header returns a new IPv4 header.
func newIpv4Header(ttl, id int, dstAddr net.IP, payloadLen int) *ipv4.Header {
	return &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + 20 + payloadLen,
		ID:       id,
		TTL:      ttl,
		Protocol: 6, // TCP
		Dst:      dstAddr,
	}
}
