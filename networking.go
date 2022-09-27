package main

import (
	"net"
	"strconv"
	"time"

	"github.com/go-ping/ping"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

const (
	// The number of ICMP packets we send to a client.
	icmpCount = 5
	// The time we're willing to wait for an ICMP response.
	icmpTimeout = time.Second * 10
	// The payload that our trace packets carry.
	tcpPayload  = "trace packet"
	ipv4Version = uint8(4)
)

// pingAddr sends ICMP pings to the given address and returns ping
// statistics.
func pingAddr(addr string) (*ping.Statistics, error) {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return nil, err
	}

	// Don't use UDP.  Instead, use raw socket pings which require root.
	pinger.SetPrivileged(true)
	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	if err = pinger.Run(); err != nil { // Blocks until finished.
		return nil, err
	}

	return pinger.Statistics(), nil
}

// createPkt creates and returns a trace packet for the given net.Conn object.
// Importantly, the function only returns the TCP header and the application
// payload.  The function assembles a TCP segment that resembles the given
// net.Conn and has a small dummy payload.  The returned byte slice is ready to
// be written to the wire when combined with an IP header.
func createPkt(conn net.Conn, ipID uint16) ([]byte, error) {
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
	srcPort, err := strconv.Atoi(strSrcPort)
	if err != nil {
		return nil, err
	}
	dstPort, err := strconv.Atoi(strDstPort)
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
		PSH:     true,
		ACK:     true,
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

// sendRawPkt sends a raw trace packet to the given destination.  We need a raw
// socket because we are manually setting the IP header's IP ID and TTL, which
// is typically done by the kernel's network stack.
//
// We abuse net.ListenPacket to get a raw socket.  We only care about sending
// packets and not about receiving them, so we use ip4:89 (OSPF) to "receive"
// packets that we are unlikely to encounter.
func sendRawPkt(ipID uint16, ttl uint8, dstAddr net.IP, payload []byte) error {
	c, err := net.ListenPacket("ip4:89", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		return err
	}
	defer r.Close()

	// TODO: Revisit.
	iph := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + 20 + len(payload),
		ID:       int(ipID),
		TTL:      int(ttl),
		Protocol: 6, // TCP
		Dst:      dstAddr,
	}
	if err := r.WriteTo(iph, payload, nil); err != nil {
		return err
	}
	return nil
}
