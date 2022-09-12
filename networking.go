package main

import (
	"net"
	"strconv"
	"time"

	"github.com/go-ping/ping"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	if err = pinger.Run(); err != nil { // Blocks until finished.
		return nil, err
	}

	return pinger.Statistics(), nil
}

// createPkt creates and returns a trace packet for the given net.Conn object,
// containing the given IP ID.  The function assembles a TCP segment that
// resembles the given net.Conn and has a small dummy payload.  The returned
// byte slice is ready to be written to the wire.
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

	// Assemble our trace packet.
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		Version:  ipv4Version,
		Id:       ipID,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
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
	// SerializePacket?
	if err := gopacket.SerializeLayers(
		buf,
		options,
		ipLayer,
		tcpLayer,
		gopacket.Payload([]byte(tcpPayload)),
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
