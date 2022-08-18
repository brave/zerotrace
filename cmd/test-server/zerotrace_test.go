package main

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestProcessTCPpkt(t *testing.T) {
	c, _ := net.Pipe()
	z := newZeroTrace("lo", c)

	ttl := uint8(10)
	ipID := uint16(20)
	srvAddr := "10.0.0.1"
	ipLayer := &layers.IPv4{
		TTL:   ttl,
		Id:    ipID,
		SrcIP: net.ParseIP(srvAddr),
		DstIP: net.ParseIP("10.0.0.254"),
	}
	opts := gopacket.SerializeOptions{}

	pktBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(pktBuf, opts, ipLayer); err != nil {
		t.Fatalf("Failed to serialize gopacket layers: %v", err)
	}
	pkt := gopacket.NewPacket(pktBuf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	// Feed the function an IP address that should be ignored.
	z.processTCPpkt(pkt, "1.2.3.4")
	if len(z.SentPktsIPId) != 0 {
		t.Fatalf("Expected 0 sent packet but got %d.", len(z.SentPktsIPId))
	}

	// Now feed the function an IP address that should be processed.
	z.processTCPpkt(pkt, srvAddr)
	if len(z.SentPktsIPId) != 1 {
		t.Fatalf("Expected 1 sent packet but got %d.", len(z.SentPktsIPId))
	}
	// Make sure that the map element looks exactly as expected.
	sentPktData, exists := z.SentPktsIPId[int(ttl)]
	if !exists {
		t.Fatalf("Could not find sent packet data for TTL %d.", ttl)
	}
	if sentPktData[0].HopIPId != ipID {
		t.Fatalf("Expected IP ID %d but got %d.", ipID, sentPktData[0].HopIPId)
	}
}
