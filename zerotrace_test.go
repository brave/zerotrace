package main

import (
	"encoding/hex"
	"errors"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	panicChanErr = "send on closed channel"
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

// TestProcessICMPpkt tests the processICMPpkt function.
// The following is the HEX+ASCII dump of the sample packet used in the test:
// 0000   80 65 7c e2 f4 9d 00 1c 73 00 00 99 08 00 45 00   .e|.....s.....E.
// 0010   00 38 07 cf 00 00 40 01 f1 9e c0 a8 00 01 c0 a8   .8....@.........
// 0020   00 06 0b 00 77 ea 00 00 00 00 45 00 00 57 00 00   ....w.....E..W..
// 0030   40 00 01 06 91 f9 c0 a8 00 06 ac 3a 7a bf 01 bb   @..........:z...
// 0040   55 b6 5c 14 c9 8f                                 U.\...
// 18:51:11.166865 IP 192.168.0.1 > 192.168.0.6: ICMP time exceeded in-transit, length 36
func TestProcessICMPpkt(t *testing.T) {
	c, _ := net.Pipe()
	z := newZeroTrace("lo", c)
	var counter int

	// Test for ideal case, ICMP packet error is processed, data extracted and must panic when pushing to channel
	hexstream := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea000000004500005700004000010691f9c0a80006ac3a7abf01bb55b65c14c98f"
	decodedByteArray, err := hex.DecodeString(hexstream)
	if err != nil {
		t.Fatalf("Test failed, hexstream could not be decoded: %v", err)
	}
	// Mock TTL, but IPID is the same as what was found in the original IP header in the received ICMP error pkt
	ttl := uint8(10)
	currTTL := int(ttl)
	ipID := uint16(0)
	// Set up data in SentPktsIPId
	z.SentPktsIPId[currTTL] = append(z.SentPktsIPId[currTTL], SentPacketData{HopIPId: ipID, HopSentTime: time.Now().UTC()})

	pkt := gopacket.NewPacket(decodedByteArray, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now().UTC()

	recvdHopChan := make(chan HopRTT)
	close(recvdHopChan)
	assert.PanicsWithError(t, panicChanErr, func() { err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan) })

	// Test for case where client IP has been reached, panics when trying to write to recvdHopChan
	z.ClientIP = "192.168.0.1"
	recvdHopChan = make(chan HopRTT)
	close(recvdHopChan)
	assert.PanicsWithError(t, panicChanErr, func() { err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan) })

	// Test for case where client IP has been reached, but z.SendPktsIPId does not have the necessary IP Id, registers an error
	// Still panics when writing to recvdHopChan
	z.SentPktsIPId = make(map[int][]SentPacketData)
	z.ClientIP = "192.168.0.1"
	recvdHopChan = make(chan HopRTT)
	close(recvdHopChan)
	assert.PanicsWithError(t, panicChanErr, func() { err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan) })

	// Test for Invalid IP header case
	hexstream_withoutIPheader := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea00000000"
	decodedByteArray, err = hex.DecodeString(hexstream_withoutIPheader)
	if err != nil {
		t.Fatalf("Test failed, hexstream could not be decoded: %v", err)
	}

	pkt = gopacket.NewPacket(decodedByteArray, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now().UTC()

	recvdHopChan = make(chan HopRTT)
	close(recvdHopChan)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	AssertEqualError(t, errors.New("Invalid IP header"), err)

	// Test for Invalid IP header case, where IP header length is less than expected
	hexstream_badIPheader := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea00000000450000570000400001"
	decodedByteArray, err = hex.DecodeString(hexstream_badIPheader)
	if err != nil {
		t.Fatalf("Test failed, hexstream could not be decoded: %v", err)
	}

	pkt = gopacket.NewPacket(decodedByteArray, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now().UTC()

	recvdHopChan = make(chan HopRTT)
	close(recvdHopChan)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	AssertEqualError(t, errors.New("IP header unavailable"), err)

	// Test with a valid ICMP echo reply packet, packet should be discarded as it is not an ICMP error packet, and IP header does not exist
	hexstream_ICMPreply := "0aa89a80fc720ad8373494a6080045000034dfbd0000fe013e290311c4fbac1f2ab60000c41d4a1a000416feee5373d31835b8344b481dfe4d2f8301c9c6658e3f68"
	decodedByteArray, err = hex.DecodeString(hexstream_ICMPreply)
	if err != nil {
		t.Fatalf("Test failed, hexstream could not be decoded: %v", err)
	}

	pkt = gopacket.NewPacket(decodedByteArray, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now().UTC()

	recvdHopChan = make(chan HopRTT)
	close(recvdHopChan)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	// Assert that there is an error (which results from IPv4.DecodeFromBytes)
	AssertError(t, err)
}
