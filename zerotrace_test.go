package main

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const (
	panicChanErr = "send on closed channel"
)

func hexToPkt(t *testing.T, hexString string) gopacket.Packet {
	decodedByteArray, err := hex.DecodeString(hexString)
	if err != nil {
		t.Fatalf("Test failed, hexstream could not be decoded: %v", err)
	}
	pkt := gopacket.NewPacket(decodedByteArray, layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now().UTC().Add(500 * time.Millisecond) // random delay to mock received packet
	return pkt
}

func TestProcessTCPpkt(t *testing.T) {
	c, _ := net.Pipe()
	z := newZeroTrace("lo", c, uuid.NewString())

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
	z := newZeroTrace("lo", c, uuid.NewString())
	var counter int

	// Test for ideal case, ICMP packet error is processed, data extracted and must panic when pushing to channel
	hexstream := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea000000004500005700004000010691f9c0a80006ac3a7abf01bb55b65c14c98f"
	pkt := hexToPkt(t, hexstream)

	// Mock TTL, but IPID is the same as what was found in the original IP header in the received ICMP error pkt
	ttl := uint8(10)
	currTTL := int(ttl)
	ipID := uint16(0)
	// Set up data in SentPktsIPId
	z.SentPktsIPId[currTTL] = append(z.SentPktsIPId[currTTL], sentPacketData{HopIPId: ipID, HopSentTime: time.Now().UTC()})
	// Open and close the channel that processICMPpkt will try to write into
	recvdHopChan := make(chan hopRTT)
	close(recvdHopChan)
	assert.PanicsWithError(t, panicChanErr, func() { _ = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan) })

	// Test for case where client IP has been reached, panics when trying to write to recvdHopChan
	z.ClientIP = "192.168.0.1"
	assert.PanicsWithError(t, panicChanErr, func() { _ = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan) })

	// Test for case where client IP has been reached, but z.SendPktsIPId does not have the necessary IP Id, registers an error
	// and does not write to recvdHopChan
	z.SentPktsIPId = make(map[int][]sentPacketData)
	z.ClientIP = "192.168.0.1"
	err := z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	assert.NoError(t, err)

	// Test for Invalid IP header case -- truncated version of the above packet
	hexstream_withoutIPheader := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea00000000"
	pkt = hexToPkt(t, hexstream_withoutIPheader)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	AssertError(t, err)
	AssertEqualValue(t, "Invalid IP header", err.Error())

	// Test for Invalid IP header case, where IP header length is less than expected (also truncated version of above packet)
	hexstream_badIPheader := "80657ce2f49d001c7300009908004500003807cf00004001f19ec0a80001c0a800060b0077ea00000000450000570000400001"
	pkt = hexToPkt(t, hexstream_badIPheader)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	AssertError(t, err)
	AssertEqualValue(t, "IP header unavailable", err.Error())

	// Test with a valid ICMP echo reply packet, packet should be discarded as it is not an ICMP error packet, and IP header does not exist
	hexstream_ICMPreply := "0aa89a80fc720ad8373494a6080045000034dfbd0000fe013e290311c4fbac1f2ab60000c41d4a1a000416feee5373d31835b8344b481dfe4d2f8301c9c6658e3f68"
	pkt = hexToPkt(t, hexstream_ICMPreply)
	err = z.processICMPpkt(pkt, currTTL, &counter, recvdHopChan)
	// Assert that there is an error (which results from IPv4.DecodeFromBytes)
	AssertError(t, err)
}
