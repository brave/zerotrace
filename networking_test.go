package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	srcAddr = "10.0.0.1"
	dstAddr = "10.0.0.2"
	srcPort = 12345
	dstPort = 8080
)

// mockConn mocks a TCP connection by overriding the RemoteAddr and LocalAddr
// functions because that's all that the createPkt function needs.
type mockConn struct {
	net.TCPConn
}

func (m *mockConn) createAddr(strAddr string) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", strAddr)
	if err != nil {
		panic(err)
	}
	return addr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.createAddr(fmt.Sprintf("%s:%d", dstAddr, dstPort))
}
func (m *mockConn) LocalAddr() net.Addr {
	return m.createAddr(fmt.Sprintf("%s:%d", srcAddr, srcPort))
}

func TestPingAddr(t *testing.T) {
	// Test with a valid IP
	pingStats, err := pingAddr("127.0.0.1")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	AssertEqualValue(t, "127.0.0.1", pingStats.Addr)

	// Test with invalid IP
	_, err = pingAddr("127.0.0.0.1")
	var dnsError *net.DNSError
	if !errors.As(err, &dnsError) {
		t.Errorf("Expected DNS Error, got %v", err)
	}
}

func TestCreatePkt(t *testing.T) {
	conn := &mockConn{}
	rawPkt, err := createPkt(conn)
	if err != nil {
		t.Fatalf("Failed to create packet for given conn: %v", err)
	}
	pkt := gopacket.NewPacket(rawPkt, layers.LayerTypeIPv4, gopacket.Default)

	// Verify payload.
	seen := pkt.ApplicationLayer().Payload()
	expected := []byte(tcpPayload)
	if !bytes.Equal(expected, seen) {
		t.Fatalf("Expected payload %q but got %q.", expected, seen)
	}

	// Verify IP version.
	ipLayer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipLayer.Version != ipv4Version {
		t.Fatalf("Expected IP version %d but got %d.", ipv4Version, ipLayer.Version)
	}

	// Verify source and destination IP addresses.
	expectedAddr := net.ParseIP(srcAddr)
	if !ipLayer.SrcIP.Equal(expectedAddr) {
		t.Fatalf("Expected address %d but got %s.", expectedAddr, ipLayer.SrcIP)
	}
	expectedAddr = net.ParseIP(dstAddr)
	if !ipLayer.DstIP.Equal(expectedAddr) {
		t.Fatalf("Expected address %d but got %s.", expectedAddr, ipLayer.DstIP)
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer.SrcPort != srcPort {
		t.Fatalf("Expected src port %d but got %d.", srcPort, tcpLayer.SrcPort)
	}
	if tcpLayer.DstPort != dstPort {
		t.Fatalf("Expected dst port %d but got %d.", dstPort, tcpLayer.DstPort)
	}

	// Verify TCP flags.
	if tcpLayer.FIN == true ||
		tcpLayer.SYN == true ||
		tcpLayer.RST == true ||
		tcpLayer.URG == true ||
		tcpLayer.ECE == true ||
		tcpLayer.CWR == true ||
		tcpLayer.NS == true {
		t.Fatal("Expected all TCP flags except PSH and ACK to be unset.")
	}
	if tcpLayer.PSH == false || tcpLayer.ACK == false {
		t.Fatal("Expected TCP flags PSH and ACK to be set.")
	}
}
