package zerotrace

import (
	"bytes"
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

func TestCreatePkt(t *testing.T) {
	conn := &mockConn{}
	ipID := uint16(1234)
	rawPkt, err := createPkt(conn, ipID)
	if err != nil {
		t.Fatalf("Failed to create packet for given conn: %v", err)
	}
	pkt := gopacket.NewPacket(rawPkt, layers.LayerTypeTCP, gopacket.Default)

	// Verify payload.
	if pkt.ApplicationLayer() == nil {
		t.Fatal("no app layer")
	}
	seen := pkt.ApplicationLayer().Payload()
	expected := []byte(tcpPayload)
	if !bytes.Equal(expected, seen) {
		t.Fatalf("Expected payload %q but got %q.", expected, seen)
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
