package zerotrace

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	// The number of probes we're sending for a given TTL.
	numProbes = 3
	// The TTL at which we start sending trace packets.
	ttlStart = 5
	// The TTL at which we stop sending trace packets.
	ttlEnd = 32
	// The number of bytes per frame that we want libpcap to capture.  500
	// bytes is enough for ICMP TTL exceeded packets.
	snapLen = 500
	// The time we're willing to wait for packets to accumulate in our receive
	// buffer.
	pktBufTimeout = time.Millisecond * 10
)

var (
	l = log.New(os.Stderr, "latsrv: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

// ZeroTrace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145
type ZeroTrace struct {
	sync.RWMutex
	iface    string
	targetIP net.IP
}

// NewZeroTrace instantiates and returns a new ZeroTrace object that's going to
// use the given interface for its measurement.
func NewZeroTrace(iface string) (*ZeroTrace, error) {
	// s := conn.RemoteAddr().String()
	// host, _, err := net.SplitHostPort(s)
	// if err != nil {
	// 	return nil, err
	// }
	// net.ParseIP(host)

	return &ZeroTrace{
		iface: iface,
	}, nil
}

// getIface returns the name of the interface that we're supposed to use for
// packet capturing.
func (z *ZeroTrace) getIface() string {
	z.RLock()
	defer z.RUnlock()
	return z.iface
}

// getTargetIP returns the IP address of the traceroute destination.
func (z *ZeroTrace) getTargetIP() net.IP {
	z.RLock()
	defer z.RUnlock()
	return z.targetIP
}

// sendTracePkts sends trace packets to our target.  Once a packet was sent,
// it's written to the given channel.  The given function is used to create an
// IP ID that is set in the trace packet's IP header.
func (z *ZeroTrace) sendTracePkts(c chan *tracePkt, createIPID func() uint16, conn net.Conn) {
	for ttl := ttlStart; ttl <= ttlEnd; ttl++ {
		tempConn := conn.(*tls.Conn)
		tcpConn := tempConn.NetConn()
		ipConn := ipv4.NewConn(tcpConn)

		// Set our net.Conn's TTL for future outgoing packets.
		if err := ipConn.SetTTL(ttl); err != nil {
			l.Printf("Error setting TTL: %v", err)
			return
		}

		for n := 0; n < numProbes; n++ {
			ipID := createIPID()
			pkt, err := createPkt(conn, ipID)
			if err != nil {
				l.Printf("Error creating packet: %v", err)
				return
			}

			if err := sendRawPkt(
				ipID,
				uint8(ttl),
				z.getTargetIP(),
				pkt,
			); err != nil {
				l.Printf("Error sending raw packet: %v", err)
			}

			c <- &tracePkt{
				ttl:  uint8(ttl),
				ipID: ipID,
				sent: time.Now().UTC(),
			}
		}
		l.Printf("Sent %d trace packets with TTL %d.", numProbes, ttl)
	}
	l.Println("Done sending trace packets.")
}

// CalcRTT coordinates our 0trace traceroute and returns the RTT to the target
// or, if the target won't respond to us, the RTT of the hop that's closest.
func (z *ZeroTrace) CalcRTT(conn net.Conn) (time.Duration, error) {

	state := newTrState(z.getTargetIP())
	ticker := time.NewTicker(time.Second)
	quit := make(chan bool)
	defer close(quit)

	// Set up our pcap handle.
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(z.getIface(), snapLen, promiscuous, pktBufTimeout)
	if err != nil {
		return 0, err
	}
	if err = pcapHdl.SetBPFFilter("icmp"); err != nil {
		return 0, err
	}
	defer pcapHdl.Close()

	// Spawn goroutine that listens for incoming ICMP response packets.
	respChan := make(chan *respPkt)
	go z.recvRespPkts(pcapHdl, respChan, quit)

	// Spawn goroutine that sends trace packets.
	traceChan := make(chan *tracePkt)
	go z.sendTracePkts(traceChan, state.createIPID, conn)

loop:
	for {
		select {
		// We just sent a trace packet.
		case tracePkt := <-traceChan:
			state.AddTracePkt(tracePkt)

		// We just received a packet in response to a trace packet.
		case respPkt := <-respChan:
			if err := state.AddRespPkt(respPkt); err != nil {
				l.Printf("Error adding response packet: %v", err)
			}

		// Check if we're done with the traceroute.
		case <-ticker.C:
			state.Summary()
			if state.IsFinished() {
				break loop
			}
		}
	}

	return state.CalcRTT(), nil
}

// recvRespPkts uses the given pcap handle to read incoming packets and filters
// for ICMP TTL exceeded packets that are then sent to the given channel.  The
// function returns when the given quit channel is closed.
func (z *ZeroTrace) recvRespPkts(pcapHdl *pcap.Handle, c chan *respPkt, quit chan bool) {
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())

	for {
		select {
		case <-quit:
			l.Println("Done reading packets.")
			return
		case pkt := <-packetStream.Packets():
			if pkt == nil {
				continue
			}
			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			icmpLayer := pkt.Layer(layers.LayerTypeICMPv4)

			if ipLayer == nil || icmpLayer == nil {
				continue
			}

			// If it is an ICMP packet, check if it is the ICMP TTL
			// exceeded one we are looking for
			respPkt, err := z.extractRcvdPkt(pkt)
			if err != nil {
				l.Printf("Failed to extract response packet: %v", err)
				continue
			}
			l.Printf("Got resp. packet with IP ID=%d\n\tTTL: %d\n\t"+
				"Sent: %s\n\tRecvd: %s (from %s)\n",
				respPkt.ipID,
				respPkt.ttl,
				respPkt.sent,
				respPkt.recvd,
				respPkt.recvdFrom)
			c <- respPkt
		}
	}
}

// extractRcvdPkt extracts what we need (IP ID, timestamp, address) from the
// given network packet.
func (z *ZeroTrace) extractRcvdPkt(packet gopacket.Packet) (*respPkt, error) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)

	ipID, err := extractIPID(icmpPkt.LayerPayload())
	if err != nil {
		return nil, err
	}

	// We're not interested in the response packet's TTL because by
	// definition, it's always going to be 1.
	return &respPkt{
		ipID:      ipID,
		recvd:     packet.Metadata().Timestamp,
		recvdFrom: ipv4Layer.SrcIP,
	}, nil
}
