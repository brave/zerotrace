package main

import (
	"crypto/tls"
	"net"
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
	ifaceName string
)

type zeroTrace struct {
	sync.RWMutex
	iface    string
	Conn     net.Conn
	ClientIP net.IP
}

// newZeroTrace instantiates and returns a new zeroTrace struct with the
// interface, net.Conn underlying connection, client IP and port data
func newZeroTrace(iface string, conn net.Conn) (*zeroTrace, error) {
	s := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	return &zeroTrace{
		iface:    iface,
		Conn:     conn,
		ClientIP: net.ParseIP(host),
	}, nil
}

func (z *zeroTrace) sendTracePkts(c chan *tracePkt, createIPID func() uint16) {
	for ttl := ttlStart; ttl <= ttlEnd; ttl++ {
		tempConn := z.Conn.(*tls.Conn)
		tcpConn := tempConn.NetConn()
		ipConn := ipv4.NewConn(tcpConn)

		// Set our net.Conn's TTL for future outgoing packets.
		if err := ipConn.SetTTL(ttl); err != nil {
			l.Printf("Error setting TTL: %v", err)
			return
		}

		for n := 0; n < numProbes; n++ {
			ipID := createIPID()
			pkt, err := createPkt(z.Conn, ipID)
			if err != nil {
				l.Printf("Error creating packet: %v", err)
				return
			}

			if err := sendRawPkt(
				ipID,
				uint8(ttl),
				z.ClientIP,
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

// calcRTT coordinates our 0trace traceroute and returns the RTT to the
// destination or, if the destination won't respond to us, the RTT of the hop
// that's closest.
func (z *zeroTrace) calcRTT() (time.Duration, error) {
	state := newTrState(z.ClientIP)
	ticker := time.NewTicker(time.Second)
	quit := make(chan bool)
	defer close(quit)

	// Set up our pcap handle.
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(z.iface, snapLen, promiscuous, pktBufTimeout)
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
	go z.sendTracePkts(traceChan, state.createIPID)

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

// Run reaches the underlying connection and sets up necessary pcap handles and
// implements the 0trace method of sending TTL-limited probes on an existing
// TCP connection
func (z *zeroTrace) Run() error {
	var err error

	l.Printf("Starting new 0trace measurement to %s.", z.Conn.RemoteAddr())
	rtt, err := z.calcRTT()
	if err != nil {
		return err
	}
	l.Printf("Network-level RTT: %s", rtt)
	return err
}

func (z *zeroTrace) recvRespPkts(pcapHdl *pcap.Handle, c chan *respPkt, quit chan bool) {
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

func (z *zeroTrace) extractRcvdPkt(packet gopacket.Packet) (*respPkt, error) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)

	ipID, err := extractIPID(icmpPkt.LayerPayload())
	if err != nil {
		l.Println(packet.String())
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
