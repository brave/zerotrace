package zerotrace

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

var (
	l = log.New(os.Stderr, "0trace: ", log.Ldate|log.Lmicroseconds|log.LUTC|log.Lshortfile)
)

type receiver chan *respPkt

// Config holds configuration options for the ZeroTrace object.
type Config struct {
	// NumProbes determines the number of probes we're sending for a given TTL.
	NumProbes int
	// TTLStart determines the TTL at which we start sending trace packets.
	TTLStart int
	// TTLEnd determines the TTL at which we stop sending trace packets.
	TTLEnd int
	// SnapLen determines the number of bytes per frame that we want libpcap to
	// capture.  500 bytes is enough for ICMP TTL exceeded packets.
	SnapLen int32
	// PktBufTimeout determines the time we're willing to wait for packets to
	// accumulate in our receive buffer.
	PktBufTimeout time.Duration
	// Interface determines the network interface that we're going to use to
	// listen for incoming network packets.
	Interface string
}

// NewDefaultConfig returns a configuration object containing the following
// defaults.  *Note* that you probably need to change the networking interface.
//
//	NumProbes:     3
//	TTLStart:      5
//	TTLEnd:        32
//	SnapLen:       500
//	PktBufTimeout: time.Millisecond * 10
//	Interface:     "eth0"
func NewDefaultConfig() *Config {
	return &Config{
		NumProbes:     3,
		TTLStart:      5,
		TTLEnd:        32,
		SnapLen:       500,
		PktBufTimeout: time.Millisecond * 10,
		Interface:     "eth0",
	}
}

// ZeroTrace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145
type ZeroTrace struct {
	cfg                *Config
	quit               chan struct{}
	incoming, outgoing chan receiver
	rawConn            *ipv4.RawConn
	ipids              *ipIdPool
}

// OpenZeroTrace instantiates and starts a new ZeroTrace object that's going to
// use the given configuration for its measurement.
func OpenZeroTrace(c *Config) (*ZeroTrace, error) {
	var err error
	zt := &ZeroTrace{
		cfg:      c,
		incoming: make(chan receiver),
		outgoing: make(chan receiver),
		quit:     make(chan struct{}),
		ipids:    newIpIdState(),
	}
	zt.rawConn, err = createRawIpConn()
	if err != nil {
		return nil, err
	}

	go zt.listen()
	return zt, nil
}

// Close closes this ZeroTrace object.
func (z *ZeroTrace) Close() {
	close(z.quit)
}

// CalcRTT coordinates our 0trace traceroute and returns the RTT to the target
// or, if the target won't respond to us, the RTT of the hop that's closest.
// The given net.Conn represents an already-established TCP connection to the
// target.  Note that the TCP connection may be corrupted as part of the 0trace
// measurement.
func (z *ZeroTrace) CalcRTT(conn net.Conn) (time.Duration, error) {
	var (
		state     *trState
		wg        sync.WaitGroup
		respChan  = make(chan *respPkt)
		traceChan = make(chan *tracePkt)
	)
	defer close(respChan)
	defer close(traceChan)

	remoteIP, err := extractRemoteIP(conn)
	if err != nil {
		return 0, err
	}
	state = newTrState(remoteIP)

	// Register for receiving a copy of newly-captured ICMP responses.
	z.incoming <- respChan
	defer func() { z.outgoing <- respChan }()

	// Spawn goroutine that sends trace packets.
	wg.Add(1)
	go z.sendTracePkts(traceChan, conn, &wg)

	for {
		select {
		case tracePkt := <-traceChan:
			state.addTracePkt(tracePkt) // Sent new trace packet.
		case respPkt := <-respChan:
			state.addRespPkt(respPkt) // Received new response packet.
		case <-state.done():
			wg.Wait()
			return state.calcRTT()
		}
	}
}

// sendTracePkts sends a burst of trace packets to our target.  Once a packet
// was sent, it's written to the given channel.
func (z *ZeroTrace) sendTracePkts(
	c chan *tracePkt,
	conn net.Conn,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	dstAddr, err := extractRemoteIP(conn)
	if err != nil {
		l.Printf("Error extracting remote IP address from connection: %v", err)
		return
	}
	pktPayload, err := createPkt(conn)
	if err != nil {
		l.Printf("Error creating trace packet payload: %v", err)
		return
	}

	start := time.Now().UTC()
	defer func() {
		diff := time.Now().UTC().Sub(start)
		l.Printf("Sent trace packets in: %v", diff)
	}()
	for ttl := z.cfg.TTLStart; ttl <= z.cfg.TTLEnd; ttl++ {
		// Parallelize the sending of trace packets.
		go func(ttl int) {
			hdr := newIpv4Header(ttl, 0, dstAddr, len(pktPayload))
			// Send n probe packets for redundancy, in case some get lost.
			// Each probe packet shares a TTL but has a unique ID.
			for n := 0; n < z.cfg.NumProbes; n++ {
				ipID, err := z.ipids.borrow()
				if err != nil {
					l.Printf("Error borrowing IPID: %v", err)
					continue
				}
				hdr.ID = int(ipID)
				if err = z.rawConn.WriteTo(hdr, pktPayload, nil); err != nil {
					l.Printf("Error sending trace packet: %v", err)
					continue
				}
				c <- &tracePkt{
					ttl:  uint8(ttl),
					ipID: ipID,
					sent: time.Now().UTC(),
				}
			}
		}(ttl)
	}
}

// listen opens a pcap handle and begins listening for incoming ICMP packets.
// New traceroutes register themselves with this function's event loop to
// receive a copy of newly-captured ICMP packets.
func (z *ZeroTrace) listen() {
	var (
		ticker    = time.NewTicker(3 * time.Second)
		receivers = make(map[receiver]bool)
		stream    *gopacket.PacketSource
	)

	pcapHdl, err := openPcap(z.cfg.Interface, z.cfg.SnapLen, z.cfg.PktBufTimeout)
	if err != nil {
		l.Fatalf("Error opening pcap device: %v", err)
	}
	defer pcapHdl.Close()
	stream = gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())

	l.Println("Starting listening loop.")
	for {
		select {
		case <-z.quit:
			return
		case <-ticker.C:
			z.ipids.releaseUnanswered()
		case r := <-z.incoming:
			receivers[r] = true
		case r := <-z.outgoing:
			delete(receivers, r)
		case pkt := <-stream.Packets():
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
				l.Printf("Error extracting response packet: %v", err)
			}
			z.ipids.release(respPkt.ipID)
			// Fan-out new packet to all running traceroutes.
			for r := range receivers {
				r <- respPkt
			}
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

	// We're not interested in the response packet's TTL because by definition,
	// it's always going to be 1.
	return &respPkt{
		ipID:      ipID,
		recvd:     packet.Metadata().Timestamp,
		recvdFrom: ipv4Layer.SrcIP,
	}, nil
}
