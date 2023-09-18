package zerotrace

import (
	"errors"
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

var (
	l         = log.New(os.Stderr, "0trace: ", log.Ldate|log.Lmicroseconds|log.LUTC|log.Lshortfile)
	errNoIcmp = errors.New("not an ICMP packet")
)

type receiver chan *respPkt

// ZeroTrace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145
type ZeroTrace struct {
	cfg                *Config
	quit               chan struct{}
	incoming, outgoing chan receiver
	rawConn            *ipv4.RawConn
	ipids              *ipIdPool
	pcap               *pcap.Handle
}

// NewZeroTrace returns a new ZeroTrace object that uses the given
// configuration.
func NewZeroTrace(c *Config) *ZeroTrace {
	return &ZeroTrace{
		cfg:      c,
		incoming: make(chan receiver),
		outgoing: make(chan receiver),
		quit:     make(chan struct{}),
		ipids:    newIpIdPool(),
	}
}

// Start starts the ZeroTrace object.  This function instructs ZeroTrace to
// start its event loop and to begin capturing network packets.
func (z *ZeroTrace) Start() error {
	var err error
	z.rawConn, err = createRawIpConn()
	if err != nil {
		return err
	}

	z.pcap, err = openPcap(z.cfg.Interface, z.cfg.SnapLen, z.cfg.PktBufTimeout)
	if err != nil {
		return err
	}
	go z.listen(gopacket.NewPacketSource(
		z.pcap,
		z.pcap.LinkType(),
	).Packets())

	return nil
}

// Close closes the ZeroTrace object.
func (z *ZeroTrace) Close() {
	z.pcap.Close()
	close(z.quit)
}

// CalcRTT starts a new 0trace traceroute and returns the RTT to the target
// or, if the target won't respond to us, the RTT of the hop that's closest.
// The given net.Conn represents an already-established TCP connection to the
// target.  Note that the TCP connection may be corrupted as part of the 0trace
// measurement.
func (z *ZeroTrace) CalcRTT(conn net.Conn) (time.Duration, error) {
	var (
		state     *trState
		wg        sync.WaitGroup
		ticker    = time.NewTicker(250 * time.Millisecond)
		respChan  = make(chan *respPkt, 1)
		traceChan = make(chan *tracePkt, 1)
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
		case <-ticker.C:
			wg.Wait()
			if state.isFinished() {
				return state.calcRTT()
			}
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
func (z *ZeroTrace) listen(pktStream chan gopacket.Packet) {
	var (
		ticker    = time.NewTicker(3 * time.Second)
		receivers = make(map[receiver]bool)
	)

	l.Println("Starting listening loop.")
	defer l.Println("Leaving listening loop.")
	for {
		select {
		case <-z.quit:
			return
		case <-ticker.C:
			z.ipids.releaseUnanswered()
			l.Printf("Released un-answered IP IDs; %d left.", z.ipids.size())
		case r := <-z.incoming:
			l.Println("Registering new packet receiver.")
			receivers[r] = true
		case r := <-z.outgoing:
			l.Printf("Unregistering packet receiver; %d left.", len(receivers))
			delete(receivers, r)
		case pkt := <-pktStream:
			respPkt, err := z.parseIcmpPkt(pkt)
			if err != nil {
				l.Printf("Error parsing ICMP packet: %v", err)
			}
			z.ipids.release(respPkt.ipID)
			// Fan-out new packet to all running traceroutes.
			for r := range receivers {
				// A receiver's channel may be full if the receiver is done with
				// the scan and has already exited its event loop.
				if len(r) == 0 {
					r <- respPkt
				}
			}
		}
	}
}

// parseIcmpPkt extracts what we need (IP ID, timestamp, address) from the
// given ICMP packet.
func (z *ZeroTrace) parseIcmpPkt(packet gopacket.Packet) (*respPkt, error) {
	if packet == nil {
		return nil, errNoIcmp
	}
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if ipv4Layer == nil || icmpLayer == nil {
		return nil, errNoIcmp
	}
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
