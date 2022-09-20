package main

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	numProbes = 3
	ttlStart  = 5
	ttlEnd    = 32
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

// sentPacketData struct keeps track of the IP ID value and Sent time for each TCP packet sent
type sentPacketData struct {
	HopIPId     uint16
	HopSentTime time.Time
}

type hopRTT struct {
	IP  net.IP
	RTT float64
}

type sentTracePkts map[int][]sentPacketData

func (s sentTracePkts) contain(ttl int, ipID uint16) bool {
	for k, vs := range s {
		if k == ttl {
			for _, v := range vs {
				if v.HopIPId == ipID {
					return true
				}
			}
		}
	}
	return false
}

type zeroTrace struct {
	sync.RWMutex
	iface            string
	Conn             net.Conn
	UUID             string
	PcapHdl          *pcap.Handle
	ClientIP         string
	ClientPort       int
	sentPkts         sentTracePkts
	CurrTTLIndicator int
}

// newZeroTrace instantiates and returns a new zeroTrace struct with the
// interface, net.Conn underlying connection, client IP and port data
func newZeroTrace(iface string, conn net.Conn, uuid string) *zeroTrace {
	clientIPstr := conn.RemoteAddr().String()
	clientIP, clPort, _ := net.SplitHostPort(clientIPstr)
	clientPort, _ := strconv.Atoi(clPort)

	return &zeroTrace{
		iface:      iface,
		Conn:       conn,
		UUID:       uuid,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		sentPkts:   make(sentTracePkts),
	}
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
				net.ParseIP(z.ClientIP),
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
	state := newTrState(net.ParseIP(z.ClientIP))
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

	/*
		// We obtain the IPID from the IP header of the original packet that is
		// present in the ICMP Error packet, and compare it to the IPID of the
		// packet we sent with a particular TTL value Note: In the server side when
		// sending a packet, if the "Don't Fragment" flag is set, some (server)
		// OSes assign 0x0000 as the IP ID This does not break the logic here much,
		// since we await the ICMP error response for each TTL (or move on after
		// tracerouteHopTimeout) before moving on to the next one. However, it can
		// lead to confusing debug messages (from extractTracerouteHopRTT(...))
		// FYI: Currently (8/2022), the server is run on a linux AWS machine
		// running Ubuntu 22.04 LTS and the IPID for a particular flow is
		// monotonically increasing/incrementing
		recvTimestamp := packet.Metadata().Timestamp
		if currHop.String() == z.ClientIP {
			val := hopRTT{
				IP:  currHop,
				RTT: z.extractTracerouteHopRTT(currTTL, ipID, recvTimestamp, true),
			}
			// May recieve ICMP responses from Client IP during the connection that
			// are unrelated to 0trace so check for error from
			// extractTracerouteHopRTT
			if val.RTT != 0 {
				hops <- val
			}
			return nil
		}

		// We're not dealing with a TTL exceeded ICMP packet.  Ignore it.
		if icmpPkt.TypeCode.Code() != layers.ICMPv4CodeTTLExceeded {
			return nil
		}

		if z.sentPkts.contain(currTTL, ipID) {
			hops <- hopRTT{
				IP:  currHop,
				RTT: z.extractTracerouteHopRTT(currTTL, ipID, recvTimestamp, false),
			}
			*counter = currTTL
		}
		return nil
	*/
}

// processICMPpkt takes the packet (known to contain an ICMP layer, and is not
// a duplicate for the TTL we have already evaluated) it extracts the received
// timestamp, and IP Id from the IP header of the original packet from the ICMP
// error packet it extracts the Hop RTT data, and passes the extracted data to
// the hops channel if: the packet contains the TTL Exceeded error code, and
// the sentPkts map contains the found IP Id at the current TTL, or errors
// if any
func (z *zeroTrace) processICMPpkt(packet gopacket.Packet, currTTL int, counter *int, hops chan hopRTT) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipl, _ := ipLayer.(*layers.IPv4)
	currHop := ipl.SrcIP

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
	ipID, err := extractIPID(icmpPkt.LayerPayload())
	if err != nil {
		return err
	}

	// We obtain the IPID from the IP header of the original packet that is
	// present in the ICMP Error packet, and compare it to the IPID of the
	// packet we sent with a particular TTL value Note: In the server side when
	// sending a packet, if the "Don't Fragment" flag is set, some (server)
	// OSes assign 0x0000 as the IP ID This does not break the logic here much,
	// since we await the ICMP error response for each TTL (or move on after
	// tracerouteHopTimeout) before moving on to the next one. However, it can
	// lead to confusing debug messages (from extractTracerouteHopRTT(...))
	// FYI: Currently (8/2022), the server is run on a linux AWS machine
	// running Ubuntu 22.04 LTS and the IPID for a particular flow is
	// monotonically increasing/incrementing
	recvTimestamp := packet.Metadata().Timestamp
	if currHop.String() == z.ClientIP {
		val := hopRTT{
			IP:  currHop,
			RTT: z.extractTracerouteHopRTT(currTTL, ipID, recvTimestamp, true),
		}
		// May recieve ICMP responses from Client IP during the connection that
		// are unrelated to 0trace so check for error from
		// extractTracerouteHopRTT
		if val.RTT != 0 {
			hops <- val
		}
		return nil
	}

	// We're not dealing with a TTL exceeded ICMP packet.  Ignore it.
	if icmpPkt.TypeCode.Code() != layers.ICMPv4CodeTTLExceeded {
		return nil
	}

	if z.sentPkts.contain(currTTL, ipID) {
		hops <- hopRTT{
			IP:  currHop,
			RTT: z.extractTracerouteHopRTT(currTTL, ipID, recvTimestamp, false),
		}
		*counter = currTTL
	}
	return nil
}

// extractTracerouteHopRTT obtains the time stamp for the TTL-limited packet
// which was sent for the "currTTL" value, and subtracts that from the
// recvTimestamp supplied to calculate RTT for the current hop and returns the
// HopRTT object with the calculated RTT value.  logs the current TTL value if
// the client has already been reached
func (z *zeroTrace) extractTracerouteHopRTT(currTTL int, ipid uint16, recvTimestamp time.Time, clientReached bool) float64 {
	if clientReached {
		l.Println("Traceroute reached client (ICMP response) at hop: ", currTTL)
	} else {
		l.Println("Received packet ipid: ", ipid, " TTL: ", currTTL)
	}
	var hopRTTVal time.Duration
	sentTime, err := getSentTimestampfromIPId(z.sentPkts[currTTL], ipid)
	if err != nil {
		l.Println("Error getting timestamp from sent pkt: ", err)
		hopRTTVal = 0
	} else {
		hopRTTVal = recvTimestamp.Sub(sentTime)
	}
	return fmtTimeMs(hopRTTVal)
}
