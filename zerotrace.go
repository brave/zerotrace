package main

import (
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
	ttlStart             = 5
	ttlEnd               = 32
	tracerouteHopTimeout = time.Second * 10
	snaplen              = 65536
	promisc              = true
	ipversion            = 4
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

type zeroTrace struct {
	sync.RWMutex
	Iface            string
	Conn             net.Conn
	UUID             string
	PcapHdl          *pcap.Handle
	ClientIP         string
	ClientPort       int
	SentPktsIPId     map[int][]sentPacketData
	CurrTTLIndicator int
}

type tracerouteResults struct {
	UUID      string
	Timestamp string
	HopData   map[int]hopRTT
}

// newZeroTrace instantiates and returns a new zeroTrace struct with the
// interface, net.Conn underlying connection, client IP and port data
func newZeroTrace(iface string, conn net.Conn, uuid string) *zeroTrace {
	clientIPstr := conn.RemoteAddr().String()
	clientIP, clPort, _ := net.SplitHostPort(clientIPstr)
	clientPort, _ := strconv.Atoi(clPort)

	return &zeroTrace{
		Iface:        iface,
		Conn:         conn,
		UUID:         uuid,
		ClientIP:     clientIP,
		ClientPort:   clientPort,
		SentPktsIPId: make(map[int][]sentPacketData),
	}
}

// createIPID returns the next available IP ID for use in outgoing trace
// packets.  We rely on the IP ID field to link incoming ICMP error packets to
// previously-sent trace packets, so it's important that IP IDs are only used
// once.  This function takes care of that.
func (z *zeroTrace) createIPID() uint16 {
	z.RLock()
	defer z.RUnlock()

	var maxIPID uint16
	for _, pktSigs := range z.SentPktsIPId {
		for _, pktSig := range pktSigs {
			if pktSig.HopIPId > maxIPID {
				maxIPID = pktSig.HopIPId
			}
		}
	}
	return maxIPID + 1
}

// trackPktSig tracks an outgoing trace packet's "signature" by recording its
// TTL, IP ID, and the time it was sent.  We need this information to link
// trace packets to incoming ICMP error packets.
func (z *zeroTrace) trackPktSig(ttl int, ipID uint16, sent time.Time) {
	z.Lock()
	defer z.Unlock()

	z.SentPktsIPId[ttl] = append(
		z.SentPktsIPId[ttl],
		sentPacketData{HopIPId: ipID, HopSentTime: time.Now().UTC()},
	)
}

// traceroute sends probes of incrementing TTL, await response from channel
// that identifies the hop which sent the ICMP response and stops sending any
// more probes if connection errors out
func (z *zeroTrace) traceroute(recvdHopData chan hopRTT) (map[int]hopRTT, error) {
	traceroute := make(map[int]hopRTT)

	for ttl := ttlStart; ttl <= ttlEnd; ttl++ {
		ipID := z.createIPID()
		pkt, err := createPkt(z.Conn, ipID)
		if err != nil {
			return traceroute, err
		}

		// Set our net.Conn's TTL for future outgoing packets.
		if err := ipv4.NewConn(z.Conn).SetTTL(ttl); err != nil {
			return traceroute, err
		}
		// Write our serialized packet to the wire.
		if _, err := z.Conn.Write(pkt); err != nil {
			return traceroute, err
		}
		z.trackPktSig(ttl, ipID, time.Now().UTC())
		l.Println("Sent ", ttl, " packet")

		z.CurrTTLIndicator = ttl
		ticker := time.NewTicker(tracerouteHopTimeout)
		defer ticker.Stop()
		select {
		case hopData := <-recvdHopData:
			traceroute[ttl] = hopData
		case <-ticker.C:
			l.Println("Traceroute Hop Timeout at Hop ", ttl, ". Moving on to the next hop.")
			var empty net.IP
			traceroute[ttl] = hopRTT{empty, 0}
			continue
		}
		if traceroute[ttl].IP.String() == z.ClientIP {
			// The client has been reached and RTT has been recorded, so we can break
			break
		}
	}
	return traceroute, nil
}

// Run reaches the underlying connection and sets up necessary pcap handles and
// implements the 0trace method of sending TTL-limited probes on an existing
// TCP connection
func (z *zeroTrace) Run() error {
	var err error
	if z.PcapHdl, err = z.setupPcapAndFilter(); err != nil {
		return err
	}

	recvdHopChan := make(chan hopRTT)
	quit := make(chan bool)
	// Fire go routine to start listening for packets on the handler before
	// sending TTL limited probes
	go z.recvPackets(z.PcapHdl, recvdHopChan, quit)

	traceroute, err := z.traceroute(recvdHopChan)
	results := tracerouteResults{
		UUID:      z.UUID,
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		HopData:   traceroute,
	}
	logAsJson(results)

	quit <- true
	return err
}

// setupPcap sets up the pcap handle on the required interface, and applies the
// filter and returns it
func (z *zeroTrace) setupPcapAndFilter() (*pcap.Handle, error) {
	pcapHdl, err := pcap.OpenLive(z.Iface, snaplen, promisc, time.Second)
	if err != nil {
		return nil, err
	}
	if err = pcapHdl.SetBPFFilter("icmp"); err != nil {
		return nil, err
	}
	return pcapHdl, nil
}

// recvPackets listens on the provided pcap handler for packets sent, processes
// TCP and ICMP packets differently, and aborts if signalled
func (z *zeroTrace) recvPackets(pcapHdl *pcap.Handle, hops chan hopRTT, quit chan bool) {
	z.SentPktsIPId = make(map[int][]sentPacketData)
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())
	var counter int

	for {
		select {
		case <-quit:
			return
		case packet := <-packetStream.Packets():
			currTTL := z.CurrTTLIndicator
			if packet == nil {
				continue
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

			if ipLayer != nil {
				// If it is an ICMP packet, check if it is the ICMP TTL
				// exceeded one we are looking for
				if icmpLayer != nil && counter != currTTL {
					err := z.processICMPpkt(packet, currTTL, &counter, hops)
					if err != nil {
						continue
					}
				}
			}
			if counter > ttlEnd {
				return
			}
		}
	}

}

// processICMPpkt takes the packet (known to contain an ICMP layer, and is not
// a duplicate for the TTL we have already evaluated) it extracts the received
// timestamp, and IP Id from the IP header of the original packet from the ICMP
// error packet it extracts the Hop RTT data, and passes the extracted data to
// the hops channel if: the packet contains the TTL Exceeded error code, and
// the SentPktsIPId map contains the found IP Id at the current TTL, or errors
// if any
func (z *zeroTrace) processICMPpkt(packet gopacket.Packet, currTTL int, counter *int, hops chan hopRTT) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipl, _ := ipLayer.(*layers.IPv4)
	currHop := ipl.SrcIP

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
	ipHeaderIcmp, err := getHeaderFromICMPResponsePayload(icmpPkt.LayerPayload())
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
	ipid := ipHeaderIcmp.Id
	recvTimestamp := packet.Metadata().Timestamp
	if currHop.String() == z.ClientIP {
		val := hopRTT{IP: currHop, RTT: z.extractTracerouteHopRTT(currTTL, ipid, recvTimestamp, true)}
		// May recieve ICMP responses from Client IP during the connection that
		// are unrelated to 0trace so check for error from
		// extractTracerouteHopRTT
		if val.RTT != 0 {
			hops <- val
		}
		return nil
	}
	if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if z.SentPktsIPId[currTTL] != nil && sliceContains(z.SentPktsIPId[currTTL], ipid) {
			hops <- hopRTT{IP: currHop, RTT: z.extractTracerouteHopRTT(currTTL, ipid, recvTimestamp, false)}
			*counter = currTTL
		}
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
	sentTime, err := getSentTimestampfromIPId(z.SentPktsIPId[currTTL], ipid)
	if err != nil {
		l.Println("Error getting timestamp from sent pkt: ", err)
		hopRTTVal = 0
	} else {
		hopRTTVal = recvTimestamp.Sub(sentTime)
	}
	return fmtTimeMs(hopRTTVal)
}
