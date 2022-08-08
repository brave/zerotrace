package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	beginTTLValue        = 5
	MaxTTLHops           = 32
	stringToSend         = "test string tcp"
	tracerouteHopTimeout = time.Second * 10
	snaplen              = 65536
	promisc              = true
	ipversion            = 4
)

var (
	buffer  gopacket.SerializeBuffer
	options = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	deviceName   string
	icmpPktError = errors.New("IP header unavailable")
)

type SentPacketData struct {
	HopIPId     uint16
	HopSentTime time.Time
}

type HopRTT struct {
	IP  net.IP
	RTT float64
}

type zeroTrace struct {
	Iface            string
	Conn             net.Conn
	UUID             string
	PcapHdl          *pcap.Handle
	ClientIP         string
	ClientPort       int
	IPIdHop          map[int][]SentPacketData
	CurrTTLIndicator int
}

type TracerouteResults struct {
	UUID      string
	Timestamp string
	HopData   map[int]HopRTT
}

// newZeroTrace instantiates and returns a new zeroTrace struct with the interface, net.Conn underlying connection, uuid and client IP and port data
func newZeroTrace(iface string, conn net.Conn, uuid string, clientIP string, clientPort int) *zeroTrace {
	return &zeroTrace{
		Iface:      iface,
		Conn:       conn,
		UUID:       uuid,
		ClientIP:   clientIP,
		ClientPort: clientPort,
	}
}

// Run reaches the underlying connection and sets up necessary pcap handles
// and implements the 0trace method of sending TTL-limited probes on an existing TCP connection
func (z *zeroTrace) Run() (map[int]HopRTT, error) {
	var err error
	z.PcapHdl, err = z.setupPcapAndFilter()
	if err != nil {
		return nil, err
	}

	recvdHopData := make(chan HopRTT)
	traceroute := make(map[int]HopRTT)

	// Fire go routine to start listening for packets on the handler before sending TTL limited probes
	go z.recvPackets(z.PcapHdl, recvdHopData)

	// Send TTL limited probes and await response from channel that identifies the hop which sent the ICMP response
	// Stop sending any more probes if connection errors out
	for ttlValue := beginTTLValue; ttlValue <= MaxTTLHops; ttlValue++ {
		sendError := z.sendTracePacket(ttlValue)
		if sendError != nil {
			return traceroute, sendError
		}
		z.CurrTTLIndicator = ttlValue
		ticker := time.NewTicker(tracerouteHopTimeout)
		defer ticker.Stop()
		select {
		case hopData := <-recvdHopData:
			traceroute[ttlValue] = hopData
		case <-ticker.C:
			ErrLogger.Println("Traceroute Hop Timeout at Hop ", ttlValue, ". Moving on to the next hop.")
			var empty net.IP
			traceroute[ttlValue] = HopRTT{empty, 0}
			continue
		}
		if traceroute[ttlValue].IP.String() == z.ClientIP {
			break
		}
	}
	return traceroute, nil
}

// setupPcap sets up the pcap handle on the required interface, and applies the filter and returns it
func (z *zeroTrace) setupPcapAndFilter() (*pcap.Handle, error) {
	pcapHdl, err := pcap.OpenLive(z.Iface, snaplen, promisc, time.Second)
	if err != nil {
		ErrLogger.Println("Handle error:", err)
		return nil, err
	}
	if err = pcapHdl.SetBPFFilter(fmt.Sprintf("(tcp and port %d and host %s) or icmp", z.ClientPort, z.ClientIP)); err != nil {
		ErrLogger.Fatal(err)
		return nil, err
	}
	return pcapHdl, nil
}

// recvPackets listens on the provided pcap handler for packets sent, processes TCP and ICMP packets differently
func (z *zeroTrace) recvPackets(pcapHdl *pcap.Handle, hops chan HopRTT) {
	tempConn := z.Conn.(*tls.Conn)
	tcpConn := tempConn.NetConn()

	localSrcAddr := tcpConn.LocalAddr().String()
	serverIP, _, _ := net.SplitHostPort(localSrcAddr)

	z.IPIdHop = make(map[int][]SentPacketData)
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())
	var counter int

	for packet := range packetStream.Packets() {
		currTTL := z.CurrTTLIndicator
		if packet == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer != nil {
			// To identify the TCP packet that we have sent
			if tcpLayer != nil {
				z.processTCPpkt(packet, serverIP)
			}
			// If it is an ICMP packet, check if it is the ICMP TTL exceeded one we are looking for
			if icmpLayer != nil && counter != currTTL {
				clientFound, err := z.processICMPpkt(packet, currTTL, &counter, hops)
				if err == icmpPktError {
					continue
				} else if clientFound {
					return
				}
			}
		}
		if counter > MaxTTLHops {
			return
		}
	}
}

// sendTracePacket sets the ttlValue, sends the TTL limited probe on the tcpConn and return errors if any
func (z *zeroTrace) sendTracePacket(ttlValue int) error {
	tempConn := z.Conn.(*tls.Conn)
	tcpConn := tempConn.NetConn()
	ipConn := ipv4.NewConn(tcpConn)

	rawBytes := []byte(stringToSend)
	localSrcAddr := tcpConn.LocalAddr().String()
	localSrcIP, localSrcPortString, _ := net.SplitHostPort(localSrcAddr)
	localSrcPort, _ := strconv.Atoi(localSrcPortString)

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		Version:  ipversion,
		SrcIP:    net.ParseIP(localSrcIP),
		DstIP:    net.ParseIP(z.ClientIP),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(localSrcPort),
		DstPort: layers.TCPPort(z.ClientPort),
		PSH:     true,
		ACK:     true,
	}
	_ = tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()

	serializeErr := gopacket.SerializeLayers(buffer, options,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	if serializeErr != nil {
		ErrLogger.Println("Send Packet Error: Serialize: ", serializeErr)
		return serializeErr
	}

	ttlErr := ipConn.SetTTL(int(ttlValue))
	if ttlErr != nil {
		ErrLogger.Println("Send Packet Error: Setting ttl: ", ttlErr)
		return ttlErr
	}

	outgoingPacket := buffer.Bytes()
	if _, err := tcpConn.Write(outgoingPacket); err != nil {
		ErrLogger.Println("Send Packet Error writing to connection: ", err)
		return err
	}
	ErrLogger.Println("Sent ", ttlValue, " packet")
	return nil
}

// processICMPpkt takes the packet (known to contain an ICMP layer, and is not a duplicate for the TTL we have already evaluated)
// it extracts the received timestamp, and IP Id from the IP header of the original packet from the ICMP error packet
// it extracts the Hop RTT data, and passes the extracted data to the hops channel if:
// the packet contains the TTL Exceeded error code, and the ipIdHop map contains the found IP Id at the current TTL,
// or the client IP has been reached
// it retuns true if the client has been reached, and returns false if otherwise, and error if any
func (z *zeroTrace) processICMPpkt(packet gopacket.Packet, currTTL int, counter *int, hops chan HopRTT) (bool, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipl, _ := ipLayer.(*layers.IPv4)
	currHop := ipl.SrcIP

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
	ipHeaderIcmp, err := getHeaderFromICMPResponsePayload(icmpPkt.LayerPayload())
	if err != nil {
		return false, icmpPktError
	}

	ipid := ipHeaderIcmp.Id
	recvTimestamp := packet.Metadata().Timestamp
	if currHop.String() == z.ClientIP {
		hops <- z.extractTracerouteHopData(currTTL, currHop, ipid, recvTimestamp, true)
		return true, nil
	}
	if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if z.IPIdHop[currTTL] != nil && sliceContains(z.IPIdHop[currTTL], ipid) {
			hops <- z.extractTracerouteHopData(currTTL, currHop, ipid, recvTimestamp, false)
			*counter = currTTL
		}
	}
	return false, nil
}

// processTCPpkt processes packet (known to contain a TCP layer)
// as long the packet's srcIP matches the serverIP, it updates the z.IPIdHop map with the TTL and IPID seen on the packet
// In case of retransmissions we might see repeated sequence numbers on packets, although the underlying TTL set (using setTTL) has changed
// However, IP Id will remain unique per packet and can be used to correlate received packets
// (RFC 1812 says _at least_ IP header must be returned along with the packet)
func (z *zeroTrace) processTCPpkt(packet gopacket.Packet, serverIP string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipl, _ := ipLayer.(*layers.IPv4)
	packetTTL := int(ipl.TTL)
	currHop := ipl.SrcIP.String()
	if currHop == serverIP {
		sentTime := packet.Metadata().Timestamp
		currIPId := ipl.Id
		if !sliceContains(z.IPIdHop[packetTTL], currIPId) {
			z.IPIdHop[packetTTL] = append(z.IPIdHop[packetTTL], SentPacketData{HopIPId: currIPId, HopSentTime: sentTime})
		}
	}
}

// extractTracerouteHopData obtains the time stamp for the TTL-limited packet which was sent for the "currTTL" value,
// and subtracts that from the recvTimestamp supplied to calculate RTT for the current hop
// and returns the HopRTT object with the calculated RTT value.
// logs the current TTL value if the client has already been reached
func (z *zeroTrace) extractTracerouteHopData(currTTL int, currHop net.IP, ipid uint16, recvTimestamp time.Time, clientReached bool) HopRTT {
	if clientReached {
		ErrLogger.Println("Traceroute reached client (ICMP response) at hop: ", currTTL)
	} else {
		ErrLogger.Println("Received packet ipid: ", ipid, " TTL: ", currTTL)
	}
	var hopRTTVal time.Duration
	sentTime, err := getSentTimestampfromIPId(z.IPIdHop[currTTL], ipid)
	if err != nil {
		ErrLogger.Println("Error getting timestamp from sent pkt: ", err)
		hopRTTVal = 0
	} else {
		hopRTTVal = recvTimestamp.Sub(sentTime)
	}
	return HopRTT{IP: currHop, RTT: fmtTimeMs(hopRTTVal)}
}
