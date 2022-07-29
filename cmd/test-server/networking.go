package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/go-ping/ping"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	ICMPCount            = 5
	ICMPTimeout          = time.Second * 10
	batchSizeLimit       = 100
	beginTTLValue        = 5
	MaxTTLHops           = 32
	stringToSend         = "test string tcp"
	tracerouteHopTimeout = time.Second * 10
	snaplen              = 65536
	promisc              = true
)

var (
	buffer  gopacket.SerializeBuffer
	options = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	timerPerHopPerUUID = make(map[string]time.Time)
	deviceName         string
	currTTLIndicator   = make(map[string]int)
	icmpPktError       = errors.New("IP header unavailable")
)

type RtItem struct {
	IP        string
	PktSent   int
	PktRecv   int
	PktLoss   float64
	MinRtt    float64
	AvgRtt    float64
	MaxRtt    float64
	StdDevRtt float64
}

type Results struct {
	UUID        string
	IPaddr      string
	Timestamp   string
	IcmpPing    []RtItem
	AvgIcmpStat float64
}

type SentPacketData struct {
	HopIPId     uint16
	HopSentTime time.Time
}

type HopRTT struct {
	IP  net.IP
	RTT float64
}

type TracerouteResults struct {
	UUID      string
	Timestamp string
	HopData   map[int]HopRTT
}

// IcmpPinger sends ICMP pings and returns statistics
func IcmpPinger(ip string) RtItem {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		panic(err)
	}
	pinger.Count = ICMPCount
	pinger.Timeout = ICMPTimeout
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
	stat := pinger.Statistics()
	icmp := RtItem{ip, stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss, fmtTimeMs(stat.MinRtt),
		fmtTimeMs(stat.AvgRtt), fmtTimeMs(stat.MaxRtt), fmtTimeMs(stat.StdDevRtt)}
	return icmp
}

// getMeanIcmpRTT gets Avg RTT from all successful ICMP measurements, to display on webpage
func getMeanIcmpRTT(icmp []RtItem) float64 {
	var sum float64 = 0
	var len float64 = 0
	for _, x := range icmp {
		if x.AvgRtt == 0 {
			continue
		}
		sum += x.AvgRtt
		len += 1
	}
	var avg float64 = sum / len
	if math.IsNaN(avg) {
		return 0.0
	}
	return avg
}

// start0trace reaches the underlying connection and sets up necessary pcap handles
// and implements the 0trace method of sending TTL-limited probes on an existing TCP connection
func start0trace(uuid string, netConn net.Conn) map[int]HopRTT {
	clientIPstr := netConn.RemoteAddr().String()
	clientIP, clPort, _ := net.SplitHostPort(clientIPstr)
	clientPort, _ := strconv.Atoi(clPort)

	handle, err := pcap.OpenLive(deviceName, snaplen, promisc, time.Second)
	if err != nil {
		ErrLogger.Println("Handle error:", err)
	}

	if err = handle.SetBPFFilter(fmt.Sprintf("(tcp and port %d and host %s) or icmp", clientPort, clientIP)); err != nil {
		log.Fatal(err)
	}
	recvdHop := make(chan HopRTT)
	traceroute := make(map[int]HopRTT)

	tempConn := netConn.(*tls.Conn)
	tcpConn := tempConn.NetConn()
	dstIP := net.ParseIP(clientIP)
	ipConn := ipv4.NewConn(tcpConn)

	localSrcAddr := tcpConn.LocalAddr().String()
	localSrcIP, _, _ := net.SplitHostPort(localSrcAddr)
	// Fire go routine to start listening for packets on the handler before sending TTL limited probes
	go recvPackets(uuid, handle, localSrcIP, clientIP, recvdHop)

	// Send TTL limited probes and await response from channel that identifies the hop which sent the ICMP response
	// Stop sending any more probes if connection errors out
	for ttlValue := beginTTLValue; ttlValue <= MaxTTLHops; ttlValue++ {
		sentString := stringToSend + strconv.Itoa(ttlValue)
		sendError := sendTracePacket(tcpConn, ipConn, dstIP, clientPort, sentString, ttlValue)
		if sendError != nil {
			break
		}
		currTTLIndicator[uuid] = ttlValue
		ticker := time.NewTicker(tracerouteHopTimeout)
		defer ticker.Stop()
		select {
		case hopData := <-recvdHop:
			traceroute[ttlValue] = hopData
		case <-ticker.C:
			ErrLogger.Println("Traceroute Hop Timeout at Hop ", ttlValue, ". Moving on to the next hop.")
			var empty net.IP
			traceroute[ttlValue] = HopRTT{empty, 0}
			continue
		}
		if traceroute[ttlValue].IP.String() == clientIP {
			break
		}
	}
	return traceroute
}

// sendTracePacket sends the TTL limited probe on the tcpConn, and sets the ttlValue using ipConn.SetTTL, and return errors if any
func sendTracePacket(tcpConn net.Conn, ipConn *ipv4.Conn, dstIP net.IP, clientPort int, sentString string, ttlValue int) error {
	rawBytes := []byte(sentString)
	localSrcAddr := tcpConn.LocalAddr().String()
	localSrcIP, localSrcPortString, _ := net.SplitHostPort(localSrcAddr)
	localSrcPort, _ := strconv.Atoi(localSrcPortString)

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		SrcIP:    net.ParseIP(localSrcIP),
		DstIP:    dstIP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(int(localSrcPort)),
		DstPort: layers.TCPPort(clientPort),
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

// recvPackets listens on the provided pcap handler for packets sent, processes TCP and ICMP packets differently
func recvPackets(uuid string, handle *pcap.Handle, serverIP string, clientIP string, hops chan HopRTT) {
	var ipIdHop = make(map[int][]SentPacketData)
	packetStream := gopacket.NewPacketSource(handle, handle.LinkType())
	var counter int
	timerPerHopPerUUID[uuid] = time.Now().UTC()

	for packet := range packetStream.Packets() {
		currTTL := currTTLIndicator[uuid]
		if packet == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer != nil {
			// To identify the TCP packet that we have sent
			if tcpLayer != nil {
				processTCPpkt(packet, serverIP, ipIdHop)
			}
			// If it is an ICMP packet, check if it is the ICMP TTL exceeded one we are looking for
			if icmpLayer != nil && counter != currTTL {
				clientFound, err := processICMPpkt(packet, clientIP, currTTL, &counter, ipIdHop, hops)
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

// processICMPpkt takes the packet (known to contain an ICMP layer, and is not a duplicate for the TTL we have already evaluated)
// it extracts received timestamp and the IP header of the original packet from the ICMP packet payload which it uses to get the original IP Id
// it extracts the Hop RTT data, and passes the extracted data to the hops channel if:
// the packet contains the TTL Exceeded error code, and the ipIdHop map contains the found IP Id at the current TTL,
// or the client IP has been reached
// it retuns true if the client has been reached, and returns false if otherwise, and error if any
func processICMPpkt(packet gopacket.Packet, clientIP string, currTTL int, counter *int, ipIdHop map[int][]SentPacketData, hops chan HopRTT) (bool, error) {
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
	if currHop.String() == clientIP {
		hops <- extractTracerouteHopData(currTTL, currHop, ipid, recvTimestamp, counter, true, ipIdHop)
		return true, nil
	}
	if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if ipIdHop[currTTL] != nil && sliceContains(ipIdHop[currTTL], ipid) {
			hops <- extractTracerouteHopData(currTTL, currHop, ipid, recvTimestamp, counter, false, ipIdHop)
		}
	}
	return false, nil
}

// extractTracerouteHopData obtains the time stamp for the TTL-limited packet which was sent for the "currTTL" value,
// and subtracts that from the recvTimestamp supplied to calculate RTT for the current hop
// and returns the HopRTT object with the calculated RTT value.
// It updates the counter object to the currTTL value and
// logs the current TTL value if the client has already been reached
func extractTracerouteHopData(currTTL int, currHop net.IP, ipid uint16, recvTimestamp time.Time, counter *int, clientReached bool, ipIdHop map[int][]SentPacketData) HopRTT {
	if clientReached {
		ErrLogger.Println("Traceroute reached client (ICMP response) at hop: ", currTTL)
	} else {
		ErrLogger.Println("Received packet ipid: ", ipid, " TTL: ", currTTL)
	}
	var hopRTTVal time.Duration
	sentTime, err := getSentTimestampfromIPId(ipIdHop[currTTL], ipid)
	if err != nil {
		ErrLogger.Println("Error getting timestamp from sent pkt: ", err)
		hopRTTVal = 0
	} else {
		hopRTTVal = recvTimestamp.Sub(sentTime)
	}
	*counter = currTTL
	return HopRTT{IP: currHop, RTT: fmtTimeMs(hopRTTVal)}
}

// processTCPpkt processes packet (known to contain a TCP layer)
// as long the packet's srcIP matches the serverIP, it updates the ipIdHop map with the TTL and IPID seen on the packet
// In case of retransmissions we might see repeated sequence numbers on packets, although the underlying TTL set (using setTTL) has changed
// However, IP Id will remain unique per packet and can be used to correlate received packets
// (RFC 1812 says _at least_ IP header must be returned along with the packet)
func processTCPpkt(packet gopacket.Packet, serverIP string, ipIdHop map[int][]SentPacketData) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipl, _ := ipLayer.(*layers.IPv4)
	packetTTL := int(ipl.TTL)
	currHop := ipl.SrcIP.String()
	if currHop == serverIP {
		sentTime := packet.Metadata().Timestamp
		currIPId := ipl.Id
		if sliceContains(ipIdHop[packetTTL], currIPId) == false {
			ipIdHop[packetTTL] = append(ipIdHop[packetTTL], SentPacketData{HopIPId: currIPId, HopSentTime: sentTime})
		}
	}
}

// getSentTimestampfromIPId traverses the []SentPacketData slice and returns the HopSentTime associated with the provided ipid, and error if any
func getSentTimestampfromIPId(sentDataSlice []SentPacketData, ipid uint16) (time.Time, error) {
	for _, v := range sentDataSlice {
		if v.HopIPId == ipid {
			return v.HopSentTime, nil
		}
	}
	return time.Now().UTC(), errors.New("IP Id not in sent packets")
}

// getHeaderFromICMPResponsePayload parses IP headers from ICMP Response Payload of the icmpPkt and returns IP header, and error if any
func getHeaderFromICMPResponsePayload(icmpPkt []byte) (*layers.IPv4, error) {
	if len(icmpPkt) < 1 {
		return nil, errors.New("Invalid IP header")
	}
	ipHeaderLength := int((icmpPkt[0] & 0x0F) * 4)

	if len(icmpPkt) < ipHeaderLength {
		return nil, errors.New("Length of received ICMP packet too short to decode IP")
	}
	ip := layers.IPv4{}
	ipErr := ip.DecodeFromBytes(icmpPkt[0:], gopacket.NilDecodeFeedback)

	if ipErr != nil {
		return nil, ipErr
	}

	return &ip, nil
}

// sliceContains checks if a particular IP Id (uint16 in layers.IPv4) is present in the slice of IP Ids we provide
func sliceContains(slice []SentPacketData, value uint16) bool {
	for _, v := range slice {
		if v.HopIPId == value {
			return true
		}
	}
	return false
}
