package main

import (
	"errors"
	"math"
	"net"
	"time"

	"github.com/go-ping/ping"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ICMPCount   = 5
	ICMPTimeout = time.Second * 10
)

var (
	icmpPktError = errors.New("IP header unavailable")
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
		if !sliceContains(ipIdHop[packetTTL], currIPId) {
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
