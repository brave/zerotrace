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
	timerPerHopPerUUID = make(map[string]time.Time)
	deviceName         string
	currTTLIndicator   = make(map[string]int)
)

type zeroTrace struct {
	Iface      string
	Conn       net.Conn
	UUID       string
	PcapHdl    *pcap.Handle
	ClientIP   string
	ClientPort int
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
		currTTLIndicator[z.UUID] = ttlValue
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

	var ipIdHop = make(map[int][]SentPacketData)
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())
	var counter int
	timerPerHopPerUUID[z.UUID] = time.Now().UTC()

	for packet := range packetStream.Packets() {
		currTTL := currTTLIndicator[z.UUID]
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
				clientFound, err := processICMPpkt(packet, z.ClientIP, currTTL, &counter, ipIdHop, hops)
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
