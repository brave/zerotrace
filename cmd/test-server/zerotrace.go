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

type zeroTrace struct {
	Iface string
	Conn  net.Conn
	UUID  string
}

func newZeroTrace(iface string, uuid string, conn net.Conn) *zeroTrace {
	return &zeroTrace{
		Iface: iface,
		Conn:  conn,
		UUID:  uuid,
	}
}

// Run reaches the underlying connection and sets up necessary pcap handles
// and implements the 0trace method of sending TTL-limited probes on an existing TCP connection
func (z *zeroTrace) Run() (map[int]HopRTT, error) {
	pcapHdl, err := z.setupPcap()
	if err != nil {
		return nil, err
	}

	clientIPstr := z.Conn.RemoteAddr().String()
	clientIP, clPort, _ := net.SplitHostPort(clientIPstr)
	clientPort, _ := strconv.Atoi(clPort)

	if err = pcapHdl.SetBPFFilter(fmt.Sprintf("(tcp and port %d and host %s) or icmp", clientPort, clientIP)); err != nil {
		ErrLogger.Fatal(err)
	}
	recvdHopData := make(chan HopRTT)
	traceroute := make(map[int]HopRTT)

	// Fire go routine to start listening for packets on the handler before sending TTL limited probes
	go z.recvPackets(z.UUID, pcapHdl, clientIP, recvdHopData)

	// Send TTL limited probes and await response from channel that identifies the hop which sent the ICMP response
	// Stop sending any more probes if connection errors out
	for ttlValue := beginTTLValue; ttlValue <= MaxTTLHops; ttlValue++ {
		sendError := z.sendTracePacket(ttlValue)
		if sendError != nil {
			return nil, sendError
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
		if traceroute[ttlValue].IP.String() == clientIP {
			break
		}
	}
	return traceroute, nil
}

// setupPcap sets up the pcap handle on the required interface and returns it
func (z *zeroTrace) setupPcap() (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(z.Iface, snaplen, promisc, time.Second)
	if err != nil {
		ErrLogger.Println("Handle error:", err)
		return nil, err
	}
	return handle, nil
}

// recvPackets listens on the provided pcap handler for packets sent, processes TCP and ICMP packets differently
func (z *zeroTrace) recvPackets(uuid string, pcapHdl *pcap.Handle, clientIP string, hops chan HopRTT) {
	tempConn := z.Conn.(*tls.Conn)
	tcpConn := tempConn.NetConn()

	localSrcAddr := tcpConn.LocalAddr().String()
	serverIP, _, _ := net.SplitHostPort(localSrcAddr)

	var ipIdHop = make(map[int][]SentPacketData)
	packetStream := gopacket.NewPacketSource(pcapHdl, pcapHdl.LinkType())
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

// sendTracePacket sets the ttlValue, sends the TTL limited probe on the tcpConn and return errors if any
func (z *zeroTrace) sendTracePacket(ttlValue int) error {
	// Get client IP and port
	clientIPstr := z.Conn.RemoteAddr().String()
	clientIP, clPort, _ := net.SplitHostPort(clientIPstr)
	clientPort, _ := strconv.Atoi(clPort)

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
		DstIP:    net.ParseIP(clientIP),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(localSrcPort),
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
