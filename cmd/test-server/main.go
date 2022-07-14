// Reference for webserver that speaks websocket: https://github.com/gorilla/websocket
// Reference for client side websocket code:
// https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/go-ping/ping"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/net/ipv4"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"
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
	directoryPath      string
	timerPerHopPerUUID = make(map[string]time.Time)
	upgrader           = websocket.Upgrader{}
	InfoLogger         *log.Logger
	ErrLogger          *log.Logger
	deviceName         string
	currTTLIndicator   = make(map[string]int)
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

// Implementing this since Golang time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

// Handler for the echo webserver that speaks WebSocket
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/echo") {
		return
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			ErrLogger.Println("read:", err)
			break
		}
		// ReadMessage() returns messageType int, p []byte, err error]
		var wsData map[string]interface{}
		json.Unmarshal(message, &wsData)
		if wsData["type"] != "ws-latency" {
			// Only log the final message with all latencies calculated
			InfoLogger.Println(string(message))
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			ErrLogger.Println("write:", err)
			break
		}
	}
}

// Parse IP headers from ICMP Response Payload
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

// Check if a particular IP Id (uint16 in layers.IPv4) is in the slice of IP Id's we have sent with a particular TTL value
func sliceContains(slice []SentPacketData, value uint16) bool {
	for _, v := range slice {
		if v.HopIPId == value {
			return true
		}
	}
	return false
}

func getSentTimestampfromIPId(sentDataSlice []SentPacketData, ipid uint16) (time.Time, error) {
	for _, v := range sentDataSlice {
		if v.HopIPId == ipid {
			return v.HopSentTime, nil
		}
	}
	return time.Now().UTC(), errors.New("IP Id not in sent packets")
}

// Listen on the provided pcap handler for packets sent
func recvPackets(uuid string, handle *pcap.Handle, serverIP string, clientIP string, hops chan HopRTT) {
	var ipIdHop = make(map[int][]SentPacketData)
	packetStream := gopacket.NewPacketSource(handle, handle.LinkType())
	var counter int
	timerPerHopPerUUID[uuid] = time.Now().UTC()
	var hopRTTVal time.Duration

	for packet := range packetStream.Packets() {
		currTTL := currTTLIndicator[uuid]
		if packet == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer != nil {
			ipl, _ := ipLayer.(*layers.IPv4)
			currHop := ipl.SrcIP.String()
			// To identify the TCP packet that we have sent
			if tcpLayer != nil {
				packetTTL := int(ipl.TTL)
				if currHop == serverIP {
					// in case of retransmissions we might see the same sequence number sent when the TTL was set to different values
					// but IP Id will remain unique per packet and can be used to correlate received packets
					// (RFC 1812 says _at least_ IP header must be returned along with the packet)
					sentTime := packet.Metadata().Timestamp
					currIPId := ipl.Id
					if sliceContains(ipIdHop[packetTTL], currIPId) == false {
						ipIdHop[packetTTL] = append(ipIdHop[packetTTL], SentPacketData{HopIPId: currIPId, HopSentTime: sentTime})
					}
				}
			}

			// If it is an ICMP packet, check if it is the ICMP TTL exceeded one we are looking for
			if icmpLayer != nil && counter != currTTL {
				icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
				ipHeaderIcmp, err := getHeaderFromICMPResponsePayload(icmpPkt.LayerPayload())
				if err != nil {
					continue
				}
				ipid := ipHeaderIcmp.Id
				recvTimestamp := packet.Metadata().Timestamp
				if currHop == clientIP {
					sentTime, err := getSentTimestampfromIPId(ipIdHop[currTTL], ipid)
					if err != nil {
						ErrLogger.Println(err)
						hopRTTVal = 0
					} else {
						hopRTTVal = recvTimestamp.Sub(sentTime)
					}
					ErrLogger.Println("Traceroute reached client (ICMP response) at hop: ", currTTL)
					counter = currTTL // ensure skipped ttls are fine
					hops <- HopRTT{IP: ipl.SrcIP, RTT: fmtTimeMs(hopRTTVal)}
					return
				}
				if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
					if ipIdHop[currTTL] != nil && sliceContains(ipIdHop[currTTL], ipid) {
						ErrLogger.Println("Received packet ipid: ", ipid, " TTL: ", currTTL)
						sentTime, err := getSentTimestampfromIPId(ipIdHop[currTTL], ipid)
						if err != nil {
							ErrLogger.Println("Bad Error: ", err) // this should not happen because we are making the same checks
							hopRTTVal = 0
						} else {
							hopRTTVal = recvTimestamp.Sub(sentTime)
						}
						counter = currTTL // ensure skipped ttls are fine
						hops <- HopRTT{IP: ipl.SrcIP, RTT: fmtTimeMs(hopRTTVal)}
					}
				}
			}
		}
		if counter > MaxTTLHops {
			return
		}
	}
}

// Send the TTL limited probe
func sendTracePacket(tcpConn net.Conn, ipConn *ipv4.Conn, dstIP net.IP, clientPort int, sentString string, ttlValue int) bool {
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
		ErrLogger.Println("Serialize error: ", serializeErr)
		return false
	}

	ttlErr := ipConn.SetTTL(int(ttlValue))
	if ttlErr != nil {
		ErrLogger.Println("Error setting ttl: ", ttlErr)
		return false
	}

	outgoingPacket := buffer.Bytes()
	if _, err := tcpConn.Write(outgoingPacket); err != nil {
		ErrLogger.Println("Error writing to connection: ", err)
		return false
	}
	ErrLogger.Println("Sent ", ttlValue, " packet")
	return true
}

// Reach the underlying connection and set up necessary handler and initalize 0trace set up
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
		sent := sendTracePacket(tcpConn, ipConn, dstIP, clientPort, sentString, ttlValue)
		currTTLIndicator[uuid] = ttlValue
		if sent == false {
			break
		}
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

// Handler that speaks WebSocket for extracting underlying connection to use for 0trace
func traceHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/trace") {
		return
	}
	var uuid string
	for k, v := range r.URL.Query() {
		if k == "uuid" {
			uuid = v[0]
		}
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	myConn := c.UnderlyingConn()
	traceroute := start0trace(uuid, myConn)
	results := TracerouteResults{
		UUID:      uuid,
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		HopData:   traceroute,
	}
	zeroTraceResult, err := json.Marshal(results)
	if err!= nil {
		ErrLogger.Println("Error logging 0trace results: ", err)
		InfoLogger.Println(results) // Dump results in non-JSON format
	}
	zeroTraceString := string(zeroTraceResult)
	InfoLogger.Println(zeroTraceString)
}

// Send ICMP pings and return statistics
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

// Avg RTT from all successful ICMP measurements, to display on webpage
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
	if len == 0 {
		return 0
	}
	var avg float64 = sum / len
	return avg
}

// Checks if request method is GET, and ensures URL path is right
func checkHTTPParams(w http.ResponseWriter, r *http.Request, pathstring string) bool {
	if r.URL.Path != pathstring {
		http.NotFound(w, r)
		return true
	}
	if r.Method != "GET" {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
		return true
	}
	return false
}

// Handler for ICMP measurements which also serves the webpage via a template
func pingHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/ping") {
		return
	}
	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)

	// Concurrently send ICMP pings for a <batchSizeLimit> number of IPs
	var icmpResults []RtItem
	icmpResults = append(icmpResults, IcmpPinger(clientIP))

	// Combine all results
	results := Results{
		UUID:   uuid.NewString(),
		IPaddr: clientIP,
		//RFC3339 style UTC date time with added seconds information
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		IcmpPing:    icmpResults,
		AvgIcmpStat: getMeanIcmpRTT(icmpResults),
	}

	jsObj, err := json.Marshal(results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resultString := string(jsObj)
	InfoLogger.Println(resultString)
	var WebTemplate, _ = template.ParseFiles(path.Join(directoryPath, "pingpage.html"))
	WebTemplate.Execute(w, results)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/") {
		return
	}
	path := path.Join(directoryPath, "/index.html")
	http.ServeFile(w, r, path)
}

func main() {
	var logfilePath string
	var errlogPath string
	flag.StringVar(&directoryPath, "dirpath", "", "Path where this code lives, used to index the html file paths")
	flag.StringVar(&logfilePath, "logfile", "logFile.jsonl", "Path to log file")
	flag.StringVar(&errlogPath, "errlog", "errlog.txt", "Path to err log file")
	flag.StringVar(&deviceName, "deviceName", "eth0", "Interface name to listen on, default: eth0")
	flag.Parse()
	file, err := os.OpenFile(logfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	errFile, err := os.OpenFile(errlogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	InfoLogger = log.New(file, "", 0)
	ErrLogger = log.New(errFile, "", log.Ldate|log.Ltime)
	certPath := "/etc/letsencrypt/live/test.reethika.info/"
	fullChain := path.Join(certPath, "fullchain.pem")
	privKey := path.Join(certPath, "privkey.pem")
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/echo", echoHandler)
	http.HandleFunc("/trace", traceHandler)
	http.ListenAndServeTLS(":443", fullChain, privKey, nil)
}
