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
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
)

const ICMPCount = 5
const ICMPTimeout = time.Second * 10

const batchSizeLimit int = 100
const beginTTLValue = 5
const MaxTTLHops = 32

var buffer gopacket.SerializeBuffer
var options = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

const stringToSend = "heeloo tcp"
const tracerouteHopTimeout = 2 * time.Minute

var directoryPath string
var timerPerHopPerUUID = make(map[string]time.Time)

// FIXME: These should not be global variables in a multi-client setting
var timeStart = make(map[int]time.Time)
var hopRTT = make(map[int]time.Duration)

// Use with default options
var upgrader = websocket.Upgrader{}

var (
	InfoLogger *log.Logger
)
var (
	ErrLogger *log.Logger
)
var deviceName string

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

type TracerouteResults struct {
	UUID   string
	Hops   map[int]net.IP
	HopRTT map[int]time.Duration
}

// Check if a particular IP Id (uint16 in layers.IPv4) is in the slice of IP Id's we have sent with a particular TTL value
func sliceContains(slice []uint16, value uint16) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// Implementing this since Golang time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

// Increment IPs to enumerate all IPs in a subnet // not used now
func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Get all adjacent IPs to ping // not used now
func getAdjacentIPs(clientIP string) ([]string, error) {
	var requiredSubnet = clientIP + "/24"
	var adjIPs []string
	ip, ipnet, err := net.ParseCIDR(requiredSubnet)
	if err != nil {
		return []string{}, err
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); increment(ip) {
		adjIPs = append(adjIPs, ip.String())
	}
	return adjIPs, nil
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

// Parse IP and TCP headers from ICMP Response Payload
func getHeadersFromICMPResponsePayload(data []byte) (*layers.IPv4, *layers.TCP, error) {
	if len(data) < 1 {
		return nil, nil, errors.New("Invalid IP header")
	}
	ipHeaderLength := int((data[0] & 0x0F) * 4)

	if len(data) < ipHeaderLength {
		return nil, nil, errors.New("Length of received ICMP packet too short to decode IP")
	}
	ip := layers.IPv4{}
	tcp := layers.TCP{}
	ipErr := ip.DecodeFromBytes(data[0:], gopacket.NilDecodeFeedback)
	tcpErr := tcp.DecodeFromBytes(data[ipHeaderLength:], gopacket.NilDecodeFeedback)

	if ipErr != nil && tcpErr != nil {
		return nil, nil, ipErr
	}

	return &ip, &tcp, nil
}

// Returns current time, used to reset counter timer
func resetTimerForCounter() time.Time {
	return time.Now()
}

// Check if tracerouteHopTimeout has been reached since the timeToCheck was set
func hasTracerouteHopTimedout(timeToCheck time.Time) bool {
	timenow := time.Now()
	if timenow.Sub(timeToCheck) >= tracerouteHopTimeout {
		return true
	}
	return false
}

// Listen on the provided pcap handler for packets sent
func recvPackets(uuid string, handle *pcap.Handle, serverIP string, clientIP string, hops chan net.IP) {
	var ipIdHop = make(map[int][]uint16)
	packetStream := gopacket.NewPacketSource(handle, handle.LinkType())
	counter := beginTTLValue
	timerPerHopPerUUID[uuid] = time.Now()
	for packet := range packetStream.Packets() {
		// if a particular hop is taking too long, then return nil and move on to sending packets to find the next hop
		if hasTracerouteHopTimedout(timerPerHopPerUUID[uuid]) {
			counter += 1
			timerPerHopPerUUID[uuid] = resetTimerForCounter()
			hops <- nil
		}
		recvTime := time.Now()
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
					if sliceContains(ipIdHop[packetTTL], ipl.Id) == false {
						ipIdHop[packetTTL] = append(ipIdHop[packetTTL], ipl.Id)
					}
				} else if currHop == clientIP {
					// possibly the response from the client IP
					ErrLogger.Println("Traceroute reached client (TCP response) at hop: ", counter)
					return
				}
			}
			// If it is an ICMP packet, check if it is the ICMP TTL exceeded one we are looking for
			if icmpLayer != nil {
				icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
				if currHop == clientIP {
					ErrLogger.Println("Traceroute reached client (ICMP response) at hop: ", counter)
					hops <- ipl.SrcIP
					return
				}
				if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
					ipHeaderIcmp, _, err := getHeadersFromICMPResponsePayload(icmpPkt.LayerPayload())
					if err != nil {
						// ErrLogger.Println("Error getting header from ICMP packet: ", err)
						continue
					}
					ipid := ipHeaderIcmp.Id
					if ipIdHop[counter] != nil && sliceContains(ipIdHop[counter], ipid) {
						ErrLogger.Println("Received packet ipid: ", ipid, " TTL: ", counter)
						hopRTT[counter] = recvTime.Sub(timeStart[counter])
						counter += 1
						timerPerHopPerUUID[uuid] = resetTimerForCounter()
						hops <- ipl.SrcIP
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
func sendTracePacket(tcpConn net.Conn, ipConn *ipv4.Conn, dstIP net.IP, clPort int, sentString string, ttlValue int) bool {
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
		DstPort: layers.TCPPort(clPort),
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
func start0trace(uuid string, clientIP string, clientPort string, netConn net.Conn) map[int]net.IP {
	handle, err := pcap.OpenLive(deviceName, 65536, true, time.Second)
	if err != nil {
		ErrLogger.Println("Handle error:", err)
	}
	clPort, _ := strconv.Atoi(clientPort)

	if err = handle.SetBPFFilter(fmt.Sprintf("(tcp and port %d and host %s) or icmp", clPort, clientIP)); err != nil {
		log.Fatal(err)
	}
	recvdHop := make(chan net.IP)
	traceroute := make(map[int]net.IP)

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
		timeStart[ttlValue] = time.Now()
		sent := sendTracePacket(tcpConn, ipConn, dstIP, clPort, sentString, ttlValue)
		if sent == false {
			break
		}
		hop := <-recvdHop
		if hop == nil {
			ErrLogger.Println("Moving on to the next hop")
		}
		traceroute[ttlValue] = hop
		if hop.String() == clientIP {
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
	clientIPstr := r.RemoteAddr
	clientIP, clientPort, _ := net.SplitHostPort(clientIPstr)

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		return
	}
	defer c.Close()
	myConn := c.UnderlyingConn()
	traceroute := start0trace(uuid, clientIP, clientPort, myConn)
	results := TracerouteResults{UUID: uuid, Hops: traceroute, HopRTT: hopRTT}
	zeroTraceResult, _ := json.Marshal(results)
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

	ipsToPing := []string{clientIP}
	ipTotal := len(ipsToPing)
	offset := 0
	numBatches := int(math.Ceil(float64(ipTotal / batchSizeLimit)))

	// Concurrently send ICMP pings for a <batchSizeLimit> number of IPs
	var icmpResults []RtItem

	for i := 0; i <= numBatches; i++ {
		lower := offset
		upper := offset + batchSizeLimit

		if upper > ipTotal {
			upper = ipTotal
		}
		batchIPs := ipsToPing[lower:upper]
		offset += batchSizeLimit

		var icmpWaitGroup sync.WaitGroup

		icmpWaitGroup.Add(len(batchIPs))

		for id := range batchIPs {
			go func(IP string, id int) {
				defer icmpWaitGroup.Done()
				icmpResults = append(icmpResults, IcmpPinger(IP))
			}(batchIPs[id], id)
		}
		icmpWaitGroup.Wait()
	}

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
