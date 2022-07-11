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
	"github.com/montanaflynn/stats"
	"golang.org/x/net/ipv4"
	"html/template"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ICMPCount = 5
const ICMPTimeout = time.Second * 10
const NumTCPPkts = 5

// TCP RTO is 1s (RFC 6298), so having a 1s timeout for RTT measurement makes sense
const TCPTimeout = time.Duration(1000) * time.Millisecond
const TCPInterval = time.Duration(1100) * time.Millisecond

// rate per batch becomes roughly 100 IPs * (5 ICMP packets + 5 TCP packets *7 ports) packets per IP
const batchSizeLimit int = 100
const beginTTLValue = 5
const MaxTTLHops = 32

var buffer gopacket.SerializeBuffer
var options = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

const stringToSend = "heeloo tcp"

var PortsToTest = [...]int{53, 80, 443, 3389, 8080, 9100}
var directoryPath string

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

type tcpProbeResult struct {
	Destination    string
	SequenceNumber uint64
	Timeinms       float64
}

type tcpResult struct {
	Port      int
	TimesInms []float64
	MinRtt    float64
	AvgRtt    float64
	MaxRtt    float64
	StdDevRtt float64
}

type tcpStruct struct {
	IP     string
	Probes []tcpResult
}

type Results struct {
	UUID        string
	IPaddr      string
	Timestamp   string
	IcmpPing    []RtItem
	AvgIcmpStat float64
	TcpPing     []tcpStruct
	AvgTcpStat  float64
}

type TracerouteResults struct {
	UUID        string
	Hops		map[int]net.IP
}

// Implementing this since Golang time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

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

func debugPrintClientInfo(r *http.Request, handlerName string) {
	clientIPstr := r.RemoteAddr
	clientIP, clientPort, _ := net.SplitHostPort(clientIPstr)
	log.Println(handlerName, " HANDLER is : ", clientIP, " and port is: ", clientPort)
}

// Handler for the echo webserver that speaks WebSocket
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/echo") {
		return
	}
	debugPrintClientInfo(r, "echo")
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

// Parse TCP header from ICMP Response Payload
func getTCPHeaderFromICMPResponsePayload(data []byte) (*layers.TCP, error) {
	if len(data) < 1 {
		return nil, errors.New("received invalid IP header")
	}
	ipHeaderLength := int((data[0] & 0x0F) * 4)

	if len(data) < ipHeaderLength {
		return nil, errors.New("length of ICMP packet too short to decode IP")
	}

	tcp := layers.TCP{}

	tcp.DecodeFromBytes(data[ipHeaderLength:], gopacket.NilDecodeFeedback)
	return &tcp, nil
}

func recvPackets(handle *pcap.Handle, serverIP string, hops chan net.IP, stringToSend string) {
	packetStream := gopacket.NewPacketSource(handle, handle.LinkType())
	counter := beginTTLValue
	var sentString string
	sentString = stringToSend + strconv.Itoa(counter)
	var prevHop string
	for packet := range packetStream.Packets() {
		if packet == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// Don't need the tcpLayer for now but could be used for srcPort, dstPort, or any of the flags
		// tcpLayer := packet.Layer(layers.LayerTypeTCP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if ipLayer != nil && icmpLayer != nil {
			ipl, _ := ipLayer.(*layers.IPv4)
			// tcp, _ := tcpLayer.(*layers.TCP)
			icmpPkt, _ := icmpLayer.(*layers.ICMPv4)
			currHop := ipl.SrcIP.String()
			// log.Println("Server IP: ", serverIP)
			// log.Println("This packet IP: ", currHop)
			// if currHop == serverIP {
			// 	log.Println("Found packet, payload: ", string(tcp.LayerPayload()))
			// }
			if icmpPkt.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
				// Check if the ICMP time exceeded packet contains the original datagram's data (payload) or if it is a new hop (and not responses to retransmissions)
				if strings.Contains(string(icmpPkt.LayerPayload()), sentString) || prevHop != currHop {
					log.Println("REcved packet with: ", sentString)
					counter += 1
					sentString = stringToSend + strconv.Itoa(counter)
					prevHop = currHop
					hops <- ipl.SrcIP
				}
			}
			_, err := getTCPHeaderFromICMPResponsePayload(icmpPkt.LayerPayload())
			if err != nil {
				continue
			}
		}
		if counter > MaxTTLHops {
			return
		}
	}

}

func sendTracePacket(tcpConn net.Conn, ipConn *ipv4.Conn, dstIP net.IP, clPort int, sentString string, ttlValue int) bool {
	rawBytes := []byte(sentString)
	localSrcAddr := tcpConn.LocalAddr().String()
	localSrcIP, localSrcPortString, _ := net.SplitHostPort(localSrcAddr)
	localSrcPort, _ := strconv.Atoi(localSrcPortString)

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		// Id:       uint16(ipid),
		Version:  4,
		SrcIP:    net.ParseIP(localSrcIP),
		DstIP:    dstIP,
	}
	seqnum := uint32(11111 + ttlValue)
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(int(localSrcPort)),
		DstPort: layers.TCPPort(clPort),
		Seq:     seqnum, // increment it, though this is not respected in the sent packet
		PSH:     true,
		ACK:     true,
		// SYN: true,
	}
	_ = tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	ttlErr := ipConn.SetTTL(int(ttlValue))
	if ttlErr != nil {
		ErrLogger.Println("Error setting ttl: ", ttlErr)
		return false
	}
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()

	serializeErr := gopacket.SerializeLayers(buffer, options,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	if serializeErr != nil {
		ErrLogger.Println("Serialize error: ", serializeErr)
		return false
	}
	outgoingPacket := buffer.Bytes()
	if _, err := tcpConn.Write(outgoingPacket); err != nil {
		ErrLogger.Println("Error writing to connection: ", err)
		return false
	}
	return true
}

func funcTcpConn(clientIP string, clientPort string, netConn net.Conn) map[int]net.IP {
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

	go recvPackets(handle, localSrcIP, recvdHop, stringToSend)

	for ttlValue := beginTTLValue; ttlValue <= MaxTTLHops; ttlValue++ {
		sentString := stringToSend + strconv.Itoa(ttlValue)
		log.Println("From loop: ", sentString)
		sent := sendTracePacket(tcpConn, ipConn, dstIP, clPort, sentString, ttlValue)
		if sent == false {
			break
		}
		traceroute[ttlValue] = <-recvdHop
	}
	return traceroute
}

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
	log.Println("Found uuid: ", uuid)
	clientIPstr := r.RemoteAddr
	clientIP, clientPort, _ := net.SplitHostPort(clientIPstr)
	debugPrintClientInfo(r, "trace")

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		return
	}
	defer c.Close()
	myConn := c.UnderlyingConn()
	traceroute := funcTcpConn(clientIP, clientPort, myConn)
	results := TracerouteResults{UUID: uuid, Hops: traceroute}
	zeroTraceResult, _ := json.Marshal(results)
	zeroTraceString := string(zeroTraceResult)
	InfoLogger.Println(zeroTraceString)	
}

func getTcpRttStats(arr []float64) (float64, float64, float64, float64) {
	data := stats.LoadRawData(arr)
	min, _ := stats.Min(data)
	avg, _ := stats.Mean(data)
	max, _ := stats.Max(data)
	stddev, _ := stats.StandardDeviation(data)
	return min, avg, max, stddev
}

// Function that sends out TcpPing and returns RTT
func sendTcpPing(dst string, seq uint64, timeout time.Duration) float64 {
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", dst, timeout)
	endTime := time.Now()
	if err == nil || strings.Contains(err.Error(), "connection refused") {
		if err == nil {
			defer conn.Close()
		}
		var t = fmtTimeMs(endTime.Sub(startTime))
		result := tcpProbeResult{dst, seq, t}
		resultJson, parseErr := json.Marshal(result)
		if parseErr != nil {
			ErrLogger.Println("JSON Error in TCPing: ", parseErr)
		} else {
			resultString := string(resultJson)
			// Intermediate results also logged to ErrLogger
			ErrLogger.Println(resultString)
		}
		return t
	} else {
		ErrLogger.Println(dst, " connection failed with:", err)
	}
	return 0
}

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

func TcpPinger(ip string) tcpStruct {
	// TCP Pinger
	var tcpResultArr []tcpResult
	rand.Seed(time.Now().UnixNano()) // Or each time we restart server the sequences would repeat
	var portsWaitGroup sync.WaitGroup
	portsWaitGroup.Add(len(PortsToTest))
	for _, port := range PortsToTest {
		go func(port int) {
			defer portsWaitGroup.Done()
			var seqNumber uint64 = uint64(rand.Uint32())
			var dst = fmt.Sprintf("%s:%d", ip, port)
			ticker := time.NewTicker(TCPInterval)
			var tResult []float64
			for x := 0; x < NumTCPPkts; x++ {
				seqNumber++
				select {
				case <-ticker.C:
					tResult = append(tResult, sendTcpPing(dst, seqNumber, TCPTimeout))
				}
			}
			ticker.Stop()
			min, avg, max, stddev := getTcpRttStats(tResult)
			tcpResultArr = append(tcpResultArr, tcpResult{port, tResult, min, avg, max, stddev})
		}(port)
	}
	portsWaitGroup.Wait()
	return tcpStruct{ip, tcpResultArr}
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
	var avg float64 = sum / len
	return avg
}

// Avg RTT from all successful TCP measurements regardless of port, to display on webpage
func getMeanTcpRTT(tcp []tcpStruct) float64 {
	var sum float64 = 0
	var len float64 = 0
	// for each IP in subnet
	for _, x := range tcp {
		// for each port per IP
		for _, p := range x.Probes {
			if p.AvgRtt == 0 {
				continue
			}
			sum += p.AvgRtt
			len += 1
		}
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

// Handler for ICMP and TCP measurements which also serves the webpage via a template
func pingHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/ping") {
		return
	}
	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)
	debugPrintClientInfo(r, "ping")

	// adjIPstoPing, err := getAdjacentIPs(clientIP)
	// if err != nil {
	// 	log.Println("Error obtaining adjacent IPs: ", err)
	// }
	adjIPstoPing := []string{}
	ipTotal := len(adjIPstoPing)
	offset := 0
	numBatches := int(math.Ceil(float64(ipTotal / batchSizeLimit)))

	// Concurrently send ICMP and TCP pings to all <PortsToTest>, for a <batchSizeLimit> number of IPs
	var icmpResults []RtItem
	var tcpResultsObj []tcpStruct
	for i := 0; i <= numBatches; i++ {
		lower := offset
		upper := offset + batchSizeLimit

		if upper > ipTotal {
			upper = ipTotal
		}
		batchIPs := adjIPstoPing[lower:upper]
		offset += batchSizeLimit

		var icmpWaitGroup sync.WaitGroup
		var tcpWaitGroup sync.WaitGroup

		icmpWaitGroup.Add(len(batchIPs))
		tcpWaitGroup.Add(len(batchIPs))

		for id := range batchIPs {
			go func(IP string, id int) {
				defer icmpWaitGroup.Done()
				icmpResults = append(icmpResults, IcmpPinger(IP))
			}(batchIPs[id], id)
			go func(IP string, id int) {
				defer tcpWaitGroup.Done()
				tcpResultsObj = append(tcpResultsObj, TcpPinger(IP))
			}(batchIPs[id], id)
		}
		icmpWaitGroup.Wait()
		tcpWaitGroup.Wait()
	}

	// Combine all results
	// results := Results{
	// 	UUID:   uuid.NewString(),
	// 	IPaddr: clientIP,
	// 	//RFC3339 style UTC date time with added seconds information
	// 	Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
	// 	IcmpPing:    icmpResults,
	// 	AvgIcmpStat: getMeanIcmpRTT(icmpResults),
	// 	TcpPing:     tcpResultsObj,
	// 	AvgTcpStat:  getMeanTcpRTT(tcpResultsObj),
	// }

	results := Results{
		UUID:   uuid.NewString(),
		IPaddr: clientIP,
		//RFC3339 style UTC date time with added seconds information
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
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
