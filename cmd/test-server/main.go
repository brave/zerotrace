// Reference for webserver that speaks websocket: https://github.com/gorilla/websocket
// Reference for client side websocket code: https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-ping/ping"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/montanaflynn/stats"
	"html/template"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const ICMPCount = 5
const ICMPTimeout = time.Second * 10
const NumTCPPkts = 5
const TCPTimeout = time.Duration(1000) * time.Millisecond // TCP RTO is 1s (RFC 6298), so having a 1s timeout for RTT measurement makes sense
const TCPInterval = time.Duration(1100) * time.Millisecond
const batchSizeLimit int = 100 // rate per batch becomes roughly 100 IPs * (5 ICMP packets + 5 TCP packets *7 ports) packets per IP

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

// Handler for the echo webserver that speaks WebSocket
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/echo" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
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
	icmp := RtItem{ip, stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss, fmtTimeMs(stat.MinRtt), fmtTimeMs(stat.AvgRtt), fmtTimeMs(stat.MaxRtt), fmtTimeMs(stat.StdDevRtt)}
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
	treturn tcpStruct{ip, tcpResultArr}
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

// Handler for ICMP and TCP measurements which also serves the webpage via a template
func pingHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ping" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
		return
	}
	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)
	adjIPstoPing, err := getAdjacentIPs(clientIP)
	if err != nil {
		log.Println("Error obtaining adjacent IPs: ", err)
	}
	ipTotal := len(adjIPstoPing)
	offset := 0
	numBatches := int(math.Ceil(float64(ipTotal / batchSizeLimit)))
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
	results := Results{
		UUID:        uuid.NewString(),
		IPaddr:      clientIP,
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000000"), //RFC3339 style UTC date time with added seconds information
		IcmpPing:    icmpResults,
		AvgIcmpStat: getMeanIcmpRTT(icmpResults),
		TcpPing:     tcpResultsObj,
		AvgTcpStat:  getMeanTcpRTT(tcpResultsObj),
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
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
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
	http.ListenAndServeTLS(":443", fullChain, privKey, nil)
}
