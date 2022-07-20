package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"github.com/go-ping/ping"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	InfoLogger *log.Logger
	EvalLogger *log.Logger
)

type Hops struct {
	Hop int
	IP  string
}

type Result struct {
	ClientIP   string
	Traceroute []Hops
	Lasthop    string
	Lastping   RtItem
	ClientPing RtItem
}

type AvgRTTcompare struct {
	ClientIP	string
	LastHop    float64
	ClientHop  float64
	Difference float64
}

const ICMPCount = 5
const ICMPTimeout = time.Second * 10
const batchSizeLimit int = 200 // rate becomes roughly 1000 per batch

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

// From proxy-detection-server icmp pinger code
func IcmpPing(ip string) (RtItem, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		log.Println(err)
		return RtItem{}, err
	}
	pinger.Count = ICMPCount
	pinger.Timeout = ICMPTimeout
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		log.Println(err)
		return RtItem{}, err
	}
	stat := pinger.Statistics()
	icmp := RtItem{ip, stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss, fmtTimeMs(stat.MinRtt), fmtTimeMs(stat.AvgRtt), fmtTimeMs(stat.MaxRtt), fmtTimeMs(stat.StdDevRtt)}
	// jsObj, _ := json.Marshal(icmp)
	// resultString := string(jsObj)
	return icmp, nil

}

func calcAvgDifference(last RtItem, client RtItem) (float64, bool) {
	if last.AvgRtt == 0 || client.AvgRtt == 0 {
		return 0, false
	}
	return client.AvgRtt - last.AvgRtt, true
}

func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

func main() {
	var outputfilePath string
	var evalrttfilePath string
	var tracefile string
	flag.StringVar(&outputfilePath, "outputfile", "output.jsonl", "Path to full output file")
	flag.StringVar(&evalrttfilePath, "evalrttfile", "eval-rtt.jsonl", "Path to eval rtt file")
	flag.StringVar(&tracefile, "tracefile", "", "Path to input 0trace file")
	flag.Parse()

	file, err := os.OpenFile(outputfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	InfoLogger = log.New(file, "", 0)

	evalfile, err := os.OpenFile(evalrttfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	EvalLogger = log.New(evalfile, "", 0)

	clientparts := strings.Split(tracefile, ".txt")
	ipPath := clientparts[0]
	ipsplit := strings.Split(ipPath, "/")
	clientIP := ipsplit[len(ipsplit)-1]
	readfile, _ := os.Open(tracefile)
	content := bufio.NewScanner(readfile)
	found := false
	var result []Hops
	var lastHop string

	allLines := make([]string, 0)
	for content.Scan() {
		allLines = append(allLines, content.Text())
	}
	for _, lines := range allLines {
		if strings.Contains(lines, "TRACE RESULTS") {
			found = true
			continue
		}
		if !found {
			continue
		}
		parts := strings.Split(lines, " ")
		hop := parts[0]
		hopInt, _ := strconv.Atoi(hop)
		if hopInt == 0 || len(parts) == 1 {
			continue
		} else {
			ipaddr := parts[1]
			currHop := Hops{Hop: hopInt, IP: ipaddr}
			lastHop = ipaddr
			result = append(result, currHop)
		}
	}
	if len(result) == 0 {
		found = false
	}
	if found == true {
		last, err := IcmpPing(lastHop)
		if err != nil {
			InfoLogger.Fatal("IcmpPing fail file: ", file, " err: ", err)
		}
		client, err := IcmpPing(clientIP)
		if err != nil {
			InfoLogger.Fatal("IcmpPing fail file: ", file, " err: ", err)
		}
		fullResult := Result{ClientIP: clientIP, Traceroute: result, Lasthop: lastHop, Lastping: last, ClientPing: client}
		diff, ok := calcAvgDifference(last, client)
		if ok {
			rttStat := AvgRTTcompare{ClientIP: clientIP, LastHop: last.AvgRtt, ClientHop: client.AvgRtt, Difference: diff}
			rttResult, err := json.Marshal(rttStat)
			if err != nil {
				EvalLogger.Println("Error logging RTT diff results: ", err)
				EvalLogger.Println(rttResult) // Dump results in non-JSON format
			}
			rttStatString := string(rttResult)
			EvalLogger.Println(rttStatString)
		}
		traceResult, err := json.Marshal(fullResult)
		if err != nil {
			InfoLogger.Println("Error logging 0trace results: ", err)
			InfoLogger.Println(fullResult) // Dump results in non-JSON format
		}
		traceString := string(traceResult)
		InfoLogger.Println(traceString)
	}

}
