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

const zeroTraceBeginString = "TRACE RESULTS"

var (
	InfoLogger *log.Logger
	EvalLogger *log.Logger
)

type Hops struct {
	Hop int
	IP  string
}

type Result struct {
	Timestamp  string
	ClientIP   string
	Traceroute []Hops
	Lasthop    string
	Lastping   RtItem
	ClientPing RtItem
}

type AvgRTTcompare struct {
	Timestamp  string
	ClientIP   string
	LastHop    float64
	ClientHop  float64
	Difference float64
}

const ICMPCount = 5
const ICMPTimeout = time.Second * 10

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

// IcmpPing conducts the ICMP ping measurement, code from proxy-detection-server
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
	return icmp, nil

}

// checkValidEvalResult checks if last hop is the same as the client hop and if so, returns an RTT differnce of 0.
// Otherwise it checks if both hops were reachable and only then calculates the difference between the AvgRtts and returns it.
// If neither of these cases, the evaluation result is invalid and ok (bool) is set to false
func checkValidEvalResult(last RtItem, client RtItem) (float64, bool) {
	var diff float64
	if last.IP == client.IP {
		diff = 0 // ping the hops but don't check for difference
	} else if last.AvgRtt != 0 && client.AvgRtt != 0 {
		diff = client.AvgRtt - last.AvgRtt
	} else {
		return 0, false
	}
	return diff, true
}

func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

// parseTracerouteFile takes the path of a 0trace output file as input
// and parses and returns the traceroute hops, clientIP from the path, and the last hop obtained by 0trace
func parseTracerouteFile(tracefile string) ([]Hops, string, string) {
	clientparts := strings.Split(tracefile, ".txt")
	ipPath := clientparts[0]
	ipsplit := strings.Split(ipPath, "/")
	clientIP := ipsplit[len(ipsplit)-1]

	readfile, _ := os.Open(tracefile) // opens in read mode
	content := bufio.NewScanner(readfile)
	found := false

	var result []Hops
	var lastHop string

	// read all lines into slice
	allLines := make([]string, 0)
	for content.Scan() {
		allLines = append(allLines, content.Text())
	}

	for _, lines := range allLines {
		if strings.Contains(lines, zeroTraceBeginString) {
			found = true
			continue
		}
		// skip all lines prior to zeroTraceBeginString
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
	return result, clientIP, lastHop
}

// runIcmpPingForEval runs an ICMP Ping measurement for the given two IP (strings) and returns the RtItem for each
func runIcmpPingForEval(lastHop string, clientIP string) (RtItem, RtItem) {
	last, err := IcmpPing(lastHop)
	if err != nil {
		InfoLogger.Fatal("IcmpPing fail for client: ", clientIP, " err: ", err)
	}

	client, err := IcmpPing(clientIP)
	if err != nil {
		InfoLogger.Fatal("IcmpPing fail for client: ", clientIP, " err: ", err)
	}
	return last, client
}

// logStructasJson logs the given object to the provided logger
func logStructasJson(obj any, GivenLogger *log.Logger) {
	objResult, err := json.Marshal(obj)
	if err != nil {
		GivenLogger.Println("Error logging results: ", err)
		GivenLogger.Println(objResult) // Dump results in non-JSON format
	}
	objResultString := string(objResult)
	GivenLogger.Println(objResultString)
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

	result, clientIP, lastHop := parseTracerouteFile(tracefile)

	if len(result) > 0 {
		last, client := runIcmpPingForEval(lastHop, clientIP)
		fullResult := Result{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
			ClientIP:   clientIP,
			Traceroute: result,
			Lasthop:    lastHop,
			Lastping:   last,
			ClientPing: client,
		}
		logStructasJson(fullResult, InfoLogger)

		diff, ok := checkValidEvalResult(last, client)
		if ok {
			rttStat := AvgRTTcompare{
				Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
				ClientIP:   clientIP,
				LastHop:    last.AvgRtt,
				ClientHop:  client.AvgRtt,
				Difference: diff,
			}
			logStructasJson(rttStat, EvalLogger)
		}
	}
}
