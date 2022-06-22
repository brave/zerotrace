package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-ping/ping"
	"log"
	"math"
	"os"
	"sync"
	"time"
)

var (
	InfoLogger *log.Logger
)

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
func IcmpPing(ip string) string {
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
	jsObj, _ := json.Marshal(icmp)
	resultString := string(jsObj)
	return resultString

}

func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

func main() {
	var logfilePath string
	var ipfilePath string
	flag.StringVar(&logfilePath, "logfile", "output.jsonl", "Path to log file")
	flag.StringVar(&ipfilePath, "inputfile", "ip-list.txt", "Path to input IP file")
	flag.Parse()

	file, err := os.OpenFile(logfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	InfoLogger = log.New(file, "", 0)

	ipfile, _ := os.Open(ipfilePath)

	content := bufio.NewScanner(ipfile)
	lines := make([]string, 0)
	for content.Scan() {
		lines = append(lines, content.Text())
	}

	ipTotal := len(lines)
	offset := 0
	numBatches := int(math.Ceil(float64(ipTotal / batchSizeLimit)))

	if ipTotal == 0 {
		log.Fatal("Input file ", ipfilePath, " is empty")
	}	

	fmt.Println("Number of Batches (of 200 each): ", numBatches)
	for i := 0; i <= numBatches; i++ {
		lower := offset
		upper := offset + batchSizeLimit

		if upper > ipTotal {
			upper = ipTotal
		}
		batchIPs := lines[lower:upper]
		offset += batchSizeLimit

		var itemProcessingGroup sync.WaitGroup
		itemProcessingGroup.Add(len(batchIPs))

		for id := range batchIPs {
			go func(IP string, id int) {
				defer itemProcessingGroup.Done()
				resultString := IcmpPing(IP)
				InfoLogger.Printf("%s", resultString)
			}(batchIPs[id], id)
		}
		itemProcessingGroup.Wait()
	}
}
