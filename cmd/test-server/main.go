// Refer for webserver that speaks websocket: https://github.com/gorilla/websocket and for clientside websocket code:https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"encoding/json"
	"flag"
	"github.com/go-ping/ping"
	"github.com/gorilla/websocket"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"
)

var (
	InfoLogger *log.Logger
)
var (
	EchoLogger *log.Logger
)

var wsTemplate, _ = template.ParseFiles("index.html")

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

// Implementing this since Golang time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

// Use with default options
var upgrader = websocket.Upgrader{}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		EchoLogger.Println("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			EchoLogger.Println("read:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			EchoLogger.Println("write:", err)
			break
		}
	}
}

func pingSrv(w http.ResponseWriter, r *http.Request) {
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

	pinger, err := ping.NewPinger(clientIP)
	if err != nil {
		panic(err)
	}
	pinger.Count = 3
	pinger.Timeout = time.Second * 10
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	item := RtItem{clientIP, stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss, fmtTimeMs(stats.MinRtt), fmtTimeMs(stats.AvgRtt), fmtTimeMs(stats.MaxRtt), fmtTimeMs(stats.StdDevRtt)}
	jsObj, err := json.Marshal(item)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonString := string(jsObj)
	InfoLogger.Println(jsonString)
	wsTemplate.Execute(w, jsonString)
}

func main() {
	var logfilePath string
	var echologPath string
	flag.StringVar(&logfilePath, "logfile", "logFile.txt", "Path to log file")
	flag.StringVar(&echologPath, "echolog", "echoLog.txt", "Path to echo server log file")
	flag.Parse()
	file, err := os.OpenFile(logfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	echoFile, err := os.OpenFile(echologPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	InfoLogger = log.New(file, "", log.Ldate|log.Ltime)
	EchoLogger = log.New(echoFile, "", log.Ldate|log.Ltime)
	certPath := "/etc/letsencrypt/live/test.reethika.info/"
	fullChain := path.Join(certPath, "fullchain.pem")
	privKey := path.Join(certPath, "privkey.pem")
	http.HandleFunc("/ping", pingSrv)
	http.HandleFunc("/echo", echo)
	http.ListenAndServeTLS(":443", fullChain, privKey, nil)
}
