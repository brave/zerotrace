package main

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// indexHandler serves the default index page with reasons for scanning IPs on this server and point of contact
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/") {
		return
	}
	path := path.Join(directoryPath, "/index.html")
	http.ServeFile(w, r, path)
}

// pingHandler for ICMP measurements which also serves the webpage via a template
func pingHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/ping") {
		return
	}
	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)

	icmpResults := IcmpPinger(clientIP)

	// Combine all results
	results := Results{
		UUID:   uuid.NewString(),
		IPaddr: clientIP,
		//RFC3339 style UTC date time with added seconds information
		Timestamp:   time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		IcmpPing:    icmpResults,
		AvgIcmpStat: icmpResults.AvgRtt,
	}

	jsObj, err := json.Marshal(results)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resultString := string(jsObj)
	InfoLogger.Println(resultString)
	var WebTemplate, _ = template.ParseFiles(path.Join(directoryPath, "pingpage.html"))
	if err := WebTemplate.Execute(w, results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// traceHandler speaks WebSocket for extracting underlying connection to use for 0trace
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
	var upgrader = websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	myConn := c.UnderlyingConn()

	zeroTraceInstance := newZeroTrace(deviceName, myConn, uuid)

	traceroute, err := zeroTraceInstance.Run()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	results := TracerouteResults{
		UUID:      uuid,
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		HopData:   traceroute,
	}
	zeroTraceResult, err := json.Marshal(results)
	if err != nil {
		ErrLogger.Println("Error logging 0trace results: ", err)
		InfoLogger.Println(results) // Dump results in non-JSON format
	}
	zeroTraceString := string(zeroTraceResult)
	InfoLogger.Println(zeroTraceString)
}

// echoHandler for the echo webserver that speaks WebSocket
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/echo") {
		return
	}
	var upgrader = websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ErrLogger.Println("upgrade:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		if err := json.Unmarshal(message, &wsData); err != nil {
			ErrLogger.Println("unmarshal:", err)
			break
		}
		if wsData["type"] != "ws-latency" {
			if wsUUID, ok := wsData["UUID"].(string); ok {
				// Only log the final message with all latencies calculated, and don't log other unsolicited echo messages
				if isValidUUID(string(wsUUID)) {
					InfoLogger.Println(string(message))
				}
			}
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			ErrLogger.Println("write:", err)
			break
		}
	}
}
