package main

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"path"
	"time"

	"github.com/gorilla/websocket"
)

// serveFormTemplate serves the form
func serveFormTemplate(w http.ResponseWriter) {
	var WebTemplate, _ = template.ParseFiles(path.Join(directoryPath, "measure.html"))
	if err := WebTemplate.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// measureHandler serves the form which collects user's contact data and ground-truth (VPN/Direct) before experiment begins
func measureHandler(w http.ResponseWriter, r *http.Request) {
	if checkHTTPParams(w, r, "/measure") {
		return
	}
	if r.Method == "GET" {
		serveFormTemplate(w)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		details, err := validateForm(r.FormValue("email"), r.FormValue("exp_type"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsObj, err := json.Marshal(details)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resultString := string(jsObj)
		InfoLogger.Println(resultString)
		http.Redirect(w, r, "/ping?uuid="+details.UUID, 302)
	}
}

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
	var uuid string
	for k, v := range r.URL.Query() {
		if k == "uuid" && isValidUUID(v[0]) {
			uuid = v[0]
		} else {
			http.Error(w, "Invalid UUID", http.StatusInternalServerError)
			return
		}
	}

	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)

	icmpResults := icmpPinger(clientIP)

	// Combine all results
	results := Results{
		UUID:   uuid,
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
		if k == "uuid" && isValidUUID(v[0]) {
			uuid = v[0]
		} else {
			http.Error(w, "Invalid UUID", http.StatusInternalServerError)
			return
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

	zeroTraceInstance := newZeroTrace(deviceName, myConn)

	traceroute, err := zeroTraceInstance.Run()
	if err != nil {
		ErrLogger.Println("ZeroTrace Run Error: ", err)
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
