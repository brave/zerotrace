package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// measureHandler serves the form that collects the user's contact data and
// ground truth (i.e., if we are dealing with a VPN or a direct connection)
// before the experiment begins.
func measureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := measureTemplate.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		details, err := validateForm(
			r.FormValue("email"),
			r.FormValue("exp_type"),
			r.FormValue("device"),
			r.FormValue("location_vpn"),
			r.FormValue("location_user"),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		logAsJson(details)
		http.Redirect(w, r, "/ping?uuid="+details.UUID, 302)
	}
}

// indexHandler serves the default index page which explains what measurements
// we are running.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, indexPage)
}

// pingHandler implements a one-off measurement for the connecting client.  It
// does the following:
//
//   1. Send ICMP packets to the client to determine the RTT.
//   2. Serve the client JavaScript that initiates a WebSocket connection with
//      us, again to determine the application-level RTT.
//   3. Start another WebSocket connection to run a 0trace measurement, to
//      determine an even more accurate RTT.
func pingHandler(w http.ResponseWriter, r *http.Request) {
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

	icmpResults, err := icmpPinger(clientIP)
	if err != nil {
		l.Println("ICMP Ping Error: ", err)
	}

	// Combine all results
	results := Results{
		UUID:   uuid,
		IPaddr: clientIP,
		//RFC3339 style UTC date time with added seconds information
		Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		IcmpPing:   *icmpResults,
		MinIcmpRtt: icmpResults.MinRtt,
	}
	logAsJson(results)
	if err := pingTemplate.Execute(w, results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// traceHandler accepts incoming WebSocket connections and, once one is
// established, uses it to run a 0trace measurement to the client.  This is
// likely to corrupt the underlying TCP connection but we don't care about
// that.
func traceHandler(w http.ResponseWriter, r *http.Request) {
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
		l.Println("upgrade:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	myConn := c.UnderlyingConn()

	zeroTraceInstance := newZeroTrace(ifaceName, myConn, uuid)

	err = zeroTraceInstance.Run()
	if err != nil {
		l.Println("ZeroTrace Run Error: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// echoHandler accepts incoming WebSocket connections and determines the round
// trip time between the client and us by taking advantage of a handful of
// "ping" messages.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	var upgrader = websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		l.Println("upgrade:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return

	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			l.Println("read:", err)
			break
		}
		// ReadMessage() returns messageType int, p []byte, err error]
		var wsData map[string]interface{}
		if err := json.Unmarshal(message, &wsData); err != nil {
			l.Println("unmarshal:", err)
			break
		}
		if wsData["type"] != "ws-latency" {
			if wsUUID, ok := wsData["UUID"].(string); ok {
				// Only log the final message with all latencies calculated,
				// and don't log other unsolicited echo messages
				if isValidUUID(string(wsUUID)) {
					l.Println(string(message))
				}
			}
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			l.Println("write:", err)
			break
		}
	}
}
