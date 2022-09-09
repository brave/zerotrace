// Reference for webserver that speaks websocket: https://github.com/gorilla/websocket
// Reference for client side websocket code:
// https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/google/gopacket/pcap"
)

const (
	ifaceNameAny = "any"
)

var (
	l = log.New(os.Stderr, "latsrv: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

// checkHTTPParams checks if request method is GET, and ensures URL path is right
func checkHTTPParams(w http.ResponseWriter, r *http.Request, pathstring string) bool {
	if r.URL.Path != pathstring {
		http.NotFound(w, r)
		return true
	}
	if r.Method != "GET" && pathstring != "/measure" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	return false
}

// hasAnyInterface returns true if the system has a networking interface called
// "any".
func hasAnyInterface() bool {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return false
	}

	l.Print("Iterating over interfaces:")
	for _, iface := range ifaces {
		l.Printf("\t- %s", iface.Name)
		if iface.Name == ifaceNameAny {
			return true
		}
	}
	return false
}

func main() {
	var addr string
	flag.StringVar(&ifaceName, "iface", ifaceNameAny, "Interface name to listen on, default: any")
	flag.StringVar(&addr, "addr", ":8080", "Address to listen on, default: :8080")
	flag.Parse()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/echo", echoHandler)
	http.HandleFunc("/trace", traceHandler)
	http.HandleFunc("/measure", measureHandler)

	if ifaceName == ifaceNameAny && !hasAnyInterface() {
		l.Fatal("We were told to use the 'any' interface but it's not present.")
	}

	l.Printf("Starting Web service to listen on %s.", addr)
	l.Println(http.ListenAndServe(addr, nil))
}
