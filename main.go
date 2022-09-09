// Reference for webserver that speaks websocket: https://github.com/gorilla/websocket
// Reference for client side websocket code:
// https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path"

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

// redirectToTLS helps redirect HTTP connections to HTTPS
func redirectToTLS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

// hasAnyInterface returns true if the system has a networking interface called
// "any".
func hasAnyInterface() bool {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		if iface.Name == ifaceNameAny {
			return true
		}
	}
	return false
}

func main() {
	flag.StringVar(&ifaceName, "iface", ifaceNameAny, "Interface name to listen on, default: any")
	flag.Parse()

	certPath := "/etc/letsencrypt/live/test.reethika.info/"
	fullChain := path.Join(certPath, "fullchain.pem")
	privKey := path.Join(certPath, "privkey.pem")
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/echo", echoHandler)
	http.HandleFunc("/trace", traceHandler)
	http.HandleFunc("/measure", measureHandler)

	if ifaceName == ifaceNameAny && !hasAnyInterface() {
		l.Fatal("We were told to use the 'any' interface but it's not present.")
	}

	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectToTLS)); err != nil {
			l.Printf("ListenAndServe port 80 error: %v", err)
		}
	}()
	l.Println(http.ListenAndServeTLS(":443", fullChain, privKey, nil))
}
