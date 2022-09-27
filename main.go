// Reference for webserver that speaks websocket: https://github.com/gorilla/websocket
// Reference for client side websocket code:
// https://web.archive.org/web/20210614154432/https://incolumitas.com/2021/06/07/detecting-proxies-and-vpn-with-latencies/
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/google/gopacket/pcap"
	"golang.org/x/crypto/acme/autocert"
)

const (
	ifaceNameAny = "any"
)

var (
	l = log.New(os.Stderr, "latsrv: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

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

	router := chi.NewRouter()
	router.Get("/", indexHandler)
	router.Get("/ping", pingHandler)
	router.Get("/echo", echoHandler)
	router.Get("/trace", traceHandler)
	router.Post("/measure", measureHandler)

	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("certs"),
	}
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil)) //nolint:errcheck
	server := &http.Server{
		Addr:    addr,
		Handler: router,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	if ifaceName == ifaceNameAny && !hasAnyInterface() {
		l.Fatal("We were told to use the 'any' interface but it's not present.")
	}

	l.Printf("Starting Web service to listen on %s.", addr)
	l.Println(server.ListenAndServeTLS("", ""))
}
