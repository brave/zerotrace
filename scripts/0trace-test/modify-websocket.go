package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

var addr = flag.String("addr", ":80", "http service address")

var buffer gopacket.SerializeBuffer
var options gopacket.SerializeOptions

const TCPTimeout = time.Duration(1000) * time.Millisecond

var upgrader = websocket.Upgrader{} // use default options

func tcpConn(clientIP string, clientPort string, netConn net.Conn) {
	tcpConn := netConn.(*net.TCPConn)

	clPort, _ := strconv.Atoi(clientPort)
	dstIP := net.ParseIP(clientIP)
	// Send raw bytes over wire
	rawBytes := []byte("heeloo tcp")

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		DstIP:    dstIP,
		TTL:      uint8(5), // low TTL so it does not reach client
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(443),
		DstPort: layers.TCPPort(clPort),
		Seq:     11111,
		ACK:     true,
		PSH:     true,
	}
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	outgoingPacket := buffer.Bytes()

	n, err := tcpConn.Write([]byte(outgoingPacket))
	if err != nil {
		log.Print(err)
	}
	if err == nil {
		log.Print("n is: ", n)
	}

}

func echo(w http.ResponseWriter, r *http.Request) {
	clientIPstr := r.RemoteAddr
	clientIP, clientPort, _ := net.SplitHostPort(clientIPstr)
	log.Println("IP: ", clientIP, " and port: ", clientPort)

	c, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

	// Writing to the raw underlying connection wrapped by c directly
	// will corrupt the WebSocket connection
	netConn := c.UnderlyingConn()
	fmt.Println(netConn.LocalAddr())
	tcpConn(clientIP, clientPort, netConn)

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			log.Println("write:", err)
			break
		}
	}

}

func home(w http.ResponseWriter, r *http.Request) {
	homeTemplate.Execute(w, "ws://"+r.Host+"/echo")
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	http.HandleFunc("/echo", echo)
	http.HandleFunc("/", home)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>  
window.addEventListener("load", function(evt) {
    var output = document.getElementById("output");
    var input = document.getElementById("input");
    var ws;
    var print = function(message) {
        var d = document.createElement("div");
        d.textContent = message;
        output.appendChild(d);
        output.scroll(0, output.scrollHeight);
    };
    document.getElementById("open").onclick = function(evt) {
        if (ws) {
            return false;
        }
        ws = new WebSocket("{{.}}");
        ws.onopen = function(evt) {
            print("OPEN");
        }
        ws.onclose = function(evt) {
            print("CLOSE");
            ws = null;
        }
        ws.onmessage = function(evt) {
            print("RESPONSE: " + evt.data);
        }
        ws.onerror = function(evt) {
            print("ERROR: " + evt.data);
        }
        return false;
    };
    document.getElementById("send").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        print("SEND: " + input.value);
        ws.send(input.value);
        return false;
    };
    document.getElementById("close").onclick = function(evt) {
        if (!ws) {
            return false;
        }
        ws.close();
        return false;
    };
});
</script>
</head>
<body>
<table>
<tr><td valign="top" width="50%">
<p>Click "Open" to create a connection to the server, 
"Send" to send a message to the server and "Close" to close the connection. 
You can change the message and send multiple times.
<p>
<form>
<button id="open">Open</button>
<button id="close">Close</button>
<p><input id="input" type="text" value="Hello world!">
<button id="send">Send</button>
</form>
</td><td valign="top" width="50%">
<div id="output" style="max-height: 70vh;overflow-y: scroll;"></div>
</td></tr></table>
</body>
</html>
`))
