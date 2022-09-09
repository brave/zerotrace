package main

import "html/template"

var (
	measureTemplate = template.Must(template.New("measure").Parse(measurePage))
	pingTemplate    = template.Must(template.New("ping").Parse(pingPage))
)

const indexPage = `
<HTML>
<head>
<title>Measurement Home Page</title>
</head>
<body bgcolor="FFFFFf">
<div align="center">
	<h1>We are running an experimental web server on this domain </h1>
	<p>We are sending out ICMP probes and TCP SYN packets to some IPs in order to conduct latency measurements.</p>
	<p>This is done only for research purposes and if you received such measurement, but wish to opt out, please contact <a href="mailto:rramesh+web@brave.com">rramesh@brave.com</a></p>
</div>
</body>
</html>
`

const measurePage = `
<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <meta charset = "utf-8">
    <title>Calculate Latency Using WebSockets</title>
    <style>
      .buttonload {
        background-color: #cec1e7;
        border: none; /* Remove borders */
        color: black; /* White text */
        padding: 12px 24px; /* Some padding */
        font-size: 16px; /* Set a font-size */
      }
      .fa {
        margin-left: -12px;
        margin-right: 8px;
      }
      form {
        margin-left: 20px;
      }
      h1 {
        margin-top: 20px;
        margin-left: 20px;
      }
      input {
        margin: 10px;
        display: inline-block;
      }
      .required:after {
        content:" *";
        color: red;
      }
    </style>

  </head>

  <body>
    <h1>Experiment Details</h1>
    <form method="POST">
        <label class="required">Brave Email ID (username@brave.com):</label><br>
        <input type="text" placeholder="username@brave.com" name="email" required><br />
        <label class="required">Are you running this on a:</label><br>
        <input type="radio" id="device" name="device" value="mobile" required>
        <label for="mobile">Mobile Device</label><br>
        <input type="radio" id="device" name="device" value="desktop" required>
        <label for="desktop">Desktop / Laptop</label><br>
        <label class="required">Are you connecting to us through:</label><br>
        <input type="radio" id="exp_type" name="exp_type" value="direct" onclick="document.getElementById('locinfo').style.display='none'" required>
        <label for="direct">Direct Connection</label><br>
        <input type="radio" id="exp_type" name="exp_type" value="vpn" onclick="document.getElementById('locinfo').style.display='block'" required>
        <label for="vpn">VPN</label><br>
        <div id="locinfo" style="display:none;">
          <label class="required">Location of VPN server connected to (if any):</label><br>
          <input type="text" name="location_vpn" size="30" placeholder="City, state (if applicable), country"><br />
          <label class="required">Your location:</label><br>
          <input type="text" name="location_user" size="30" placeholder="City, state (if applicable), country"><br />
          <label>We only use this information to reason about the measured latencies and physical distance.</label><br>
          <label>Please enter <i>"unknown"</i> if you are unsure about your VPN server's location, or <i>"best available"</i> if you chose that in your VPN settings.</label><br>
        </div><br />
        <label>Contact @reethika and @phw on Slack if you have any questions.</label><br>
        <input type="submit" onclick="submitHandler()">
        <div id="loading" style="display:none;">
          <button class="buttonload">
            <i class="fa fa-spinner fa-spin"></i>If you have filled the input form, you will be redirected...
          </button>
        </div>
    </form>
    <script>
      function submitHandler() {
        var loading = document.getElementById("loading");
        if (loading.style.display === "none") {
          loading.style.display = "block";
        } else {
          loading.style.display = "none";
        }

      }
    </script>
  </body>
</html>
`

const pingPage = `
<!doctype html>

<html>
  <head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <meta charset = "utf-8">
    <title>Calculate Latency Using WebSockets</title>
    <style>
      p {
        display: inline-block;
      }
      .buttonload {
        background-color: #cec1e7;
        border: none; /* Remove borders */
        color: black; /* White text */
        padding: 12px 24px; /* Some padding */
        font-size: 16px; /* Set a font-size */
      }
      .fa {
        margin-left: -12px;
        margin-right: 8px;
      }
    </style>

  </head>

  <body>
    <h2>Calculate Latency Using WebSockets and Measure ICMP latency</h2>
    <p>Experiment UUID: &ensp;</p><p id="uuid"></p><br>
    <p>Your IP: &ensp;</p><p id="ip"></p> <br>
    <p>All WebSocket measurements: &ensp;</p><p id="values"></p> <br>
    <p>Median WS latency: &ensp;</p><p id="data"></p> <br>
    <p>ICMP ping statistics: We conducted measaurements to your IP. Average RTT: &ensp;</p> <p id="icmp"></p> <br>
    <div id="loading">
      <button class="buttonload">
        <i class="fa fa-spinner fa-spin"></i>Running Zero Trace Measurements, do not close this window (approx 2 minutes)...
      </button>
    </div>
      <script>
      setTimeout(() => {
        const loading = document.getElementById("loading");
        loading.style.display = "none";
      }, 120000);

      function min(values){
            if (values.length ===0) return 0;
            values.sort(function(a,b){
              return a-b;
            });
            return values[0];
          }

      function roundToTwo(num) {    
        return +(Math.round(num + "e+2")  + "e-2");
      }

      function getLatencyWebSocket() {
        return new Promise(function (resolve, reject) {
          var ipaddress = {{ .IPaddr }};
          var uuid = {{ .UUID }};
          // Create a Web Socket
          const socket = new WebSocket('wss://test.reethika.info/echo');
          socket.onerror = function (err) {
            reject(err.toString());
          }

          var messages = [];
          const latencies = [];
          var statsSent = false;
          const cooldown = 2000; // in ms

          socket.onopen = function () {
            socket.send(JSON.stringify({
              type: 'ws-latency',
              ts: roundToTwo(performance.now()),
            }));
          }

          socket.onmessage = async function (event) {
            messages.push(JSON.parse(event.data));
            await new Promise(r => setTimeout(r, cooldown));
            if (messages.length <= 10) {
              socket.send(JSON.stringify({
                type: 'ws-latency',
                ts: roundToTwo(performance.now()),
              }));
            } else {
              for (let i = 0; i < messages.length - 1; i++) {
                latencies.push(roundToTwo(messages[i+1].ts - messages[i].ts - cooldown));
              }
              if (statsSent == false) {
              const datetimeutc = new Date().toISOString();
              socket.send(JSON.stringify({
                UUID: uuid,
                IP: ipaddress,
                Timestamp: datetimeutc,
                latencies: latencies,
              }));
              statsSent = true;
            }
              resolve(latencies);
            }
          }
        });
        }
    const keepAlivePktInterval = 1000;
    const keepAliveTimePeriodms = 600000;
    function makeAnotherWs() {
          var ipaddress = {{ .IPaddr }};
          var uuid = {{ .UUID }};
          const webSocketAddr = 'wss://test.reethika.info/trace?uuid={{ .UUID }}';
          // Create a Web Socket
          const socket = new WebSocket(webSocketAddr);
          var startTime = new Date().getTime(); 
          const intervalId = setInterval(() => {
            if(new Date().getTime() - startTime > keepAliveTimePeriodms){
              clearInterval(intervalId);
              return;
            }
            socket.send("Keep alive");
          }, keepAlivePktInterval);

          socket.onerror = function (err) {
            reject(err.toString());
          }
          socket.onopen = function () {
          }
    }

	   makeAnotherWs();

     getLatencyWebSocket().then((latencies) => {
        document.getElementById('uuid').innerHTML = {{ .UUID }};
        document.getElementById('ip').innerHTML = {{ .IPaddr }};
        document.getElementById('values').innerHTML = latencies;
        document.getElementById('data').innerHTML = min(latencies);
        document.getElementById('icmp').innerHTML = {{ .MinIcmpRtt }};
      });
    </script>
  </body>
</html>
`
