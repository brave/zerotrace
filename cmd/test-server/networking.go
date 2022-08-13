package main

import (
	"time"

	"github.com/go-ping/ping"
)

const (
	icmpCount   = 5
	icmpTimeout = time.Second * 10
)

type PingMsmt struct {
	IP        string
	PktSent   int
	PktRecv   int
	PktLoss   float64
	MinRtt    float64
	AvgRtt    float64
	MaxRtt    float64
	StdDevRtt float64
}

type Results struct {
	UUID        string
	IPaddr      string
	Timestamp   string
	IcmpPing    PingMsmt
	AvgIcmpStat float64
}

// IcmpPinger sends ICMP pings and returns statistics
func IcmpPinger(ip string) PingMsmt {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		panic(err)
	}
	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
	stat := pinger.Statistics()
	icmp := PingMsmt{ip, stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss, fmtTimeMs(stat.MinRtt),
		fmtTimeMs(stat.AvgRtt), fmtTimeMs(stat.MaxRtt), fmtTimeMs(stat.StdDevRtt)}
	return icmp
}
