package main

import (
	"time"

	"github.com/go-ping/ping"
)

const (
	icmpCount   = 5
	icmpTimeout = time.Second * 10
)

type FormDetails struct {
	UUID         string
	Timestamp    string
	Contact      string
	ExpType      string
	Device       string
	LocationVPN  string
	LocationUser string
}

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
	UUID       string
	IPaddr     string
	Timestamp  string
	IcmpPing   PingMsmt
	MinIcmpRtt float64
}

// pingAddr sends ICMP pings to the given address and returns ping
// statistics.
func pingAddr(addr string) (*PingMsmt, error) {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return nil, err
	}

	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	if err = pinger.Run(); err != nil { // Blocks until finished.
		return nil, err
	}

	stat := pinger.Statistics()
	return &PingMsmt{
		addr,
		stat.PacketsSent,
		stat.PacketsRecv,
		stat.PacketLoss,
		fmtTimeMs(stat.MinRtt),
		fmtTimeMs(stat.AvgRtt),
		fmtTimeMs(stat.MaxRtt),
		fmtTimeMs(stat.StdDevRtt),
	}, nil
}
