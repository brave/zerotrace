package main

import (
	"time"

	"github.com/go-ping/ping"
)

const (
	// The number of ICMP packets we send to a client.
	icmpCount = 5
	// The time we're willing to wait for an ICMP response.
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

type Results struct {
	UUID      string
	Timestamp string
	PingStats *ping.Statistics
}

// pingAddr sends ICMP pings to the given address and returns ping
// statistics.
func pingAddr(addr string) (*ping.Statistics, error) {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return nil, err
	}

	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	if err = pinger.Run(); err != nil { // Blocks until finished.
		return nil, err
	}

	return pinger.Statistics(), nil
}
