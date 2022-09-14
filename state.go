package main

import (
	"net"
	"sync"
	"time"
)

type tracePkt struct {
	ttl       uint8
	ipID      uint16
	sent      time.Time
	recvd     time.Time
	recvdFrom net.IP
}

type respPkt tracePkt

type trState struct {
	sync.RWMutex
	dstAddr   net.IP
	tracePkts map[uint16]*tracePkt
}

func (s *trState) AddTracePkt(p *tracePkt) {
	s.Lock()
	defer s.Unlock()

	s.tracePkts[p.ipID] = p
}

func (s *trState) AddRespPkt(respPkt *respPkt) {
	s.Lock()
	defer s.Unlock()

	tracePkt, exists := s.tracePkts[respPkt.ipID]
	if !exists {
		l.Printf("Got response for non-existing trace packet (IP ID=%d).", respPkt.ipID)
	}
	// Mark the trace packet as "received".
	tracePkt.recvd = respPkt.recvd
}

func (s *trState) IsFinished() bool {
	s.RLock()
	defer s.RUnlock()

	for _, p := range s.tracePkts {
		// We know that we're done if this response packet came from the
		// destination of our traceroute.
		if p.recvdFrom.Equal(s.dstAddr) {
			return true
		}
	}
	return false
}

func (s *trState) Summary() {
	s.RLock()
	defer s.RUnlock()

	numRcvd := 0
	for _, p := range s.tracePkts {
		if !p.recvd.IsZero() {
			numRcvd++
		}
	}
	l.Printf("%d packets sent so far.", len(s.tracePkts))
	l.Printf("%d packets received so far.", numRcvd)
}

func (s *trState) CalcRTT() time.Duration {
	s.RLock()
	defer s.RUnlock()

	closestPkt := &tracePkt{}
	for _, p := range s.tracePkts {
		if p.ttl > closestPkt.ttl {
			closestPkt = p
		}
	}
	return closestPkt.recvd.Sub(closestPkt.sent)
}
