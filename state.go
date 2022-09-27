package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	reqTimeout = time.Second * 5
)

var (
	errInvalidResp = errors.New("got response for non-existing trace packet")
)

// tracePkts represents a trace packet that we send to the client to determine
// the network-level RTT.
type tracePkt struct {
	ttl       uint8
	ipID      uint16
	sent      time.Time
	recvd     time.Time
	recvdFrom net.IP
}

// respPkt represents a packet that we received in response to a trace packet.
// For simplicity, we re-use the trace packet here; in particular, the "recvd"
// and "recvdFrom" fields.
type respPkt tracePkt

// IsAnswered returns true if the given trace packet has seen a response.
func (p *tracePkt) IsAnswered() bool {
	return !p.sent.IsZero() && !p.recvd.IsZero()
}

// String implements the Stringer interface.
func (p *tracePkt) String() string {
	return fmt.Sprintf("Trace packet with IP ID=%d\n\tTTL: %d\n\t"+
		"Sent: %s\n\tRecvd: %s (from %s)\n",
		p.ipID, p.ttl, p.sent, p.recvd, p.recvdFrom,
	)
}

// trState represents our traceroute state machine.  We keep track of the
// following:
//   1) The IP address of the client that is the target of our traceroute.
//   2) Packets that we sent and received as part of the traceroute.
//   3) The IP IDs that we use as part of the traceroute.
type trState struct {
	sync.RWMutex
	dstAddr   net.IP
	tracePkts map[uint16]*tracePkt
	ipIDCtr   uint16
}

// newTrState returns a new traceroute state object.
func newTrState(dstAddr net.IP) *trState {
	return &trState{
		dstAddr:   dstAddr,
		tracePkts: make(map[uint16]*tracePkt),
	}
}

// createIPID returns the next available IP ID for use in outgoing trace
// packets.  We rely on the IP ID field to link incoming ICMP error packets to
// previously-sent trace packets, so it's important that IP IDs are only used
// once, to prevent ambiguity in linking.  This function provides a simple,
// monotonically increasing counter.
func (s *trState) createIPID() uint16 {
	s.Lock()
	defer s.Unlock()

	if s.ipIDCtr == ^uint16(0) {
		l.Println("IP ID counter is overflowing to 0.")
	}
	s.ipIDCtr++
	return s.ipIDCtr
}

// AddTracePkt adds to the state map a trace packet.
func (s *trState) AddTracePkt(p *tracePkt) {
	s.Lock()
	defer s.Unlock()

	s.tracePkts[p.ipID] = p
}

// AddRespPkt adds to the state map a packet that we got in response to a
// previously-sent trace packet.
func (s *trState) AddRespPkt(p *respPkt) error {
	s.Lock()
	defer s.Unlock()

	tracePkt, exists := s.tracePkts[p.ipID]
	if !exists {
		return errInvalidResp
	}
	// Mark the trace packet as "received".
	tracePkt.recvd = p.recvd
	tracePkt.recvdFrom = p.recvdFrom
	return nil
}

// IsFinished returns true if our state indicates that the 0trace scan is
// finished.  That's the case when we haven't received any response packets
// since the timeout.
func (s *trState) IsFinished() bool {
	s.RLock()
	defer s.RUnlock()

	now := time.Now().UTC()
	for _, p := range s.tracePkts {
		if p.IsAnswered() {
			continue
		}
		if now.Sub(p.sent) < reqTimeout {
			return false
		}
	}
	return true
}

// Summary returns a printable string summary of the current traceroute state.
func (s *trState) Summary() string {
	s.RLock()
	defer s.RUnlock()

	numRcvd := 0
	for _, p := range s.tracePkts {
		if p.IsAnswered() {
			numRcvd++
		}
	}
	return fmt.Sprintf("%d pkts sent; %d pkts received so far.",
		len(s.tracePkts), numRcvd)
}

// CalcRTT determines the RTT between us and the client by looking for the
// trace packet that was answered by the client itself *or* for the trace
// packet that made it the farthest to the client (i.e., the packet whose TTL
// is the highest).
func (s *trState) CalcRTT() time.Duration {
	s.RLock()
	defer s.RUnlock()

	l.Printf("Iterating over %d trace packets.", len(s.tracePkts))
	var closestPkt *tracePkt
	for _, p := range s.tracePkts {
		if !p.IsAnswered() {
			continue
		}
		if closestPkt == nil {
			closestPkt = p
		}

		// If we got a response from the target itself, we're done.
		if p.recvdFrom.Equal(s.dstAddr) {
			l.Println("Got response packet from the target itself.")
			closestPkt = p
			break
		}

		if p.ttl > closestPkt.ttl {
			closestPkt = p
		}

		// If the TTL is identical, pick the packet whose RTT is the lowest.
		if p.ttl == closestPkt.ttl {
			closestPktRTT := closestPkt.recvd.Sub(closestPkt.sent)
			pRTT := p.recvd.Sub(p.sent)
			if pRTT < closestPktRTT {
				closestPkt = p
			}
		}
	}
	l.Printf("Closest trace packet: %s", closestPkt)
	return closestPkt.recvd.Sub(closestPkt.sent)
}
