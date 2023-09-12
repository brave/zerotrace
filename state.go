package zerotrace

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	reqTimeout  = time.Second * 3
	ipidTimeout = time.Second * 10
)

var (
	errInvalidResp = errors.New("got response for non-existing trace packet")
	errNoMoreIds   = errors.New("all IP IDs are currently in flight")
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

func (p *respPkt) String() string {
	return fmt.Sprintf("<- %s (ttl=%d, ip id=%d)", p.recvdFrom.String(), p.ttl, p.ipID)
}

// respPkt represents a packet that we received in response to a trace packet.
// For simplicity, we re-use the trace packet here; in particular, the "recvd"
// and "recvdFrom" fields.
type respPkt tracePkt

// isAnswered returns true if the given trace packet has seen a response.
func (p *tracePkt) isAnswered() bool {
	return !p.sent.IsZero() && !p.recvd.IsZero()
}

// String implements the Stringer interface.
func (p *tracePkt) String() string {
	return fmt.Sprintf("%s (TTL=%d, IP ID=%d)",
		p.recvdFrom, p.ttl, p.ipID,
	)
}

// trState represents our traceroute state machine.  We keep track of the
// following:
//  1. The IP address of the client that is the target of our traceroute.
//  2. Packets that we sent and received as part of the traceroute.
//  3. The IP IDs that we use as part of the traceroute.
type trState struct {
	sync.RWMutex
	dstAddr   net.IP
	tracePkts map[uint16]*tracePkt
}

// newTrState returns a new traceroute state object.
func newTrState(dstAddr net.IP) *trState {
	return &trState{
		dstAddr:   dstAddr,
		tracePkts: make(map[uint16]*tracePkt),
	}
}

type ipIdState struct {
	sync.Mutex // Guards ipids.
	ipids      map[uint16]time.Time
}

func newIpIdState() *ipIdState {
	return &ipIdState{
		ipids: make(map[uint16]time.Time),
	}
}

func (s *ipIdState) size() int {
	s.Lock()
	defer s.Unlock()

	return len(s.ipids)
}

func (s *ipIdState) borrow() (uint16, error) {
	s.Lock()
	defer s.Unlock()

	if len(s.ipids) == math.MaxUint16 {
		return 0, errNoMoreIds
	}

	start := uint16(rand.Intn(math.MaxUint16))
	for id := start + 1; id != start; id++ {
		if _, exists := s.ipids[id]; !exists {
			s.ipids[id] = time.Now().UTC()
			return id, nil
		}
	}

	return 0, nil
}

func (s *ipIdState) releaseUnanswered() {
	s.Lock()
	defer s.Unlock()

	now := time.Now().UTC()
	for id, added := range s.ipids {
		if now.Sub(added) > ipidTimeout {
			delete(s.ipids, id)
		}
	}
}

func (s *ipIdState) release(id uint16) {
	s.Lock()
	defer s.Unlock()

	delete(s.ipids, id)
}

// AddTracePkt adds to the state map a trace packet.
func (s *trState) addTracePkt(p *tracePkt) {
	s.Lock()
	defer s.Unlock()

	s.tracePkts[p.ipID] = p
}

// AddRespPkt adds to the state map a packet that we got in response to a
// previously-sent trace packet.
func (s *trState) addRespPkt(p *respPkt) error {
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

// isFinished returns true if our state indicates that the 0trace scan is
// finished.  That's the case when we haven't received any response packets
// since the timeout.
func (s *trState) isFinished() bool {
	s.RLock()
	defer s.RUnlock()

	now := time.Now().UTC()
	for _, p := range s.tracePkts {
		if p.isAnswered() {
			continue
		}
		if now.Sub(p.sent) < reqTimeout {
			return false
		}
	}
	return true
}

// summary returns a printable string summary of the current traceroute state.
func (s *trState) summary() string {
	s.RLock()
	defer s.RUnlock()

	numRcvd := 0
	for _, p := range s.tracePkts {
		if p.isAnswered() {
			numRcvd++
		}
	}
	return fmt.Sprintf("%d pkts sent; %d pkts received so far.",
		len(s.tracePkts), numRcvd)
}

// calcRTT determines the RTT between us and the client by looking for the
// trace packet that was answered by the client itself *or* for the trace
// packet that made it the farthest to the client (i.e., the packet whose TTL
// is the highest).
func (s *trState) calcRTT() (time.Duration, error) {
	s.RLock()
	defer s.RUnlock()

	var closestPkt *tracePkt
	for _, p := range s.tracePkts {
		if !p.isAnswered() {
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
	if closestPkt != nil {
		l.Printf("Closest response packet from: %s", closestPkt)
		return closestPkt.recvd.Sub(closestPkt.sent), nil
	}
	return time.Duration(0), errors.New("no response packets")
}
