package zerotrace

import (
	"errors"
	"math"
	"net"
	"testing"
	"time"
)

var (
	dummyAddr = net.ParseIP("1.2.3.4")
)

func failOnErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}
}

func TestIsAnswered(t *testing.T) {
	p := &tracePkt{}

	if p.isAnswered() {
		t.Fatal("Expected empty trace packet to be un-answered.")
	}

	now := time.Now().UTC()
	p.sent = now
	p.recvd = now
	if !p.isAnswered() {
		t.Fatal("Expected answered trace packet to be answered.")
	}
}

func TestNewTrState(t *testing.T) {
	s := newTrState(dummyAddr)
	if s.tracePkts == nil {
		t.Fatal("Map in trState struct uninitialized.")
	}
}

func TestAddTracePkt(t *testing.T) {
	s := newTrState(dummyAddr)

	s.addTracePkt(&tracePkt{
		ttl:  1,
		ipID: 1,
		sent: time.Now().UTC(),
	})
	expected := 1
	if len(s.tracePkts) != expected {
		t.Fatalf("Expected %d recorded packets but got %d.",
			expected, len(s.tracePkts))
	}
}

func TestAddRespPkt(t *testing.T) {
	s := newTrState(dummyAddr)
	p := &respPkt{
		ipID:      1,
		ttl:       1,
		recvd:     time.Now().UTC(),
		recvdFrom: net.ParseIP("1.2.3.4"),
	}

	// Adding a packet in response to a non-existing trace packet should give
	// us an error.
	if err := s.addRespPkt(p); !errors.Is(err, errInvalidResp) {
		t.Fatalf("Expected error %v but got %v.", errInvalidResp, err)
	}

	s.addTracePkt(&tracePkt{
		ttl:  1,
		ipID: 1,
		sent: time.Now().UTC(),
	})
	if err := s.addRespPkt(p); err != nil {
		t.Fatalf("Expected error nil but got %v.", err)
	}
}

func TestIsFinished(t *testing.T) {
	s := newTrState(dummyAddr)
	now := time.Now().UTC()
	p := &tracePkt{
		ttl:  1,
		ipID: 1,
		sent: now,
	}

	s.addTracePkt(p)
	if s.isFinished() {
		t.Fatal("Expected traceroute to be unfinished.")
	}

	p.sent = now.Add(-reqTimeout)
	if !s.isFinished() {
		t.Fatal("Expected traceroute to be finished.")
	}

	p.recvd = now
	if !s.isFinished() {
		t.Fatal("Expected traceroute to be finished.")
	}
}

func TestSummary(t *testing.T) {
	s := newTrState(dummyAddr)
	if len(s.summary()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}

	now := time.Now().UTC()
	s.addTracePkt(&tracePkt{
		ipID:  1,
		ttl:   1,
		sent:  now,
		recvd: now,
	})
	if len(s.summary()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}
}

func TestCalcRTT(t *testing.T) {
	var (
		err error
		rtt time.Duration
		s   = newTrState(dummyAddr)
		now = time.Now().UTC()
	)

	expectedRTT := time.Second
	s.addTracePkt(&tracePkt{
		ttl:   1,
		ipID:  1,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})
	rtt, err = s.calcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a trace packet with an identical TTL but a lower RTT.
	expectedRTT = time.Millisecond * 500
	s.addTracePkt(&tracePkt{
		ttl:   1,
		ipID:  2,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})
	rtt, err = s.calcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a trace packet with a higher TTL (i.e., it got closer to the
	// target).
	expectedRTT = time.Second * 2
	s.addTracePkt(&tracePkt{
		ttl:   2,
		ipID:  2,
		sent:  now.Add(-expectedRTT),
		recvd: now,
	})
	rtt, err = s.calcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add an unanswered packet and make sure that it doesn't affect the RTT.
	s.addTracePkt(&tracePkt{
		ttl:  3,
		ipID: 3,
		sent: now.Add(-time.Second * 10),
	})
	rtt, err = s.calcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a packet whose TTL is lower than the existing ones but it got
	// answered by the destination itself, so it should be used to calculate
	// the RTT.
	expectedRTT = time.Second * 3
	s.addTracePkt(&tracePkt{
		ttl:       1,
		ipID:      4,
		sent:      now.Add(-expectedRTT),
		recvd:     now,
		recvdFrom: dummyAddr,
	})
	rtt, err = s.calcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
}

func TestExhaustGlobalState(t *testing.T) {
	var (
		err error
		s   = newIpIdState()
	)

	// Exhaust the global state.
	for i := 0; i < math.MaxUint16; i++ {
		_, err = s.borrow()
		failOnErr(t, err)
	}
	assertEqual(t, s.size(), math.MaxUint16)
	// The global state is now full.  Subsequent requests for IP IDs should
	// return an error.
	_, err = s.borrow()
	assertEqual(t, err, errNoMoreIds)
}

func TestGlobalState(t *testing.T) {
	var (
		numIDs = 100
		ipids  = []uint16{}
		s      = newIpIdState()
	)

	for i := 0; i < numIDs; i++ {
		id, err := s.borrow()
		failOnErr(t, err)
		ipids = append(ipids, id)
	}
	assertEqual(t, s.size(), numIDs)

	for _, id := range ipids {
		s.release(id)
	}
	assertEqual(t, s.size(), 0)
}

func assertEqual(t *testing.T, is, should interface{}) {
	t.Helper()
	if should != is {
		t.Fatalf("Expected value\n%v\nbut got\n%v", should, is)
	}
}
