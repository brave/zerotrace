package zerotrace

import (
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
