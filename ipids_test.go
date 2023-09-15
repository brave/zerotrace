package zerotrace

import (
	"math"
	"testing"
)

func TestExhaustGlobalState(t *testing.T) {
	var (
		err error
		s   = newIpIdPool()
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
		s      = newIpIdPool()
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

func BenchmarkBorrow(b *testing.B) {
	var (
		err error
		p   *ipIdPool
	)

	for i := 0; i < b.N; i++ {
		p = newIpIdPool()
		for j := 0; j < math.MaxUint16; j++ {
			_, err = p.borrow()
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func assertEqual(t *testing.T, is, should interface{}) {
	t.Helper()
	if should != is {
		t.Fatalf("Expected value\n%v\nbut got\n%v", should, is)
	}
}
