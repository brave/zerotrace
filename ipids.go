package zerotrace

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

var (
	errNoMoreIds = errors.New("all IP IDs are currently in flight")
)

// ipIdPool keeps track of IP IDs that we use for traceroutes.
type ipIdPool struct {
	sync.Mutex // Guards ipids.
	ipids      map[uint16]time.Time
}

func newIpIdState() *ipIdPool {
	return &ipIdPool{
		ipids: make(map[uint16]time.Time),
	}
}

// size returns the number of IP IDs that are currently in flight.
func (s *ipIdPool) size() int {
	s.Lock()
	defer s.Unlock()

	return len(s.ipids)
}

// borrow "borrows" an IP ID that's meant to be returned later.
func (s *ipIdPool) borrow() (uint16, error) {
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
	return 0, errNoMoreIds // Should never happen.
}

// releaseUnanswered releases expired IP IDs that were not explicitly released.
func (s *ipIdPool) releaseUnanswered() {
	s.Lock()
	defer s.Unlock()

	now := time.Now().UTC()
	for id, added := range s.ipids {
		if now.Sub(added) > ipidTimeout {
			delete(s.ipids, id)
		}
	}
}

// release returns a previously-borrowed IP ID.
func (s *ipIdPool) release(id uint16) {
	s.Lock()
	defer s.Unlock()

	delete(s.ipids, id)
}
