package zerotrace

import "time"

// Config holds configuration options for the ZeroTrace object.
type Config struct {
	// NumProbes determines the number of probes we're sending for a given TTL.
	NumProbes int
	// TTLStart determines the TTL at which we start sending trace packets.
	TTLStart int
	// TTLEnd determines the TTL at which we stop sending trace packets.
	TTLEnd int
	// SnapLen determines the number of bytes per frame that we want libpcap to
	// capture.  500 bytes is enough for ICMP TTL exceeded packets.
	SnapLen int32
	// PktBufTimeout determines the time we're willing to wait for packets to
	// accumulate in our receive buffer.
	PktBufTimeout time.Duration
	// Interface determines the network interface that we're going to use to
	// listen for incoming network packets.
	Interface string
}

// NewDefaultConfig returns a configuration object containing the following
// defaults.  *Note* that you probably need to change the networking interface.
//
//	NumProbes:     3
//	TTLStart:      5
//	TTLEnd:        32
//	SnapLen:       500
//	PktBufTimeout: time.Millisecond * 10
//	Interface:     "eth0"
func NewDefaultConfig() *Config {
	return &Config{
		NumProbes:     3,
		TTLStart:      5,
		TTLEnd:        32,
		SnapLen:       500,
		PktBufTimeout: time.Millisecond * 10,
		Interface:     "eth0",
	}
}
