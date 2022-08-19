package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIcmpPinger(t *testing.T) {

	// Test with a valid IP
	icmpResults, err := icmpPinger("127.0.0.1")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	assert.IsType(t, PingMsmt{}, icmpResults)
	assert.Equal(t, "127.0.0.1", icmpResults.IP)

	// Test with invalid IP
	_, err = icmpPinger("127.0.0.0.1")
	assert.Equal(t, "lookup 127.0.0.0.1: no such host", err.Error())

	// Test with IP that will fail
	_, err = icmpPinger("0.0.0.0")
	assert.Equal(t, "write udp 0.0.0.0:0->0.0.0.0:0: sendto: socket is not connected", err.Error())

}
