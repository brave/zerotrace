package main

import (
	"errors"
	"testing"
)

func TestIcmpPinger(t *testing.T) {

	// Test with a valid IP
	icmpResults, err := icmpPinger("127.0.0.1")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	AssertEqualValue(t, "127.0.0.1", icmpResults.IP)

	// Test with invalid IP
	_, err = icmpPinger("127.0.0.0.1")
	AssertEqualError(t, errors.New("lookup 127.0.0.0.1: no such host"), err)

	// Test with IP that will fail
	_, err = icmpPinger("0.0.0.0")
	AssertEqualError(t, errors.New("write udp 0.0.0.0:0->0.0.0.0:0: sendto: socket is not connected"), err)

}
