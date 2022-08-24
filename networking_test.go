package main

import (
	"errors"
	"net"
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
	var dnsError *net.DNSError
	if !errors.As(err, &dnsError) {
		t.Errorf("Expected DNS Error, got %v", err)
	}
}
