package main

import (
	"errors"
	"net"
	"testing"
)

func TestPingAddr(t *testing.T) {
	// Test with a valid IP
	pingStats, err := pingAddr("127.0.0.1")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	AssertEqualValue(t, "127.0.0.1", pingStats.Addr)

	// Test with invalid IP
	_, err = pingAddr("127.0.0.0.1")
	var dnsError *net.DNSError
	if !errors.As(err, &dnsError) {
		t.Errorf("Expected DNS Error, got %v", err)
	}
}
