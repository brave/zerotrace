package main

import (
	"testing"
)

func TestNewZeroTrace(t *testing.T) {
	conn := &mockConn{}
	if _, err := NewZeroTrace("foobar", conn); err != nil {
		t.Fatalf("Failed to create zerotrace object: %v", err)
	}
}
