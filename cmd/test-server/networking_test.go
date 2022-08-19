package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIcmpPinger(t *testing.T) {

	// Test with invalid IP
	assert.PanicsWithError(t, "lookup 192.0.2.256: no such host", func() { _ = icmpPinger("192.0.2.256") })

}
