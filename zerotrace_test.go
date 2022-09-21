package zerotrace

import (
	"testing"
)

func TestNewZeroTrace(t *testing.T) {
	if _, err := NewZeroTrace("foobar"); err != nil {
		t.Fatalf("Failed to create zerotrace object: %v", err)
	}
}
