package zerotrace

import (
	"errors"
	"testing"
)

func TestExtractRemoteIP(t *testing.T) {
	c := &mockConn{}
	ip, err := extractRemoteIP(c)
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}

	if ip.String() != dstAddr {
		t.Fatalf("Expected IP address %s but got %s.", dstAddr, ip.String())
	}
}

func TestInvalidExtractIPID(t *testing.T) {
	ipHdr := []byte{0x00}
	_, err := extractIPID(ipHdr)
	if !errors.Is(err, errInvalidIPHeader) {
		t.Fatalf("Expected error %v but got %v.", errInvalidIPHeader, err)
	}
}

func TestExtractIPID(t *testing.T) {
	// The "payload" of an ICMP packet, which is the 20-byte IP header of the
	// original IP packet that resulted in the ICMP error response.
	ipHdr := []byte{
		0x45, 0x20, 0x00, 0x3c, 0x19, 0x97, 0x00, 0x00, 0x00, 0x11,
		0xcf, 0x35, 0xc0, 0xa8, 0x01, 0x0d, 0x08, 0x08, 0x08, 0x08,
	}
	expectedIPID := uint16(0x1997)

	ipID, err := extractIPID(ipHdr)
	if err != nil {
		t.Fatalf("Failed to extract IP ID from ICMP packet: %v", err)
	}

	if ipID != expectedIPID {
		t.Fatalf("Expected IP ID %d but got %d.", expectedIPID, ipID)
	}
}

func TestExtractTTL(t *testing.T) {
	// The "payload" of an ICMP packet, which is the 20-byte IP header of the
	// original IP packet that resulted in the ICMP error response.
	ipHdr := []byte{
		0x45, 0x20, 0x00, 0x3c, 0x19, 0x97, 0x00, 0x00, 0x0f, 0x11,
		0xcf, 0x35, 0xc0, 0xa8, 0x01, 0x0d, 0x08, 0x08, 0x08, 0x08,
	}
	expectedTTL := uint8(0x0f)

	ttl, err := extractTTL(ipHdr)
	if err != nil {
		t.Fatalf("Failed to extract TTL from ICMP packet: %v", err)
	}

	if ttl != expectedTTL {
		t.Fatalf("Expected TTL %d but got %d.", expectedTTL, ttl)
	}
}
