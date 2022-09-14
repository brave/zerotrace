package main

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	currentTime = time.Now().UTC()
)

func AssertEqualValue(t *testing.T, expected any, actual any) {
	t.Helper()
	if expected != actual {
		t.Errorf("Expected %v, got %v",
			expected, actual)
	}
}

func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("Expected an error but got nil")
	}
}

func TestValidateForm(t *testing.T) {
	// Send valid email and experiment type, check that returned object is exactly as expected
	details, err := validateForm("user@brave.com", "vpn", "mobile", "city, country", "different city, country")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	AssertEqualValue(t, "user@brave.com", details.Contact)
	AssertEqualValue(t, "vpn", details.ExpType)

	// Send invalid email
	_, err = validateForm("baduser@invalid.com", "vpn", "", "", "")
	AssertError(t, err)
	AssertEqualValue(t, invalidInputErr, err)

	// Send invalid expType
	_, err = validateForm("user@brave.com", "unknown", "", "", "")
	AssertError(t, err)
	AssertEqualValue(t, invalidInputErr, err)

	// Send invalid device
	_, err = validateForm("user@brave.com", "vpn", "badDevice", "", "")
	AssertError(t, err)
	AssertEqualValue(t, invalidInputErr, err)

	// Send empty input
	_, err = validateForm("", "", "", "", "")
	AssertError(t, err)
	AssertEqualValue(t, invalidInputErr, err)
}

func TestGetSentTimestampfromIPId(t *testing.T) {
	// Test the only untested portion of this function
	sentPktsIPId := make(map[int][]sentPacketData)
	sentPktsIPId[1] = append(sentPktsIPId[1], sentPacketData{HopIPId: 1, HopSentTime: currentTime})
	sentPktsIPId[1] = append(sentPktsIPId[1], sentPacketData{HopIPId: 2, HopSentTime: currentTime})

	// Retrieve the sent time for a valid IP ID from the slice that was passed
	t1, err := getSentTimestampfromIPId(sentPktsIPId[1], 1)
	if t1 != currentTime {
		t.Fatalf("Expected to retrieve HopSentTime correctly, but got: %v", t1)
	}
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	// Retrieve the sent time for a invalid IP ID that does not exist in the slice that was passed
	_, err = getSentTimestampfromIPId(sentPktsIPId[1], 1000)
	AssertError(t, err)
	AssertEqualValue(t, "IP Id not in sent packets", err.Error())
}

func TestIsValidUUID(t *testing.T) {
	// Fake UUID (random string) fails test
	testUUID := "fake-uuid"
	AssertEqualValue(t, false, isValidUUID(testUUID))

	// UUID obtained from uuid passes
	testUUID = uuid.NewString()
	AssertEqualValue(t, true, isValidUUID(testUUID))
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
