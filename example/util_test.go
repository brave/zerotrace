package main

import (
	"testing"

	"github.com/google/uuid"
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

func TestIsValidUUID(t *testing.T) {
	// Fake UUID (random string) fails test
	testUUID := "fake-uuid"
	AssertEqualValue(t, false, isValidUUID(testUUID))

	// UUID obtained from uuid passes
	testUUID = uuid.NewString()
	AssertEqualValue(t, true, isValidUUID(testUUID))
}
