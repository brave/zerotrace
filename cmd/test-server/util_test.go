package main

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	invalidInputErr = errors.New("Invalid Input")
)

func TestValidateForm(t *testing.T) {
	// Send valid email and experiment type, check that returned object is exactly as expected
	details, err := validateForm("user@brave.com", "vpn")
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
	assert.IsType(t, FormDetails{}, details)
	assert.Equal(t, "user@brave.com", details.Contact)
	assert.Equal(t, "vpn", details.ExpType)

	// Send invalid email
	_, err = validateForm("baduser@invalid.com", "vpn")
	assert.Equal(t, invalidInputErr, err)

	// Send invalid expType
	_, err = validateForm("user@brave.com", "unknown")
	assert.Equal(t, invalidInputErr, err)

	// Send empty input
	_, err = validateForm("", "")
	assert.Equal(t, invalidInputErr, err)
}
