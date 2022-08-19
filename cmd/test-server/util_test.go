package main

import (
	"errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var (
	invalidInputErr = errors.New("Invalid Input")
	currentTime     = time.Now().UTC()
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

func TestGetSentTimestampfromIPId(t *testing.T) {
	// Test the only untested portion of this function
	sentPktsIPId := make(map[int][]SentPacketData)
	sentPktsIPId[1] = append(sentPktsIPId[1], SentPacketData{HopIPId: 1, HopSentTime: currentTime})
	sentPktsIPId[1] = append(sentPktsIPId[1], SentPacketData{HopIPId: 2, HopSentTime: currentTime})

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
	assert.Error(t, errors.New("IP Id not in sent packets"), err)

}

func TestIsValidUUID(t *testing.T) {
	// Fake UUID (random string) fails test
	testUUID := "fake-uuid"
	assert.Equal(t, false, isValidUUID(testUUID))

	// UUID obtained from uuid passes
	testUUID = uuid.NewString()
	assert.Equal(t, true, isValidUUID(testUUID))
}
