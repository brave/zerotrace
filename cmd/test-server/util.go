package main

import (
	"time"

	"github.com/google/uuid"
)

// isValidUUID checks if UUID u is valid
func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

// fmtTimeMs returns the value (time.Duration) in milliseconds, the inbuilt time.Milliseconds() function only returns an int64 value
func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}
