package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var (
	invalidInputErr = errors.New("Invalid Input")
)

type formDetails struct {
	UUID         string
	Timestamp    string
	Contact      string
	ExpType      string
	Device       string
	LocationVPN  string
	LocationUser string
}

func logAsJson(obj any) {
	objM, err := json.Marshal(obj)
	if err != nil {
		l.Println("Error logging results: ", err)
		l.Println(obj) // Dump results in non-JSON format
	}
	objString := string(objM)
	l.Println(objString)
}

// validateForm validates user input obtained from /measure webpage
func validateForm(email string, expType string, device string, locationVPN string, locationUser string) (*formDetails, error) {
	if match, _ := regexp.MatchString(`^\w+@brave\.com$`, email); !match {
		return nil, invalidInputErr
	}
	if expType != "vpn" && expType != "direct" {
		return nil, invalidInputErr
	}
	if device != "mobile" && device != "desktop" {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationVPN); !match {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationUser); !match {
		return nil, invalidInputErr
	}

	details := formDetails{
		UUID:         uuid.NewString(),
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		Contact:      email,
		ExpType:      expType,
		Device:       device,
		LocationVPN:  locationVPN,
		LocationUser: locationUser,
	}
	return &details, nil
}

// isValidUUID checks if UUID u is valid
func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
