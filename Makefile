.PHONY: all test coverage lint clean

godeps = *.go go.mod go.sum

all: test lint

test:
	go test -cover ./...

coverage:
	go test -coverprofile=cover.out .
	go tool cover -html=cover.out
	rm cover.out

lint:
	golangci-lint run
