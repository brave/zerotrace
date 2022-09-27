.PHONY: all test coverage lint clean

binary = latsrv
godeps = *.go go.mod go.sum

all: test lint $(binary)

test:
	go test -cover ./...

coverage:
	go test -coverprofile=cover.out .
	go tool cover -html=cover.out
	rm cover.out

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm -f $(binary)
