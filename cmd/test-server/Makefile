.PHONY: all test lint clean

binary = latsrv
godeps = *.go go.mod go.sum

all: test lint $(binary)

test:
	go test -cover ./...

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm -f $(binary)
