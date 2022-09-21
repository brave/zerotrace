binary = latsrv
godeps = *.go go.mod go.sum

.PHONY: all $(binary) lint clean

all: lint $(binary)

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm -f $(binary)
