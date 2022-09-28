binary = example
godeps = *.go

.PHONY: all $(binary) lint clean

all: lint $(binary)

lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

clean:
	rm -f $(binary)
