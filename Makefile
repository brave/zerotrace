DEPS = *.go go.mod go.sum

.PHONY: all
all: test lint

.PHONY: test
test: $(DEPS)
	go test -cover -race ./...
	go vet ./...
	govulncheck ./...

.PHONY: coverage
coverage: $(DEPS)
	go test -coverprofile=cover.out .
	go tool cover -html=cover.out
	rm cover.out

.PHONY: lint
lint: $(DEPS)
	golangci-lint run
