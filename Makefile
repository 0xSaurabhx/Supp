BINARY := supp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build run test race vet staticcheck bench clean release

all: vet build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/supp

run: build
	./$(BINARY) server

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

staticcheck:
	@command -v staticcheck >/dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	$$(go env GOPATH)/bin/staticcheck ./...

bench:
	go test -bench=. -benchmem ./internal/dns/ ./internal/filter/

clean:
	rm -f $(BINARY) $(BINARY)-* && rm -rf dist

release:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/supp
	CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 ./cmd/supp
