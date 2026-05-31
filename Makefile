# LinAudit -- one statically-linked Go binary, standard library only (no external
# modules), so the build is offline and reproducible. Target: linux/amd64.

BIN     := linaudit
PKG     := ./cmd/linaudit
PREFIX  ?= /usr/local
DESTDIR ?=
GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: all build test race vet fmt clean install

all: build

# Build the static binary.
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN) $(PKG)

# Run the test suite (parity vectors, parsers, classify, scrypt, evdev decode).
test:
	CGO_ENABLED=0 go test ./...

# Run tests under the race detector (cgo is used for the test binary only).
race:
	CGO_ENABLED=1 go test -race ./...

vet:
	CGO_ENABLED=0 go vet ./...

# List any files that are not gofmt-clean (empty output == clean).
fmt:
	gofmt -l .

clean:
	rm -f $(BIN) inject

# Install just the binary. Units/configs/store are system-specific; see README.
install: build
	install -m755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
