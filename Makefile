BINARY=blacknet
VERSION?=1.0.0
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build web test vet clean bench race docker

all: web build

build:
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/blacknet

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath $(LDFLAGS) -o blacknet.exe ./cmd/blacknet

web:
	cd web && npm install --no-audit --no-fund && npm run build

test:
	go test ./... -count=1

vet:
	go vet ./...

race:
	CGO_ENABLED=1 go test -race ./... -count=1

bench:
	go test -bench=. -benchmem ./internal/dnsserver/

docker:
	docker compose build

clean:
	rm -rf $(BINARY) blacknet.exe web/dist
