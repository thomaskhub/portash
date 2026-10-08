.PHONY: build test e2e

build:
	go build -trimpath -ldflags "-s -w" -o dist/portash ./cmd/portash

test:
	go vet ./... && go test -race ./...

e2e:
	sudo ./scripts/e2e-local.sh
