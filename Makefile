.PHONY: build test vet bench fuzz demo lint clean

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

bench:
	go test -run '^$$' -bench . -benchtime 1s ./...

# native fuzz targets (seed corpus always runs as part of `make test`)
fuzz:
	go test -run '^$$' -fuzz FuzzDecodings -fuzztime 30s ./internal/labels/

demo: build
	go run ./cmd/referee demo

lint: vet test

clean:
	rm -rf referee remote-out referee-receipts*.jsonl referee-heads*.jsonl
