APP := vuln-watch
BIN := bin/$(APP)

.PHONY: help tidy fmt test lint build run clean

help:
	@printf "Targets:\n"
	@printf "  tidy  - go mod tidy\n"
	@printf "  fmt   - gofmt\n"
	@printf "  test  - go test ./...\n"
	@printf "  lint  - golangci-lint (if installed)\n"
	@printf "  build - build binary\n"
	@printf "  run   - run with example config\n"
	@printf "  clean - remove build artifacts\n"

tidy:
	go mod tidy

fmt:
	gofmt -w .

test:
	go test ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed; skipping"; fi

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/vuln-watch

run:
	go run ./cmd/vuln-watch --config ./configs/example.yaml

clean:
	rm -rf bin dist
