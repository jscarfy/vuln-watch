#!/usr/bin/env bash
set -euo pipefail
go test ./...
go run ./cmd/vuln-watch --config ./configs/example.yaml
