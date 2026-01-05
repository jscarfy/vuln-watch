#!/usr/bin/env bash
set -euo pipefail

if [ ! -f go.mod ] || [ ! -d .git ]; then
  echo "ERROR: run_local.sh must be executed from vuln-watch repo root (go.mod + .git required)."
  exit 1
fi

echo "== repo =="
git rev-parse --show-toplevel
echo "== branch =="
git branch --show-current
echo "== origin =="
git remote get-url origin || true
echo

mkdir -p .vuln-watch reports configs

go run ./cmd/vuln-watch-gen --gomod ./go.mod --out ./configs/generated.yaml

go run ./cmd/vuln-watch \
  --config ./configs/generated.yaml \
  --state ./.vuln-watch/state.json \
  --only-new=false \
  --write-state=true \
  --out ./reports/report.md \
  --timeout 20s \
  --retries 2 \
  --concurrency 8 \
  --cache-dir ./.vuln-watch/cache

echo "wrote: reports/report.md"
head -n 80 reports/report.md || true
