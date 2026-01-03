# vuln-watch

Track vulnerabilities for the dependencies you care about and get notified (CI, cron, or local runs).

## MVP (today)
- Read a YAML config of packages
- Query OSV for known vulns
- Print a concise report
- (Optional) non-zero exit for CI gating

## Roadmap (indefinitely developable)
- GitHub Action / scheduled runs
- Slack/Email/Webhook notifications
- Diff reports (new vulns since last run)
- SBOM ingestion (CycloneDX/SPDX)
- Lockfile parsing (go.mod, go.sum, package-lock, pnpm-lock, poetry.lock, etc.)
- Policy engine (severity thresholds, allowlists, deadlines)
- Multi-repo dashboard (hosted)

## Quickstart
```bash
make run
# show all vulns (not only new):
go run ./cmd/vuln-watch --config ./configs/example.yaml --only-new=false
# persist seen vulns into a state file:
go run ./cmd/vuln-watch --config ./configs/example.yaml --state ./.vuln-watch/state.json
```

## Config
See `configs/example.yaml`.

## Disclaimer
This tool provides best-effort information and is not a substitute for a full security program.
