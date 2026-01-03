# Ingest

Planned ingestion sources:
- go.mod / go.sum (Go)
- package-lock.json / pnpm-lock.yaml (Node)
- poetry.lock (Python)
- sbom (CycloneDX / SPDX)

Goal:
Generate a normalized list of PURLs so vuln-watch can run without hand-maintained config.
