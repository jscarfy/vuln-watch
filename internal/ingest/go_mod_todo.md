# go.mod ingest TODO

Approach:
- Parse go.mod with golang.org/x/mod/modfile
- For each require:
  - Build purl: pkg:golang/<module>@<version>
- Write out to:
  - config YAML (merge with existing sources)
  - or a generated "packages.json" consumed by the runner

Edge cases:
- replace directives
- indirect dependencies (choose include/exclude)
