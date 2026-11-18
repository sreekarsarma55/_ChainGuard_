# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [0.1.0] - first public release

### Added
- `chainguard scan`: runs Syft and cdxgen, scans every SBOM with Trivy and Grype, and writes a run directory with the raw outputs, a normalised inventory, correlated findings and a summary. Targets: a project directory, an image archive, or `image:<ref>`.
- A canonical component model keyed on Package URLs, with source-package identity, per-ecosystem version canonicalisation, Maven group resolution, and the removal of entries that are not installed software.
- A merged SBOM (CycloneDX and SPDX) that both scanners scan, and a hand-off check against direct scans of images.
- Vulnerability alias resolution through OSV.dev, with an on-disk cache and an offline mode.
- Enrichment from dated EPSS and CISA KEV snapshots, plus CVSS, fix availability and dependency depth.
- A priority score from 0 to 100 with a per-factor explanation, configurable in YAML.
- `chainguard gate`: a YAML policy with integrity checks that fail closed, rules, and time-boxed exceptions. Exit code 0 for PASS or WARN, 1 for FAIL, 2 if the policy or run cannot be read.
- Reports: SARIF 2.1.0 for GitHub code scanning, JSON, and a Markdown job summary.
- A GitHub Action (`action.yml`) and a Docker image with the pinned toolchain.
- `chainguard reprocess`, `report`, `tools`, `db update` and `sbom normalize|repair|merge`.
