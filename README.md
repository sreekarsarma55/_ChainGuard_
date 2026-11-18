# ChainGuard

[![CI](https://github.com/sreekarsarma55/_ChainGuard_/actions/workflows/ci.yml/badge.svg)](https://github.com/sreekarsarma55/_ChainGuard_/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

**A CI/CD security gate that runs several SBOM generators and vulnerability scanners, merges what they find, and passes or fails your build.**

Most pipelines check their dependencies with one SBOM generator and one scanner. Each tool misses things, and the tools disagree with each other, often only because they name the same package or vulnerability differently. ChainGuard runs two generators (Syft and cdxgen) and two scanners (Trivy and Grype) on your project or container image, repairs what gets lost between them, and combines the results into one list of findings. It ranks the findings by how likely they are to matter, and a YAML policy turns them into **PASS**, **WARN** or **FAIL**, with every reason written down.

- **One result instead of four.** Package identities, versions and vulnerability IDs (CVE, GHSA, distribution IDs) are normalised, so the same issue is counted once.
- **A gate you can explain.** Every verdict lists the rules that fired and the findings behind them. By default, a vulnerability that is known to be exploited (CISA KEV) or in the critical band fails the build.
- **Fails closed.** A tool that crashed, an empty SBOM, or missing vulnerability data is a FAIL, never a quiet pass.
- **Reproducible.** Tool versions are pinned, scans use dated vulnerability-database and EPSS/KEV snapshots, and every run records exactly what it used.
- **Works where you work.** A command-line tool, a Docker image, and a GitHub Action that reports in the job summary and in code scanning.

## Quick start

You need Linux, macOS or WSL2 with Python 3.11+, Node.js 20+ and `curl` (plus a JDK and Maven to scan Java projects). Or just Docker: see the [user guide](docs/USER_GUIDE.md#with-docker).

```bash
git clone https://github.com/sreekarsarma55/_ChainGuard_.git
cd _ChainGuard_

scripts/install-tools.sh                 # Syft, Grype, Trivy and cdxgen at the pinned versions
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
chainguard db update                     # vulnerability databases and EPSS/KEV snapshots (a few minutes, once)

chainguard scan examples/java-app --gate
echo "exit code: $?"                     # 0 PASS or WARN, 1 FAIL, 2 the policy or run could not be read
```

The Java example is deliberately vulnerable, so the gate fails it. A scan takes under a minute and ends like this:

```
Gate: FAIL · 83 findings on installed software · 3 failing, 50 warning, 0 excepted
  FAIL  rule known-exploited: 3 finding(s): Listed in CISA KEV as exploited in the wild
        CVE-2021-44228 on maven/org.apache.logging.log4j/log4j-core@2.14.1 (score 95.0, critical; fixed in 2.12.2, 2.15.0, 2.3.1)
        CVE-2022-22965 on maven/org.springframework/spring-webmvc@5.3.17 (score 94.58, critical; fixed in 5.2.20.RELEASE, 5.3.18)
        CVE-2021-45046 on maven/org.apache.logging.log4j/log4j-core@2.14.1 (score 93.19, critical; fixed in 2.12.2, 2.16.0, 2.3.1)
  WARN  rule high-priority-fixable: 50 finding(s): Priority band high, and a fixed version exists
```

Each finding names the fixed version. The counts on your machine will differ a little, because the vulnerability databases change daily. Results land in `chainguard-out/<run-id>/`, with a `summary.md` to read first.

## In GitHub Actions

```yaml
name: ChainGuard
on: [pull_request, push]
permissions:
  contents: read
  security-events: write          # to upload findings to code scanning
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: sreekarsarma55/_ChainGuard_@main     # pin a tag or a commit in real use
        with:
          path: .                  # a project directory, or an image archive
```

The job fails when the gate fails. The decision and the findings appear in the job summary, and, on public repositories (or with GitHub Advanced Security), as code-scanning alerts on the line that declares each vulnerable package. Inputs and outputs are in the [user guide](docs/USER_GUIDE.md#in-github-actions).

## What it checks

| | |
|---|---|
| **Targets** | A project directory, a container image archive (`docker save`), or `image:<ref>` |
| **Ecosystems tested** | Java (Maven, Gradle), Python, JavaScript (npm), and Debian, Ubuntu and Alpine images |
| **Generators** | Syft, cdxgen |
| **Scanners** | Trivy, Grype |
| **Enrichment** | EPSS, CISA KEV, CVSS, fix availability, dependency depth |
| **Outputs** | `verdict.json`, SARIF 2.1.0, JSON, Markdown, and the merged SBOM (CycloneDX and SPDX) |

## Documentation

| | |
|---|---|
| [User guide](docs/USER_GUIDE.md) | Install, scan, read the result, write a policy and exceptions, tune the score, use the Action, troubleshoot |
| [How it works](docs/HOW_IT_WORKS.md) | One scan, stage by stage |
| [Architecture](docs/ARCHITECTURE.md) | The model, the design rules and the code layout |
| [Contributing](CONTRIBUTING.md) | Set up, run the tests, send a change |
| [Security policy](SECURITY.md) | Reporting a vulnerability in ChainGuard |
| [Changelog](CHANGELOG.md) | What changed in each release |

## Status and limits

ChainGuard is **pre-1.0**. It works and is tested, but expect rough edges, and the command-line options may change before 1.0.

- **Platforms.** CI runs on Ubuntu. The install script supports Linux and macOS; macOS and Windows (through WSL2) are untested by us.
- **Operating-system findings are noisy.** Distributions publish advisories per *source* package, so a finding can concern a binary package that does not contain the vulnerable code (headers, `-dev` and data packages). Expect a large share of operating-system findings to be false positives. Findings that both scanners report are much more reliable than findings only one reports.
- **The priority score is a heuristic.** Known exploitation (KEV) is the strongest signal and the default rules rest on it. The finer ordering of other findings is not better than CVSS alone, so tune the weights against your own review before relying on it.
- **No reachability analysis.** It does not tell you whether your code calls the vulnerable function.
- **Unlocked projects can change between scans.** Without a lockfile, the dependency tree is resolved on the day of the scan. The gate warns about it.
- **It knows what the tools and databases know.** A vulnerability that no advisory database lists is invisible to it.
- **It runs other people's tools.** Syft, cdxgen, Trivy and Grype are downloaded at pinned versions. Review `src/chainguard/toolchain.env` and `scripts/install-tools.sh` if that matters to you.

## Contributing

Bug reports, fixes and ideas are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first; it is short.

## Licence

[Apache-2.0](LICENSE). The tools ChainGuard runs and the vulnerability data it downloads keep their own licences.

## Safety

The projects under [`examples/`](examples/README.md) pin known-vulnerable dependencies **on purpose**, as test targets. Never deploy them. GitHub may show Dependabot alerts for them; those are expected.
