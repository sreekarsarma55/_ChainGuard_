# User guide

How to install ChainGuard, scan a project or an image, read the result, tune the rules, and use it as a GitHub Action. For how it works inside, read [`HOW_IT_WORKS.md`](HOW_IT_WORKS.md).

**Contents:** [What it does](#what-it-does) · [Install](#install) · [Your first scan](#your-first-scan) · [Reading the result](#reading-the-result) · [The policy](#the-policy) · [The priority score](#the-priority-score) · [GitHub Actions](#in-github-actions) · [Scanning images](#scanning-container-images) · [All commands](#all-commands) · [Keeping runs reproducible](#keeping-runs-reproducible) · [Troubleshooting](#troubleshooting) · [What ChainGuard does not do](#what-chainguard-does-not-do)

---

## What it does

You point ChainGuard at a project directory or a container image. It builds a list of the software inside (an SBOM) with two independent tools, checks it against vulnerability databases with two scanners, merges what they find into one result, ranks the findings by real-world risk, and gives a verdict:

| Verdict | Meaning | Exit code |
|---|---|---|
| **PASS** | Nothing the policy acts on | 0 |
| **WARN** | Findings worth fixing, nothing that blocks the build | 0 |
| **FAIL** | A known-exploited or critical finding, or a run that cannot be trusted | 1 |
| *(error)* | The policy or the run could not be read | 2 |

With the default policy, a vulnerability listed in CISA's Known Exploited Vulnerabilities catalogue (KEV), or one in the *critical* priority band, fails the build.

## Install

You need one of two things: Docker (easiest, nothing else to install), or Linux, macOS or WSL2 with Python 3.11+, Node.js 20+ and `curl` (plus a JDK and Maven to scan Java projects).

### With Docker

The [`Dockerfile`](../Dockerfile) is the fixed environment: the pinned tools, Python 3.12, Node 22, JDK 17 and Maven.

```bash
docker build -t chainguard .
docker run --rm --user "$(id -u):$(id -g)" -v chainguard-cache:/cache chainguard db update
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -v chainguard-cache:/cache chainguard scan path/to/project --gate
```

- Use the same `--user` for every command that shares the cache volume.
- On Windows with Docker Desktop (PowerShell), drop `--user …` and write `${PWD}`.
- The image contains no Docker CLI. To scan an image, run `docker save -o image.tar <ref>` on the host and scan the `.tar`.

### Without Docker

```bash
scripts/install-tools.sh                 # Syft, Grype, Trivy, cdxgen at the pinned versions (src/chainguard/toolchain.env)
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
chainguard tools                         # installed versus pinned versions, database status
chainguard db update                     # vulnerability databases, and dated EPSS and KEV snapshots
```

`install-tools.sh` takes an optional directory for the binaries (`scripts/install-tools.sh ~/bin`). It downloads each release over HTTPS and verifies the checksums. `chainguard db update` takes a couple of minutes the first time. **Scans never update the databases**, so a scan today and a scan next week use the same data until you update on purpose.

`chainguard tools` should show every tool as `ok` once the databases are downloaded:

```
Tool    Installed   Pinned    Status    Vulnerability DB
syft    1.52.0      1.52.0    ok
cdxgen  12.8.5      12.8.5    ok
trivy   0.74.0      0.74.0    ok        2026-11-17T19:04:24Z · Java DB 2026-11-18T00:58:01Z
grype   0.119.0     0.119.0   ok        2026-11-17T06:20:58Z
EPSS    snapshot    -         ok        2026-11-17
KEV     snapshot    -         ok        2026.11.17
```

## Your first scan

The repository carries three small vulnerable projects under [`examples/`](../examples/README.md) (`java-app`, `python-app`, `node-app`). They pin vulnerable dependencies *on purpose*; scan them, never run them.

```bash
chainguard scan examples/java-app --gate
echo "exit code: $?"
```

It took 37 seconds on a 2-CPU machine. It prints a summary of each stage, then the verdict. The important lines of the real output:

```
Correlated: 83 pairs on installed software · consensus, generators × scanners (of 4): 4: 83
Enrichment: EPSS 2026-11-17 · KEV 2026.11.17 · 83 of 83 pairs scored · 3 in KEV
Priority: critical 3 · high 50 · medium 21 · low 9 · highest CVE-2021-44228 on
          maven/org.apache.logging.log4j/log4j-core@2.14.1 (95.0: epss 1 (+30), kev true (+25),
          cvss 10 (+20), fix true (+10), depth unknown (+5), consensus 4 of 4 (+5))

Gate: FAIL · 83 findings on installed software · 3 failing, 50 warning, 0 excepted
  FAIL  rule known-exploited: 3 finding(s): Listed in CISA KEV as exploited in the wild
        CVE-2021-44228 on maven/org.apache.logging.log4j/log4j-core@2.14.1 (score 95.0, critical; fixed in 2.12.2, 2.15.0, 2.3.1)
        CVE-2022-22965 on maven/org.springframework/spring-webmvc@5.3.17 (score 94.58, critical; fixed in 5.2.20.RELEASE, 5.3.18)
        CVE-2021-45046 on maven/org.apache.logging.log4j/log4j-core@2.14.1 (score 93.19, critical; fixed in 2.12.2, 2.16.0, 2.3.1)
  WARN  integrity unlocked_manifest: dependency manifests not locked (D5): pom.xml
  WARN  rule high-priority-fixable: 50 finding(s): Priority band high, and a fixed version exists
```

Read it from the bottom. The build **fails** because three findings are in KEV, and each one names the fixed version. Upgrading `log4j-core` to a release past those versions, and `spring-webmvc` to 5.3.18 or later, is what makes the build pass. The 50 warnings are high-priority findings with a fix, to schedule. The `unlocked_manifest` warning says Maven has no lockfile, so the dependency tree was resolved on the day of the scan.

The numbers will differ a little on your machine, because the databases move every day.

## Reading the result

Each scan writes a directory `chainguard-out/<run-id>/`:

| File | What it holds | Who reads it |
|---|---|---|
| `summary.md` | The whole run in prose and tables: components per generator, vulnerabilities per pipeline, the correlated findings, the ten highest-priority ones and why, the hand-off check, and how much the tools agreed | **You, first** |
| `verdict.json` | The gate's decision, every reason, the findings behind it and the exceptions applied | Scripts, audits |
| `report.md` | A short summary for a CI job page | Developers, in CI |
| `report.sarif` | The findings in the SARIF format, for GitHub code scanning | GitHub |
| `report.json` | The same, as plain JSON | Other tools |
| `findings.json` | Every finding: each scanner's claim (IDs, severity, CVSS, fix), consensus, EPSS, KEV, score, band and the points each factor gave | Analysis |
| `inventory.json` | The canonical components, and which generator found each | Analysis |
| `handoff.json` | Every (component, CVE) pair an SBOM pipeline lost against a direct scan, and why | Analysis |
| `fused.cdx.json`, `fused.spdx.json` | The merged SBOM the fused pipelines scanned. You can use it as the project's SBOM | You |
| `manifest.json` | Target, tool versions, database and snapshot dates, the build environment, and every command with its time and result | Reproducibility |
| `raw/` | Each tool's untouched output and log | Debugging |

Everything in `findings.json` is derived from `raw/`, so `chainguard reprocess <run-dir>` can re-derive it without running any tool again.

A finding is a **(component, CVE) pair**. Its **consensus** is how many of the four possible sources reported it: the generators that list the component times the scanners that report the vulnerability. A finding with consensus 4 is seen by both generators and both scanners. A finding that only one scanner reports is far more likely to be a false positive than one both report, so consensus is real evidence.

## The policy

The gate reads a YAML policy. The default is [`src/chainguard/policy.yaml`](../src/chainguard/policy.yaml). To use your own, copy it and pass it:

```bash
chainguard scan myproject --policy my-policy.yaml      # --policy implies --gate
chainguard gate chainguard-out/<run-id> --policy my-policy.yaml    # judge a finished run again
```

### Integrity checks

These decide whether the run can be trusted at all. Each is `fail`, `warn` or `ignore`.

| Check | Fires when | Default |
|---|---|---|
| `tool_failure` | A generator or scanner step failed | fail |
| `empty_sbom` | A generator succeeded but its SBOM lists no components | fail |
| `no_scan` | No SBOM pipeline's scan succeeded | fail |
| `not_prioritised` | The run has no priority scores | fail |
| `missing_snapshot` | No EPSS or no KEV snapshot was used, so those rules saw nothing | fail |
| `fused_loss` | The merged SBOM lost findings against a direct scan | warn |
| `unlocked_manifest` | A dependency manifest has no lockfile | warn |

The gate **fails closed**: if something went wrong, you get a FAIL, never a quiet pass.

### Rules

A rule has an `id`, a `description`, a `when` (all conditions must hold) and an `action` (`fail` or `warn`). A finding takes the most severe action of the rules it matches. The default rules:

```yaml
rules:
  - id: known-exploited
    when: {kev: true}
    action: fail
  - id: critical-priority
    when: {band: critical}
    action: fail
  - id: high-priority-fixable
    when: {band: high, fix_available: true}
    action: warn
```

The conditions you can use:

| Condition | Value | Holds when the finding… |
|---|---|---|
| `band` | `critical`, `high`, `medium`, `low` | is in this priority band |
| `score_min` | 0–100 | has at least this priority score |
| `kev` | `true` / `false` | is (not) in the CISA KEV catalogue |
| `epss_min` | 0–1 | has at least this EPSS score (probability of exploitation) |
| `epss_percentile_min` | 0–1 | has at least this EPSS percentile |
| `cvss_min` | 0–10 | has at least this CVSS score |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEGLIGIBLE` or `UNKNOWN` (one or a list) | has this highest scanner severity |
| `fix_available` | `true` / `false` | does (not) have a fixed version |
| `depth_max` | whole number ≥ 1 | is at most this deep in the dependency graph (1 = direct) |
| `consensus_min` | whole number | was reported by at least this many of the four sources |
| `vulnerability` | pattern | matches this CVE |
| `component` | pattern | matches this component key |
| `type` | e.g. `maven`, `deb` | is in this ecosystem |

A condition on a value that is not known (no EPSS score, no depth) does **not** hold, and the integrity checks catch missing data instead.

For example, to also warn on findings that are likely to be exploited and have a fix (on the Java fixture this matched 9 findings):

```yaml
  - id: likely-exploited-and-fixable
    description: An EPSS score of at least 0.5, and a fixed version exists
    when: {epss_min: 0.5, fix_available: true}
    action: warn
```

A typo in a condition, an action or a key is refused when the policy loads, so a mistake cannot silently switch a check off.

### Exceptions

An exception accepts a finding **until a date**, with a reason and an approver. We tested it on the Java example above:

```yaml
exceptions:
  - vulnerability: CVE-2021-44228
    component: maven/org.apache.logging.log4j/log4j-core@2.14.1   # optional; a pattern; leave out for every component
    reason: Lookups are disabled by configuration, see ticket SEC-123
    approved_by: security team
    expires: 2027-01-31
```

With three such exceptions, the same run went from **FAIL** to **WARN** (`3 excepted`). When evaluated on a date after they expire (`chainguard gate <run> --policy my-policy.yaml --on 2027-02-15`), it went back to **FAIL**, and the gate reported `exception expired … it no longer applies`. An exception with no expiry, or one expiring more than `max_exception_days` (default 90) after the evaluation date, makes the policy invalid.

## The priority score

Each finding gets a score from 0 to 100, a weighted mean of six factors, from [`src/chainguard/priority.yaml`](../src/chainguard/priority.yaml):

| Factor | Weight | Value, from 0 to 1 |
|---|---:|---|
| `epss` | 0.30 | The EPSS percentile |
| `kev` | 0.25 | 1 if in CISA KEV, else 0 |
| `cvss` | 0.20 | The highest CVSS score ÷ 10 |
| `fix` | 0.10 | 1 if a fixed version exists |
| `depth` | 0.10 | 1 ÷ the component's depth: 1 for a direct dependency, 0.5 at depth 2 |
| `consensus` | 0.05 | The share of the four sources that reported it |

Bands: **critical** from 80, **high** from 60, **medium** from 40, **low** below. Every finding records how many points each factor gave, so a score is always explained (see the `Priority:` line in the first-scan output).

To change the weights, copy the file and use `--priority-config my-priority.yaml` (or the Action's `priority-config` input). **Be careful**: the default weights were chosen by judgement, not fitted to data, and the finer ordering they give is not better than CVSS alone once known exploitation (KEV) is set aside. That is why the default policy acts on KEV and the critical band, not on fine differences in score. Check any change against your own review of the findings.

## In GitHub Actions

[`action.yml`](../action.yml) runs the whole pipeline in the fixed environment: it builds the image, downloads the databases and snapshots, scans, and lets the gate decide. The job fails when the gate fails. `report.md` goes to the job summary and `report.sarif` to code scanning.

```yaml
name: ChainGuard
on: [pull_request, push]
permissions:
  contents: read
  security-events: write          # for the SARIF upload
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: sreekarsarma55/_ChainGuard_@main
        with:
          path: app                        # a project directory, or an image archive
          policy: chainguard-policy.yaml   # optional
```

**Inputs:**

| Input | Meaning | Default |
|---|---|---|
| `path` | The project directory or image archive to scan (required) | |
| `policy` | Your policy YAML | the packaged one |
| `priority-config` | Your priority weights | the packaged one |
| `upload-sarif` | Send `report.sarif` to code scanning | `true` |
| `sarif-all` | Put every finding in the SARIF log, not only those the policy acts on | `false` |
| `category` | The code-scanning category, if one repository scans several targets | `chainguard/<path>` |
| `location` | The file results point at when the target has no manifest, e.g. an image's Dockerfile | |
| `out` | Where run directories go | `chainguard-out` |

**Outputs:** `decision` (PASS, WARN, FAIL, or ERROR if the run could not be judged), `exit-code`, `run-dir` and `sarif`.

Notes:
- **Code scanning** on a *private* repository needs GitHub Advanced Security. Set `upload-sarif: "false"` there. Public repositories can upload.
- **Pin the action** to a commit or tag in real use, not `@main`.
- **A scan of a small project takes tens of seconds** on a 2-CPU runner, plus a few minutes the first time to build the image and download the databases (the cache then serves them).

## Scanning container images

```bash
docker save -o image.tar python:3.12-slim
chainguard scan image.tar --gate
chainguard scan image:python:3.12-slim --gate        # the same, saving the image for you (needs docker or podman)
```

For an image, ChainGuard also scans it *directly* with each scanner and compares every SBOM pipeline with that scan, the **hand-off check** (`handoff.json`, and a line in `summary.md`). Use `--no-direct` to skip it, or `--direct` to run it for a project directory too.

An image has no `pom.xml` for results to point at, so pass `--location Dockerfile` (or the Action's `location` input) to attach code-scanning alerts to a file in your repository.

Operating-system findings are the noisiest. Distributions publish advisories per *source* package, so a finding can concern a binary package that does not contain the vulnerable code (headers, `-dev` and data packages). Expect many of them to be false positives, far more than for language packages. Read them accordingly.

## All commands

| Command | What it does |
|---|---|
| `chainguard scan <target>` | Run every generator and scanner, fuse, correlate, enrich, score. Add `--gate` to judge it |
| `chainguard gate <run-dir>` | Judge a finished run against a policy. Writes `verdict.json` and the reports |
| `chainguard report <run-dir>` | Write `report.sarif`, `report.json` and `report.md` again from a judged run (`--sarif-all` for every finding) |
| `chainguard reprocess <run-dir>…` | Re-derive the inventory, findings and summary from `raw/`. No tool runs. Use it after changing the alias or enrichment options |
| `chainguard tools` | Installed versus pinned tool versions, and database status |
| `chainguard db update` | Download fresh Trivy and Grype databases and the EPSS and KEV snapshots |
| `chainguard sbom normalize <file>` | Read any CycloneDX or SPDX 2.x JSON SBOM into canonical components |
| `chainguard sbom repair <file>` | Write each OS component's source package into every field scanners read |
| `chainguard sbom merge a.json b.json -o out.json` | Merge several SBOMs into one scanner-ready document |
| `chainguard version` | Print the version |

Useful options of `scan` (run `chainguard scan --help` for all):

| Option | Meaning |
|---|---|
| `--out DIR` | Where run directories go (default `chainguard-out`) |
| `--generators syft,cdxgen` / `--scanners trivy,grype` | Choose which tools run |
| `--sbom-format cyclonedx\|spdx` | The format requested from the generators |
| `--no-fuse` | Skip the merged SBOM and its scans |
| `--cdxgen-type java\|python\|js…` | Force cdxgen's project type |
| `--offline` | Never query OSV.dev; use only the cache, and count the IDs it lacks |
| `--epss DATE` / `--kev VERSION` | Use a specific stored snapshot instead of the newest |
| `--no-enrichment` | Skip EPSS, KEV and the other enrichment |
| `--strict-pins` | Fail if a tool's version differs from the pin |
| `--timeout SECONDS` | Per tool call (default 1800) |
| `--priority-config`, `--policy`, `--on DATE` | Your own weights, your own policy, and the date exceptions are judged on |
| `--no-reports`, `--sarif PATH`, `--sarif-all`, `--job-summary` | Control the reports |

## Keeping runs reproducible

- **Tool versions are pinned** in [`src/chainguard/toolchain.env`](../src/chainguard/toolchain.env). Change one at a time. `--strict-pins` fails a scan when the installed version differs.
- **Databases and snapshots are explicit.** `db update` is the only thing that downloads them. Each snapshot is stored under its own date and never overwritten, and every run's `manifest.json` records which it used.
- **The build environment matters.** The SBOM generators' output depends on which Python, Java and Maven are on the `PATH`. `manifest.json` records them. For comparable results, use the Docker image.
- **Caches.** OSV lookups and snapshots live in `$CHAINGUARD_CACHE`, or `~/.cache/chainguard` if it is not set.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `chainguard: command not found` | The virtual environment is not active. Run `. .venv/bin/activate`, or use `python3 -m chainguard` in place of `chainguard` |
| `install-tools.sh` fails at cdxgen with `ENOENT … node_modules/@cyclonedx` | npm's global folder does not exist or is not writable. Give npm a prefix you own: `export NPM_CONFIG_PREFIX=$HOME/.npm-global; export PATH=$NPM_CONFIG_PREFIX/bin:$PATH`, then run the script again |
| `chainguard tools` says `database missing` | Run `chainguard db update` |
| The gate says FAIL with `missing_snapshot` | No EPSS or KEV snapshot was found. Run `chainguard db update`, or check `$CHAINGUARD_CACHE` is the same for the update and the scan |
| The gate says FAIL with `tool_failure` | A generator or scanner failed. Read its log in `<run>/raw/` and the `manifest.json` entry for the step |
| A Python project's component list looks short | cdxgen needs a Python on the `PATH` to resolve transitive dependencies. If only `python3` exists, ChainGuard passes it and notes this in the report |
| Java scan is slow the first time | Maven downloads the dependency tree. Later scans reuse the cache |
| Results differ from yesterday's | The vulnerability databases changed. Run `chainguard tools` to see their dates |
| `permission denied` in Docker | Use the same `--user "$(id -u):$(id -g)"` for every command that shares a cache volume |
| SARIF upload fails on a private repository | Code scanning there needs GitHub Advanced Security. Set `upload-sarif: "false"` |

## What ChainGuard does not do

ChainGuard is pre-1.0. Know its limits:

- **It does not say whether a vulnerability is *reachable* in your code.** Many operating-system findings concern packages that do not contain the vulnerable code.
- **Its ranking beyond known exploitation is a heuristic.** Trust the KEV rule; treat the finer score order as a hint.
- **It knows only what the tools and databases know.** A vulnerability that no advisory database lists is invisible to it.
- **It does not cover every ecosystem.** It has been tried on Java, Python, JavaScript and Debian, Ubuntu and Alpine images, not on C/C++, Go or .NET.
- **Unlocked projects change between scans.** Without a lockfile, the dependency tree is resolved on the day of the scan. The gate warns about it.
- **The projects under `examples/` are deliberately vulnerable and must never be deployed.**
