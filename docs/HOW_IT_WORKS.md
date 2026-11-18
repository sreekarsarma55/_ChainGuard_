# How ChainGuard works

This page follows one scan from start to finish: what each stage does and why it exists. To *use* ChainGuard, read the [user guide](USER_GUIDE.md). The design rules (D1–D11) and the code layout are in [`ARCHITECTURE.md`](ARCHITECTURE.md).

```
target ──► 1 generate SBOMs ──► 2 scan each SBOM ──► 3 normalise ──► 4 fuse ──► 5 scan the fused SBOM
(directory, (Syft, cdxgen)      (Trivy, Grype)       (one model)     (one SBOM)
 image)                                                                              │
         ┌───────────────────────────────────────────────────────────────────────────┘
         ▼
   6 resolve aliases ──► 7 correlate ──► 8 enrich ──► 9 prioritise ──► 10 gate ──► 11 reports
   (GHSA → CVE)          (one finding    (EPSS, KEV,   (score 0–100)    PASS/WARN/   SARIF, JSON,
                          per component   CVSS, fix,                    FAIL         job summary
                          + CVE)          depth)
```

## The problem

A CI pipeline checks its dependencies in two steps. A *generator* writes a Software Bill of Materials (SBOM), a list of the components in the build. A *scanner* reads the SBOM and reports the known vulnerabilities. Usually one tool does each step, and the tools disagree, for three reasons:

- **Information gets lost between the steps.** Linux distributions publish advisories against the *source* package, while an SBOM lists the *binary* packages, and each generator records the link in a different field. A scanner that cannot see it misses most operating-system findings. The same scanner can find far fewer vulnerabilities in an SBOM of an image than when it scans the image directly.
- **Names differ.** One vulnerability is a CVE to one scanner and a GitHub advisory to another. One package is `3.2` in one tool and `3.2.0` in another. Counting them naively double-counts, or hides real agreement.
- **Each tool sees something different.** One generator resolves the full dependency tree and the other does not. One lists files as if they were packages.

ChainGuard runs several tools, repairs what is lost between them, and does not trust any single one.

## The stages

**1. Generate SBOMs.** Syft and cdxgen each write one for the target: a project directory, an image archive, or `image:<ref>`. Before they run, ChainGuard looks for dependency lockfiles. Without one, the dependency tree is resolved on the day of the scan, and only some generators resolve it, so the result can change from scan to scan. The gate warns about it (D5).

**2. Scan each SBOM.** Trivy and Grype each scan every SBOM, which makes four *pipelines*: Syft+Trivy, Syft+Grype, cdxgen+Trivy and cdxgen+Grype. For an image, each scanner also scans the image directly. That scan is the reference for the hand-off check in stage 7.

**3. Normalise.** Every component becomes one canonical record keyed by its Package URL (PURL), so the same component from two tools is one component:
- *Source packages* (D2). ChainGuard reads the source package from every place the four tools record it, and writes it back into every field the scanners read.
- *Versions* (D4). PEP 440, Debian epochs and Maven versions are compared by their own ecosystem's rules, so Django `3.2` and `3.2.0` are one component.
- *What is not software* (D9). Generators list files and package-repository entries as if they were components. ChainGuard leaves them out of the inventory and counts them.
- *Maven groups* (D11). A jar that two generators list under different groups is one component, keyed on the group with the best evidence, such as a SHA-1 lookup in Maven Central.

**4. Fuse.** The normalised inventory is written as one merged SBOM, in CycloneDX and SPDX, with every field a scanner reads, including an operating-system component (D3, D7). Without that component, Trivy cannot choose a vulnerability source for operating-system packages at all.

**5. Scan the fused SBOM.** Both scanners scan the merged SBOM. These are the *fused* pipelines, the ones the policy judges. `--no-fuse` turns stages 4 and 5 off.

**6. Resolve aliases (D1).** Every vulnerability ID is resolved to canonical CVEs through OSV.dev, with an on-disk cache so repeated runs work offline. This is what lets two scanners be compared, and one finding be counted once.

**7. Hand-off check and correlation.**
- *Hand-off check.* Each SBOM pipeline is compared with the same scanner's direct scan, pair by pair, and every lost finding is classed (misattributed, hand-off, other version, not listed). A merged SBOM that loses findings makes the gate warn.
- *Correlation* (D10). Findings are keyed on (canonical component, canonical CVE). **Consensus** counts evidence: the generators that list the component times the scanners that report the vulnerability, out of four. Counting pipelines instead would measure their hand-off failures as well, and make a well-supported finding look weak because one pipeline lost it.

**8. Enrich.** Each finding gets:
- the **EPSS** score (the probability of exploitation, from FIRST) and whether it is in the **CISA KEV** catalogue (known exploited), both from *dated snapshots* that `chainguard db update` stores and never overwrites, so a run says exactly which it used;
- the highest **CVSS** score;
- whether a **fix** exists;
- the component's **depth** in the dependency graph (1 for a direct dependency).

Grype ships EPSS and KEV values of its own. They are compared with the snapshots, never used.

**9. Prioritise.** Each finding gets a score from 0 to 100, a weighted mean of EPSS, KEV, CVSS, fix, depth and consensus. The weights are in [`priority.yaml`](../src/chainguard/priority.yaml), and every finding records how many points each factor gave. Known exploitation is the strongest signal; beyond it, the order is a heuristic.

**10. Gate.** The policy ([`policy.yaml`](../src/chainguard/policy.yaml)) turns the run into PASS, WARN or FAIL, with reasons:
- *Integrity checks* decide whether the run can be trusted at all. The gate **fails closed**: a tool that failed, an empty SBOM, a run with no scan, or no EPSS or KEV data is a FAIL.
- *Rules* act on each finding. By default anything in KEV, or in the critical band, fails the build.
- *Exceptions* accept a finding until a date, with a reason and an approver. One with no expiry, or an expiry too far away, is refused, and an expired one stops applying.

**11. Reports.** The gate writes `report.sarif` for GitHub code scanning (each alert at the line that declares the package), `report.json` for other tools, and `report.md`, a short summary for the CI run page.

## Where each stage lives

See the table of modules in [`ARCHITECTURE.md`](ARCHITECTURE.md#code-layout).
