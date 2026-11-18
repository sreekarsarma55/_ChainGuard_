# Security policy

## Reporting a vulnerability in ChainGuard

Please **do not open a public issue** for a security problem in ChainGuard itself.

Use GitHub's private reporting: open the **Security** tab of this repository, choose **Report a vulnerability**, and describe the problem, how to reproduce it, and what you think the impact is. We will acknowledge the report, work on a fix, and credit you in the release notes unless you prefer not to be named.

## What is in scope

- ChainGuard's code, the GitHub Action (`action.yml`) and the Docker image built from the `Dockerfile`.
- Ways to make the gate **pass a build it should fail**, for example by crafting a project or SBOM that hides a finding or crashes a tool without the gate noticing. The gate is meant to fail closed, so these are the bugs we most want to hear about.

## What is out of scope

- Vulnerabilities in Syft, cdxgen, Trivy, Grype or the vulnerability data ChainGuard downloads. Report those to their own projects.
- The projects under [`examples/`](examples/README.md). They contain known-vulnerable dependencies **on purpose**, as test targets. GitHub may raise Dependabot alerts for them; those are expected and are not vulnerabilities in ChainGuard.

## Supported versions

Only the latest release and `main` receive fixes while ChainGuard is pre-1.0.
