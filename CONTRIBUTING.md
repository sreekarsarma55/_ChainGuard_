# Contributing to ChainGuard

Thanks for helping. Bug reports, fixes, new checks and documentation fixes are all welcome.

## Set up

You need Python 3.11+. To scan anything, you also need the pinned tools (see the [user guide](docs/USER_GUIDE.md#install)); to run the tests you do not.

```bash
git clone https://github.com/sreekarsarma55/_ChainGuard_.git
cd _ChainGuard_
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
scripts/run-checks.sh          # lint, format check and every test, in about 15 seconds
```

`scripts/run-checks.sh` runs what CI's lint and test jobs run. Two further CI jobs need Docker: a smoke scan of the [examples](examples/README.md) in the container, and the GitHub Action itself.

## Tests

Most tests are small programs under `tests/checks/` that build synthetic SBOMs, scans and runs, and exit 1 with the failing cases printed. `pytest` runs each as one test. They need no scanner and no network, except `check_aliases.py`, which asks OSV.dev for a few advisories (`pytest --offline` skips it).

- A bug fix should come with a case that fails without it. Add it to the check for the module you changed, or add a new `tests/checks/check_<topic>.py`.
- Keep cases small and named for what they protect. Synthetic data shaped like a real image is better than a real image.

## Style

- `ruff check` and `ruff format` (line length 120) must pass. `scripts/run-checks.sh` runs both.
- Comments explain *why*, and say which tool behaviour a rule works around. Keep the design rules in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) up to date when you add or change one.
- The tool pins live in one file, `src/chainguard/toolchain.env`. Change one tool per pull request, and say what you ran before and after.

## Sending a change

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Branch from `main`, keep the change focused, and open a pull request describing what changed and how you tested it.
3. CI must pass. A maintainer will review it.

## Releasing (maintainers)

Update `CHANGELOG.md` and the version in `pyproject.toml`, merge, then tag: `git tag v0.2.0 && git push origin v0.2.0`.

## Conduct

Be kind and assume good faith. Harassment and abuse are not tolerated, and maintainers may remove content and contributors that break this.
