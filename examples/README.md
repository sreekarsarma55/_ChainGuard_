# Examples

Three tiny projects to try ChainGuard on. Each pins **known-vulnerable dependencies on purpose**.

| Directory | Ecosystem | What it contains |
|---|---|---|
| [`java-app`](java-app/) | Maven | log4j-core 2.14.1 (Log4Shell), commons-text 1.9 (Text4Shell), spring-webmvc 5.3.17 (Spring4Shell), and old jackson-databind, snakeyaml and commons-collections |
| [`python-app`](python-app/) | pip | Django, Flask, requests and others at old, vulnerable versions, with a `Dockerfile` that installs them in a container |
| [`node-app`](node-app/) | npm | Old axios, express, jsonwebtoken, lodash and other packages, with a lockfile |

```bash
chainguard scan examples/java-app --gate      # FAIL: known-exploited vulnerabilities
chainguard scan examples/node-app --gate      # WARN
chainguard scan examples/python-app --gate    # WARN
```

**Scan them, never run or deploy them.** GitHub may show Dependabot alerts for these directories. They are expected: dismiss them as test fixtures. CI uses these projects as a smoke test of the whole pipeline.
