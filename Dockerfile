# syntax=docker/dockerfile:1
#
# ChainGuard's fixed build environment (design rule D8): the pinned toolchain, plus the
# interpreters and build tools the SBOM generators shell out to, at known versions.
#
#   docker build -t chainguard .
#   docker run --rm --user "$(id -u):$(id -g)" -v chainguard-cache:/cache chainguard db update
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -v chainguard-cache:/cache \
#       chainguard scan path/to/project
#
# - Vulnerability databases, plus pip, npm and Maven caches, live in /cache. Mount a volume
#   there so databases are not downloaded on every run.
# - /work is the working directory; mount the project there. Results go to /work/chainguard-out.
# - Image targets: run `docker save -o image.tar <ref>` on the host and scan the .tar.
#   The image contains no Docker CLI.
# - Base images are pinned by digest. Bump them deliberately, like the tool pins in
#   src/chainguard/toolchain.env, and run the tests and a scan of the examples afterwards.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

FROM ${NODE_IMAGE} AS node

FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="ChainGuard" \
      org.opencontainers.image.description="Fused SBOM generation and vulnerability scanning for CI/CD (Syft, cdxgen, Trivy, Grype)" \
      org.opencontainers.image.source="https://github.com/sreekarsarma55/_ChainGuard_"

# Node.js for cdxgen, from the official image. Both images use Debian bookworm, so glibc matches.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# JDK and Maven for Java projects, git for target provenance, curl for the tool installer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git maven openjdk-17-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

# The pinned scanners and generators, installed by the same script developers use.
COPY src/chainguard/toolchain.env /opt/chainguard/src/chainguard/toolchain.env
COPY scripts/install-tools.sh /opt/chainguard/scripts/install-tools.sh
RUN /opt/chainguard/scripts/install-tools.sh /usr/local/bin \
 && npm cache clean --force

COPY pyproject.toml README.md LICENSE /opt/chainguard/
COPY src /opt/chainguard/src
RUN pip install --no-cache-dir /opt/chainguard

# Runs as the non-root user "chainguard" by default. /cache and HOME are writable by any user,
# so `--user "$(id -u):$(id -g)"` also works and keeps files in mounted directories owned by you.
# With such a --user there is no passwd entry, and Java's user.home becomes "?": Gradle would then put its
# cache under ./?/.gradle inside the scanned project, and cdxgen list Gradle's own plugins as the project's
# dependencies (313 components instead of 66 on java-log4shell-app). GRADLE_USER_HOME keeps it in /cache.
RUN useradd --create-home --uid 1000 --shell /bin/bash chainguard \
 && mkdir -p /cache /work \
 && chmod 1777 /cache /home/chainguard \
 && chown chainguard:chainguard /work \
 && git config --system --add safe.directory '*'

ENV HOME=/home/chainguard \
    XDG_CACHE_HOME=/cache \
    NPM_CONFIG_CACHE=/cache/npm \
    PIP_CACHE_DIR=/cache/pip \
    MAVEN_OPTS=-Dmaven.repo.local=/cache/m2 \
    GRADLE_USER_HOME=/cache/gradle \
    PYTHONDONTWRITEBYTECODE=1

USER chainguard
WORKDIR /work
ENTRYPOINT ["chainguard"]
CMD ["--help"]
