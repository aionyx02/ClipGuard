# Linux container for the red-team syntax validators (phase-5.md §5.3.5,
# §5.10; docs/spikes/s8-syntax-validation.md §5).
#
# Build (context = redteam/):
#   docker build -f redteam/validate.Dockerfile -t pw-validate redteam
# Run the validator tests locked down (this is the sandbox on Linux CI):
#   docker run --rm --network none --read-only --tmpfs /tmp \
#     --pids-limit 64 --memory 512m --cap-drop ALL \
#     --security-opt no-new-privileges --user 10001:10001 pw-validate
#
# redteam/validate/sandbox.py only trusts PASTEWARDEN_SANDBOX=container after
# verifying it: non-root, only `lo` in /sys/class/net, read-only root fs.
# Network is needed at build time only (apt, pwsh tarball, uv sync).

FROM ubuntu:24.04

ARG TARGETARCH
ARG PWSH_VERSION=7.7.0
# sha256 of the official release tarballs (pinned 2026-11-25).
ARG PWSH_SHA256_AMD64=c89d9c682d2c403dfe726f3df948e359675235a5bd6fab535776de69729ca0cb
ARG PWSH_SHA256_ARM64=e59c89776eaa59790d44b3edd14277435225ab08b6e7603763101b89de83d935

# bash 5.2, zsh 5.9, dash (/bin/sh), Python 3.12.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash zsh dash python3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x64; sum="$PWSH_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$PWSH_SHA256_ARM64" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${arch}.tar.gz"; \
    curl -fsSL -o /tmp/pwsh.tgz "$url"; \
    echo "$sum  /tmp/pwsh.tgz" | sha256sum -c -; \
    mkdir -p /opt/microsoft/powershell/7; \
    tar -xzf /tmp/pwsh.tgz -C /opt/microsoft/powershell/7; \
    chmod 0755 /opt/microsoft/powershell/7/pwsh; \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh; \
    rm /tmp/pwsh.tgz

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON=/usr/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1

WORKDIR /src/redteam
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
COPY src ./src
COPY tests ./tests
RUN uv sync --frozen \
 && find /src /opt/venv -name __pycache__ -prune -exec rm -rf {} +

RUN groupadd -g 10001 pw && useradd -u 10001 -g 10001 -M -d /tmp -s /usr/sbin/nologin pw

ENV PASTEWARDEN_SANDBOX=container \
    PASTEWARDEN_REQUIRE_VALIDATORS=bash,sh,zsh,powershell \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

USER 10001:10001
CMD ["/opt/venv/bin/python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/validate"]
