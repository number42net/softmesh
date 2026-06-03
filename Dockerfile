# syntax=docker/dockerfile:1.7
#
# Generic image for any deployable service in this uv workspace. The service to
# build is selected with `--build-arg SERVICE=<name>`, where <name> is the
# package/project name (which equals its console-script name), e.g.
# mesh-gateway, room-server, home-auto-client, observer.
#
# Built and pushed via ./build.sh (linux/amd64 -> private-repo.n-42.com).

ARG PYTHON_VERSION=3.12

# ---- builder: resolve + install only the selected service into a venv --------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# uv provides fast, lockfile-faithful installs. Pinned-ish via the uv image tag.
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /uvx /bin/

ARG SERVICE
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Workspace metadata + all member manifests/sources. uv needs the whole
# workspace present to resolve the path-based member dependencies.
COPY pyproject.toml uv.lock ./
COPY packages ./packages

# Install just the chosen service and its dependency closure (no dev tools),
# as a self-contained venv (members built as wheels, so no source needed at
# runtime). --frozen fails loudly if uv.lock is out of date.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package "${SERVICE}"

# ---- runtime: minimal image with just the venv -------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG SERVICE
LABEL org.opencontainers.image.title="softmesh-${SERVICE}" \
      org.opencontainers.image.source="https://github.com/number42net/softmesh"

# Identical base as the builder, so the venv's interpreter path stays valid.
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    APP_CMD="${SERVICE}"

# Run as an unprivileged user. The gateway needs access to the USB serial
# device at runtime (mount it and grant the user the right group/permissions,
# or override the user in the deployment).
RUN useradd --create-home --uid 10001 app
USER app
WORKDIR /home/app

# Exec the service's console script and forward any container args (flags) to
# it, e.g. `docker run <img> --region NL --tx-power 22`.
ENTRYPOINT ["/bin/sh", "-c", "exec \"$APP_CMD\" \"$@\"", "--"]
