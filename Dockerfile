# Dockerfile — LiteLLM + littlessollm (MIT-only OIDC SSO + API-JWT auth)
#
# Base image already ships litellm itself; we only add our own auth modules
# on top, installed as the `littlessollm` package. Build context = repo root
# (see repo_scripts/build-container-multiarch.sh).
#
# LITELLM_VERSION pins the upstream image. litellm publishes both a floating
# `main-latest` tag and version-pinned `main-vX.Y.Z(-stable)` tags; litellm's
# own docs recommend pinning a version (or digest) over `:latest` for
# reproducible builds/rollbacks: https://docs.litellm.ai/docs/proxy/deploy
#
# The default below is ONLY a fallback for a bare `docker build .` run
# without our tooling (kept roughly current, but not authoritative).
# repo_scripts/build-container-multiarch.sh is the actual source of truth:
# it curls ghcr.io live for the newest "-stable" tag at build time and passes
# it in via --build-arg (or honors an explicit LITELLM_VERSION env override
# for a fully reproducible/pinned build) — it never reads this line back, so
# there's a one-way flow (script decides -> Dockerfile receives), not the
# other way round. It also tags our own image to match (plus a floating
# :latest alias) — see that script for details.
ARG LITELLM_VERSION=main-v1.83.14-stable
FROM ghcr.io/berriai/litellm-database:${LITELLM_VERSION}

# Re-declare after FROM (ARG scope resets per build stage) so the value
# survives into ENV below — exposed at runtime for introspection
# (`docker exec <container> env | grep LITELLM_VERSION`).
ARG LITELLM_VERSION
ENV LITELLM_VERSION=${LITELLM_VERSION}

WORKDIR /app

# tini: PID 1 init — correct SIGTERM/SIGINT forwarding + zombie reaping in
# containers (Linux gives PID 1 special signal-disposition treatment that
# plain uvicorn doesn't handle correctly on its own). The base image is
# Chainguard Wolfi (apk, not apt/deb) and ships a `tini` package directly, so
# no need to fetch a static binary from GitHub.
RUN apk add --no-cache tini

COPY pyproject.toml README_pypi.md LICENSE.md ./
COPY littlessollm ./littlessollm

# The base image's /app/.venv is uv-managed and ships NO pip at all, and it's
# built with `include-system-site-packages = false` -- so `apk add py3-pip`
# does NOT help here: that installs pip for the system interpreter
# (/usr/bin/python3), invisible to this isolated venv. `python3` on PATH
# already resolves to /app/.venv/bin/python3, so `python3 -m ensurepip`
# (stdlib, no extra package needed) bootstraps pip directly into the venv
# itself, matching the *exact* Python it will run under.
#
# redis extra: only needed if REDIS_URL points at a real cache backend;
# harmless to always install — the in-memory cache is used when unset.
RUN python3 -m ensurepip --upgrade \
 && python3 -m pip install --no-cache-dir ".[redis]"

# Purely informational build provenance, exposed via ENV for runtime
# introspection, same as LITELLM_VERSION above. Nothing at runtime may
# *depend* on these. GH_REF/GH_SHA are only set by the CI workflow; BUILDTIME
# also by build-container-multiarch.sh (computed once per run, so all
# platform images of one build carry the identical value). The sentinel
# defaults cover local/bare builds where a value isn't passed.
# Deliberately declared+consumed LAST: the values change on every build
# (BUILDTIME) resp. every commit (GH_SHA), so consuming them any earlier
# would invalidate the layer cache from that point on — including the
# expensive pip-install layer.
ARG GH_REF=gh_ref_is_undefined
ENV GITHUB_REF=${GH_REF}
ARG GH_SHA=gh_sha_is_undefined
ENV GITHUB_SHA=${GH_SHA}
ARG BUILDTIME=buildtime_is_undefined
ENV BUILDTIME=${BUILDTIME}

# tini -g (process-group signaling): littlessollm-entrypoint runs uvicorn as
# a *subprocess* (not via exec — tini itself now owns the PID-1/zombie-reaping
# job), so plain tini — which by default only signals its direct child —
# would miss uvicorn without -g.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "littlessollm-entrypoint"]
CMD ["uvicorn", "littlessollm.asgi:app", "--host", "0.0.0.0", "--port", "4000"]
