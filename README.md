# littlessollm — a little SSO (+ API auth) for LiteLLM

WIP - not tested at all yet.

Minimal, **MIT-only**, config-driven OIDC UI-SSO + API-JWT auth add-on for
[LiteLLM](https://github.com/BerriAI/litellm). Replaces enterprise SSO and
enterprise JWT auth with your own code — no `litellm_enterprise` import, no
license check bypassed.

> Status: **alpha** — the auth modules (UI-SSO, API-JWT→virtual-key
> middleware, secrets loader, entrypoint wrapper) are implemented and
> unit-tested; wiring against a real IdP/litellm deployment is the next
> step.

## Two gates we do NOT trigger

- **UI-SSO** (litellm's `ui_sso.py`): only fires when
  `MICROSOFT_/GOOGLE_/GENERIC_CLIENT_ID` is set → don't set any of them.
- **API-JWT** (litellm's `user_api_key_auth.py`): `enable_jwt_auth: true`
  raises without a license → leave it `false`.

Both safeguards instead run entirely through `littlessollm`, on top of
litellm's MIT core.

## What's in here

| Part | Path | What it is |
|---|---|---|
| **Auth package** | `littlessollm/` | `config.py` (YAML loader + secrets), `sso.py` (UI login router), `auth.py` (API-auth middleware), `asgi.py` (no-fork wiring into the real LiteLLM app), `entrypoint.py` (secrets-from-file wrapper). |
| **Deploy examples** | `k8s-deploy/` | `idp-mapping.example.yaml` (ConfigMap content), `k8s-idp-auth.yaml` (ConfigMap + Secret + Deployment). |
| **Container** | `Dockerfile` | Base = `ghcr.io/berriai/litellm-database`, `littlessollm` installed on top. |
| **Container & CI toolkit** | `repo_scripts/` | Multi-arch (amd64+arm64) image build to ghcr.io + one-time GitHub bootstrap. |
| **`blurimage.py`** | `repo_scripts/` | Standalone OCR redaction tool (unrelated to the auth add-on, carried along from the repo toolkit). |

## Config vs. secrets (separated, secrets as files)

- **ConfigMap (not secret):** `idp-mapping.yaml` — endpoints, `client_id`,
  group→team/role/model mapping, limits, `public_prefixes`.
- **Secrets (secret) as FILES, not env:** `OIDC_CLIENT_SECRET`, `REDIS_URL`.
  Optionally more. Env remains the fallback.

Why files instead of env: env vars are inherited by child processes and
routinely end up in `os.environ` dumps/crash reporters. A file with
owner/group + chmod restricts who can read it and doesn't show up in such
dumps. (No protection against root or processes running as the same UID —
but it strongly reduces accidental exposure.)

Resolution in `littlessollm.config.secret(NAME)` (first match wins):

1. `<NAME>_FILE` → path to a file holding exactly this one secret
   (Docker/k8s convention, e.g. `/run/secrets/OIDC_CLIENT_SECRET`)
2. `IDP_SECRETS_FILE` → a single YAML `{ NAME: value, ... }` for several
3. Environment variable `<NAME>` → fallback

k8s footgun (solved in the manifest): secret volume files are `root:root`.
With `mode 0400` the non-root app CANNOT read them. Correct:
`defaultMode: 0440` + pod `securityContext` with
`runAsUser/runAsGroup/fsGroup`, so the app reads via the group.

Docker Compose equivalent: `secrets:` mounts to `/run/secrets/<name>`; then
set `OIDC_CLIENT_SECRET_FILE=/run/secrets/OIDC_CLIENT_SECRET`.

Note: `LITELLM_MASTER_KEY` and `DATABASE_URL` are read by litellm **itself**
(not our modules) → they follow litellm's own mechanism (env, or
`os.environ/...` in `general_settings`, or litellm's own secret manager).
The `*_FILE` path via `littlessollm.config.secret()` only covers the
secrets our modules read — that's what `littlessollm-entrypoint` is for
(see below).

`IDP_MAPPING_CONFIG` and `IDP_SECRETS_FILE` are re-read on mtime change →
ConfigMap/Secret updates take effect without a pod restart.

## Start

```bash
export IDP_MAPPING_CONFIG=/etc/litellm/idp-mapping.yaml
export LITELLM_CONFIG=/app/config.yaml
# Secrets via env/secret: OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, REDIS_URL, LITELLM_MASTER_KEY

# via wrapper (recommended; loads *_FILE secrets, then runs uvicorn):
littlessollm-entrypoint uvicorn littlessollm.asgi:app --host 0.0.0.0 --port 4000
```

## litellm's own secrets from files (entrypoint wrapper)

`LITELLM_MASTER_KEY`, `DATABASE_URL`, `LITELLM_SALT_KEY` are read by
**litellm itself from the env** — `littlessollm.config.secret()` doesn't
cover those. `littlessollm-entrypoint` solves this: it materializes
file-backed secrets into the child process's env just before start (as a
subprocess — no more `exec`, see below) and forwards its exit code.

Precedence (highest first):

1. `<NAME>_FILE` → single file (wins) — **only for known names** from
   `SECRET_BASE_NAMES` (default: `LITELLM_MASTER_KEY`, `DATABASE_URL`,
   `LITELLM_SALT_KEY`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `REDIS_URL`;
   extensible via a comma-separated env var, no code change needed).
   Deliberately not an allowlist-free scan over every env var: base images
   often set their own `*_FILE` vars for other purposes (e.g.
   `SSL_CERT_FILE` for a CA bundle) — a blind scan would have
   misinterpreted that as a secret, written the (often large) file content
   into the env, and crashed the child process with
   `Argument list too long` (ARG_MAX).
2. `IDP_SECRETS_FILE` → aggregated YAML (overrides env when
   `SECRETS_FILE_OVERRIDE_ENV=true`, the default)
3. existing env → **fallback/default** (untouched if no file is present)

Without a file, everything stays at its default. With
`REQUIRE_SECRETS=A,B`, startup fails hard if A/B can't be resolved from
either a file or the env.

PID-1/signal handling in the container is now owned by `tini -g` (see the
Dockerfile), not the wrapper itself — it starts the target command as a
regular subprocess instead of replacing itself via `execvp`.

Honest limitation: secrets read from a file end up in the litellm
process's env regardless — the wrapper keeps them *at rest* as a
restrictively chmod'd file (tmpfs), keeps them out of the k8s object
spec/`describe`, and makes rotation possible. It does NOT remove them from
the running litellm process's `os.environ`. If you need that too, render
the values into a `config.yaml` on tmpfs and point litellm there instead —
or use litellm's own secret-manager integration (Vault/AWS/GCP).

Docker/Compose: mount secrets to `/run/secrets/<name>`, then set
`LITELLM_MASTER_KEY_FILE=/run/secrets/LITELLM_MASTER_KEY` etc.

## YAML schema (short form)

```
oidc: {discovery_url, issuer, jwks_url, audience, algorithms, scope,
       group_claim, sub_claim, redirect_uri, client_id?, allowed_email_domain?}
ui_sso: {role_map: {role: [groups...]}, default_role}
api_auth:
  default_team_id, default_role
  team_map:       {team_id: [groups...]}
  models_by_team: {team_id: [models...]}      # empty = all
  limits_by_team: {team_id: {tpm_limit,rpm_limit,max_budget,budget_duration}}
  cache:          {skew_seconds, key_grace_seconds, min_key_seconds}
  public_prefixes: [...]
```

Full example: [`k8s-deploy/idp-mapping.example.yaml`](k8s-deploy/idp-mapping.example.yaml).

## Request flow (API)

`Authorization: Bearer <IdP-JWT>` to `/v1/*`:

1. `sk-...` / no token → passed through unchanged to LiteLLM.
2. JWT → verify signature (JWKS), `iss`/`aud`/`exp`.
3. Claims → team/models/role/limits (from YAML).
4. Get-or-create virtual key (`generate_key_helper_fn`), cached per `sub`.
5. Header → `Bearer sk-...`, LiteLLM handles spend/team/limits.

## Key lifecycle

Cache TTL = token_remaining - skew ; key duration = token_remaining +
grace. The key expires shortly after the token; a new or expired token
forces a fresh mint.

## Version fragility (MIT APIs, but verify after upgrades)

`ReturnedUITokenObject` + HS256/master_key cookie; `generate_key_helper_fn`
signature; `fastapi_sso.sso.generic.create_provider`. All three are
currently mirrored exactly, but they're internal MIT APIs without a
stability guarantee — double-check after litellm/fastapi-sso upgrades.

## Security

JWT validation is auth-critical → PyJWT + PyJWKClient, no custom crypto.
Alternatively, offload validation to the edge (Envoy/APISIX/Authelia) and
keep only the identity→key mapping in the middleware.

## Quickstart (dev)

The dev setup uses Python 3.14 (see `Makefile`). The package itself
declares `requires-python = ">=3.13"` — deliberately lower than the dev
standard: the actual target environment is
`ghcr.io/berriai/litellm-database`, which ships (verified) Python 3.13.13,
not 3.14. `pip install` would otherwise fail there on the
`Requires-Python` check.

```bash
make install                       # venv + deps (incl. dev + redis extra)
make tests                         # pytest
make lint                          # ruff format --check + ruff check
make tcheck                        # mypy --strict
make prepare                       # tests + commit-checks (incl. gitleaks)
```

## Container image

Base: `ghcr.io/berriai/litellm-database` (Chainguard/Wolfi, `apk`+`uv`
venv, no Debian/apt). Deliberately not rebuilt on a standard Python image:
**all** official litellm images (including the non-DB variant) run on
Wolfi, and the "-database" variant additionally bundles a ready-made
Prisma client generation + Node-built admin UI — rebuilding that ourselves
would duplicate exactly the litellm-internal build pipeline this project
is designed not to fork. `LITELLM_VERSION` is instead determined **live**:
`repo_scripts/build-container-multiarch.sh` `curl`s the ghcr.io tag index
at build time for the current newest `main-vX.Y.Z-stable` tag (litellm's
own recommendation — not `:latest`, see the
[litellm docs](https://docs.litellm.ai/docs/proxy/deploy)) and passes it
in via `--build-arg`; the `ARG LITELLM_VERSION=...` in the Dockerfile is
only an offline fallback for a bare `docker build .` without this script.
Override for a reproducible pin:
`LITELLM_VERSION=main-vX.Y.Z-stable make container`.

Multi-arch image (amd64 + arm64, arm64 built natively on a remote Podman
host), pushed to **`ghcr.io/vroomfondel/littlessollm`** (tag =
`litellm-<version>` + a `:latest` alias):

```bash
make container-local     # local arch only, no push
make container           # full multi-arch build + push
```

See `repo_scripts/build-container-multiarch.sh` and the config layering in
`repo_scripts/include.sh` → `include.local.sh` (secrets, gitignored).

k8s example deployment: [`k8s-deploy/k8s-idp-auth.yaml`](k8s-deploy/k8s-idp-auth.yaml).

## Disclaimer

- **Not an official LiteLLM/BerriAI project.** `littlessollm` is an
  independent, unaffiliated add-on. "LiteLLM" is a trademark of BerriAI;
  no affiliation, endorsement, or sponsorship is implied.
- **Relies on litellm-internal APIs** (`generate_key_helper_fn`,
  `ReturnedUITokenObject`, `general_settings`, ...) — these are not
  publicly versioned/stable interfaces. This can break after litellm or
  fastapi-sso upgrades; see "Version fragility" above. Test against a
  staging environment before every litellm upgrade.
- **Security-critical code (auth).** JWT validation, secret handling, and
  virtual-key provisioning decide who gets access — review/test this
  yourself before production use. This is not a substitute for a security
  audit.
- **Status: alpha.** Unit-tested, but not yet wired against a real
  IdP/litellm production deployment (see the status note above).
- Provided **"AS IS", without warranty of any kind** — see
  [LICENSE.md](LICENSE.md) (MIT). No liability for any claim, damages, or
  other liability arising from the use of this software.

## License

This project is licensed under the MIT license where applicable/possible — see [LICENSE.md](LICENSE.md). Some files/parts may use other licenses: [MIT](LICENSEMIT.md) | [GPL](LICENSEGPL.md) | [LGPL](LICENSELGPL.md). Always check per‑file headers/comments.


## Authors
- Repo owner (primary author)
- Additional attributions are noted inline in code comments


## Acknowledgments
- Inspirations and snippets are referenced in code comments where appropriate.


## ⚠️ Note

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.
