#!/usr/bin/env python3
"""Materializes file-backed secrets into the environment, then runs a command.

Starts the actual target process (typically ``litellm``/``uvicorn``) after
materializing secrets from FILES into its environment -- for secrets that
LiteLLM itself reads from the environment (``LITELLM_MASTER_KEY``,
``DATABASE_URL``, ``LITELLM_SALT_KEY``, ...). ``littlessollm.config.secret()``
only covers the secrets our own modules (:mod:`littlessollm.sso`,
:mod:`littlessollm.auth`) read.

Resolution / precedence (highest first):
    1. ``<NAME>_FILE`` -- a file holding exactly this one secret, for known
       names from :data:`DEFAULT_SECRET_BASE_NAMES` only (file wins).
    2. ``IDP_SECRETS_FILE`` -- a YAML file ``{ NAME: value, ... }`` (overrides
       the environment when ``SECRETS_FILE_OVERRIDE_ENV=true``, the default).
    3. The environment as already set -- fallback/default (left untouched).

Step 1 is deliberately an allowlist, not a blind scan over every environment
variable ending in ``_FILE``: base images commonly set their own, unrelated
``*_FILE`` variables (e.g. ``SSL_CERT_FILE`` for a CA bundle). A blind scan
would misinterpret "SSL_CERT" as a secret, write that (often large) file's
content into the environment, and can crash the child process with
"Argument list too long" (``ARG_MAX``) once the environment grows too big.

Fallback behavior: if no file exists for a given name, the environment is
NOT touched, so the target process keeps running with its own default.
Required secrets are only enforced when explicitly requested via
``REQUIRE_SECRETS``.

:func:`main` then runs the actual start command as a subprocess (no more
``exec``) and forwards its exit code. The PID-1/signal/zombie-reaping
problem that process replacement via ``execvp`` used to solve manually is
now handled by ``tini -g`` in the container (see the Dockerfile: ``-g``
makes tini signal the whole *process group*, not just this direct child of
tini). Secret VALUES are never logged, only names and their source.
"""

import os
import subprocess
import sys
from collections.abc import MutableMapping

# Known secret base names this wrapper materializes from `<NAME>_FILE`:
# LiteLLM's own (LITELLM_MASTER_KEY/DATABASE_URL/LITELLM_SALT_KEY) plus
# littlessollm's own (OIDC_*, REDIS_URL). Extensible without a code change
# via the comma-separated SECRET_BASE_NAMES environment variable --
# deliberately NOT a generic scan over every environment variable (see the
# module docstring).
DEFAULT_SECRET_BASE_NAMES = (
    "LITELLM_MASTER_KEY",
    "DATABASE_URL",
    "LITELLM_SALT_KEY",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "REDIS_URL",
)


def secret_base_names(env: MutableMapping[str, str]) -> list[str]:
    """Return the secret base names to check, defaults plus any extras.

    Args:
        env: The environment to read ``SECRET_BASE_NAMES`` from.

    Returns:
        :data:`DEFAULT_SECRET_BASE_NAMES` followed by any comma-separated
        extra names from the ``SECRET_BASE_NAMES`` environment variable,
        de-duplicated while preserving order.
    """
    extra = [s.strip() for s in env.get("SECRET_BASE_NAMES", "").split(",") if s.strip()]
    return list(dict.fromkeys([*DEFAULT_SECRET_BASE_NAMES, *extra]))


def read_secret_file(path: str) -> str:
    """Read a single-secret file, stripping only trailing newlines.

    Args:
        path: Path to the file.

    Returns:
        The file content with trailing ``\\r``/``\\n`` characters stripped.
    """
    with open(path) as f:
        return f.read().rstrip("\r\n")


def load_aggregated_secrets(path: str | None) -> dict[str, str]:
    """Load the aggregated ``IDP_SECRETS_FILE`` YAML.

    Args:
        path: Path to the aggregated secrets YAML, or ``None``.

    Returns:
        ``{name: value}`` for every entry, values coerced to ``str``, or
        ``{}`` if ``path`` is unset, missing, or unparsable.
    """
    if not path or not os.path.isfile(path):
        return {}
    try:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return {str(k): str(v) for k, v in data.items()}
    except Exception as e:  # noqa: BLE001
        print(f"[entrypoint] WARN: IDP_SECRETS_FILE unparsable: {e}", file=sys.stderr)
        return {}


def populate_env_from_secrets(env: MutableMapping[str, str], *, override_env: bool = True) -> dict[str, str]:
    """Materialize file-backed secrets into ``env`` (mutated in place).

    Precedence: ``<NAME>_FILE`` > aggregated ``IDP_SECRETS_FILE`` > the
    environment as already set.

    Args:
        env: The environment mapping to update (typically ``os.environ``).
        override_env: Whether the aggregated ``IDP_SECRETS_FILE`` may
            overwrite a name that's already set in ``env``. Per-name
            ``<NAME>_FILE`` always wins regardless of this flag.

    Returns:
        ``{base_name: source}`` for everything that was set (the "source"
        is either the ``<NAME>_FILE`` variable name or the literal string
        ``"IDP_SECRETS_FILE"``). Values are never included, only names.
    """
    populated: dict[str, str] = {}

    # 1) <NAME>_FILE for known secret names (file wins over env) -- an
    #    allowlist, not a scan over every environment variable (see the
    #    module docstring).
    for base in secret_base_names(env):
        key = f"{base}_FILE"
        val = env.get(key)
        if not val:
            continue
        if os.path.isfile(val):
            try:
                env[base] = read_secret_file(val)
                populated[base] = key
            except OSError as e:
                print(f"[entrypoint] WARN: cannot read {key}: {e} -> fallback to env", file=sys.stderr)
        else:
            print(f"[entrypoint] WARN: {key} set but file missing -> fallback to env", file=sys.stderr)

    # 2) Aggregated file (fills in whatever step 1 didn't already set)
    for base, value in load_aggregated_secrets(env.get("IDP_SECRETS_FILE")).items():
        if base in populated:
            continue  # per-name file wins
        if base in env and not override_env:
            continue  # keep the explicit environment value
        env[base] = value
        populated[base] = "IDP_SECRETS_FILE"

    return populated


def missing_required(env: MutableMapping[str, str], required: list[str]) -> list[str]:
    """Return which of ``required`` names are unresolved (falsy) in ``env``.

    Args:
        env: The environment mapping to check.
        required: Names that must resolve to a truthy value.

    Returns:
        The subset of ``required`` that is missing or empty in ``env``.
    """
    return [name for name in required if not env.get(name)]


def resolve_command(argv: list[str]) -> list[str]:
    """Determine the command to run: ``argv`` > ``LITELLM_START_CMD`` > default.

    Args:
        argv: Command-line arguments passed to this wrapper (``sys.argv[1:]``).

    Returns:
        ``argv`` if non-empty; otherwise the shell-split ``LITELLM_START_CMD``
        environment variable if set; otherwise the default uvicorn
        invocation for :mod:`littlessollm.asgi`.
    """
    if argv:
        return argv
    env_cmd = os.getenv("LITELLM_START_CMD")
    if env_cmd:
        import shlex

        return shlex.split(env_cmd)
    return ["uvicorn", "littlessollm.asgi:app", "--host", "0.0.0.0", "--port", "4000"]


def main() -> None:
    """Materialize file-backed secrets, then run the target command.

    Reads ``REQUIRE_SECRETS`` (comma-separated names that must resolve or
    the process exits with status 1) and ``SECRETS_FILE_OVERRIDE_ENV``
    (whether the aggregated secrets file may override an already-set
    environment variable), materializes secrets via
    :func:`populate_env_from_secrets`, then runs :func:`resolve_command`'s
    result as a subprocess and exits with its return code.
    """
    require = [s.strip() for s in os.getenv("REQUIRE_SECRETS", "").split(",") if s.strip()]
    override_env = os.getenv("SECRETS_FILE_OVERRIDE_ENV", "true").lower() in ("1", "true", "yes")

    populated = populate_env_from_secrets(os.environ, override_env=override_env)

    unresolved = missing_required(os.environ, require)
    if unresolved:
        print(f"[entrypoint] ERROR: required secrets missing: {', '.join(unresolved)}", file=sys.stderr)
        sys.exit(1)

    # Log names and source ONLY, never values.
    if populated:
        summary = ", ".join(f"{k}<-{v}" for k, v in sorted(populated.items()))
        print(f"[entrypoint] secrets from file: {summary}", file=sys.stderr)
    else:
        print("[entrypoint] no file secrets found; using env/defaults", file=sys.stderr)

    # Run the actual command as a subprocess (no more exec -- tini -g in the
    # container now owns signal forwarding + zombie reaping) and forward its
    # exit code.
    cmd = resolve_command(sys.argv[1:])
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
