"""Configuration loader for littlessollm.

Loads the non-secret IdP mapping (a YAML file, typically mounted from a
Kubernetes ConfigMap) and resolves secrets with a file-over-environment
precedence. Both sources are re-read automatically whenever their mtime
changes, so ConfigMap/Secret updates take effect without a pod restart.

Secret resolution order for :func:`secret` (first match wins):
    1. ``<NAME>_FILE`` -- path to a file holding exactly this one secret
       (the Docker/Kubernetes secret-as-file convention, e.g.
       ``/run/secrets/OIDC_CLIENT_SECRET``).
    2. ``IDP_SECRETS_FILE`` -- a single YAML file ``{ NAME: value, ... }``
       holding several secrets.
    3. The ``<NAME>`` environment variable -- fallback.

File-based secrets are preferred over plain environment variables: env vars
are inherited by every child process and routinely end up in
``os.environ`` dumps / crash reporters, whereas a file can be restricted via
file ownership and mode instead.
"""

import os
import threading
from dataclasses import dataclass
from typing import TypedDict, cast

import yaml

CONFIG_PATH = os.getenv("IDP_MAPPING_CONFIG", "/etc/litellm/idp-mapping.yaml")


class OidcConfig(TypedDict, total=False):
    """The ``oidc:`` section of the mapping YAML.

    Attributes:
        discovery_url: The IdP's OpenID Connect discovery document URL.
        issuer: Expected ``iss`` claim / OIDC issuer identifier.
        jwks_url: URL of the IdP's JSON Web Key Set, used to validate API
            bearer tokens.
        audience: Expected ``aud`` claim for API tokens.
        algorithms: Accepted JWT signing algorithms, e.g. ``["RS256"]``.
        scope: OAuth scopes requested during the UI-SSO login flow.
        group_claim: Name of the claim carrying the user's group memberships.
        sub_claim: Name of the claim used as the stable user identifier.
        redirect_uri: OAuth redirect URI for the UI-SSO callback route.
        client_id: OAuth client ID. Not secret; falls back to the
            ``OIDC_CLIENT_ID`` secret (see :func:`secret`) when omitted here.
        allowed_email_domain: If set, only this email domain may log in via
            UI-SSO.
    """

    discovery_url: str
    issuer: str
    jwks_url: str
    audience: str
    algorithms: list[str]
    scope: list[str]
    group_claim: str
    sub_claim: str
    redirect_uri: str
    client_id: str
    allowed_email_domain: str


class UiSsoConfig(TypedDict, total=False):
    """The ``ui_sso:`` section: IdP group to LiteLLM admin-UI role mapping.

    Attributes:
        role_map: Ordered mapping of LiteLLM role name to the list of IdP
            groups that grant it. The first match, in mapping insertion
            order, wins.
        default_role: Role assigned when no group in ``role_map`` matches.
    """

    role_map: dict[str, list[str]]
    default_role: str


class TeamLimits(TypedDict, total=False):
    """Per-team rate/budget limits applied when minting a virtual key.

    Attributes:
        tpm_limit: Tokens-per-minute limit.
        rpm_limit: Requests-per-minute limit.
        max_budget: Maximum spend budget.
        budget_duration: Budget reset interval, e.g. ``"30d"``.
    """

    tpm_limit: int
    rpm_limit: int
    max_budget: float
    budget_duration: str


class CacheConfig(TypedDict, total=False):
    """The ``api_auth.cache:`` section: virtual-key cache tuning.

    Attributes:
        skew_seconds: Subtracted from the token's remaining lifetime to get
            the cache TTL, so a fresh key is minted slightly before the
            token actually expires.
        key_grace_seconds: Added to the token's remaining lifetime to get
            the minted virtual key's duration, so the key outlives the
            token by this much (covers in-flight requests).
        min_key_seconds: Floor applied to both the cache TTL and the key
            duration.
    """

    skew_seconds: int
    key_grace_seconds: int
    min_key_seconds: int


class ApiAuthConfig(TypedDict, total=False):
    """The ``api_auth:`` section: IdP group to team/model/role/limit mapping.

    Attributes:
        default_team_id: Team assigned when no group in ``team_map`` matches.
        default_role: Role assigned when no group in ``role_map`` matches.
        team_map: Ordered mapping of team ID to the list of IdP groups that
            select it. The first match, in mapping insertion order, wins.
        role_map: Ordered mapping of LiteLLM role name to the list of IdP
            groups that grant it.
        models_by_team: Team ID to allowed model names. An empty or absent
            list means "all models".
        limits_by_team: Team ID to :class:`TeamLimits`.
        cache: Virtual-key cache tuning, see :class:`CacheConfig`.
        public_prefixes: Path prefixes the API-auth middleware never
            intercepts (health checks, the UI, docs, ...).
    """

    default_team_id: str
    default_role: str
    team_map: dict[str, list[str]]
    role_map: dict[str, list[str]]
    models_by_team: dict[str, list[str]]
    limits_by_team: dict[str, TeamLimits]
    cache: CacheConfig
    public_prefixes: list[str]


class MappingConfig(TypedDict, total=False):
    """The full parsed ``idp-mapping.yaml`` document.

    Attributes:
        oidc: IdP endpoints and token-validation settings.
        ui_sso: IdP group to admin-UI role mapping.
        api_auth: IdP group to team/model/role/limit mapping for API auth.
    """

    oidc: OidcConfig
    ui_sso: UiSsoConfig
    api_auth: ApiAuthConfig


@dataclass
class _MappingCacheState:
    """Internal mtime-keyed cache for the parsed mapping document."""

    mtime: float | None = None
    data: MappingConfig | None = None


@dataclass
class _SecretsCacheState:
    """Internal mtime-and-path-keyed cache for the aggregated secrets file."""

    mtime: float | None = None
    data: dict[str, str] | None = None
    path: str | None = None


_lock = threading.Lock()
_mapping_cache = _MappingCacheState()

_secret_lock = threading.Lock()
_secrets_cache = _SecretsCacheState()


# ---------------------------------------------------------------------------
# Mapping (ConfigMap)
# ---------------------------------------------------------------------------
def get_config() -> MappingConfig:
    """Load and cache the mapping YAML pointed to by ``IDP_MAPPING_CONFIG``.

    The file is re-read whenever its mtime changes, so ConfigMap updates
    take effect without restarting the process.

    Returns:
        The parsed mapping document.

    Raises:
        RuntimeError: If the file at :data:`CONFIG_PATH` cannot be stat'd
            (missing, unreadable, ...).
    """
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError as e:
        raise RuntimeError(f"IDP_MAPPING_CONFIG not readable at {CONFIG_PATH}: {e}") from e
    with _lock:
        if _mapping_cache.data is None or mtime != _mapping_cache.mtime:
            with open(CONFIG_PATH) as f:
                # yaml.safe_load() is inherently untyped (arbitrary YAML) --
                # cast() documents that we trust the file to match
                # MappingConfig rather than silently widening the field.
                _mapping_cache.data = cast(MappingConfig, yaml.safe_load(f) or {})
            _mapping_cache.mtime = mtime
        assert _mapping_cache.data is not None  # set immediately above
        return _mapping_cache.data


def oidc() -> OidcConfig:
    """Return the ``oidc:`` section of the mapping config.

    Returns:
        The section, or ``{}`` if absent.
    """
    value: OidcConfig = get_config().get("oidc", {})
    return value


def ui_sso() -> UiSsoConfig:
    """Return the ``ui_sso:`` section of the mapping config.

    Returns:
        The section, or ``{}`` if absent.
    """
    value: UiSsoConfig = get_config().get("ui_sso", {})
    return value


def api_auth() -> ApiAuthConfig:
    """Return the ``api_auth:`` section of the mapping config.

    Returns:
        The section, or ``{}`` if absent.
    """
    value: ApiAuthConfig = get_config().get("api_auth", {})
    return value


# ---------------------------------------------------------------------------
# Secrets (file preferred, environment variable as fallback)
# ---------------------------------------------------------------------------
def _read_file_secret(path: str) -> str | None:
    """Read a single-secret file, stripping only trailing newlines.

    Args:
        path: Path to the file.

    Returns:
        The file content with trailing ``\\r``/``\\n`` characters stripped
        (other whitespace in the secret is left untouched), or ``None`` if
        the file cannot be read.
    """
    try:
        with open(path) as f:
            return f.read().rstrip("\r\n")
    except OSError:
        return None


def _aggregated_secrets() -> dict[str, str]:
    """Load and cache the aggregated ``IDP_SECRETS_FILE`` YAML.

    Returns:
        ``{name: value}`` for every entry in the file, with values coerced
        to ``str``, or ``{}`` if ``IDP_SECRETS_FILE`` is unset or the file
        is unreadable.
    """
    path = os.getenv("IDP_SECRETS_FILE")
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    with _secret_lock:
        if _secrets_cache.data is None or mtime != _secrets_cache.mtime or path != _secrets_cache.path:
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
            _secrets_cache.data = {str(k): str(v) for k, v in raw.items()}
            _secrets_cache.mtime = mtime
            _secrets_cache.path = path
        assert _secrets_cache.data is not None  # set immediately above
        return _secrets_cache.data


def secret(name: str, default: str | None = None, required: bool = False) -> str | None:
    """Resolve one secret by name, file sources taking precedence over env.

    Resolution order (first match wins): ``<name>_FILE`` -> the aggregated
    ``IDP_SECRETS_FILE`` -> the ``<name>`` environment variable -> ``default``.

    Args:
        name: The secret's base name, e.g. ``"OIDC_CLIENT_SECRET"``.
        default: Value to use if nothing resolves.
        required: If true, raise instead of returning a falsy value.

    Returns:
        The resolved secret value, or ``default`` (which may be ``None``).

    Raises:
        RuntimeError: If ``required`` is true and the secret could not be
            resolved from any source.
    """
    val: str | None = None

    per_secret_path = os.getenv(f"{name}_FILE")
    if per_secret_path:
        val = _read_file_secret(per_secret_path)

    if val is None:
        agg = _aggregated_secrets().get(name)
        if agg is not None:
            val = agg

    if val is None:
        val = os.getenv(name, default)

    if required and not val:
        raise RuntimeError(f"missing required secret '{name}' (checked {name}_FILE, IDP_SECRETS_FILE, env)")
    return val


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def first_match(mapping: dict[str, list[str]], groups: set[str]) -> str | None:
    """Return the first mapping key whose group list intersects ``groups``.

    Iteration follows the mapping's insertion order, so earlier keys act as
    higher-priority entries.

    Args:
        mapping: ``{key: [group, ...]}``, e.g. a ``team_map`` or ``role_map``.
        groups: The IdP groups the current user belongs to.

    Returns:
        The first matching key, or ``None`` if no key matches.
    """
    for target, allowed in (mapping or {}).items():
        if groups.intersection(allowed or []):
            return target
    return None
