"""API-JWT authentication middleware for LiteLLM (config-driven).

Secures ``/v1/*`` requests against the IdP without the enterprise-gated
``enable_jwt_auth`` setting: an IdP JWT is verified against the IdP's JWKS
(signature, ``iss``/``aud``/``exp``), its claims are mapped to a
team/role/model/limit set via the YAML mapping (:mod:`littlessollm.config`),
and a LiteLLM virtual key is minted (or reused from cache) via
``generate_key_helper_fn`` -- a MIT-licensed LiteLLM API. The request's
``Authorization`` header is then rewritten to that virtual key before
LiteLLM's own routing/auth sees the request.

The virtual-key cache's TTL and the minted key's duration are both derived
from the token's remaining lifetime, see :func:`_resolve_key`.
"""

import asyncio
import time
from typing import TYPE_CHECKING, Any, TypedDict

import jwt  # PyJWT
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import config as cfg

if TYPE_CHECKING:
    from redis.asyncio import Redis

_mint_locks: dict[str, asyncio.Lock] = {}
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def _jwks_client() -> jwt.PyJWKClient:
    """Return a cached :class:`jwt.PyJWKClient` for the configured JWKS URL.

    Returns:
        A JWKS client, created and cached on first use per URL.
    """
    url = cfg.oidc()["jwks_url"]
    if url not in _jwks_clients:
        _jwks_clients[url] = jwt.PyJWKClient(url, cache_keys=True)
    return _jwks_clients[url]


# ---------------------------------------------------------------------------
# Cache (Redis or in-memory), TTL derived from the token's expiry
# ---------------------------------------------------------------------------
class _Cache:
    """A minimal string cache backed by Redis, or an in-memory dict.

    Redis is used when the ``REDIS_URL`` secret resolves to a value
    (recommended for multi-replica deployments, so all replicas share the
    same identity-to-virtual-key mapping); otherwise falls back to a
    per-process in-memory dict.
    """

    def __init__(self) -> None:
        """Initialize the cache, connecting to Redis if configured."""
        self._redis: Redis | None = None
        self._mem: dict[str, tuple[str, float]] = {}
        url = cfg.secret("REDIS_URL")
        if url:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> str | None:
        """Fetch a cached value.

        Args:
            key: The cache key.

        Returns:
            The cached value, or ``None`` if absent or expired.
        """
        if self._redis is not None:
            raw = await self._redis.get(key)
            # decode_responses=True guarantees str at runtime; PyJWT's/
            # redis-py's stubs still allow bytes, so narrow explicitly
            # rather than widening this method's return type to Any.
            if isinstance(raw, bytes):
                return raw.decode()
            return raw
        item = self._mem.get(key)
        if not item:
            return None
        value, expires_at = item
        if time.time() >= expires_at:
            self._mem.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Store a value with a time-to-live.

        Args:
            key: The cache key.
            value: The value to store.
            ttl: Time-to-live in seconds (floored at 1).
        """
        if self._redis is not None:
            await self._redis.set(key, value, ex=max(ttl, 1))
        else:
            self._mem[key] = (value, time.time() + max(ttl, 1))


_cache_singleton: _Cache | None = None


def _cache() -> _Cache:
    """Return the process-wide :class:`_Cache` singleton, creating it lazily.

    Returns:
        The cache instance.
    """
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = _Cache()
    return _cache_singleton


# ---------------------------------------------------------------------------
# Claim -> team / model / role / limit mapping
# ---------------------------------------------------------------------------
class ResolvedIdentity(TypedDict):
    """A JWT's claims, resolved to LiteLLM key-provisioning parameters.

    Attributes:
        user_id: Stable user identifier (from the configured ``sub_claim``).
        user_email: The user's email, if the token carries an ``email`` claim.
        team_id: Resolved team ID, or ``None`` if neither a group matched
            nor ``default_team_id`` is configured.
        user_role: Resolved LiteLLM role.
        models: Allowed model names (empty means "all models").
        tpm_limit: Tokens-per-minute limit, if configured for the team.
        rpm_limit: Requests-per-minute limit, if configured for the team.
        max_budget: Spend budget, if configured for the team.
        budget_duration: Budget reset interval, if configured for the team.
    """

    user_id: str
    user_email: str | None
    team_id: str | None
    user_role: str
    models: list[str]
    tpm_limit: int | None
    rpm_limit: int | None
    max_budget: float | None
    budget_duration: str | None


def _map_identity(claims: dict[str, Any]) -> ResolvedIdentity:
    """Map JWT claims to a team/model/role/limit identity.

    Args:
        claims: The verified JWT claims. Structurally dynamic: which claim
            carries the subject/groups is itself configured via the YAML
            mapping (``sub_claim``/``group_claim``), so this is typed as
            ``dict[str, Any]`` rather than a fixed schema -- a genuine case
            where the shape is only known at runtime, not a shortcut.

    Returns:
        The resolved identity, ready to pass into ``generate_key_helper_fn``.
    """
    a = cfg.api_auth()
    o = cfg.oidc()
    raw = claims.get(o.get("group_claim", "groups")) or []
    groups = {raw} if isinstance(raw, str) else set(raw)

    team_id = cfg.first_match(a.get("team_map", {}), groups) or a.get("default_team_id")
    user_role = cfg.first_match(a.get("role_map", {}), groups) or a.get("default_role", "internal_user")
    models = (a.get("models_by_team", {}) or {}).get(team_id or "", [])
    limits = (a.get("limits_by_team", {}) or {}).get(team_id or "", {})

    return ResolvedIdentity(
        user_id=claims[o.get("sub_claim", "sub")],
        user_email=claims.get("email"),
        team_id=team_id,
        user_role=user_role,
        models=models,
        tpm_limit=limits.get("tpm_limit"),
        rpm_limit=limits.get("rpm_limit"),
        max_budget=limits.get("max_budget"),
        budget_duration=limits.get("budget_duration"),
    )


async def _mint_key(claims: dict[str, Any], key_seconds: int) -> str:
    """Mint a new LiteLLM virtual key for the given claims.

    Args:
        claims: The verified JWT claims (see :func:`_map_identity`).
        key_seconds: The virtual key's validity duration, in seconds.

    Returns:
        The minted virtual key (``sk-...``).
    """
    from litellm.proxy.management_endpoints.key_management_endpoints import generate_key_helper_fn

    ident = _map_identity(claims)
    response = await generate_key_helper_fn(
        request_type="key",
        duration=f"{key_seconds}s",
        table_name="key",
        user_id=ident["user_id"],
        user_email=ident["user_email"],
        user_role=ident["user_role"],
        team_id=ident["team_id"],
        models=ident["models"] or [],
        tpm_limit=ident["tpm_limit"],
        rpm_limit=ident["rpm_limit"],
        max_budget=ident["max_budget"],
        budget_duration=ident["budget_duration"],
        metadata={"auth_source": "idp_jwt", "idp_sub": ident["user_id"], "idp_iss": claims.get("iss")},
    )
    token: str = response["token"]
    return token


async def _resolve_key(claims: dict[str, Any]) -> str:
    """Return a cached virtual key for ``claims``, minting one if needed.

    The cache TTL and the minted key's duration are both derived from the
    token's remaining lifetime (``exp`` minus now): cache TTL = remaining -
    skew; key duration = remaining + grace. This means the virtual key
    outlives the cache entry by ``skew + grace`` seconds, and a new or
    refreshed token always forces a re-mint rather than reusing a stale key.

    Args:
        claims: The verified JWT claims.

    Returns:
        A virtual key (``sk-...``), from cache or freshly minted.
    """
    a = cfg.api_auth().get("cache", {})
    skew = int(a.get("skew_seconds", 30))
    grace = int(a.get("key_grace_seconds", 60))
    min_secs = int(a.get("min_key_seconds", 60))

    now = int(time.time())
    remaining = int(claims.get("exp", now)) - now
    cache_ttl = max(remaining - skew, min_secs)
    key_seconds = max(remaining + grace, min_secs + grace)

    sub = claims[cfg.oidc().get("sub_claim", "sub")]
    cache_key = f"idp2vk:{cfg.oidc()['issuer']}:{sub}"

    sk = await _cache().get(cache_key)
    if sk:
        return sk

    lock = _mint_locks.setdefault(sub, asyncio.Lock())
    async with lock:
        sk = await _cache().get(cache_key)
        if sk:
            return sk
        sk = await _mint_key(claims, key_seconds)
        await _cache().set(cache_key, sk, cache_ttl)
        return sk


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
class IdpJwtToVirtualKey(BaseHTTPMiddleware):
    """Rewrites a valid IdP JWT bearer token into a LiteLLM virtual key.

    Registered outermost on the app (see :mod:`littlessollm.asgi`), so it
    runs before LiteLLM's own ``user_api_key_auth`` dependency: by the time
    LiteLLM's routing sees the request, ``Authorization`` already carries an
    ordinary ``sk-...`` key.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Validate an IdP JWT (if present) and rewrite it to a virtual key.

        Requests without a bearer token, with an existing ``sk-...`` key, or
        matching one of the configured ``public_prefixes`` pass through
        unchanged.

        Args:
            request: The incoming request.
            call_next: The next handler in the middleware chain.

        Returns:
            The downstream response, or a ``401``/``500`` JSON error
            response if token validation or key provisioning fails.
        """
        default_public_prefixes = [
            "/health",
            "/my-sso",
            "/sso",
            "/ui",
            "/docs",
            "/openapi.json",
            "/get_image",
            "/favicon",
            "/.well-known",
        ]
        prefixes = tuple(cfg.api_auth().get("public_prefixes", default_public_prefixes))
        if request.url.path.startswith(prefixes):
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""

        if not token or token.startswith("sk-") or token.count(".") != 2:
            return await call_next(request)

        o = cfg.oidc()
        try:
            signing_key = _jwks_client().get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=o.get("algorithms", ["RS256"]),
                audience=o["audience"],
                issuer=o["issuer"],
                options={"require": ["exp", "iss", "aud", o.get("sub_claim", "sub")]},
            )
        except Exception as e:  # noqa: BLE001
            return JSONResponse(
                {"error": {"message": f"invalid IdP token: {e}", "type": "auth_error"}}, status_code=401
            )

        try:
            sk = await _resolve_key(claims)
        except Exception as e:  # noqa: BLE001
            return JSONResponse(
                {"error": {"message": f"could not provision key: {e}", "type": "auth_error"}}, status_code=500
            )

        new_headers = [(k, v) for (k, v) in request.scope["headers"] if k.lower() != b"authorization"]
        new_headers.append((b"authorization", f"Bearer {sk}".encode()))
        request.scope["headers"] = new_headers
        return await call_next(request)
