"""UI-SSO login routes for the LiteLLM admin dashboard (config-driven).

A self-contained OpenID Connect login flow for the LiteLLM Admin UI, built
entirely on LiteLLM's MIT-licensed core: no ``litellm_enterprise`` import, no
license check bypassed.

Endpoints and mapping come from the YAML mapping (:mod:`littlessollm.config`);
secrets come from file or environment (see :func:`littlessollm.config.secret`).
Do not set any of ``MICROSOFT_CLIENT_ID`` / ``GOOGLE_CLIENT_ID`` /
``GENERIC_CLIENT_ID`` -- doing so would activate LiteLLM's own built-in
(enterprise-gated) 5-user SSO instead of this module.
"""

from dataclasses import dataclass

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi_sso.sso.base import DiscoveryDocument, SSOBase
from fastapi_sso.sso.generic import create_provider

from . import config as cfg

router = APIRouter()


@dataclass
class _DiscoveryCache:
    """Cached OIDC discovery document, keyed by the discovery URL it came from."""

    url: str | None = None
    document: DiscoveryDocument | None = None


_discovery_cache = _DiscoveryCache()


async def _discovery() -> DiscoveryDocument:
    """Fetch and cache the IdP's OpenID Connect discovery document.

    Re-fetched whenever the configured ``discovery_url`` changes (e.g. after
    a mapping-config reload); otherwise served from cache.

    Returns:
        The endpoints this module needs: ``authorization_endpoint``,
        ``token_endpoint``, ``userinfo_endpoint``.
    """
    url = cfg.oidc()["discovery_url"]
    if _discovery_cache.url != url:
        async with httpx.AsyncClient(timeout=10) as client:
            data = (await client.get(url)).json()
        _discovery_cache.document = {
            "authorization_endpoint": data["authorization_endpoint"],
            "token_endpoint": data["token_endpoint"],
            "userinfo_endpoint": data["userinfo_endpoint"],
        }
        _discovery_cache.url = url
    assert _discovery_cache.document is not None  # set immediately above
    return _discovery_cache.document


async def _provider() -> SSOBase:
    """Build a generic OIDC provider instance for the configured IdP.

    Returns:
        An ``fastapi_sso`` provider ready to drive the login/callback flow.
    """
    o = cfg.oidc()
    d = await _discovery()
    redirect_uri = o["redirect_uri"]
    provider_class = create_provider(name="littlessollm-oidc", discovery_document=d)
    # client_id is not secret: prefer the ConfigMap (oidc.client_id), fall
    # back to a file/env secret. str(...): both branches are guaranteed
    # non-None here (cfg.secret(..., required=True) raises otherwise).
    client_id: str = str(o.get("client_id") or cfg.secret("OIDC_CLIENT_ID", required=True))
    client_secret: str = str(cfg.secret("OIDC_CLIENT_SECRET", required=True))
    return provider_class(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        allow_insecure_http=redirect_uri.startswith("http://"),
        scope=o.get("scope", ["openid", "email", "profile", "groups"]),
    )


def _map_role(groups: list[str]) -> str:
    """Map a user's IdP groups to a LiteLLM admin-UI role.

    Args:
        groups: The IdP groups the user belongs to.

    Returns:
        The resolved role, or ``ui_sso.default_role`` if no group matches.
    """
    u = cfg.ui_sso()
    role = cfg.first_match(u.get("role_map", {}), set(groups))
    return role or u.get("default_role", "internal_user_viewer")


async def _fetch_groups(access_token: str | None) -> list[str]:
    """Fetch the caller's IdP group memberships from the userinfo endpoint.

    Args:
        access_token: The OAuth access token obtained during login, or
            ``None`` if unavailable.

    Returns:
        The group names from the configured ``group_claim``, or ``[]`` if
        there is no access token or the userinfo request fails.
    """
    if not access_token:
        return []
    d = await _discovery()
    claim = cfg.oidc().get("group_claim", "groups")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        return []
    userinfo: dict[str, object] = resp.json()
    raw = userinfo.get(claim)
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []


@router.get("/my-sso/login")
async def my_sso_login() -> RedirectResponse:
    """Start the OIDC login flow by redirecting to the IdP.

    Returns:
        A redirect to the IdP's authorization endpoint.
    """
    sso = await _provider()
    async with sso:
        return await sso.get_login_redirect()


@router.get("/my-sso/callback")
async def my_sso_callback(request: Request) -> RedirectResponse:
    """Handle the OIDC callback: verify the IdP, then log into the LiteLLM UI.

    Exchanges the authorization code, verifies the user's identity and
    (optional) allowed email domain, resolves their admin-UI role from their
    IdP groups, mints a LiteLLM UI session key via ``generate_key_helper_fn``,
    and redirects to the dashboard with a signed session cookie -- mirroring
    exactly what LiteLLM's own (enterprise-gated) SSO would produce, so the
    dashboard needs no changes of its own.

    Args:
        request: The incoming callback request (carries the IdP's
            authorization code).

    Returns:
        A redirect to the LiteLLM dashboard, with the session cookie set.

    Raises:
        HTTPException: 401 if the IdP returned no usable email, or 403 if
            ``allowed_email_domain`` is configured and the email doesn't match.
    """
    sso = await _provider()
    async with sso:
        openid = await sso.verify_and_process(request)
        access_token = sso.access_token

    if openid is None or not openid.email:
        raise HTTPException(status_code=401, detail="SSO returned no user email")

    user_email = openid.email.lower()
    user_id = openid.id or user_email

    allowed_domain = cfg.oidc().get("allowed_email_domain")
    if allowed_domain and not user_email.endswith("@" + allowed_domain):
        raise HTTPException(status_code=403, detail="Email domain not allowed")

    user_role = _map_role(await _fetch_groups(access_token))

    # ---- Core LiteLLM imports (its globals only exist once litellm has
    # started, so these must stay deferred rather than module-level) ----
    import jwt
    import litellm
    from litellm.constants import LITELLM_UI_SESSION_DURATION
    from litellm.proxy._types import LitellmUserRoles
    from litellm.proxy.management_endpoints.ui_sso import (
        check_and_update_if_proxy_admin_id,
        get_disabled_non_admin_personal_key_creation,
    )
    from litellm.proxy.proxy_server import (
        general_settings,
        generate_key_helper_fn,
        master_key,
        premium_user,
        prisma_client,
    )
    from litellm.proxy.utils import get_custom_url, get_server_root_path
    from litellm.types.proxy.ui_sso import ReturnedUITokenObject

    response = await generate_key_helper_fn(
        request_type="key",
        duration=LITELLM_UI_SESSION_DURATION,
        key_max_budget=litellm.max_ui_session_budget,
        aliases={},
        config={},
        spend=0,
        team_id="litellm-dashboard",
        models=[],
        user_id=user_id,
        user_email=user_email,
        user_role=user_role,
        max_budget=litellm.max_internal_user_budget,
        budget_duration=litellm.internal_user_budget_duration,
        table_name="key",
    )
    key = response["token"]
    user_id = response["user_id"]

    user_role = user_role or LitellmUserRoles.INTERNAL_USER_VIEW_ONLY.value
    user_role = await check_and_update_if_proxy_admin_id(
        user_role=user_role, user_id=user_id, prisma_client=prisma_client
    )

    token_obj = ReturnedUITokenObject(
        user_id=user_id,
        key=key,
        user_email=user_email,
        user_role=user_role,
        login_method="sso",
        premium_user=premium_user,
        auth_header_name=general_settings.get("litellm_key_header_name", "Authorization"),
        disabled_non_admin_personal_key_creation=get_disabled_non_admin_personal_key_creation(),
        server_root_path=get_server_root_path(),
    )
    jwt_token = jwt.encode(dict(token_obj), master_key or "", algorithm="HS256")

    dashboard = get_custom_url(request_base_url=str(request.base_url), route="ui/") + "?login=success"
    redirect = RedirectResponse(url=dashboard, status_code=303)
    redirect.set_cookie(
        key="token",
        value=jwt_token,
        secure=not cfg.oidc()["redirect_uri"].startswith("http://"),
        httponly=True,
        samesite="lax",
    )
    return redirect
