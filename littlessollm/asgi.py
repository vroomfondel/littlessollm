"""No-fork ASGI entry point: attaches littlessollm to the real LiteLLM app.

Registers the UI-SSO router and the API-JWT middleware directly on
LiteLLM's own FastAPI ``app`` object, without changing a single line of
LiteLLM's source.

Start::

    export LITELLM_CONFIG=/app/config.yaml
    uvicorn littlessollm.asgi:app --host 0.0.0.0 --port 4000

Recommended: run it through the wrapper, which materializes file-backed
secrets first::

    littlessollm-entrypoint uvicorn littlessollm.asgi:app --host 0.0.0.0 --port 4000

Important:
    Do not set any of ``MICROSOFT_CLIENT_ID`` / ``GOOGLE_CLIENT_ID`` /
    ``GENERIC_CLIENT_ID``, and do not set ``enable_jwt_auth: true`` -- either
    would activate LiteLLM's own enterprise-gated paths instead of the
    MIT-only code in this package.
"""

import asyncio
import os

from litellm.proxy.proxy_server import app  # the real LiteLLM FastAPI app

from .auth import IdpJwtToVirtualKey  # API auth   (/v1/*)
from .sso import router as oidc_router  # UI login (/my-sso/*)

# 1) Register the UI-SSO routes on top of LiteLLM's existing routes.
app.include_router(oidc_router)

# 2) Register the API-auth middleware BEFORE LiteLLM's own auth.
#    add_middleware() wraps the app one layer further out each time it's
#    called, and Starlette dispatches outermost-first -- so as long as this
#    runs after LiteLLM's own proxy_server import (which registers its own
#    middleware/dependencies), IdpJwtToVirtualKey ends up outermost and sees
#    every request before LiteLLM's user_api_key_auth dependency does.
app.add_middleware(IdpJwtToVirtualKey)


async def _load_config(config_path: str) -> None:
    """Load a LiteLLM proxy config file into the running app.

    Only needed if you start via plain ``uvicorn`` (as opposed to the
    ``litellm`` CLI, which already loads the config itself).

    Args:
        config_path: Path to the LiteLLM ``config.yaml``.
    """
    from litellm.proxy.proxy_server import ProxyConfig

    await ProxyConfig().load_config(router=None, config_file_path=config_path)


# Optional: load the config programmatically when LITELLM_CONFIG is set and
# we're not started via the `litellm` CLI. If you do use that CLI, delete
# this block and use the one-line patch described in the README instead.
_config_path = os.getenv("LITELLM_CONFIG")
if _config_path:
    asyncio.get_event_loop().run_until_complete(_load_config(_config_path))
