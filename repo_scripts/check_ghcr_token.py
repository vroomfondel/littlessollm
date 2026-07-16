#!/usr/bin/env python3
"""Check GitHub Container Registry (ghcr.io) token permissions for a GitHub PAT."""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_jwt(token: str) -> bool:
    """True if *token* looks like a compact JWS/JWT (three dot-separated segments).

    ghcr may hand back an *opaque* bearer token (no dots) instead of a JWT —
    e.g. for fine-grained PATs. Such tokens carry no readable `access` claims and
    must be checked by exercising the registry directly (see registry_capability_probe).
    """
    return token.count(".") >= 2


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode the payload segment of a JWT (no signature verification)."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (no payload segment)")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    result: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    return result


def basic_auth_header(username: str, password: str) -> str:
    """Return a Basic Authorization header value."""
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


# ---------------------------------------------------------------------------
# Probe 1 – Classic PAT scopes via GitHub API header
# ---------------------------------------------------------------------------


def get_oauth_scopes(token: str) -> tuple[list[str], str]:
    """Return (scopes_list, note) from the X-OAuth-Scopes response header.

    Fine-grained PATs and GitHub Apps do not populate X-OAuth-Scopes; in that
    case an empty list is returned with an explanatory note.
    """
    url = "https://api.github.com/user"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "check-ghcr-token/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.headers.get("X-OAuth-Scopes", "")
    except urllib.error.HTTPError as exc:
        # Still try to read the header even on error responses
        raw = exc.headers.get("X-OAuth-Scopes", "") if exc.headers else ""

    if not raw or not raw.strip():
        return [], "fine-grained or no scopes header; relying on registry probe"

    scopes = [s.strip() for s in raw.split(",") if s.strip()]
    return scopes, ""


# ---------------------------------------------------------------------------
# Probe 2 – ghcr.io registry v2 token probe (authoritative push/pull check)
# ---------------------------------------------------------------------------


def _registry_http(url: str, bearer: str, method: str = "GET") -> tuple[int, Any]:
    """Issue an authenticated request to the registry, returning (status, headers).

    HTTP error responses (401/403/404/…) are returned as their status code rather
    than raised, so the caller can treat them as data. Network-level failures
    (URLError, timeouts) propagate to the caller.
    """
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "check-ghcr-token/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers


def registry_capability_probe(bearer: str, repository: str) -> tuple[list[str], str]:
    """Determine granted actions by exercising the registry with the bearer token.

    Fallback for *opaque* (non-JWT) ghcr tokens that cannot be introspected:
      - pull: GET /v2/<repo>/tags/list         — read-only.
      - push: POST /v2/<repo>/blobs/uploads/    — initiates an upload session that
              is immediately cancelled; no data is uploaded.

    Returns (granted_actions, note).
    """
    base = "https://ghcr.io"
    granted: list[str] = []

    # pull — listing tags requires pull. 200 = ok; 404 = authenticated but repo
    # (or its tags) absent, which still proves the token was accepted.
    try:
        code, _ = _registry_http(f"{base}/v2/{repository}/tags/list", bearer)
        if code in (200, 404):
            granted.append("pull")
    except Exception as exc:  # noqa: BLE001
        return granted, f"opaque token; live pull probe failed: {exc}"

    # push — initiating a blob upload requires push. Cancel the session afterwards.
    try:
        code, headers = _registry_http(f"{base}/v2/{repository}/blobs/uploads/", bearer, method="POST")
        if code in (201, 202):
            granted.append("push")
            location = headers.get("Location") if headers else None
            if location:
                try:  # best-effort cleanup of the just-created upload session
                    _registry_http(urllib.parse.urljoin(base, location), bearer, method="DELETE")
                except Exception:  # noqa: BLE001
                    pass
    except Exception as exc:  # noqa: BLE001
        return granted, f"opaque token; live push probe failed: {exc}"

    return granted, "opaque token; verified via live registry probe"


def registry_token_probe(
    github_user: str,
    token: str,
    owner: str,
    image: str,
) -> dict[str, Any]:
    """Probe ghcr.io for granted registry actions via the Docker v2 token flow.

    Returns a dict:
        {
            "repository": "<owner>/<image>",
            "granted_actions": ["pull", "push"],   # may be empty
            "ok": bool,
            "error": str | None,
        }
    """
    repository = f"{owner}/{image}"
    scope = f"repository:{repository}:pull,push"
    url = f"https://ghcr.io/token?service=ghcr.io&scope={scope}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": basic_auth_header(github_user, token),
            "User-Agent": "check-ghcr-token/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data: dict[str, Any] = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        msg = f"HTTP {exc.code}: {exc.reason}"
        return {"repository": repository, "granted_actions": [], "ok": False, "error": msg}
    except Exception as exc:  # noqa: BLE001
        return {"repository": repository, "granted_actions": [], "ok": False, "error": str(exc)}

    raw_token = data.get("token", "") or data.get("access_token", "")
    if not raw_token:
        return {
            "repository": repository,
            "granted_actions": [],
            "ok": False,
            "error": "No token in registry response",
            "note": None,
        }

    note: str | None = None
    if is_jwt(raw_token):
        # JWT: read the granted actions straight from the `access` claim.
        try:
            payload = decode_jwt_payload(raw_token)
        except Exception as exc:  # noqa: BLE001
            return {
                "repository": repository,
                "granted_actions": [],
                "ok": False,
                "error": f"JWT decode error: {exc}",
                "note": None,
            }
        granted: list[str] = []
        for entry in payload.get("access", []):
            if entry.get("name") == repository:
                granted.extend(entry.get("actions", []))
    else:
        # Opaque token: cannot introspect — verify capabilities against the registry.
        granted, note = registry_capability_probe(raw_token, repository)

    ok = bool(granted)
    return {"repository": repository, "granted_actions": granted, "ok": ok, "error": None, "note": note}


# ---------------------------------------------------------------------------
# Probe 3 – List existing container packages (informational)
# ---------------------------------------------------------------------------


def _fetch_packages_url(url: str, token: str) -> list[dict[str, Any]]:
    """Fetch all pages from a GitHub packages list endpoint."""
    packages: list[dict[str, Any]] = []
    current_url: str | None = url
    while current_url:
        req = urllib.request.Request(
            current_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "check-ghcr-token/1.0",
            },
        )
        with urllib.request.urlopen(req) as resp:
            packages.extend(json.loads(resp.read()))
            # Best-effort pagination via Link header
            link_header = resp.headers.get("Link", "")
            current_url = _parse_next_link(link_header)
    return packages


def _parse_next_link(link_header: str) -> str | None:
    """Extract the URL for rel="next" from a GitHub Link header."""
    if not link_header:
        return None
    for part in link_header.split(","):
        segments = [s.strip() for s in part.split(";")]
        if len(segments) == 2 and segments[1] == 'rel="next"':
            return segments[0].strip("<>")
    return None


def list_container_packages(owner: str, token: str) -> tuple[list[str], str]:
    """Return (package_names, note) for container packages owned by *owner*.

    Tries /users/<owner>/packages first; falls back to /user/packages (for the
    authenticated user themselves) when that returns 404/403.
    """
    urls = [
        f"https://api.github.com/users/{owner}/packages?package_type=container&per_page=100",
        "https://api.github.com/user/packages?package_type=container&per_page=100",
    ]

    for url in urls:
        try:
            pkgs = _fetch_packages_url(url, token)
            names = [p["name"] for p in pkgs if isinstance(p, dict)]
            return names, ""
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                continue
            return [], f"HTTP {exc.code}: {exc.reason}"
        except Exception as exc:  # noqa: BLE001
            return [], str(exc)

    return [], "could not list packages"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

INTERESTING_SCOPES = ("read:packages", "write:packages", "delete:packages", "repo")


def _present_scopes(scopes: list[str], note: str) -> str:
    if note:
        return note
    found = [s for s in INTERESTING_SCOPES if s in scopes]
    missing = [s for s in INTERESTING_SCOPES if s not in scopes]
    parts = []
    if found:
        parts.append("present: " + ", ".join(found))
    if missing:
        parts.append("absent: " + ", ".join(missing))
    return "  ".join(parts) if parts else "(none)"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check GitHub Container Registry (ghcr.io) token permissions for a GitHub PAT."
    )
    parser.add_argument("github_user", help="GitHub username used for registry Basic-auth")
    parser.add_argument("token", help="GitHub Personal Access Token (classic ghp_... or fine-grained)")
    parser.add_argument(
        "--owner",
        default=None,
        help="Package owner (user or org). Defaults to github_user if omitted.",
    )
    parser.add_argument(
        "--image",
        default=None,
        help='Specific image/package name to probe (e.g. "littlessollm"). Defaults to "littlessollm".',
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output as JSON instead of human-readable text",
    )
    args = parser.parse_args()

    github_user: str = args.github_user
    token: str = args.token
    owner: str = args.owner if args.owner else github_user
    image: str = args.image if args.image else "littlessollm"
    image_specified: bool = bool(args.image)

    # --- Probe 1: OAuth scopes ---
    oauth_scopes, scope_note = get_oauth_scopes(token)

    # --- Probe 2: Registry token probe ---
    registry = registry_token_probe(github_user, token, owner, image)

    # --- Probe 3: List packages ---
    packages, pkg_note = list_container_packages(owner, token)

    # --- Output ---
    if args.json_output:
        print(
            json.dumps(
                {
                    "user": github_user,
                    "owner": owner,
                    "image_probed": image,
                    "image_specified": image_specified,
                    "oauth_scopes": oauth_scopes,
                    "oauth_scopes_note": scope_note,
                    "registry_probe": registry,
                    "packages": packages,
                    "packages_note": pkg_note,
                },
                indent=2,
            )
        )
    else:
        print(f"User:    {github_user}")
        print(f"Owner:   {owner}")
        print()

        # Scope line
        print(f"OAuth scopes:  {_present_scopes(oauth_scopes, scope_note)}")
        print()

        # Registry probe verdict
        repo_label = registry["repository"]
        if not image_specified:
            repo_label += "  (placeholder; actual image may not exist)"
        actions_str = ", ".join(registry["granted_actions"]) if registry["granted_actions"] else "-"
        verdict = "[OK]" if registry["ok"] else "[DENIED]"
        if registry.get("error"):
            verdict += f"  ({registry['error']})"
        elif registry.get("note"):
            verdict += f"  ({registry['note']})"
        print("Registry probe:")
        print(f"  ghcr.io  {repo_label}")
        print(f"  granted actions: {actions_str}  {verdict}")
        print()

        # Packages list
        if pkg_note and not packages:
            print(f"Packages: {pkg_note}")
        elif packages:
            print(f"Container packages for '{owner}' ({len(packages)} found):")
            col_w = max((len(p) for p in packages), default=0)
            sep = f"+{'-' * (col_w + 2)}+"
            print(sep)
            print(f"| {'Package':<{col_w}} |")
            print(sep)
            for p in sorted(packages):
                print(f"| {p:<{col_w}} |")
            print(sep)
        else:
            print(f"Packages: none found for '{owner}'")

    # Exit non-zero if registry probe shows no actions granted
    if not registry["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
