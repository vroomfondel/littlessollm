#!/bin/bash
# discover_litellm_version.sh
#
# Prints the current litellm-database "-stable" tag on ghcr.io to stdout, or
# nothing (+ exit 1) if the registry is unreachable / no "-stable" tag is
# found. Shared by build-container-multiarch.sh and
# .github/workflows/buildmultiarchandpush.yml, so local builds and CI can
# never drift onto different litellm versions.
#
# ghcr.io/berriai/litellm-database is a public package, so an anonymous
# registry token is enough.
#
# Can't just take the newest GitHub release (the way some of our other
# repos' build scripts do for e.g. pgvector: `curl .../tags | jq -r
# '.[0].name'`) -- litellm's "-stable" ghcr.io tag lags source releases a
# lot: checked 2026-07-05, GitHub was already at v1.91.0 while the newest
# -stable image was still main-v1.83.14-stable (the last 17+ releases had no
# -stable image at all). So this queries the registry's own tag list --
# ground truth of what image actually exists -- not GitHub. The registry
# paginates (2000+ tags total), which needs the response's Link header, so
# the curl call below only fetches an anonymous pull token; the paginated
# listing + version-max selection happens in a single embedded python3
# (stdlib urllib) call.

set -euo pipefail

token="$(curl -fsSL "https://ghcr.io/token?service=ghcr.io&scope=repository:berriai/litellm-database:pull" \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])')"
[[ -n "${token}" ]] || exit 1

python3 -c "
import json, re, urllib.request

token = '${token}'
url = 'https://ghcr.io/v2/berriai/litellm-database/tags/list?n=1000'
tags = []
for _ in range(50):
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.load(resp)
        tags.extend(data['tags'])
        link = resp.headers.get('Link', '')
    m = re.search(r'<([^>]+)>;\s*rel=\"next\"', link)
    if not m:
        break
    path = m.group(1)
    url = 'https://ghcr.io' + path if path.startswith('/') else path

best = None
for t in tags:
    m = re.match(r'^main-v(\d+(?:\.\d+)*)-stable\$', t)
    if not m:
        continue
    try:
        key = tuple(int(p) for p in m.group(1).split('.'))
    except ValueError:
        continue
    if best is None or key > best[0]:
        best = (key, t)
if not best:
    raise SystemExit(1)
print(best[1], end='')
"
