# Dummy-Werte (Template) – werden durch include.local.sh überschrieben
GHCR_REGISTRY="ghcr.io"
IMAGE_NAME="littlessollm"
GHCR_USER="your-github-username"
GHCR_TOKEN="ghp_dummy"

GHREPO="owner/repo"

GH_REPO_PUBLIC=false

REMOTE_ARM64_CONNECTION=""
REMOTE_ARM64_SSH_IDENTITY=""

# echo \$0 in include.sh: $0

declare -a include_local_sh
include_local_sh[0]="include.local.sh"
include_local_sh[1]="repo_scripts/include.local.sh"
include_local_sh[2]="$(dirname "$0")/repo_scripts/include.local.sh"
include_local_sh[3]="$(dirname "$0")/../repo_scripts/include.local.sh"
found=false

for path in "${include_local_sh[@]}"; do
  if [ -e "${path}" ]; then
    echo "${path} will be read..."
    source "${path}"
    found=true
    break
  fi
done

if [ "$found" = false ]; then
  echo "No include.local.sh file[s] found."
fi

# Ableitungen – können in include.local.sh bereits gesetzt werden; sonst Standardwert
: "${GHCR_OWNER:=$(echo "${GHREPO%%/*}" | tr '[:upper:]' '[:lower:]')}"
# GHCR_TOKEN fällt auf REPO_TOKEN zurück, wenn leer
: "${GHCR_TOKEN:=${REPO_TOKEN:-}}"
