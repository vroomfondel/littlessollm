#!/bin/bash
# initial_setup_github.sh
#
# Erstellt/konfiguriert das GitHub-Repo und die zugehörigen Secrets.
#
# Images werden zu ghcr.io (GitHub Container Registry) gepusht.
# CI authentifiziert sich mit dem eingebauten GITHUB_TOKEN
# (permissions: packages: write) — es muss kein Registry-Secret
# hinterlegt werden.
#
# Package-Sichtbarkeit (public/private) wird nach dem ersten Push
# über die GitHub-UI oder via API gesetzt, z.B.:
#   # gh api -X PATCH /orgs/<owner>/packages/container/<image>/visibility \
#   #   -f visibility=public

set -uo pipefail

cd "$(dirname "$0")" || exit 2

# ---------------------------------------------------------------------------
# Logging-Helfer — einheitliche, sichtbare Status-Ausgaben
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  _C_INFO=$'\033[0;34m'; _C_OK=$'\033[0;32m'; _C_WARN=$'\033[0;33m'; _C_ERR=$'\033[0;31m'; _C_OFF=$'\033[0m'
else
  _C_INFO=''; _C_OK=''; _C_WARN=''; _C_ERR=''; _C_OFF=''
fi
info() { printf '%s[INFO]%s %s\n' "$_C_INFO" "$_C_OFF" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$_C_OK"   "$_C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$_C_WARN" "$_C_OFF" "$*" >&2; }
err()  { printf '%s[FAIL]%s %s\n' "$_C_ERR"  "$_C_OFF" "$*" >&2; }

source ./include.sh
# note: source include.local.sh if found (which it should -> otherwise makes no sense)

# ---------------------------------------------------------------------------
# Pflicht-Variablen prüfen (klar melden, statt später kryptisch zu scheitern)
# ---------------------------------------------------------------------------
missing=()
for var in GHREPO GIST_TOKEN REPO_PRIV_TOKEN; do
  [[ -n "${!var:-}" ]] || missing+=("$var")
done
if (( ${#missing[@]} )); then
  err "Fehlende Pflicht-Variablen (aus include.local.sh?): ${missing[*]}"
  exit 3
fi

# Optional: GHCR-Token validieren (nicht-fatal)
if [[ -n "${GHCR_TOKEN:-}" && -n "${GHCR_USER:-}" ]]; then
  info "Validiere GHCR-Token für '$GHCR_USER' …"
  if python3 ./check_ghcr_token.py "$GHCR_USER" "$GHCR_TOKEN" \
       --owner "${GHREPO%%/*}" --image "$IMAGE_NAME"; then
    ok "GHCR-Token validiert."
  else
    warn "GHCR-Token-Validierung fehlgeschlagen (continuing)."
  fi
else
  info "Kein GHCR_TOKEN/GHCR_USER gesetzt — überspringe Token-Validierung."
fi

# Derive GH_VISIBILITY from GH_REPO_PUBLIC (default: public)
if [[ "${GH_REPO_PUBLIC:-true}" == "true" ]]; then
  GH_VISIBILITY="--public"
else
  GH_VISIBILITY="--private"
fi

# ---------------------------------------------------------------------------
# Öffentlichen Gist für Clone-Count-Badges anlegen, falls GIST_ID leer
# ---------------------------------------------------------------------------
if [[ -z "${GIST_ID:-}" ]]; then
  REPO_SHORT="${GHREPO##*/}"
  GIST_DESC="$REPO_SHORT clone tracking"

  info "GIST_ID nicht gesetzt — suche/erstelle Gist (desc: '$GIST_DESC') …"

  # Prüfen ob ein Gist mit dieser Beschreibung bereits existiert (-F: literal, kein Regex)
  EXISTING_GIST_ID=$(GH_TOKEN="$GIST_TOKEN" gh gist list --public -L 100 \
    | grep -F "$GIST_DESC" | head -1 | cut -f1)

  if [[ -n "$EXISTING_GIST_ID" ]]; then
    GIST_ID="$EXISTING_GIST_ID"
    ok "Vorhandenen Gist gefunden: $GIST_ID"
  else
    HIST_FILE="/tmp/${REPO_SHORT}_clone_history.json"
    BADGE_FILE="/tmp/${REPO_SHORT}_clone_count.json"
    GHCR_BADGE_FILE="/tmp/${REPO_SHORT}_ghcr_downloads.json"
    echo '{}' > "$HIST_FILE"
    # Badge-Dateien mit gültigem shields.io-Endpoint-Schema seeden, damit die
    # Badges zwischen Gist-Anlage und erstem update_badge.py-Lauf nicht
    # "invalid response" zeigen. update_badge.py überschreibt sie danach.
    echo '{"schemaVersion":1,"label":"Clones","message":"n/a","color":"lightgrey","namedLogo":"github","logoColor":"white"}' > "$BADGE_FILE"
    echo '{"schemaVersion":1,"label":"ghcr.io pulls","message":"n/a","color":"lightgrey","namedLogo":"github","logoColor":"white"}' > "$GHCR_BADGE_FILE"

    GIST_URL=$(GH_TOKEN="$GIST_TOKEN" gh gist create --public --desc "$GIST_DESC" \
      "$HIST_FILE" "$BADGE_FILE" "$GHCR_BADGE_FILE")
    GIST_ID="${GIST_URL##*/}"
    rm -f "$HIST_FILE" "$BADGE_FILE" "$GHCR_BADGE_FILE"

    if [[ -n "$GIST_ID" ]]; then
      ok "Gist erstellt: $GIST_URL (ID: $GIST_ID)"
    else
      err "Gist-Erstellung fehlgeschlagen — konnte keine ID aus '$GIST_URL' ableiten."
      exit 4
    fi
  fi

  # In include.local.sh persistieren (ersetzen ODER anhängen) + verifizieren
  if grep -q '^GIST_ID=' include.local.sh; then
    sed -i "s|^GIST_ID=.*|GIST_ID=\"$GIST_ID\"|" include.local.sh
  else
    printf '\nGIST_ID="%s"\n' "$GIST_ID" >> include.local.sh
  fi
  PERSISTED=$(grep -oP '^GIST_ID="?\K[^"]+' include.local.sh | head -1)
  if [[ "$PERSISTED" == "$GIST_ID" ]]; then
    ok "GIST_ID in include.local.sh persistiert."
  else
    err "GIST_ID NICHT korrekt in include.local.sh persistiert (gefunden: '${PERSISTED:-<leer>}')."
  fi
else
  info "GIST_ID bereits gesetzt: $GIST_ID"
fi

# ---------------------------------------------------------------------------
# GIST_ID-Default in update_badge.py aktualisieren, falls vorhanden & abweichend
# Ersetzt den Wert innerhalb  os.environ.get("GIST_ID", "<hier>")  — auch wenn
# er aktuell leer ist (das war die Ursache des vorherigen sed-Fehlers).
# ---------------------------------------------------------------------------
if [[ -f update_badge.py ]]; then
  CURRENT_GIST_DEFAULT=$(grep -oP 'os\.environ\.get\("GIST_ID",\s*"\K[^"]*' update_badge.py | head -1)
  if [[ -z "${GIST_ID:-}" ]]; then
    warn "GIST_ID leer — überspringe Update von update_badge.py."
  elif [[ "$CURRENT_GIST_DEFAULT" == "$GIST_ID" ]]; then
    info "update_badge.py: GIST_ID-Default bereits '$GIST_ID' — nichts zu tun."
  else
    # Gezielte Ersetzung nur innerhalb des get()-Aufrufs; \1 = Prefix bis zum
    # öffnenden Quote, \2 = schließendes Quote. Funktioniert auch bei leerem Default.
    sed -i -E "s#(os\.environ\.get\(\"GIST_ID\",[[:space:]]*\")[^\"]*(\")#\1${GIST_ID}\2#" update_badge.py
    NEW_DEFAULT=$(grep -oP 'os\.environ\.get\("GIST_ID",\s*"\K[^"]*' update_badge.py | head -1)
    if [[ "$NEW_DEFAULT" == "$GIST_ID" ]]; then
      ok "update_badge.py: GIST_ID-Default aktualisiert ('${CURRENT_GIST_DEFAULT:-<leer>}' -> '$GIST_ID')."
    else
      err "update_badge.py: Ersetzung fehlgeschlagen (immer noch '${NEW_DEFAULT:-<leer>}')."
    fi
  fi
fi

# ---------------------------------------------------------------------------
# GitHub-Repo erstellen, falls noch nicht vorhanden
# ---------------------------------------------------------------------------
if gh repo view "$GHREPO" &>/dev/null; then
  info "GitHub-Repo existiert bereits: $GHREPO"
else
  if gh repo create "$GHREPO" $GH_VISIBILITY; then
    ok "GitHub-Repo erstellt: $GHREPO ($GH_VISIBILITY)"
  else
    err "Konnte GitHub-Repo nicht erstellen: $GHREPO"
    exit 5
  fi
fi

# ---------------------------------------------------------------------------
# Secrets setzen — mit Non-Empty-Check und Erfolgsmeldung
# ---------------------------------------------------------------------------
set_secret() {
  local name="$1" value="$2"
  if [[ -z "$value" ]]; then
    warn "Secret '$name' hat leeren Wert — übersprungen."
    return 1
  fi
  if gh secret set "$name" --body "$value" --repo "$GHREPO" >/dev/null; then
    ok "Secret gesetzt: $name"
  else
    err "Konnte Secret nicht setzen: $name"
    return 1
  fi
}

set_secret GIST_ID        "${GIST_ID:-}"
set_secret GIST_TOKEN     "${GIST_TOKEN:-}"
set_secret REPO_PRIV_TOKEN "${REPO_PRIV_TOKEN:-}"

# NOTE: REPO_TOKEN only needed locally
info "Setup abgeschlossen."
