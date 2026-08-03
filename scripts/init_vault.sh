#!/usr/bin/env bash
# init_vault.sh — Prepara el vault local y los guardrails de git.
# Idempotente: nunca sobrescribe configuración ni datos existentes.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

banner "INICIALIZACIÓN DEL VAULT"

# ── 1. Estructura del vault ───────────────────────────────────────────────────
section "1. Estructura"
for d in config auditorias scans reports identities leaks; do
    mkdir -p "$VAULT_DIR/$d"
done
chmod 700 "$VAULT_DIR"
info "vault/ creado con permisos 700"

# ── 2. Configuración local ────────────────────────────────────────────────────
section "2. Configuración"
if [[ -f "$CONFIG_FILE" ]]; then
    info "Config ya existe — sin cambios: ${CONFIG_FILE/#$HOME/\~}"
else
    cp "$CONFIG_TEMPLATE" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    warn "Config creada desde la plantilla — falta personalizarla:"
    echo "        \$EDITOR ${CONFIG_FILE/#$HOME/\~}"
fi

if [[ ! -f "$VAULT_DIR/.env" ]]; then
    cat > "$VAULT_DIR/.env" <<'EOF'
# API keys del lab. Este archivo vive dentro del vault y nunca se versiona.
# export HIBP_API_KEY=""      # https://haveibeenpwned.com/API/Key
# export GITHUB_TOKEN=""      # eleva el rate limit de la API de GitHub
# export SHODAN_API_KEY=""
EOF
    chmod 600 "$VAULT_DIR/.env"
    info "vault/.env creado (plantilla vacía)"
fi

# ── 3. Guardrail de pre-commit ────────────────────────────────────────────────
section "3. Guardrail de git"
HOOKS_DIR=$(git -C "$LAB_DIR" rev-parse --git-path hooks 2>/dev/null || true)

if [[ -z "$HOOKS_DIR" ]]; then
    warn "No es un repositorio git — hook de pre-commit omitido"
else
    [[ "$HOOKS_DIR" != /* ]] && HOOKS_DIR="$LAB_DIR/$HOOKS_DIR"
    mkdir -p "$HOOKS_DIR"
    ln -sf "$LAB_DIR/scripts/hooks/pre-commit" "$HOOKS_DIR/pre-commit"
    chmod +x "$LAB_DIR/scripts/hooks/pre-commit"
    info "pre-commit enlazado — bloquea el commit de datos sensibles"
fi

# ── 4. Verificación ───────────────────────────────────────────────────────────
section "4. Verificación de higiene"
bash "$LAB_DIR/scripts/verify_hygiene.sh" || true

echo ""
echo -e "${GREEN}${BOLD}Vault listo.${NC} Siguiente paso:"
echo "  1. Editar ${CONFIG_FILE/#$HOME/\~} con tus identidades reales"
echo "  2. Correr: make audit"
echo ""
