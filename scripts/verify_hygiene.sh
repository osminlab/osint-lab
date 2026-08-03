#!/usr/bin/env bash
# verify_hygiene.sh — Audita al propio lab: ¿puede algo sensible llegar al repo público?
#
# Se corre solo (make verify) y también al final de make init.

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

FAILED=0
pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILED=1; }
skip() { echo -e "  ${BLUE}·${NC} $1"; }

echo -e "\n${BOLD}Verificación de higiene del lab${NC}"
echo ""

cd "$LAB_DIR" || exit 1

# ── 1. Nada del vault está rastreado ──────────────────────────────────────────
TRACKED_VAULT=$(git ls-files vault/ 2>/dev/null || true)
if [[ -z "$TRACKED_VAULT" ]]; then
    pass "Ningún archivo del vault está rastreado por git"
else
    fail "Archivos del vault RASTREADOS por git:"
    sed 's/^/      /' <<< "$TRACKED_VAULT"
    echo -e "      ${YELLOW}corregir: git rm -r --cached vault/${NC}"
fi

# ── 2. Rutas sensibles efectivamente ignoradas ────────────────────────────────
for path in vault/config/targets.json vault/reports/x.md config/targets.json .env; do
    if git check-ignore -q --no-index "$path" 2>/dev/null; then
        pass "Ignorado: $path"
    else
        fail "NO ignorado por .gitignore: $path"
    fi
done

# ── 3. La plantilla pública no contiene datos reales ──────────────────────────
if [[ -f "$CONFIG_FILE" ]] && command -v jq >/dev/null 2>&1; then
    LEAKED=0
    while IFS= read -r identity; do
        # Los placeholders de la plantilla no cuentan como identidad real
        [[ -z "$identity" ]] && continue
        shopt -s nocasematch
        if [[ "$identity" == your* ]]; then shopt -u nocasematch; continue; fi
        shopt -u nocasematch
        if grep -qiF "$identity" "$CONFIG_TEMPLATE" 2>/dev/null; then
            fail "La plantilla pública contiene una identidad real: «$identity»"
            LEAKED=1
        fi
    done < <(jq -r '[.identities.emails[]?, .identities.usernames[]?,
                     .identities.full_names[]?] | .[]' "$CONFIG_FILE" 2>/dev/null)
    [[ "$LEAKED" -eq 0 ]] && pass "config/targets.example.json sin identidades reales"
else
    skip "Config del vault ausente — comparación con la plantilla omitida"
fi

# ── 4. El hook de pre-commit está instalado ───────────────────────────────────
HOOKS_DIR=$(git rev-parse --git-path hooks 2>/dev/null || true)
if [[ -n "$HOOKS_DIR" && -x "$HOOKS_DIR/pre-commit" ]]; then
    pass "Hook de pre-commit instalado"
else
    fail "Hook de pre-commit NO instalado — correr: make init"
fi

# ── 5. Permisos del vault ─────────────────────────────────────────────────────
if [[ -d "$VAULT_DIR" ]]; then
    PERMS=$(stat -c "%a" "$VAULT_DIR" 2>/dev/null || echo "?")
    if [[ "$PERMS" == "700" ]]; then
        pass "Permisos del vault: 700"
    else
        fail "Permisos del vault: $PERMS (debería ser 700) — corregir: chmod 700 vault"
    fi
else
    skip "Vault no existe todavía — correr: make init"
fi

# ── 6. Nada sensible en el índice ahora mismo ─────────────────────────────────
# Solo altas y modificaciones: un borrado staged de una ruta sensible es lo deseable.
STAGED_BAD=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null \
    | grep -E '^(vault/|scans/|reports/|identities/|leaks/|config/targets\.json|\.env)' || true)
if [[ -z "$STAGED_BAD" ]]; then
    pass "Índice de git limpio de rutas sensibles"
else
    fail "Rutas sensibles en el índice:"
    sed 's/^/      /' <<< "$STAGED_BAD"
fi

echo ""
if [[ "$FAILED" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Higiene correcta.${NC} El repositorio puede publicarse sin filtrar datos."
else
    echo -e "${RED}${BOLD}Se encontraron problemas de higiene.${NC} Corregir antes de hacer push."
fi
echo ""

exit "$FAILED"
