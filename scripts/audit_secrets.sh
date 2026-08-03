#!/usr/bin/env bash
# audit_secrets.sh — Secretos en árboles de código, historial Git y almacenamiento en la nube.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

require_config
init_findings "secrets"
banner "AUDITORÍA DE SECRETOS"

CODE_DIRS=$(cfg '.local_audit.code_dirs[]')
CLOUD_DIRS=$(cfg '.local_audit.cloud_sync_dirs[]')
PATTERNS=$(jq -r '.local_audit.sensitive_patterns | join("|")' "$CONFIG_FILE")

# El propio lab se excluye de todos los escaneos: sus patrones son la definición
# de lo que busca, no un hallazgo.
is_own_lab() { [[ "$1" == "$LAB_DIR"* ]]; }

# ── 1. Patrones de secretos en código ─────────────────────────────────────────
section "1. Patrones de secretos (ripgrep)"
RG=$(command -v rg 2>/dev/null || true)
[[ -x /usr/bin/rg ]] && RG=/usr/bin/rg

if [[ -n "$RG" ]]; then
    for CODE_DIR in $CODE_DIRS; do
        [[ -d "$CODE_DIR" ]] || continue
        note "Escaneando $CODE_DIR"
        HIT_COUNT=0

        while IFS= read -r f; do
            [[ -z "$f" || "$f" == *.example ]] && continue
            is_own_lab "$f" && continue
            HIT_COUNT=$((HIT_COUNT + 1))
            warn "Patrones sensibles en: $f"
            add_finding "HIGH" "Posibles credenciales en código" \
                "$f contiene patrones del tipo: $PATTERNS"
        done < <("$RG" --no-heading -i -l -e "$PATTERNS" \
            --glob '!.venv' --glob '!node_modules' --glob '!.git' --glob '!dist' \
            "$CODE_DIR" 2>/dev/null || true)

        [[ "$HIT_COUNT" -eq 0 ]] && info "Sin patrones sensibles en $CODE_DIR"
    done

    for CLOUD_DIR in $CLOUD_DIRS; do
        [[ -d "$CLOUD_DIR" ]] || continue
        note "Escaneando almacenamiento sincronizado: $CLOUD_DIR"

        while IFS= read -r f; do
            [[ -z "$f" || "$f" == *.example ]] && continue
            crit "Secretos sincronizados a la nube: $f"
            add_finding "CRITICAL" "Credenciales en almacenamiento en la nube" \
                "$f — credenciales replicadas fuera del disco local; su exposición depende de la seguridad de la cuenta en la nube."
        done < <("$RG" --no-heading -i -l -e "$PATTERNS" \
            --glob '*.env' --glob '*.json' --glob '*.txt' --glob '*.yml' --glob '*.yaml' \
            "$CLOUD_DIR" 2>/dev/null | head -20 || true)
    done
else
    warn "ripgrep no instalado"
    add_finding "INFO" "ripgrep no disponible" "Instalar con: sudo apt install ripgrep"
fi

# ── 2. Historial Git ──────────────────────────────────────────────────────────
section "2. Historial Git (gitleaks)"
GITLEAKS="$TOOLS_DIR/gitleaks"
command -v gitleaks &>/dev/null && GITLEAKS=$(command -v gitleaks)

if [[ -x "$GITLEAKS" ]]; then
    for CODE_DIR in $CODE_DIRS; do
        [[ -d "$CODE_DIR" ]] || continue

        while IFS= read -r repo; do
            is_own_lab "$repo" && continue
            REPO_NAME=$(basename "$repo")
            printf "  %-40s " "$REPO_NAME"

            REPORT=$(mktemp "${TMPDIR:-/tmp}/gitleaks.XXXXXX.json")
            "$GITLEAKS" detect --source "$repo" --report-path "$REPORT" \
                --report-format json --no-banner --exit-code 0 &>/dev/null || true
            LEAKS=$(jq 'length' "$REPORT" 2>/dev/null || echo 0)
            rm -f "$REPORT"

            if [[ "$LEAKS" -gt 0 ]]; then
                echo -e "${RED}$LEAKS hallazgo(s)${NC}"
                add_finding "CRITICAL" "Secretos en el historial de Git" \
                    "$repo — gitleaks encontró $LEAKS secretos. Están en el historial: rotar las credenciales, reescribir el historial no basta."
            else
                echo -e "${GREEN}limpio${NC}"
            fi
        done < <(find "$CODE_DIR" -maxdepth 3 -name .git -type d -exec dirname {} \; 2>/dev/null)
    done
else
    warn "gitleaks no instalado"
    add_finding "INFO" "gitleaks no disponible" "Correr: make setup"
fi

# ── 3. Tokens OAuth de CLIs ───────────────────────────────────────────────────
section "3. Tokens de herramientas CLI"
declare -A CLI_TOKENS=(
    ["$HOME/.config/configstore/firebase-tools.json"]="Firebase CLI"
    ["$HOME/.config/gh/hosts.yml"]="GitHub CLI"
    ["$HOME/.docker/config.json"]="Docker registry"
    ["$HOME/.aws/credentials"]="AWS CLI"
    ["$HOME/.netrc"]="netrc"
)

for token_file in "${!CLI_TOKENS[@]}"; do
    [[ -f "$token_file" ]] || continue
    LABEL="${CLI_TOKENS[$token_file]}"
    PERMS=$(stat -c "%a" "$token_file" 2>/dev/null || echo "?")

    if [[ "$PERMS" != "600" && "$PERMS" != "400" ]]; then
        warn "$LABEL: credenciales con permisos $PERMS — $token_file"
        add_finding "HIGH" "Credenciales de $LABEL con permisos laxos" \
            "$token_file tiene permisos $PERMS — debería ser 600."
    else
        info "$LABEL: permisos correctos ($PERMS)"
        add_finding "LOW" "Credenciales de $LABEL presentes en disco" \
            "$token_file contiene credenciales activas. Revocar las sesiones que no uses."
    fi

    # Estas credenciales nunca deberían estar replicadas a la nube
    for CLOUD_DIR in $CLOUD_DIRS; do
        [[ -d "$CLOUD_DIR" ]] || continue
        while IFS= read -r found; do
            [[ -z "$found" ]] && continue
            crit "Credenciales de $LABEL sincronizadas a la nube: $found"
            add_finding "CRITICAL" "Credenciales de $LABEL en la nube" \
                "$found — tokens de sesión replicados fuera del disco local. Revocar y eliminar."
        done < <(find "$CLOUD_DIR" -name "$(basename "$token_file")" 2>/dev/null)
    done
done

save_findings
