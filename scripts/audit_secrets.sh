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

# Dos niveles de señal, porque no son el mismo hallazgo:
#
#   SECRET_RE   — credenciales con estructura propia (un token de GitHub solo puede
#                 ser un token de GitHub). Cada coincidencia es accionable: se reporta
#                 archivo por archivo con severidad alta.
#
#   PATTERNS    — palabras como "password" o "token". Aparecen en READMEs, plantillas
#                 de docker-compose y lockfiles sin que haya ningún secreto. Reportarlas
#                 una por archivo produce cientos de hallazgos que entierran los reales,
#                 así que se agregan en un único hallazgo informativo por directorio.
SECRET_PATTERNS=(
    'ghp_[A-Za-z0-9]{36}'                      # GitHub personal access token
    'github_pat_[A-Za-z0-9_]{50,}'             # GitHub fine-grained PAT
    'AKIA[0-9A-Z]{16}'                         # AWS access key
    'sk-[A-Za-z0-9]{32,}'                      # API keys estilo OpenAI
    'xox[baprs]-[A-Za-z0-9-]{10,}'             # Slack token
    'AIza[0-9A-Za-z_-]{35}'                    # Google API key
    'glpat-[A-Za-z0-9_-]{20}'                  # GitLab PAT
    '-----BEGIN [A-Z ]*PRIVATE KEY-----'       # Clave privada embebida
    '(postgres|postgresql|mysql|mongodb|redis|amqp)://[^:@/[:space:]]+:[^@[:space:]]{6,}@'
)
SECRET_RE=$(IFS='|'; echo "${SECRET_PATTERNS[*]}")

# El propio lab se excluye de todos los escaneos: sus patrones son la definición
# de lo que busca, no un hallazgo.
is_own_lab() { [[ "$1" == "$LAB_DIR"* ]]; }

# ── 1. Patrones de secretos en código ─────────────────────────────────────────
section "1. Secretos en árboles de código"
RG=$(command -v rg 2>/dev/null || true)
[[ -x /usr/bin/rg ]] && RG=/usr/bin/rg

# scan_re <regex> <dir> [glob...] — archivos que contienen el patrón dado.
#
# Usa ripgrep si está; si no, cae a grep -r, más lento pero presente en cualquier
# sistema. Sin fallback este módulo quedaría vacío en máquinas sin ripgrep, y la
# ausencia de hallazgos se confundiría con un resultado limpio.
#
# Se excluyen artefactos de build (.next, .pio, build, target, vendor) y lockfiles:
# contienen credenciales copiadas del fuente o ejemplos de librerías de terceros, y
# el hallazgo accionable está siempre en el archivo original, no en la copia generada.
scan_re() {
    local re="$1" dir="$2"; shift 2
    if [[ -n "$RG" ]]; then
        local globs=()
        for g in "$@"; do globs+=(--glob "$g"); done
        "$RG" --no-heading -i -l -e "$re" \
            --glob '!.venv' --glob '!node_modules' --glob '!.git' --glob '!dist' \
            --glob '!.next' --glob '!.pio' --glob '!build' --glob '!target' \
            --glob '!vendor' --glob '!__pycache__' --glob '!*.lock' \
            --glob '!package-lock.json' \
            "${globs[@]}" "$dir" 2>/dev/null || true
    else
        grep -rIl -iE "$re" "$dir" \
            --exclude-dir=.venv --exclude-dir=node_modules \
            --exclude-dir=.git --exclude-dir=dist \
            --exclude-dir=.next --exclude-dir=.pio --exclude-dir=build \
            --exclude-dir=target --exclude-dir=vendor --exclude-dir=__pycache__ \
            --exclude='*.lock' --exclude='package-lock.json' 2>/dev/null || true
    fi
}

if [[ -z "$RG" ]]; then
    note "ripgrep no encontrado — usando grep (más lento, misma cobertura)"
    add_finding "INFO" "ripgrep no instalado" \
        "El escaneo usó grep como alternativa. Instalar ripgrep acelera el módulo: sudo apt install ripgrep"
fi

for CODE_DIR in $CODE_DIRS; do
    [[ -d "$CODE_DIR" ]] || continue
    note "Escaneando $CODE_DIR"

    # 1a. Credenciales con forma reconocible — cada una es accionable
    HARD_HITS=0
    while IFS= read -r f; do
        [[ -z "$f" || "$f" == *.example ]] && continue
        is_own_lab "$f" && continue
        HARD_HITS=$((HARD_HITS + 1))
        crit "Credencial con formato reconocible: $f"
        add_finding "CRITICAL" "Credencial con formato reconocible en código" \
            "$f contiene una cadena con estructura de token o clave privada (GitHub, AWS, Google, Slack, GitLab, clave PEM o URL de conexión con contraseña). Verificar y rotar si es real."
    done < <(scan_re "$SECRET_RE" "$CODE_DIR")
    [[ "$HARD_HITS" -eq 0 ]] && info "Sin credenciales con formato reconocible en $CODE_DIR"

    # 1b. Menciones genéricas — se agregan, no se listan una por una
    SOFT_HITS=$(scan_re "$PATTERNS" "$CODE_DIR" | grep -vc "^$LAB_DIR" || true)
    if [[ "${SOFT_HITS:-0}" -gt 0 ]]; then
        note "$SOFT_HITS archivos mencionan términos sensibles (revisión manual)"
        add_finding "INFO" "Menciones de términos sensibles en $CODE_DIR" \
            "$SOFT_HITS archivos contienen términos como: $PATTERNS. La mayoría serán documentación o plantillas; sirve como mapa de dónde revisar, no como lista de fugas."
    fi
done

# Montaje de red: se acota con timeout, igual que en audit_local.sh
CLOUD_TIMEOUT=$(cfg '.local_audit.cloud_scan_timeout' "180")

for CLOUD_DIR in $CLOUD_DIRS; do
    [[ -d "$CLOUD_DIR" ]] || continue
    note "Escaneando almacenamiento sincronizado: $CLOUD_DIR (timeout ${CLOUD_TIMEOUT}s)"

    while IFS= read -r f; do
        [[ -z "$f" || "$f" == *.example ]] && continue
        crit "Secretos sincronizados a la nube: $f"
        add_finding "CRITICAL" "Credenciales en almacenamiento en la nube" \
            "$f — credenciales replicadas fuera del disco local; su exposición depende de la seguridad de la cuenta en la nube."
    done < <(timeout "$CLOUD_TIMEOUT" bash -c \
        "$(declare -f scan_re); RG='$RG'; \
         scan_re '$SECRET_RE' '$CLOUD_DIR' '*.env' '*.json' '*.txt' '*.yml' '*.yaml'" \
        2>/dev/null | head -20 || true)
done

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
