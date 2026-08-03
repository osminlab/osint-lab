#!/usr/bin/env bash
# common.sh — Rutas, configuración y helpers compartidos por los módulos Bash.
#
# Invariante del lab: TODA salida que pueda contener hallazgos o PII se escribe
# bajo VAULT_DIR, que está en .gitignore. Ningún script debe construir rutas de
# salida por su cuenta.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VAULT_DIR="$LAB_DIR/vault"
CONFIG_FILE="$VAULT_DIR/config/targets.json"
CONFIG_TEMPLATE="$LAB_DIR/config/targets.example.json"
SCANS_DIR="$VAULT_DIR/scans"
REPORTS_DIR="$VAULT_DIR/reports"
TOOLS_DIR="$LAB_DIR/tools"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

section() { echo -e "\n${CYAN}${BOLD}══ $1 ══${NC}"; }
crit()    { echo -e "  ${RED}[CRÍTICO]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[ALTO]${NC}    $1"; }
medium()  { echo -e "  ${YELLOW}[MEDIO]${NC}   $1"; }
info()    { echo -e "  ${GREEN}[OK]${NC}      $1"; }
note()    { echo -e "  ${BLUE}[INFO]${NC}    $1"; }
die()     { echo -e "${RED}error:${NC} $1" >&2; exit 1; }

banner() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════╗${NC}"
    printf "${BOLD}║  %-43s ║${NC}\n" "$1 — $(date '+%Y-%m-%d %H:%M')"
    echo -e "${BOLD}╚═══════════════════════════════════════════════╝${NC}"
}

# ── Precondiciones ────────────────────────────────────────────────────────────

require_config() {
    [[ -f "$CONFIG_FILE" ]] || die "falta $CONFIG_FILE — correr: make init"
    command -v jq >/dev/null 2>&1 || die "jq no instalado — correr: make setup"
    jq empty "$CONFIG_FILE" 2>/dev/null || die "$CONFIG_FILE no es JSON válido"
    mkdir -p "$SCANS_DIR" "$REPORTS_DIR"
    chmod 700 "$VAULT_DIR" 2>/dev/null || true

    # Una config sin personalizar produce una auditoría de dominios ajenos: avisar,
    # pero no bloquear — el usuario puede querer probar el flujo antes de configurarlo.
    if jq -e '[.. | strings] | any(test("^[Yy]our[-@ ]"))' "$CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${YELLOW}aviso:${NC} la configuración conserva placeholders de la plantilla."
        echo -e "       Los resultados no serán tuyos hasta editar ${CONFIG_FILE/#$HOME/\~}"
    fi
}

# cfg <ruta-jq> [default] — lee un valor de la config, con expansión de ~
cfg() {
    local query="$1" default="${2:-}" value
    value=$(jq -r "$query // empty" "$CONFIG_FILE" 2>/dev/null || true)
    [[ -z "$value" ]] && value="$default"
    echo "${value//\~/$HOME}"
}

# ── Acumulación de hallazgos ──────────────────────────────────────────────────
# Los hallazgos se serializan con jq, no por concatenación de strings: los paths
# reales contienen comillas, comas, llaves y Unicode que rompen el JSON manual.

FINDINGS_FILE=""
MODULE_NAME=""

init_findings() {
    MODULE_NAME="$1"
    FINDINGS_FILE=$(mktemp "${TMPDIR:-/tmp}/osint-lab-findings.XXXXXX")
    chmod 600 "$FINDINGS_FILE"
    trap 'rm -f "$FINDINGS_FILE"' EXIT
}

add_finding() {
    local severity="$1" title="$2" detail="$3"
    jq -nc \
        --arg severity "$severity" \
        --arg module   "$MODULE_NAME" \
        --arg title    "$title" \
        --arg detail   "$detail" \
        '{severity: $severity, module: $module, title: $title, detail: $detail}' \
        >> "$FINDINGS_FILE"
}

# save_findings — vuelca los hallazgos como array JSON en el vault
save_findings() {
    local scan_file="$SCANS_DIR/${MODULE_NAME}_$(date +%Y%m%d_%H%M%S).json"
    local count=0

    if [[ -s "$FINDINGS_FILE" ]]; then
        jq -s '.' "$FINDINGS_FILE" > "$scan_file"
        count=$(wc -l < "$FINDINGS_FILE")
    else
        echo "[]" > "$scan_file"
    fi
    chmod 600 "$scan_file"

    echo ""
    echo -e "${GREEN}✓ Scan guardado:${NC} ${scan_file/#$HOME/\~}"
    echo -e "${CYAN}  Hallazgos: $count${NC}"
    echo ""
}
