#!/usr/bin/env bash
# osint-lab setup — instala herramientas del sistema, venv Python y clona tools OSINT

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$LAB_DIR/tools"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

step()  { echo -e "\n${CYAN}==> $1${NC}"; }
ok()    { echo -e "${GREEN}  ✓ $1${NC}"; }
warn()  { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail()  { echo -e "${RED}  ✗ $1${NC}"; }

# ── 1. Herramientas del sistema ───────────────────────────────────────────────
step "Instalando herramientas del sistema (requiere sudo)"
sudo apt-get update -qq
sudo apt-get install -y \
    git curl wget jq tree tmux \
    python3 python3-pip python3-venv \
    ripgrep fd-find \
    nmap dnsutils whois \
    exiftool \
    sqlite3 \
    net-tools \
    bat \
    htop \
    2>/dev/null && ok "apt packages instalados" || warn "Algunos paquetes fallaron — continúa de todos modos"

# bat se instala como batcat en Ubuntu/Debian — crear alias
if command -v batcat &>/dev/null && ! command -v bat &>/dev/null; then
    mkdir -p ~/.local/bin
    ln -sf "$(which batcat)" ~/.local/bin/bat
    ok "bat → symlink creado desde batcat"
fi

# fd se instala como fdfind en Ubuntu/Debian — crear alias
if command -v fdfind &>/dev/null && ! command -v fd &>/dev/null; then
    mkdir -p ~/.local/bin
    ln -sf "$(which fdfind)" ~/.local/bin/fd
    ok "fd → symlink creado desde fdfind"
fi

# ── 2. gitleaks (binario) ─────────────────────────────────────────────────────
step "Instalando gitleaks"
GITLEAKS_BIN="$TOOLS_DIR/gitleaks"
if [[ -x "$GITLEAKS_BIN" ]]; then
    ok "gitleaks ya instalado: $GITLEAKS_BIN"
else
    GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | jq -r '.tag_name' 2>/dev/null || echo "v8.18.4")
    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz"
    TMP=$(mktemp -d)
    if wget -q "$GITLEAKS_URL" -O "$TMP/gitleaks.tar.gz"; then
        tar -xzf "$TMP/gitleaks.tar.gz" -C "$TMP"
        mv "$TMP/gitleaks" "$GITLEAKS_BIN"
        chmod +x "$GITLEAKS_BIN"
        ok "gitleaks $GITLEAKS_VER instalado en $GITLEAKS_BIN"
    else
        warn "No se pudo descargar gitleaks (sin acceso a internet o fallo de red)"
    fi
    rm -rf "$TMP"
fi

# ── 3. subfinder (requiere Go) ────────────────────────────────────────────────
step "Verificando subfinder"
SUBFINDER_BIN="$TOOLS_DIR/subfinder"
if [[ -x "$SUBFINDER_BIN" ]]; then
    ok "subfinder ya instalado"
elif command -v go &>/dev/null; then
    GOBIN="$TOOLS_DIR" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null \
        && ok "subfinder instalado" || warn "subfinder: falló instalación con Go"
else
    warn "Go no encontrado — subfinder omitido. Instala Go y corre: GOBIN=$TOOLS_DIR go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

# ── 4. Python venv ────────────────────────────────────────────────────────────
step "Configurando entorno Python"
VENV_DIR="$LAB_DIR/.venv"
if [[ -d "$VENV_DIR" ]]; then
    ok "venv ya existe en $VENV_DIR"
else
    python3 -m venv "$VENV_DIR"
    ok "venv creado en $VENV_DIR"
fi

# Activar e instalar deps
source "$VENV_DIR/bin/activate"
pip install -q --upgrade pip
pip install -q -r "$LAB_DIR/requirements.txt"
ok "Python deps instalados"
deactivate

# ── 5. Clonar herramientas OSINT ──────────────────────────────────────────────
step "Clonando herramientas OSINT"

clone_tool() {
    local name="$1" url="$2" dir="$TOOLS_DIR/$1"
    if [[ -d "$dir/.git" ]]; then
        ok "$name ya clonado — actualizando"
        git -C "$dir" pull -q
    else
        git clone -q "$url" "$dir" && ok "$name clonado" || warn "$name: clone falló"
    fi
}

# Solo se clona lo que algún módulo invoca de verdad. SpiderFoot está en el roadmap
# (docs/ROADMAP.md): clonarlo ahora serían ~200 MB sin usar.
clone_tool "theHarvester" "https://github.com/laramies/theHarvester.git"
clone_tool "sherlock"      "https://github.com/sherlock-project/sherlock.git"

# Instalar deps de theHarvester y sherlock dentro del venv
source "$VENV_DIR/bin/activate"
[[ -f "$TOOLS_DIR/theHarvester/requirements/base.txt" ]] && \
    pip install -q -r "$TOOLS_DIR/theHarvester/requirements/base.txt" && ok "theHarvester deps instalados"
[[ -f "$TOOLS_DIR/sherlock/requirements.txt" ]] && \
    pip install -q -r "$TOOLS_DIR/sherlock/requirements.txt" && ok "sherlock deps instalados"
deactivate

# ── 6. Vault y guardrails ─────────────────────────────────────────────────────
# Los directorios de salida viven en el vault, no en la raíz del repo: init_vault.sh
# los crea con los permisos correctos e instala el hook de pre-commit.
step "Inicializando vault"
bash "$LAB_DIR/scripts/init_vault.sh" >/dev/null 2>&1 && ok "vault listo" \
    || warn "init_vault falló — correr manualmente: make init"

# ── 7. Permisos de scripts ────────────────────────────────────────────────────
step "Dando permisos de ejecución a scripts"
chmod +x "$LAB_DIR/scripts/"*.sh 2>/dev/null || true
chmod +x "$LAB_DIR/scripts/"*.py 2>/dev/null || true
ok "Scripts ejecutables"

# ── 8. Resumen ────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  osint-lab setup completado${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo ""
echo "  Siguiente paso — personalizar el vault:"
echo "    \$EDITOR vault/config/targets.json     → tus identidades reales"
echo "    \$EDITOR vault/.env                    → API keys opcionales"
echo ""
echo "  Después:"
echo "    make audit    → auditoría completa"
echo "    make verify   → comprueba que nada sensible llegue a git"
echo "    make help     → todos los comandos"
echo ""

# Verificación rápida
echo -e "${CYAN}  Herramientas disponibles:${NC}"
for tool in nmap whois dig exiftool jq rg fd bat tmux; do
    if command -v "$tool" &>/dev/null; then
        printf "    %-15s %s\n" "$tool" "$(command -v "$tool")"
    else
        printf "    %-15s %s\n" "$tool" "(no encontrado)"
    fi
done
[[ -x "$TOOLS_DIR/gitleaks" ]]  && printf "    %-15s %s\n" "gitleaks"  "$TOOLS_DIR/gitleaks"  || printf "    %-15s %s\n" "gitleaks"  "(no instalado)"
[[ -x "$TOOLS_DIR/subfinder" ]] && printf "    %-15s %s\n" "subfinder" "$TOOLS_DIR/subfinder" || printf "    %-15s %s\n" "subfinder" "(requiere Go)"
[[ -d "$TOOLS_DIR/sherlock" ]]  && printf "    %-15s %s\n" "sherlock"  "$TOOLS_DIR/sherlock/sherlock.py"
[[ -d "$TOOLS_DIR/theHarvester" ]] && printf "    %-15s %s\n" "theHarvester" "$TOOLS_DIR/theHarvester/theHarvester.py"
echo ""
