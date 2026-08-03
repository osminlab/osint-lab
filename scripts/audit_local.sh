#!/usr/bin/env bash
# audit_local.sh — Superficie de exposición de la máquina local:
# puertos, Docker, .env, permisos SSH, grupos, estado del sistema.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

require_config
init_findings "local"
banner "AUDITORÍA LOCAL"

# ── 1. Puertos escuchando en interfaces externas ──────────────────────────────
section "1. Puertos en interfaces externas"
# Se excluye todo el rango loopback (127.0.0.0/8), no solo 127.0.0.1: systemd-resolved
# escucha en 127.0.0.53 y 127.0.0.54, que no son exposición de red.
EXPOSED_PORTS=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' || true)

if [[ -z "$EXPOSED_PORTS" ]]; then
    info "Sin puertos expuestos en interfaces externas"
else
    while IFS= read -r ADDR; do
        [[ -z "$ADDR" ]] && continue
        PORT="${ADDR##*:}"
        [[ "$PORT" =~ ^[0-9]+$ ]] || continue

        case "$PORT" in
            5432|3306|27017|6379|9200|11211)
                crit "Base de datos expuesta en $ADDR (puerto $PORT)"
                add_finding "CRITICAL" "Base de datos expuesta en la red" \
                    "Puerto $PORT escuchando en $ADDR — accesible desde la red local. Vincular a 127.0.0.1 en la configuración del servicio o del contenedor." ;;
            *)
                warn "Puerto $PORT expuesto en $ADDR"
                add_finding "HIGH" "Puerto $PORT expuesto en la red" \
                    "Servicio escuchando en $ADDR — visible para cualquier host de la red local." ;;
        esac
    done <<< "$EXPOSED_PORTS"
fi

# ── 2. Contenedores Docker ────────────────────────────────────────────────────
section "2. Contenedores Docker"
if command -v docker &>/dev/null && docker info &>/dev/null; then
    EXPOSED_DOCKER=$(docker ps --format '{{.Names}}: {{.Ports}}' 2>/dev/null \
        | grep -E '0\.0\.0\.0:|\[::\]:' || true)

    if [[ -n "$EXPOSED_DOCKER" ]]; then
        while IFS= read -r line; do
            crit "Contenedor con puerto publicado en todas las interfaces: $line"
            add_finding "CRITICAL" "Contenedor Docker publicado en la red" \
                "$line — accesible desde la red local. Prefijar el mapeo con 127.0.0.1 en docker-compose."
        done <<< "$EXPOSED_DOCKER"
    else
        info "Ningún contenedor publica puertos fuera de localhost"
    fi
else
    note "Docker no disponible — módulo omitido"
fi

# ── 3. Credenciales sincronizadas a la nube ───────────────────────────────────
section "3. Archivos .env en almacenamiento sincronizado"
CLOUD_DIRS=$(cfg '.local_audit.cloud_sync_dirs[]')
CLOUD_FOUND=0

for CLOUD_DIR in $CLOUD_DIRS; do
    [[ -d "$CLOUD_DIR" ]] || continue
    CLOUD_FOUND=1
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        warn "Credenciales sincronizadas a la nube: $f"
        add_finding "HIGH" "Archivo .env con credenciales en almacenamiento en la nube" \
            "$f — si la cuenta de la nube es comprometida, estas credenciales quedan expuestas."
    done < <(find "$CLOUD_DIR" -name ".env" -not -name "*.example" 2>/dev/null)
done

if [[ "$CLOUD_FOUND" -eq 0 ]]; then
    note "Ningún directorio de sincronización configurado existe en disco"
else
    info "Revisión de almacenamiento sincronizado completada"
fi

# ── 4. Archivos .env locales sin protección ───────────────────────────────────
section "4. Archivos .env en árboles de código"
CODE_DIRS=$(cfg '.local_audit.code_dirs[]')

for CODE_DIR in $CODE_DIRS; do
    [[ -d "$CODE_DIR" ]] || continue
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        [[ "$f" == "$LAB_DIR"/* ]] && continue   # el vault del propio lab no es hallazgo
        REPO_DIR=$(git -C "$(dirname "$f")" rev-parse --show-toplevel 2>/dev/null || true)

        if [[ -z "$REPO_DIR" ]]; then
            note ".env fuera de repositorio: $f"
        elif git -C "$REPO_DIR" check-ignore -q "$f" 2>/dev/null; then
            info ".env protegido por .gitignore: $f"
        else
            crit ".env NO protegido por .gitignore: $f"
            add_finding "HIGH" ".env sin protección de .gitignore" \
                "$f está dentro del repositorio $REPO_DIR pero no es ignorado — riesgo de commit accidental."
        fi
    done < <(find "$CODE_DIR" -name ".env" -not -name "*.example" \
        -not -path "*/node_modules/*" -not -path "*/.venv/*" 2>/dev/null)
done

# ── 5. Permisos de claves SSH ─────────────────────────────────────────────────
section "5. Permisos SSH"
SSH_DIR=$(cfg '.local_audit.ssh_dir' "$HOME/.ssh")

if [[ -d "$SSH_DIR" ]]; then
    while IFS= read -r f; do
        PERMS=$(stat -c "%a" "$f" 2>/dev/null || true)
        NAME=$(basename "$f")

        if [[ "$NAME" == id_* && "$NAME" != *.pub && "$PERMS" != "600" ]]; then
            crit "Clave privada con permisos $PERMS: $NAME (debe ser 600)"
            add_finding "CRITICAL" "Clave SSH privada con permisos inseguros" \
                "$f tiene permisos $PERMS — otros usuarios del sistema podrían leerla. Corregir: chmod 600 $f"
        elif [[ "$NAME" == "authorized_keys" && "$PERMS" != "600" ]]; then
            warn "authorized_keys con permisos $PERMS (debe ser 600)"
            add_finding "MEDIUM" "authorized_keys con permisos laxos" \
                "$f tiene permisos $PERMS — permitiría añadir claves de acceso."
        else
            info "$NAME: $PERMS"
        fi
    done < <(find "$SSH_DIR" -maxdepth 1 -type f 2>/dev/null)
else
    note "Directorio SSH no encontrado en $SSH_DIR"
fi

# ── 6. Grupos con escalada de privilegios ─────────────────────────────────────
section "6. Grupos de usuario"
CURRENT_GROUPS=$(id -Gn 2>/dev/null || true)
note "Grupos actuales: $CURRENT_GROUPS"

while IFS= read -r g; do
    [[ -z "$g" ]] && continue
    grep -qw "$g" <<< "$CURRENT_GROUPS" || continue

    if [[ "$g" == "docker" || "$g" == "lxd" ]]; then
        warn "Grupo '$g' activo — equivale a root sin contraseña"
        add_finding "HIGH" "Membresía en grupo $g = root efectivo" \
            "El grupo $g permite montar el sistema de archivos raíz dentro de un contenedor y escalar a root sin contraseña."
    else
        medium "Grupo de privilegios elevados activo: $g"
        add_finding "MEDIUM" "Grupo de privilegios elevados: $g" \
            "El usuario actual pertenece a $g."
    fi
done < <(cfg '.local_audit.dangerous_groups[]')

# ── 7. Estado del sistema ─────────────────────────────────────────────────────
section "7. Estado del sistema"
OS=$(lsb_release -ds 2>/dev/null || uname -srm)
KERNEL=$(uname -r)
info "OS: $OS"
info "Kernel: $KERNEL"

if command -v apt &>/dev/null; then
    # grep -c ya imprime 0 cuando no hay coincidencias, pero sale con código 1 y
    # `set -e` abortaría el script. `|| true` neutraliza el estado sin alterar la
    # salida — a diferencia de `|| echo 0`, que añadiría una segunda línea.
    PENDING=$(apt list --upgradable 2>/dev/null | grep -vc "^Listing" || true)
    if [[ "${PENDING:-0}" -gt 0 ]]; then
        medium "$PENDING actualizaciones pendientes"
        add_finding "MEDIUM" "Actualizaciones de sistema pendientes" \
            "$PENDING paquetes por actualizar — correr: sudo apt upgrade"
    else
        info "Sistema al día"
    fi
fi

# ── 8. Variables de entorno sensibles ─────────────────────────────────────────
section "8. Variables de entorno sensibles"
SENSITIVE_ENV=$(env 2>/dev/null \
    | grep -iE '^[A-Z_]*(TOKEN|API_KEY|SECRET|PASSWORD|BEARER|PRIVATE)[A-Z_]*=' || true)

if [[ -n "$SENSITIVE_ENV" ]]; then
    while IFS= read -r line; do
        VAR="${line%%=*}"
        medium "Variable sensible activa: $VAR"
        add_finding "MEDIUM" "Variable de entorno sensible activa" \
            "$VAR está exportada en la sesión — visible para cualquier proceso hijo y en /proc."
    done <<< "$SENSITIVE_ENV"
else
    info "Sin variables de entorno sensibles detectadas"
fi

save_findings
