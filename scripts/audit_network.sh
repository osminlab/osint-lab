#!/usr/bin/env bash
# audit_network.sh — DNS, correo (SPF/DMARC), WHOIS y exposición de servicios.
#
# El escaneo activo (nmap contra la IP de red local) está desactivado por defecto:
# se habilita con network_audit.aggressive_scan en la configuración. Ver docs/SECURITY.md.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

require_config
init_findings "network"
banner "AUDITORÍA DE RED"

DOMAINS=$(cfg '.identities.domains[]')
AGGRESSIVE=$(cfg '.network_audit.aggressive_scan' "false")
SCAN_LOCAL_IP=$(cfg '.network_audit.scan_local_ip' "true")
COMMON_PORTS=$(cfg '.network_audit.common_ports' "22,80,443,3306,5432,6379,8080,27017")

# ── 1. DNS y postura de correo ────────────────────────────────────────────────
section "1. DNS y postura de correo"
if command -v dig &>/dev/null; then
    for domain in $DOMAINS; do
        echo -e "\n  ${BOLD}$domain${NC}"
        A=$(dig +short "$domain" A 2>/dev/null | tr '\n' ' ')
        NS=$(dig +short "$domain" NS 2>/dev/null | tr '\n' ' ')
        MX=$(dig +short "$domain" MX 2>/dev/null | tr '\n' ' ')
        TXT=$(dig +short "$domain" TXT 2>/dev/null)

        info "A:   ${A:-(sin registro)}"
        info "NS:  ${NS:-(sin registro)}"
        info "MX:  ${MX:-(sin registro)}"

        if grep -q "v=spf1" <<< "$TXT"; then
            info "SPF configurado"
        else
            warn "$domain sin SPF — cualquiera puede suplantar el remitente"
            add_finding "MEDIUM" "Dominio sin registro SPF" \
                "$domain no publica SPF: un tercero puede enviar correo suplantando este dominio."
        fi

        # Un dominio con TXT wildcard devuelve cualquier cosa en _dmarc: solo cuenta
        # como DMARC un registro que realmente empiece por v=DMARC1.
        DMARC=$(dig +short "_dmarc.$domain" TXT 2>/dev/null | grep 'v=DMARC1' || true)
        if [[ -n "$DMARC" ]]; then
            info "DMARC: $DMARC"
            grep -qE 'p=(reject|quarantine)' <<< "$DMARC" || {
                medium "DMARC en p=none — solo monitorea, no bloquea"
                add_finding "LOW" "DMARC sin política de bloqueo" \
                    "$domain publica DMARC con p=none: reporta pero no rechaza correo suplantado."
            }
        else
            warn "$domain sin DMARC"
            add_finding "MEDIUM" "Dominio sin registro DMARC" \
                "$domain no publica DMARC: sin política ante fallos de SPF/DKIM."
        fi

        add_finding "INFO" "Superficie DNS de $domain" \
            "A: ${A:-—} | NS: ${NS:-—} | MX: ${MX:-—}"
    done
else
    warn "dig no instalado"
    add_finding "INFO" "dig no disponible" "Instalar con: sudo apt install dnsutils"
fi

# ── 2. WHOIS y vencimiento de dominios ────────────────────────────────────────
section "2. Registro de dominios (WHOIS)"
if command -v whois &>/dev/null; then
    for domain in $DOMAINS; do
        WHOIS_OUT=$(whois "$domain" 2>/dev/null | head -50 || true)
        EXPIRY=$(grep -iE 'expir' <<< "$WHOIS_OUT" | head -1 | cut -d: -f2- | xargs || true)
        REGISTRAR=$(grep -iE '^\s*registrar:' <<< "$WHOIS_OUT" | head -1 | cut -d: -f2- | xargs || true)
        PRIVACY=$(grep -icE 'privacy|redacted|whoisguard' <<< "$WHOIS_OUT" || true)

        echo -e "\n  ${BOLD}$domain${NC}"
        [[ -n "$REGISTRAR" ]] && info "Registrar: $REGISTRAR"
        [[ -n "$EXPIRY" ]] && info "Expira: $EXPIRY"

        if [[ "$PRIVACY" -eq 0 ]]; then
            medium "WHOIS sin privacidad — datos de contacto públicos"
            add_finding "MEDIUM" "WHOIS sin protección de privacidad" \
                "$domain expone datos de contacto del titular en WHOIS. Activar privacy protection en el registrar."
        else
            info "Privacidad WHOIS activa"
        fi

        [[ -n "$EXPIRY" ]] && add_finding "INFO" "Dominio $domain" \
            "Registrar: ${REGISTRAR:-—} | Expira: $EXPIRY"
    done
else
    warn "whois no instalado"
fi

# ── 3. Servicios en localhost ─────────────────────────────────────────────────
section "3. Servicios en localhost"
if command -v nmap &>/dev/null; then
    NMAP_OUT=$(nmap -sV --open -T3 127.0.0.1 2>/dev/null | grep -E '^[0-9]+/' || true)
    if [[ -n "$NMAP_OUT" ]]; then
        while IFS= read -r line; do
            PORT="${line%%/*}"
            SERVICE=$(awk '{$1=$2=""; print}' <<< "$line" | xargs)
            note "localhost:$PORT — $SERVICE"
            add_finding "INFO" "Servicio en localhost:$PORT" "$SERVICE"
        done <<< "$NMAP_OUT"
    else
        info "Sin servicios abiertos en localhost"
    fi

    # ── 4. Exposición en la red local ─────────────────────────────────────────
    section "4. Exposición en la red local"
    if [[ "$SCAN_LOCAL_IP" != "true" ]]; then
        note "scan_local_ip desactivado en la configuración — omitido"
    else
        LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' || true)
        if [[ -z "$LOCAL_IP" ]]; then
            note "No se pudo determinar la IP de red local"
        else
            if [[ "$AGGRESSIVE" == "true" ]]; then
                TIMING="-T4"
                warn "Escaneo agresivo activo (-T4) contra $LOCAL_IP"
            else
                TIMING="-T2"
                note "Escaneo conservador (-T2) contra $LOCAL_IP"
            fi

            NMAP_LOCAL=$(nmap --open $TIMING -p "$COMMON_PORTS" "$LOCAL_IP" 2>/dev/null \
                | grep -E '^[0-9]+/' || true)

            if [[ -n "$NMAP_LOCAL" ]]; then
                while IFS= read -r line; do
                    PORT="${line%%/*}"
                    crit "Puerto $PORT alcanzable en $LOCAL_IP desde la red"
                    add_finding "HIGH" "Puerto $PORT expuesto en la red local" \
                        "$LOCAL_IP:$PORT responde desde la red — cualquier dispositivo conectado puede alcanzarlo."
                done <<< "$NMAP_LOCAL"
            else
                info "Sin puertos alcanzables en $LOCAL_IP"
            fi
        fi
    fi
else
    warn "nmap no instalado"
    add_finding "INFO" "nmap no disponible" "Instalar con: sudo apt install nmap"
fi

# ── 5. Subdominios ────────────────────────────────────────────────────────────
section "5. Enumeración de subdominios"
SUBFINDER="$TOOLS_DIR/subfinder"
command -v subfinder &>/dev/null && SUBFINDER=$(command -v subfinder)

if [[ -x "$SUBFINDER" ]]; then
    for domain in $DOMAINS; do
        SUBS=$("$SUBFINDER" -d "$domain" -silent 2>/dev/null || true)
        if [[ -n "$SUBS" ]]; then
            COUNT=$(wc -l <<< "$SUBS")
            note "$domain: $COUNT subdominios públicos"
            head -10 <<< "$SUBS" | while IFS= read -r sub; do info "  $sub"; done
            add_finding "INFO" "Subdominios de $domain" \
                "$COUNT subdominios visibles públicamente: $(head -5 <<< "$SUBS" | tr '\n' ' ')"
        else
            info "$domain: sin subdominios públicos detectados"
        fi
    done
else
    note "subfinder no instalado — enumeración omitida"
fi

save_findings
