# Repository Guidelines

## Project Structure & Module Organization

`osint-lab` es un laboratorio OSINT personal de solo lectura: audita la propia huella
digital (máquina local, secretos en repos propios, DNS/correo de dominios propios,
presencia pública de identidades propias) y nunca actúa sobre terceros.

El repositorio separa motor y datos:

- `scripts/` es el motor versionado. `scripts/lib/common.sh` (Bash) y
  `scripts/lib/paths.py` (Python) centralizan rutas y helpers — ningún módulo nuevo
  debe construir una ruta de salida por su cuenta. Los módulos de auditoría en Bash
  (`audit_local.sh`, `audit_secrets.sh`, `audit_network.sh`) envuelven herramientas de
  sistema (`ss`, `docker`, `dig`, `whois`, `nmap`, `ripgrep`, `gitleaks`); los módulos
  en Python (`audit_identity.py`, `report_generator.py`) hacen llamadas HTTP, parseo y
  templating (`jinja2`).
- `config/targets.example.json` es la plantilla pública, sin datos reales.
- `tools/` son clones y binarios de terceros gestionados por `setup.sh` (theHarvester,
  sherlock, gitleaks, subfinder) — ignorado por git, reinstalable con `make setup`.
- `vault/` (creado por `make init`, permisos `700`, ignorado por git) es donde vive
  TODO lo sensible: `vault/config/targets.json` (identidades reales),
  `vault/scans/*.json` (hallazgos crudos por módulo), `vault/reports/*.{md,html}`
  (reportes consolidados), `vault/auditorias/` (análisis manuales con PII) y
  `vault/.env` (API keys). Nunca editar ni versionar nada dentro de `vault/`.
- `docs/SECURITY.md` documenta el modelo de seguridad completo; `docs/ROADMAP.md`
  lista deuda técnica pendiente.

## Build & Development Commands

```bash
make setup           # Dependencias del sistema (apt), venv Python, clones OSINT en tools/
make init            # Crea vault/ y copia config/targets.example.json → vault/config/targets.json

make audit           # Todos los módulos + reporte consolidado
make audit-local     # Puertos, Docker, .env, permisos SSH, grupos
make audit-secrets   # Secretos en repos, historial Git (gitleaks) y nube
make audit-network   # DNS, SPF/DMARC, WHOIS, exposición de servicios
make audit-identity  # Usernames (Sherlock), GitHub, brechas de datos (HIBP)
make report          # Genera .md + .html desde los últimos scans del vault

make verify          # Comprueba que nada sensible es rastreable por git — correr antes de todo push
make clean           # Borra scans y reportes del vault (conserva auditorias/ y config)
make clean-tools     # Borra las herramientas clonadas en tools/
```

Después de `make init`, editar `vault/config/targets.json` con identidades reales
antes de correr cualquier `audit-*` — los scripts fallan con un mensaje accionable si
falta esa config o `jq`. Los scripts Python se re-ejecutan solos dentro del venv del
lab si existe, así que no hace falta activarlo manualmente.

## Coding Style

- Bash: `set -euo pipefail` (o `-uo pipefail` en `verify_hygiene.sh`, que necesita
  seguir corriendo tras un fallo parcial para reportar todo). Sourcear siempre
  `scripts/lib/common.sh` para rutas, colores y los helpers `section`/`crit`/`warn`/
  `info`/`note`/`die`. Los hallazgos se serializan con `add_finding` (que usa `jq -nc`
  internamente), nunca por concatenación manual de strings JSON — los paths reales
  contienen comillas, comas y Unicode que rompen el JSON hecho a mano.
- Python: type hints en firmas de función, `pathlib.Path` para rutas (nunca `os.path`
  ni strings), y siempre `from lib import paths` + `paths.reexec_in_venv()` al inicio
  de un script nuevo bajo `scripts/`. Los hallazgos son `dict` con las claves
  `severity`, `module`, `title`, `detail` y se persisten con `paths.write_scan(...)`,
  nunca escribiendo JSON a mano fuera de esa función.
- Comentarios en español, explicando el porqué de una decisión no obvia (por ejemplo,
  por qué se excluye el rango loopback completo y no solo `127.0.0.1`), no qué hace la
  línea siguiente.
- Todo output nuevo (scan, reporte, config con datos reales) debe pasar por
  `SCANS_DIR`/`REPORTS_DIR`/`VAULT_DIR` definidos en `common.sh`/`paths.py` — nunca una
  ruta construida a mano dentro de un script de auditoría.

## Testing

El lab no tiene suite de tests todavía (ver `docs/ROADMAP.md`, prioridad alta:
smoke-tests por módulo). Al tocar un script de auditoría, la verificación mínima es:

1. Correr el `make audit-*` correspondiente contra una config de prueba en
   `vault/config/targets.json` y confirmar que produce JSON válido en `vault/scans/`
   con el esquema `{severity, module, title, detail}`.
2. Correr `make report` y confirmar que el hallazgo nuevo aparece correctamente en el
   `.md` y el `.html` generados.
3. Correr `make verify` antes de cualquier commit o push — comprueba que nada del
   vault quedó rastreado por git, que los patrones de `.gitignore` siguen cubriendo las
   rutas críticas, que la plantilla pública no recibió datos reales, que el hook de
   pre-commit está instalado y que los permisos del vault son `700`.

CI (`.github/workflows/lint.yml`) corre `shellcheck` sobre `setup.sh` y todos los
scripts bajo `scripts/*.sh`, más `python -m py_compile` sobre los scripts Python.

## Commit & PR Guidelines

Este repositorio es público; el vault no. Antes de cualquier commit o PR:

- Correr `make verify` y confirmar que pasa (exit 0) antes de hacer push.
- Nunca commitear nada bajo `vault/`, `config/targets.json` (la copia real — solo
  `config/targets.example.json` se versiona), claves privadas (`*.pem`, `*.key`,
  `id_rsa*`, `id_ed25519*`) o cualquier archivo con forma de token (GitHub, AWS,
  Slack, Google, GitLab, URLs de conexión con credenciales). El hook de pre-commit
  (`scripts/hooks/pre-commit`, instalado por `make init`) bloquea estos casos
  automáticamente; saltarlo con `--no-verify` es un acto deliberado, no el flujo
  normal.
- Mensajes de commit descriptivos sobre el motor (qué script o comportamiento cambia),
  nunca sobre hallazgos concretos — los hallazgos no salen del vault.
- Al añadir un módulo o herramienta nueva: invocarla desde el script de auditoría
  correspondiente y añadir su instalación a `setup.sh` para mantener la
  reproducibilidad del entorno completo.
