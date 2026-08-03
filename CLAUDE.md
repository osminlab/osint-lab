# CLAUDE.md

Este archivo guía a Claude Code al trabajar en este repositorio.

## Descripción del proyecto

`osint-lab` es un laboratorio OSINT personal para auditar la propia huella digital:
superficie de exposición de la máquina local, secretos filtrados en repositorios
propios, postura DNS/correo de dominios propios y presencia pública de identidades
propias (usernames, emails, perfiles). Consolida los hallazgos en un reporte `.md` y
`.html`.

**Modo de operación: solo lectura · defensivo · sobre activos propios.** El lab no
ataca ni modifica nada de lo que audita — lee estado (puertos, DNS, WHOIS, archivos,
historial de git) y reporta. El único módulo con efecto de red es `audit-network`, que
puede correr `nmap` contra la IP de red local propia; está pensado exclusivamente para
la infraestructura del operador, nunca para terceros (ver advertencia en
`docs/SECURITY.md`).

La propiedad de diseño central del repo: **el repositorio es público, el objeto que
audita es privado.**

| | Contiene | Estado |
|---|---|---|
| Repositorio (raíz, `scripts/`, `config/`, `docs/`) | El motor: scripts, plantillas, documentación | Público, versionado |
| `vault/` | Datos reales: identidades, hallazgos, reportes, auditorías | Ignorado por git, nunca sale del disco |

Ningún hallazgo, identidad ni reporte se escribe fuera de `vault/`. Ver la sección
Notas más abajo y `docs/SECURITY.md` para el modelo de amenaza completo.

## Comandos

```bash
make setup           # Dependencias del sistema, venv y herramientas OSINT
make init            # Crea vault/ y la config local desde la plantilla

make audit           # Todos los módulos + reporte consolidado
make audit-local     # Puertos, Docker, .env, permisos SSH, grupos
make audit-secrets   # Secretos en repos, historial Git y nube
make audit-network   # DNS, SPF/DMARC, WHOIS, exposición de servicios
make audit-identity  # Usernames, GitHub, brechas de datos
make report          # Reporte .md + .html desde los últimos scans

make verify          # Comprueba que nada sensible es rastreable por git
make clean           # Borra scans y reportes del vault (no toca auditorias/ ni config)
make clean-tools     # Borra las herramientas clonadas en tools/
```

`make help` (o `make` sin target) imprime esta misma tabla desde el propio Makefile.

Antes de poder correr cualquier `audit-*`, hace falta `make setup` (una vez) y
`make init` (crea `vault/` y copia `config/targets.example.json` a
`vault/config/targets.json`, que hay que editar con identidades reales). Los scripts
Bash fallan explícitamente con un mensaje accionable (`require_config` en
`scripts/lib/common.sh`) si falta la config o `jq`.

## Arquitectura

```
osint-lab/
├── Makefile                  # Interfaz de comandos — única forma soportada de invocar el lab
├── setup.sh                  # apt + venv + clona theHarvester/sherlock/gitleaks/subfinder en tools/
├── config/targets.example.json  # Plantilla pública, sin datos reales
├── scripts/
│   ├── lib/
│   │   ├── common.sh         # Rutas y helpers compartidos — lado Bash
│   │   └── paths.py          # Rutas y helpers compartidos — lado Python
│   ├── init_vault.sh         # Crea vault/, copia config, instala el hook de pre-commit
│   ├── audit_local.sh        # Bash: puertos, Docker, .env, SSH, grupos, apt, env vars
│   ├── audit_secrets.sh      # Bash: ripgrep/grep + gitleaks + tokens de CLIs
│   ├── audit_network.sh      # Bash: dig, whois, nmap, subfinder
│   ├── audit_identity.py     # Python: GitHub API, Sherlock, theHarvester, HaveIBeenPwned
│   ├── report_generator.py   # Python: consolida vault/scans/*.json en vault/reports/*.{md,html}
│   ├── verify_hygiene.sh     # Bash: audita al propio lab (vault no rastreado, permisos, hook)
│   └── hooks/pre-commit      # Bloquea commits con rutas del vault o contenido con forma de secreto
├── tools/                    # Herramientas clonadas por setup.sh (ignorado, reinstalable)
└── vault/                    # TODO lo sensible — 700, ignorado, nunca versionado
    ├── config/targets.json   # Identidades reales (copiado desde la plantilla)
    ├── .env                  # API keys opcionales (HIBP, GitHub, Shodan)
    ├── scans/                # Salidas JSON crudas por módulo
    ├── reports/              # Reportes .md/.html generados
    ├── auditorias/           # Análisis manuales con PII (no regenerables)
    └── identities/, leaks/   # Perfiles correlacionados, datos de brechas
```

**`scripts/` vs `vault/` vs `config/`:** `scripts/` y `config/` son el motor —
versionado, sin datos reales, reproducible desde cero con `make setup && make init`.
`vault/` es el único lugar donde se lee y escribe cualquier cosa con PII o hallazgos
reales; ningún script construye una ruta de salida por su cuenta, todas pasan por
`scripts/lib/common.sh` (Bash) o `scripts/lib/paths.py` (Python), que son el único
punto donde `VAULT_DIR`/`SCANS_DIR`/`REPORTS_DIR` están definidos. Un módulo nuevo
hereda la garantía de "todo va al vault" con solo importar/sourcear esa lib, sin tener
que pensarlo.

**Bash vs Python:** los tres módulos que envuelven herramientas de sistema (`ss`,
`docker`, `dig`, `whois`, `nmap`, `ripgrep`, `gitleaks`) están en Bash porque son
mayormente orquestación de comandos externos. `audit_identity.py` y
`report_generator.py` están en Python porque hacen llamadas HTTP (GitHub API, HIBP),
parseo de JSON/HTML no trivial y templating (`jinja2`) — trabajo más natural fuera de
Bash. Los scripts Python se re-lanzan solos dentro del venv del lab si existe
(`paths.reexec_in_venv()`), así que el Makefile solo necesita un intérprete de
arranque (`$(VENV)/bin/python3` si existe, si no `python3` del sistema).

Todos los módulos de auditoría comparten el mismo contrato de hallazgo:
`{severity, module, title, detail}` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`), escrito
como array JSON en `vault/scans/<módulo>_<timestamp>.json`. `report_generator.py` toma
el scan más reciente de cada módulo y genera el reporte consolidado — no hay
persistencia entre ejecuciones más allá de esos JSON.

## Notas

- **Regla única del lab:** el motor se versiona, los datos nunca. Ver
  `docs/SECURITY.md` para el modelo de seguridad completo (capas de defensa,
  permisos en disco, qué hacer si algo se filtró).
- **Nunca commitear:** nada bajo `vault/` (identidades, scans, reportes, auditorías
  manuales, `.env`), `config/targets.json` (la copia real, a diferencia de
  `config/targets.example.json`), claves privadas (`*.pem`, `*.key`, `id_rsa*`,
  `id_ed25519*`), ni nada con forma de token (GitHub, AWS, Slack, Google, GitLab, URLs
  de conexión con credenciales). El `.gitignore` cubre estos patrones por nombre y
  extensión como red de seguridad adicional a la regla de "todo va al vault".
- **Defensa en profundidad, no un único mecanismo:** `.gitignore` deny-by-default,
  rutas de salida centralizadas en `common.sh`/`paths.py`, el hook de pre-commit
  (`scripts/hooks/pre-commit`, instalado por `make init`, saltable solo con
  `--no-verify` de forma deliberada) y `make verify` (audita al propio lab: vault no
  rastreado, patrones de `.gitignore` vigentes, plantilla sin datos reales, hook
  instalado, permisos 700). Correr `make verify` antes de cualquier `git push`.
- `tools/` contiene clones de terceros (theHarvester, sherlock) y binarios
  descargados (gitleaks, subfinder) gestionados por `setup.sh` — no se versionan y son
  reinstalables; no hace falta tratarlos como código propio del repo.
- Al añadir un módulo o herramienta nueva: invocarla desde el script de auditoría
  correspondiente, usar `add_finding`/`write_scan` para persistir hallazgos (nunca
  escribir JSON a mano) y añadir su instalación a `setup.sh` para mantener la
  reproducibilidad — ver "Agregar herramientas" en el `README.md`.
- El lab no tiene tests todavía (ver `docs/ROADMAP.md`, prioridad alta: smoke-tests
  por módulo). Al tocar un script, la verificación manual mínima es correr el `make
  audit-*` correspondiente contra una config de prueba y confirmar que el JSON
  producido respeta el esquema `{severity, module, title, detail}`.
- `requirements.txt` fija versiones exactas a propósito: una auditoría debe ser
  reproducible, y un `>=` convertiría cualquier release upstream en un cambio
  silencioso de comportamiento del lab.
