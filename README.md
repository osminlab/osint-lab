# osint-lab

Laboratorio OSINT personal para auditar la propia huella digital: superficie de exposición local, secretos en repositorios, presencia pública de identidades y postura DNS de dominios propios. Genera un reporte consolidado en `.md` y `.html`.

**Modo de operación:** solo lectura · defensivo · sobre activos propios.

---

## Modelo de seguridad del lab

Este repositorio es **público**, pero el objeto que audita es privado. La separación es la propiedad de diseño más importante del proyecto:

| | Qué contiene | Estado |
|---|---|---|
| **Repositorio** | El motor: scripts, plantillas de configuración, documentación | Público |
| **`vault/`** | Datos reales: identidades, hallazgos, reportes, auditorías | Ignorado por git, nunca sale del disco |

Ningún hallazgo, identidad ni reporte se escribe fuera de `vault/`. Un hook de pre-commit bloquea el commit si algo sensible llega al índice — ver [docs/SECURITY.md](docs/SECURITY.md).

---

## Setup

```bash
make setup      # herramientas del sistema (apt), venv Python, clones de OSINT tools
make init       # crea vault/ y la configuración local a partir de la plantilla
```

Después de `make init`, editar `vault/config/targets.json` con tus identidades reales. Ese archivo vive dentro del vault y nunca se versiona.

## Comandos

| Comando | Qué hace |
|---|---|
| `make setup` | Instala dependencias del sistema, venv y herramientas |
| `make init` | Inicializa `vault/` y la config local desde la plantilla |
| `make audit` | Auditoría completa (todos los módulos + reporte) |
| `make audit-local` | Puertos expuestos, Docker, `.env` locales, permisos SSH, grupos |
| `make audit-secrets` | Secretos en repos y almacenamiento en la nube (ripgrep + gitleaks) |
| `make audit-network` | DNS, SPF/DMARC, WHOIS, nmap de dominios y hosts propios |
| `make audit-identity` | Usernames en plataformas, GitHub, HaveIBeenPwned |
| `make report` | Genera `.md` y `.html` desde los últimos scans |
| `make verify` | Comprueba que ningún dato sensible es rastreable por git |
| `make clean` | Borra scans y reportes del vault |

## Estructura

```
osint-lab/
├── Makefile                    # Interfaz de comandos
├── setup.sh                    # Instalación de dependencias
├── requirements.txt            # Dependencias Python
├── config/
│   └── targets.example.json    # Plantilla de configuración (sin datos reales)
├── scripts/
│   ├── lib/
│   │   ├── common.sh           # Rutas y helpers compartidos (Bash)
│   │   └── paths.py            # Rutas y config compartidos (Python)
│   ├── audit_local.sh          # Superficie de exposición de la máquina
│   ├── audit_secrets.sh        # Secretos en repos y nube
│   ├── audit_network.sh        # DNS, WHOIS, nmap
│   ├── audit_identity.py       # OSINT de identidad
│   └── report_generator.py     # Consolidación de reportes
├── docs/
│   ├── SECURITY.md             # Modelo de seguridad y guardrails
│   └── ROADMAP.md              # Deuda técnica y trabajo pendiente
├── tools/                      # Herramientas clonadas (ignorado)
└── vault/                      # TODO lo sensible (ignorado, nunca se versiona)
    ├── config/targets.json     # Identidades reales
    ├── auditorias/             # Auditorías manuales
    ├── scans/                  # Salidas JSON crudas
    ├── reports/                # Reportes generados
    ├── identities/             # Perfiles correlacionados
    └── leaks/                  # Datos de brechas
```

## Qué detecta

**Módulo local** — puertos escuchando en interfaces externas, contenedores Docker con puertos publicados fuera de localhost, archivos `.env` sin protección de `.gitignore`, permisos incorrectos en claves SSH privadas, pertenencia a grupos con escalada de privilegios, actualizaciones de sistema pendientes, variables de entorno sensibles activas.

**Módulo de secretos** — patrones de credenciales en árboles de código (ripgrep), secretos en historial de git (gitleaks), archivos de credenciales sincronizados a almacenamiento en la nube, tokens OAuth de CLIs.

**Módulo de red** — registros A/NS/MX/TXT, ausencia de SPF y DMARC, fecha de expiración de dominios, servicios expuestos en la IP de red local, enumeración de subdominios.

**Módulo de identidad** — presencia de usernames en plataformas públicas (Sherlock), emails y hosts asociados a dominios propios (theHarvester), metadatos públicos de perfil GitHub, aparición en brechas de datos (HaveIBeenPwned).

## Configuración

`make init` copia `config/targets.example.json` a `vault/config/targets.json`. Editar ese archivo:

```json
{
  "owner": "tu-username",
  "identities": {
    "usernames": ["tu-username"],
    "emails": ["tu@email.com"],
    "domains": ["tu-dominio.com"]
  }
}
```

## API keys opcionales

Crear `vault/.env` (ignorado por git):

```bash
export HIBP_API_KEY="..."     # https://haveibeenpwned.com/API/Key
export GITHUB_TOKEN="..."     # eleva el rate limit de la API de GitHub
export SHODAN_API_KEY="..."
```

## Agregar herramientas

1. Instalar o clonar en `tools/`
2. Invocarla desde el script de auditoría correspondiente
3. Añadir la instalación a `setup.sh` para mantener la reproducibilidad

## Licencia y alcance de uso

Herramienta de auditoría defensiva. Diseñada para ejecutarse contra activos propios: la máquina del operador, sus repositorios y los dominios que controla. El módulo de red incluye escaneo activo — ver la advertencia en [docs/SECURITY.md](docs/SECURITY.md) antes de ejecutarlo en redes compartidas o corporativas.
