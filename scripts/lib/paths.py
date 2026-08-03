"""paths.py — Rutas, configuración y arranque compartidos por los módulos Python.

Invariante del lab: toda salida que pueda contener hallazgos o PII se escribe bajo
VAULT_DIR, que está en .gitignore. Ningún script construye rutas de salida por su cuenta.
"""

import json
import os
import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent.parent
VAULT_DIR = LAB_DIR / "vault"
CONFIG_FILE = VAULT_DIR / "config" / "targets.json"
CONFIG_TEMPLATE = LAB_DIR / "config" / "targets.example.json"
SCANS_DIR = VAULT_DIR / "scans"
REPORTS_DIR = VAULT_DIR / "reports"
TOOLS_DIR = LAB_DIR / "tools"
ENV_FILE = VAULT_DIR / ".env"

VENV_PYTHON = LAB_DIR / ".venv" / "bin" / "python3"


def reexec_in_venv() -> None:
    """Se re-lanza dentro del venv del lab si existe y no está ya activo."""
    if VENV_PYTHON.exists() and Path(sys.executable).resolve() != VENV_PYTHON.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)


def load_env() -> None:
    """Carga vault/.env en el entorno. Acepta líneas con o sin 'export'."""
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def load_config() -> dict:
    """Carga la config del vault. Falla con un mensaje accionable si falta."""
    if not CONFIG_FILE.exists():
        sys.exit(f"error: falta {CONFIG_FILE}\n       correr: make init")
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {CONFIG_FILE} no es JSON válido — {exc}")


def ensure_vault() -> None:
    """Crea los directorios de salida del vault con permisos restrictivos."""
    for directory in (SCANS_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    try:
        VAULT_DIR.chmod(0o700)
    except OSError:
        pass


def write_scan(module: str, findings: list[dict]) -> Path:
    """Persiste los hallazgos de un módulo en el vault y devuelve la ruta."""
    from datetime import datetime

    ensure_vault()
    scan_file = SCANS_DIR / f"{module}_{datetime.now():%Y%m%d_%H%M%S}.json"
    scan_file.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    scan_file.chmod(0o600)
    return scan_file
