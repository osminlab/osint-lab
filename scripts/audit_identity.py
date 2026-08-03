#!/usr/bin/env python3
"""audit_identity.py — Presencia pública de identidades: usernames, emails, dominios."""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import paths  # noqa: E402

paths.reexec_in_venv()
paths.load_env()

import os  # noqa: E402

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
except ImportError:
    console = None


def pr(msg: str) -> None:
    if console:
        console.print(msg)
    else:
        # Descartar el marcado de rich cuando no está disponible
        import re

        print(re.sub(r"\[/?[a-z ]+\]", "", msg))


def section(title: str) -> None:
    pr(f"\n[bold cyan]══ {title} ══[/bold cyan]")


def ok(msg): pr(f"  [green][OK][/green]      {msg}")
def warn(msg): pr(f"  [yellow][ALTO][/yellow]    {msg}")
def crit(msg): pr(f"  [red][CRÍTICO][/red] {msg}")
def note(msg): pr(f"  [blue][INFO][/blue]    {msg}")


def _requests():
    try:
        import requests

        return requests
    except ImportError:
        warn("requests no instalado — correr: make setup")
        return None


def check_github_profile(usernames: list[str]) -> list[dict]:
    """Metadatos públicos del perfil GitHub. Usa GITHUB_TOKEN si está disponible."""
    requests = _requests()
    if not requests:
        return []

    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        note("GITHUB_TOKEN no configurado — límite de 60 req/hora")

    findings = []
    for username in usernames:
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}", headers=headers, timeout=10
            )
        except Exception as exc:
            warn(f"GitHub @{username}: {exc}")
            continue

        if r.status_code == 404:
            note(f"GitHub @{username}: no existe")
            continue
        if r.status_code == 403:
            warn("GitHub: rate limit alcanzado — configurar GITHUB_TOKEN en vault/.env")
            continue
        if r.status_code != 200:
            warn(f"GitHub @{username}: HTTP {r.status_code}")
            continue

        data = r.json()
        location = data.get("location") or "—"
        ok(
            f"GitHub @{username}: {data.get('public_repos', 0)} repos, "
            f"{data.get('followers', 0)} seguidores, ubicación: {location}"
        )

        if data.get("email"):
            warn(f"  Email público en el perfil: {data['email']}")
            findings.append({
                "severity": "MEDIUM",
                "module": "identity",
                "title": "Email expuesto en el perfil de GitHub",
                "detail": f"@{username} publica {data['email']} — recolectable por scrapers "
                          f"y usable para spear-phishing. Ocultar en Settings → Profile.",
            })

        if data.get("location"):
            findings.append({
                "severity": "LOW",
                "module": "identity",
                "title": "Ubicación pública en el perfil de GitHub",
                "detail": f"@{username} publica su ubicación: {location} — dato correlacionable.",
            })

        findings.append({
            "severity": "INFO",
            "module": "identity",
            "title": f"Perfil GitHub @{username}",
            "detail": f"Repos: {data.get('public_repos', 0)} | "
                      f"Seguidores: {data.get('followers', 0)} | "
                      f"Ubicación: {location} | Bio: {data.get('bio') or '—'}",
        })

    return findings


def resolve_tool(entry_point: str, module: str, clone_dir: str) -> list[str] | None:
    """Devuelve el comando para invocar una herramienta OSINT, o None si no está.

    Sherlock y theHarvester se distribuyen como paquetes Python y han cambiado de
    layout entre versiones (script suelto → paquete con pyproject.toml). Se prueban
    tres formas en orden de robustez, en vez de asumir una ruta fija:
      1. el ejecutable instalado en el venv del lab
      2. el módulo importable desde el venv (`python -m`)
      3. el módulo ejecutado desde el clon en tools/, sin instalar
    """
    venv_bin = paths.VENV_PYTHON.parent / entry_point
    if venv_bin.exists():
        return [str(venv_bin)]

    python_bin = str(paths.VENV_PYTHON) if paths.VENV_PYTHON.exists() else sys.executable
    probe = subprocess.run(
        [python_bin, "-c", f"import {module}"], capture_output=True, timeout=30
    )
    if probe.returncode == 0:
        return [python_bin, "-m", module]

    clone = paths.TOOLS_DIR / clone_dir
    if (clone / module).is_dir() or (clone / f"{module}.py").exists():
        return [python_bin, "-m", module]

    return None


def run_sherlock(usernames: list[str]) -> list[dict]:
    """Busca los usernames en plataformas públicas con Sherlock."""
    cmd = resolve_tool("sherlock", "sherlock_project", "sherlock")
    if not cmd:
        warn("Sherlock no encontrado — correr: make setup")
        return []

    cwd = paths.TOOLS_DIR / "sherlock"
    findings = []

    for username in usernames:
        note(f"Sherlock: {username}")
        try:
            result = subprocess.run(
                [*cmd, username, "--print-found", "--timeout", "10"],
                capture_output=True, text=True, timeout=300,
                cwd=str(cwd) if cwd.is_dir() else None,
            )
        except subprocess.TimeoutExpired:
            warn(f"Sherlock: timeout para {username}")
            continue
        except Exception as exc:
            warn(f"Sherlock: {exc}")
            continue

        found = [l for l in result.stdout.splitlines() if l.startswith("[+]")]
        for line in found:
            body = line.removeprefix("[+] ").strip()
            platform, _, url = body.partition(": ")
            findings.append({
                "severity": "INFO",
                "module": "identity",
                "title": f"Username '{username}' presente en {platform.strip()}",
                "detail": f"URL: {url.strip()}",
                "username": username,
                "platform": platform.strip(),
                "url": url.strip(),
            })

        ok(f"Sherlock {username}: {len(found)} perfiles encontrados")

        if len(found) > 20:
            findings.append({
                "severity": "MEDIUM",
                "module": "identity",
                "title": f"Superficie de identidad amplia para '{username}'",
                "detail": f"{len(found)} plataformas usan el mismo username — facilita "
                          f"correlacionar cuentas entre servicios.",
            })

    return findings


def run_theharvester(domains: list[str]) -> list[dict]:
    """Emails y hosts asociados a dominios propios, vía theHarvester."""
    cmd = resolve_tool("theHarvester", "theHarvester", "theHarvester")
    if not cmd:
        warn("theHarvester no encontrado — correr: make setup")
        return []

    cwd = paths.TOOLS_DIR / "theHarvester"
    findings = []

    for domain in domains:
        note(f"theHarvester: {domain}")
        try:
            result = subprocess.run(
                [*cmd, "-d", domain, "-b", "bing,duckduckgo,crtsh", "-l", "50"],
                capture_output=True, text=True, timeout=300,
                cwd=str(cwd) if cwd.is_dir() else None,
            )
        except subprocess.TimeoutExpired:
            warn(f"theHarvester: timeout para {domain}")
            continue
        except Exception as exc:
            warn(f"theHarvester: {exc}")
            continue

        # El banner de theHarvester incluye el email de su propio autor, y la salida
        # mezcla adornos ASCII con los resultados. Solo cuentan las direcciones cuyo
        # dominio sea el auditado o un subdominio suyo: lo demás no es del objetivo.
        email_re = re.compile(
            r"[A-Za-z0-9._%%+-]+@(?:[A-Za-z0-9-]+\.)*%s" % re.escape(domain),
            re.IGNORECASE,
        )
        emails, hosts = [], []
        for raw in (result.stdout + result.stderr).splitlines():
            line = raw.strip()
            emails.extend(email_re.findall(line))
            if line.startswith("- ") and domain in line:
                hosts.append(line[2:].strip())
        emails = sorted(set(emails))

        for email in emails[:10]:
            warn(f"  Email expuesto: {email}")
            findings.append({
                "severity": "MEDIUM",
                "module": "identity",
                "title": f"Email de {domain} indexado públicamente",
                "detail": f"{email} es recolectable desde buscadores — objetivo de phishing y spam.",
            })

        if not emails:
            ok(f"theHarvester {domain}: sin emails indexados")

        if hosts:
            findings.append({
                "severity": "INFO",
                "module": "identity",
                "title": f"Hosts asociados a {domain}",
                "detail": f"{len(hosts)} hosts: {', '.join(hosts[:5])}",
            })

    return findings


def check_hibp(emails: list[str]) -> list[dict]:
    """Aparición de los emails en brechas conocidas (HaveIBeenPwned)."""
    key = os.environ.get("HIBP_API_KEY", "")
    if not key:
        note("HIBP_API_KEY no configurada — módulo omitido")
        note("Obtener en https://haveibeenpwned.com/API/Key y añadir a vault/.env")
        return []

    requests = _requests()
    if not requests:
        return []

    findings = []
    for email in emails:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": key, "user-agent": "osint-lab"},
                timeout=15,
            )
        except Exception as exc:
            warn(f"HIBP: {exc}")
            continue

        if r.status_code == 404:
            ok(f"{email}: sin brechas conocidas")
            continue
        if r.status_code == 401:
            warn("HIBP: API key inválida")
            break
        if r.status_code == 429:
            warn("HIBP: rate limit — reintentar más tarde")
            break
        if r.status_code != 200:
            warn(f"HIBP: HTTP {r.status_code}")
            continue

        breaches = r.json()
        names = [b["Name"] for b in breaches]
        crit(f"{email} aparece en {len(breaches)} brechas")

        # Las brechas con contraseñas son materialmente distintas del resto
        with_passwords = [
            b["Name"] for b in breaches
            if "Passwords" in b.get("DataClasses", [])
        ]
        if with_passwords:
            findings.append({
                "severity": "CRITICAL",
                "module": "identity",
                "title": "Contraseñas filtradas en brechas de datos",
                "detail": f"{email} aparece con contraseñas en: {', '.join(with_passwords)}. "
                          f"Rotar esas contraseñas y cualquier reutilización de las mismas.",
            })

        findings.append({
            "severity": "HIGH",
            "module": "identity",
            "title": "Email presente en brechas de datos",
            "detail": f"{email} en {len(breaches)} brechas: {', '.join(names)}",
        })

    return findings


def main() -> None:
    config = paths.load_config()
    identities = config.get("identities", {})
    usernames = identities.get("usernames", [])
    emails = identities.get("emails", [])
    domains = identities.get("domains", [])

    header = f"AUDITORÍA DE IDENTIDAD — {datetime.now():%Y-%m-%d %H:%M}"
    if console:
        console.print(Panel.fit(f"[bold]{header}[/bold]", style="cyan"))
    else:
        print(f"\n=== {header} ===")

    findings: list[dict] = []

    section("1. Perfiles GitHub")
    findings += check_github_profile(usernames)

    section("2. Sherlock — usernames en plataformas públicas")
    findings += run_sherlock(usernames)

    section("3. theHarvester — emails y hosts de dominios propios")
    findings += run_theharvester(domains)

    section("4. HaveIBeenPwned — brechas de datos")
    findings += check_hibp(emails)

    section("Resumen")
    if console:
        table = Table(box=box.ROUNDED)
        table.add_column("Severidad", style="bold")
        table.add_column("Hallazgo")
        table.add_column("Detalle")
        colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue",
                  "LOW": "green", "INFO": "white"}
        for f in findings:
            sev = f.get("severity", "INFO")
            table.add_row(
                f"[{colors.get(sev, 'white')}]{sev}[/]", f["title"], f["detail"][:80]
            )
        console.print(table)
    else:
        for f in findings:
            print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")

    scan_file = paths.write_scan("identity", findings)
    print(f"\n✓ Scan guardado: {scan_file}")
    print(f"  Hallazgos: {len(findings)}\n")


if __name__ == "__main__":
    main()
