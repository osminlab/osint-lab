#!/usr/bin/env python3
"""report_generator.py — Consolida los últimos scans del vault en un reporte .md y .html.

Los reportes contienen hallazgos reales y se escriben exclusivamente en vault/reports/.
"""

import html
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import paths  # noqa: E402

paths.reexec_in_venv()

try:
    from jinja2 import Template

    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
SEV_COLOR = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#d4ac0d",
             "LOW": "#3498db", "INFO": "#95a5a6"}
MODULE_LABEL = {"local": "Máquina local", "secrets": "Secretos",
                "network": "Red y DNS", "identity": "Identidad"}


def load_latest_scans() -> tuple[list[dict], dict[str, datetime]]:
    """Toma el scan más reciente de cada módulo. Devuelve hallazgos y timestamps."""
    findings: list[dict] = []
    timestamps: dict[str, datetime] = {}

    for scan in sorted(paths.SCANS_DIR.glob("*.json"),
                       key=lambda f: f.stat().st_mtime, reverse=True):
        module = scan.stem.split("_")[0]
        if module in timestamps:
            continue
        try:
            data = json.loads(scan.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  aviso: no se pudo leer {scan.name} — {exc}", file=sys.stderr)
            continue
        if isinstance(data, list):
            timestamps[module] = datetime.fromtimestamp(scan.stat().st_mtime)
            findings.extend(data)

    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 99))
    return findings, timestamps


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def generate_markdown(findings: list[dict], owner: str, ts: str,
                      timestamps: dict[str, datetime]) -> str:
    counts = count_by_severity(findings)
    actionable = sum(counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM"))

    lines = [
        f"# Reporte de auditoría OSINT — {ts}",
        "",
        f"**Sujeto:** {owner}  ",
        f"**Generado:** {datetime.now():%Y-%m-%d %H:%M}  ",
        f"**Hallazgos:** {len(findings)} ({actionable} accionables)",
        "",
        "> Documento con hallazgos de seguridad reales. No compartir ni versionar.",
        "",
        "---",
        "",
        "## Resumen ejecutivo",
        "",
    ]

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            lines.append(f"- {SEV_EMOJI[sev]} **{sev}**: {counts[sev]}")

    if timestamps:
        lines += ["", "**Módulos ejecutados:**", ""]
        for module, when in sorted(timestamps.items()):
            label = MODULE_LABEL.get(module, module)
            lines.append(f"- {label} — {when:%Y-%m-%d %H:%M}")

    lines += ["", "---", "", "## Hallazgos por módulo", ""]

    for module_key, module_label in MODULE_LABEL.items():
        module_findings = [f for f in findings if f.get("module") == module_key]
        if not module_findings:
            continue

        lines += [f"### {module_label}", "",
                  "| Severidad | Hallazgo | Detalle |", "|---|---|---|"]
        for f in module_findings:
            sev = f.get("severity", "INFO")
            title = f.get("title", "").replace("|", "\\|")
            detail = f.get("detail", "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {SEV_EMOJI.get(sev, '⚪')} {sev} | {title} | {detail} |")
        lines.append("")

    lines += ["---", "",
              f"*Generado por osint-lab el {datetime.now():%Y-%m-%d %H:%M}*"]
    return "\n".join(lines)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Auditoría OSINT — {{ owner }} — {{ ts }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, 'Segoe UI', sans-serif; background: #0d1117;
         color: #c9d1d9; line-height: 1.6; }
  .header { background: linear-gradient(135deg, #161b22, #21262d); padding: 2rem;
            border-bottom: 1px solid #30363d; }
  .header h1 { font-size: 1.8rem; color: #58a6ff; }
  .header p { color: #8b949e; margin-top: 0.3rem; font-size: 0.9rem; }
  .warn-banner { background: #3d1d1d; border-left: 3px solid #e74c3c; color: #f0b0b0;
                 padding: 0.75rem 1rem; margin: 1.5rem 0; font-size: 0.85rem;
                 border-radius: 4px; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                  gap: 1rem; margin: 1.5rem 0; }
  .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                  padding: 1rem; text-align: center; }
  .summary-card .count { font-size: 2rem; font-weight: bold; }
  .summary-card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase;
                         letter-spacing: 0.05em; margin-top: 0.2rem; }
  .section { margin: 2rem 0; }
  .section h2 { color: #58a6ff; font-size: 1.15rem; border-bottom: 1px solid #30363d;
                padding-bottom: 0.5rem; margin-bottom: 1rem; }
  .table-wrap { overflow-x: auto; border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; }
  th { background: #21262d; color: #8b949e; padding: 0.75rem 1rem; text-align: left;
       font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 0.75rem 1rem; border-top: 1px solid #21262d; font-size: 0.88rem;
       vertical-align: top; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
           font-size: 0.7rem; font-weight: 700; color: #fff; white-space: nowrap; }
  .badge-CRITICAL { background: #e74c3c; }
  .badge-HIGH     { background: #e67e22; }
  .badge-MEDIUM   { background: #d4ac0d; color: #000; }
  .badge-LOW      { background: #2980b9; }
  .badge-INFO     { background: #566573; }
  .footer { text-align: center; color: #484f58; padding: 2rem;
            border-top: 1px solid #21262d; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1100px;margin:0 auto">
    <h1>Auditoría OSINT — {{ owner }}</h1>
    <p>Generado: {{ generated }} &nbsp;|&nbsp; {{ total }} hallazgos
       ({{ actionable }} accionables)</p>
  </div>
</div>
<div class="container">
  <div class="warn-banner">
    Este reporte contiene hallazgos de seguridad reales. No compartir, no versionar,
    no subir a servicios en la nube.
  </div>
  <div class="summary-grid">
    {% for sev, color in sev_colors.items() %}{% if counts.get(sev, 0) > 0 %}
    <div class="summary-card" style="border-color: {{ color }}">
      <div class="count" style="color: {{ color }}">{{ counts[sev] }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endif %}{% endfor %}
  </div>

  {% for module_key, module_label in modules.items() %}
  {% set mf = findings_by_module.get(module_key, []) %}{% if mf %}
  <div class="section">
    <h2>{{ module_label }} <span style="color:#8b949e;font-weight:400;font-size:0.85rem">
        ({{ mf|length }})</span></h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Severidad</th><th>Hallazgo</th><th>Detalle</th></tr></thead>
        <tbody>
          {% for f in mf %}
          <tr>
            <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
            <td>{{ f.title }}</td>
            <td style="color:#8b949e">{{ f.detail }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}{% endfor %}
</div>
<div class="footer">osint-lab &nbsp;|&nbsp; auditoría defensiva personal &nbsp;|&nbsp; {{ ts }}</div>
</body>
</html>"""


def generate_html(findings: list[dict], owner: str, ts: str) -> str:
    counts = count_by_severity(findings)
    actionable = sum(counts.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM"))

    findings_by_module: dict[str, list[dict]] = {}
    for f in findings:
        findings_by_module.setdefault(f.get("module", "other"), []).append(f)

    if HAS_JINJA:
        return Template(HTML_TEMPLATE).render(
            owner=owner, ts=ts,
            generated=f"{datetime.now():%Y-%m-%d %H:%M}",
            total=len(findings), actionable=actionable,
            counts=counts, sev_colors=SEV_COLOR,
            findings_by_module=findings_by_module, modules=MODULE_LABEL,
        )

    # Fallback sin Jinja2: los hallazgos incluyen rutas y datos del sistema,
    # así que se escapan antes de interpolarlos en el HTML.
    rows = "".join(
        "<tr>"
        f'<td style="color:{SEV_COLOR.get(f.get("severity", "INFO"), "#ccc")}">'
        f'{html.escape(f.get("severity", "INFO"))}</td>'
        f'<td>{html.escape(f.get("title", ""))}</td>'
        f'<td>{html.escape(f.get("detail", ""))}</td>'
        "</tr>"
        for f in findings
    )
    return (
        f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        f"<title>Auditoría OSINT — {html.escape(owner)}</title></head><body>"
        f"<h1>Auditoría OSINT — {html.escape(owner)} — {ts}</h1>"
        f"<table border='1'>{rows}</table></body></html>"
    )


def main() -> None:
    config = paths.load_config()
    owner = config.get("owner") or "—"
    ts = f"{datetime.now():%Y-%m-%d_%H%M}"

    paths.ensure_vault()
    print(f"\n  Cargando scans desde {paths.SCANS_DIR}...")
    findings, timestamps = load_latest_scans()

    if not findings:
        print("  Sin hallazgos en el vault. Correr primero: make audit")
        sys.exit(0)

    print(f"  {len(findings)} hallazgos de {len(timestamps)} módulos")

    md_file = paths.REPORTS_DIR / f"{ts}_audit.md"
    html_file = paths.REPORTS_DIR / f"{ts}_audit.html"

    md_file.write_text(generate_markdown(findings, owner, ts, timestamps), encoding="utf-8")
    html_file.write_text(generate_html(findings, owner, ts), encoding="utf-8")
    md_file.chmod(0o600)
    html_file.chmod(0o600)

    print(f"\n  ✓ Markdown: {md_file}")
    print(f"  ✓ HTML:     {html_file}")
    print(f"\n  Abrir: xdg-open {html_file}")

    counts = count_by_severity(findings)
    print("\n  Resumen:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            print(f"    {SEV_EMOJI[sev]} {sev}: {counts[sev]}")
    print()


if __name__ == "__main__":
    main()
