# Modelo de seguridad del lab

Este repositorio es público. Audita algo que no lo es. Todo lo que sigue existe para
que esa asimetría no se rompa por accidente.

## Regla única

> **El motor se versiona. Los datos, nunca.**

| Categoría | Ejemplos | Dónde vive | Versionado |
|---|---|---|---|
| Motor | scripts, Makefile, plantillas | raíz del repo | Sí |
| Documentación | README, este archivo, ROADMAP | `docs/` | Sí |
| Identidades reales | emails, dominios, usernames, nombres | `vault/config/` | No |
| Hallazgos | scans JSON, reportes `.md`/`.html` | `vault/scans`, `vault/reports` | No |
| Auditorías manuales | análisis escritos a mano con PII | `vault/auditorias/` | No |
| Credenciales | API keys, tokens | `vault/.env` | No |

## Capas de defensa

La protección no depende de recordar nada. Son cuatro capas independientes: para que
un dato sensible llegue a GitHub tendrían que fallar las cuatro.

**1. `.gitignore` deny-by-default** — `vault/` completo, más patrones por nombre y
extensión para credenciales y salidas de auditoría. Incluye las rutas del layout
anterior (`scans/`, `reports/`, `identities/`, `leaks/`) como red de seguridad.

**2. Rutas centralizadas en código** — ningún script construye rutas de salida por su
cuenta. `scripts/lib/common.sh` y `scripts/lib/paths.py` son el único lugar donde se
definen, y todas apuntan dentro del vault. Un módulo nuevo hereda la garantía sin
tener que pensarlo.

**3. Hook de pre-commit** — instalado por `make init`. Bloquea el commit si en el
índice hay rutas del vault, archivos de credenciales, contenido con forma de token
(GitHub, AWS, Slack, Google, claves privadas, URLs con credenciales) o alguna de las
identidades reales configuradas en tu vault. Se puede saltar con `--no-verify`; es
deliberado que requiera un acto explícito.

**4. `make verify`** — auditoría del propio lab: comprueba que nada del vault esté
rastreado, que los patrones de `.gitignore` sigan cubriendo las rutas críticas, que la
plantilla pública no haya recibido datos reales, que el hook esté instalado y que los
permisos del vault sean 700. Correrlo antes de cualquier push.

## Guardrail global de git (fuera de este repo)

Las cuatro capas anteriores protegen `osint-lab`. El hallazgo más grave de la primera
auditoría estaba en otro repositorio, así que la misma idea se aplica a nivel de
usuario. No forma parte de este repo —vive en `$HOME`— pero se documenta aquí porque
es donde se explica el modelo:

| Configuración | Qué hace |
|---|---|
| `core.excludesFile` → `~/.gitignore_global` | Ignora `.env`, `*.pem`, `*-key.json`, `*.tfstate` y similares en **todos** los repos |
| `core.hooksPath` → `~/.git-hooks` | Hook de pre-commit que corre `gitleaks git --staged` en cualquier repo |
| `user.email` → `…@users.noreply.github.com` | Los commits dejan de publicar la dirección real |

Comprobar el estado con:

```bash
git config --global --get-regexp 'core\.(excludesFile|hooksPath)|user\.email'
```

`core.hooksPath` **desactiva los hooks de `.git/hooks`** en todos los repositorios. El
hook global lo compensa delegando explícitamente al hook local del repo cuando existe,
de modo que el guardrail propio de este lab sigue ejecutándose después del global. Al
construir esa delegación hay que resolver la ruta desde `git rev-parse --git-dir`: la
forma aparentemente natural, `git rev-parse --git-path hooks/pre-commit`, respeta
`core.hooksPath` y devuelve el propio hook global, que al hacer `exec` sobre sí mismo
entra en recursión infinita.

## Permisos en disco

`vault/` es `700`; los scans, reportes y configuración se escriben con `600`. Esto
protege frente a otros usuarios del sistema, no frente a un compromiso de tu cuenta.
Si el disco no está cifrado, el vault tampoco lo está: considerar LUKS o cifrar el
directorio con `age`/`gpg`.

## Advertencia sobre escaneo activo

`make audit-network` incluye nmap. Contra `127.0.0.1` es inocuo. Contra la IP de red
local genera tráfico observable:

- `network_audit.scan_local_ip` — desactívalo para omitir por completo el escaneo de red.
- `network_audit.aggressive_scan` — `false` por defecto usa `-T2`; en `true` usa `-T4`,
  que es rápido pero **puede disparar IDS y alertas en redes corporativas, de trabajo o
  compartidas**. Actívalo solo en tu propia red.

Escanear infraestructura ajena sin autorización explícita es ilegal en muchas
jurisdicciones. El lab está diseñado para activos propios.

## Consideraciones sobre datos de terceros

Los módulos de secretos y local escanean tus árboles de código, que pueden contener
credenciales de clientes o de empleadores. Los hallazgos quedan en el vault, en tu
disco. Antes de compartir un reporte con alguien — aunque sea para pedir ayuda —
revisar qué rutas y qué nombres aparecen en él.

## Si algo se filtró

1. **Rotar primero.** Un secreto en el historial de git es un secreto comprometido;
   reescribir el historial no lo revierte, solo dificulta encontrarlo.
2. Purgar el historial con `git filter-repo --path <ruta> --invert-paths`.
3. `git push --force` — y asumir que los objetos pueden seguir accesibles por SHA en
   GitHub durante un tiempo, y en cualquier fork o clon existente.
4. Correr `make verify` para confirmar que la vía de filtración quedó cerrada.
