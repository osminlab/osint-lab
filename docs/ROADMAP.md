# Roadmap

Estado del lab y trabajo pendiente. Sin detalles de hallazgos: esos viven en el vault.

## Estado actual

Cuatro módulos de auditoría (local, secretos, red, identidad) que escriben hallazgos
normalizados en JSON, y un generador que los consolida en un reporte `.md` + `.html`.
Toda salida va al vault; el repositorio solo contiene el motor.

## Prioridad alta

**Cobertura de configuración sin consumir.** Tres campos de `targets.json` están
declarados pero ningún módulo los lee:

- `identities.full_names` → alimentar búsquedas de theHarvester y consultas de nombre
- `identities.social_profiles` → verificar que los perfiles declarados siguen activos
  y qué exponen públicamente
- `api_keys.SHODAN_API_KEY` → consulta de Shodan por IP pública y dominios propios

**Tests.** El lab no tiene ninguno. El mínimo útil: smoke-tests que ejecuten cada
módulo contra una configuración de prueba y verifiquen que producen JSON válido con el
esquema esperado (`severity`, `module`, `title`, `detail`). Los bugs que aparecieron al
reorganizar el repo — `set -e` abortando en `grep -c`, loopback mal filtrado, DMARC
confundido con un TXT wildcard — los habría atrapado un smoke-test.

**Modo `--dry-run`.** Ejecutar el flujo completo con datos sintéticos, sin tocar la red
ni el sistema. Necesario para demostrar el lab a terceros y para desarrollar sin correr
nmap ni consumir cuota de APIs.

## Prioridad media

**Seguimiento temporal.** Cada auditoría es hoy una foto aislada. Comparar contra la
auditoría anterior permitiría reportar lo que importa: qué apareció, qué desapareció,
qué lleva N ciclos sin remediarse. La baseline en `vault/auditorias/` es el punto de
partida natural.

**Ejecución periódica.** No hay cron ni systemd timer. Una auditoría trimestral que
haya que recordar manualmente no se hace. Un timer que corra `make audit` y notifique
solo si aparecen hallazgos nuevos.

**SpiderFoot.** Se retiró de `setup.sh` porque ningún módulo lo invocaba y son ~200 MB.
Reintegrar cuando exista el módulo que lo use, no antes.

**amass.** Misma situación: retirado de las dependencias apt. `subfinder` ya cubre
enumeración de subdominios; amass solo se justifica si se quiere correlación pasiva más
profunda.

## Prioridad baja

**Screenshot del reporte HTML en el README.** Requiere primero el modo `--dry-run`
para generar una captura con datos ficticios en vez de hallazgos reales.

**Deduplicación de hallazgos.** El módulo local y el de red reportan por separado un
mismo puerto expuesto. El reporte gana en legibilidad si se correlacionan.

**Salida del reporte en JSON.** Además de `.md` y `.html`, para poder consumirlo desde
otras herramientas.

## Resuelto

Registro de lo que se corrigió en la reorganización del 2026-08-03, para no reabrirlo:

- Documento de auditoría con PII y baseline de vulnerabilidades fuera del repo público
- `.gitignore` deny-by-default; separación `targets.example.json` / vault
- Salidas centralizadas en `vault/` vía `scripts/lib/` (antes: cuatro directorios en la
  raíz con reglas de ignore frágiles)
- Hook de pre-commit y `make verify` como guardrails automáticos
- JSON construido con `jq` en vez de concatenación de strings
- `owner` leído de la configuración (antes hardcodeado en el generador de reportes)
- `GITHUB_TOKEN` para elevar el rate limit de la API de GitHub
- nmap agresivo desactivado por defecto y configurable
- Dependencias Python con versiones fijas; `pandas` eliminado por no usarse
- Escapado HTML en el fallback sin Jinja2 del generador de reportes
