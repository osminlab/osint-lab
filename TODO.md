# TODO

Pendientes abiertos al 2026-08-03. Los hallazgos de auditoría no se listan aquí —
viven en `vault/reports/`. Este archivo es solo trabajo sobre el lab y acciones de
remediación que dependen del operador.

> Cuidado al editar: este archivo es público. Nada de rutas con credenciales, nombres
> de clientes ni detalles explotables. Describir la acción, no el secreto.

---

## Remediación — requiere acción manual

Estas salieron de la primera auditoría real y no las puede cerrar el lab por sí solo.

- [ ] **Rotar la service account de Google Cloud commiteada en un repo local.**
      Está en el historial de git (`Initial commit`), sin `.gitignore`, con permisos
      `664`. El repo no tiene remoto, así que no está publicada, pero una clave que
      estuvo world-readable y en un historial se considera comprometida. Es credencial
      de un tercero, no propia. Ruta exacta en el último reporte del vault.
      1. Revocar la key en la consola de GCP y emitir una nueva
      2. Añadir el patrón a `.gitignore` del repo
      3. Purgar del historial con `git filter-repo`
      4. Mover la nueva key fuera del árbol del repo

- [ ] **Restringir PostgreSQL a localhost.** `nmap` confirma el puerto 5432 alcanzable
      desde la red WiFi. En el `docker-compose` correspondiente, prefijar el mapeo con
      `127.0.0.1:` y recrear el contenedor.

- [ ] **Publicar SPF y DMARC para `osminlab.space`.** Sin ambos, cualquiera puede enviar
      correo suplantando el dominio. El DNS está en Cloudflare; son dos registros TXT.
      Empezar con `p=none` para observar, y subir a `p=quarantine` cuando el reporte
      esté limpio.

- [ ] **Rotar los secretos que gitleaks encontró en historiales de git.** Cinco repos
      afectados, 29 secretos en total; el más cargado acumula 23. Ninguno es público
      (dos privados, tres sin remoto), así que la urgencia es media — pero un secreto
      en el historial ya no es secreto: basta con que uno de esos repos se publique o
      se comparta. Rutas y conteos en el último reporte del vault.
      Revisar con: `tools/gitleaks detect --source <repo> --report-format json`

- [ ] **Proteger los `.env` sin `.gitignore`.** 19 archivos en un mismo monorepo de
      ejemplos. Basta una regla en el `.gitignore` de la raíz de ese repo.

- [ ] **Evaluar la salida del grupo `docker`.** Equivale a root sin contraseña. La
      alternativa es rootless Docker o `podman`. Es un cambio de flujo de trabajo, no
      una corrección puntual: decidir si compensa.

---

## Higiene de secretos — hábitos, no arreglos puntuales

Los 29 secretos en historiales y la service account commiteada siguieron todos el
mismo camino: **el secreto vivió dentro del árbol del repo**. A partir de ahí, que
llegue a git es cuestión de un `git add .` distraído. Cada punto ataca un eslabón
distinto de esa cadena.

- [ ] **Sacar las credenciales del árbol de los repos.** Es la única medida que
      elimina el problema en vez de contenerlo. Las claves de servicio van a
      `~/.config/<proveedor>/` o `~/.secrets/`, y el código lee la ruta desde una
      variable de entorno. Si el archivo no está dentro del repo, ningún fallo de
      `.gitignore` puede publicarlo.

- [ ] **Usar Bitwarden para los valores, no archivos `.env`.** `bw` ya está instalado
      y sin usar. El patrón: el valor vive en la bóveda, el repo solo referencia.
      ```bash
      export DB_PASSWORD=$(bw get password "proyecto-x-db")
      ```

- [ ] **Repos privados por defecto.** Los cinco repos con secretos en el historial
      resultaron privados o locales — por suerte, no por diseño. Publicar debe ser una
      decisión consciente que incluya pasar `gitleaks detect` antes.

- [ ] **Preferir credenciales de corta vida.** Un secreto que estuvo en un historial o
      en un archivo world-readable ya no es secreto: reescribir el historial oculta la
      evidencia, no revierte la exposición. Tokens con expiración y permisos mínimos
      reducen la ventana en la que una fuga importa.

- [ ] **Firmar los commits con la clave SSH.** Sin firma, cualquiera puede hacer
      commits con tu nombre y email, que son públicos. No requiere GPG:
      ```bash
      git config --global gpg.format ssh
      git config --global user.signingkey ~/.ssh/id_ed25519.pub
      git config --global commit.gpgsign true
      ```
      Falta subir `id_ed25519.pub` a GitHub como *signing key* (además de como
      authentication key) para que aparezca el badge «Verified».

- [ ] **Script de remediación guiado.** Un comando del lab que recorra los pendientes
      de este archivo y verifique cuáles siguen abiertos tras cada arreglo, en vez de
      comprobarlos a mano.

---

## Huella personal — la PII no se rota

Los secretos se cambian; la identidad no. Todo lo que ya está indexado (artículo
institucional, ranking de GitHub, perfiles públicos) es irreversible. Lo que sí
controlas es no añadir puntos de correlación nuevos.

- [ ] **Decidir sobre la correlación de identidad.** Sherlock encontró 14 perfiles
      entre `osminlab` y `hectorosminn`. Un username consistente es bueno para marca
      personal y malo para privacidad: permite unir todas tus cuentas desde una sola
      búsqueda. No hay respuesta correcta, pero conviene que sea deliberada — separar
      el username profesional del personal, o asumir el coste conscientemente.

- [ ] **Revisar la privacidad de Facebook.** La auditoría manual del 2026-05-20
      registró fotos visibles sin necesidad de iniciar sesión.

- [ ] **Ubicación pública en GitHub.** «San Salvador, El Salvador» en el perfil, más
      la universidad y el área de estudio en fuentes indexadas. Combinados permiten
      identificarte de forma unívoca. Decidir si el valor profesional compensa.

- [ ] **Los commits antiguos conservan el Gmail.** El cambio a
      `@users.noreply.github.com` corta la filtración hacia adelante; los commits ya
      hechos siguen exponiéndolo. Reescribir historiales solo compensa en repos
      públicos y con pocos commits.

---

## Lab — funcionalidad

- [ ] **Escaneo completo del almacenamiento en la nube.** El montaje rclone no termina
      de recorrerse en los 180s de `local_audit.cloud_scan_timeout`, así que ese frente
      queda sin cubrir. Subir el timeout para una pasada completa, o cachear el listado
      remoto entre ejecuciones en vez de recorrerlo cada vez.

- [ ] **Consumir los campos de config declarados pero no leídos.**
      - `identities.full_names` → búsquedas por nombre en theHarvester
      - `identities.social_profiles` → verificar que los perfiles siguen activos y qué exponen
      - `SHODAN_API_KEY` → consulta por IP pública y dominios propios

- [ ] **Configurar `HIBP_API_KEY`** en `vault/.env`. Sin ella, el módulo de brechas de
      datos no corre — y es el que responde si tu email ya está en un dump público.

- [ ] **Configurar `GITHUB_TOKEN`** en `vault/.env`. Sin él, la API de GitHub limita a
      60 peticiones por hora.

- [ ] **Instalar `subfinder`.** Requiere Go; es lo único de `setup.sh` que sigue sin
      resolverse. Sin él no hay enumeración de subdominios.

- [ ] **Reducir el ruido de Sherlock.** Devuelve perfiles en plataformas donde el
      username coincide por casualidad. Contrastar contra `identities.social_profiles`
      para separar «cuenta tuya» de «alguien con tu mismo nick».

---

## Lab — calidad

- [ ] **Smoke-tests.** No hay ninguno. El mínimo útil: ejecutar cada módulo contra una
      config de prueba y verificar que produce JSON válido con el esquema esperado.
      Los bugs que aparecieron al reorganizar el repo — `set -e` abortando en `grep -c`,
      loopback mal filtrado, DMARC confundido con un TXT wildcard — los habría atrapado
      un smoke-test.

- [ ] **Modo `--dry-run`.** Ejecutar el flujo completo con datos sintéticos, sin tocar
      la red ni el sistema. Necesario para demostrar el lab y para desarrollar sin
      consumir cuota de APIs ni correr nmap.

- [ ] **Seguimiento temporal.** Cada auditoría es una foto aislada. Comparar contra la
      anterior permitiría reportar qué apareció, qué desapareció y qué lleva N ciclos
      sin remediarse. La baseline archivada en el vault es el punto de partida.

- [ ] **Ejecución periódica.** Un timer que corra `make audit` y notifique solo si hay
      hallazgos nuevos. Una auditoría que haya que recordar manualmente no se hace.

- [ ] **Deduplicar hallazgos entre módulos.** El módulo local y el de red reportan por
      separado el mismo puerto expuesto.

- [ ] **Salida del reporte en JSON**, además de `.md` y `.html`, para consumirlo desde
      otras herramientas.

- [ ] **Screenshot del reporte en el README.** Depende de `--dry-run`: hace falta poder
      generar una captura con datos ficticios en lugar de hallazgos reales.

---

## Reintegrar cuando haya módulo que las use

Retiradas de `setup.sh` por no ser invocadas por nada:

- [ ] **SpiderFoot** — ~200 MB de clon sin usar
- [ ] **amass** — `subfinder` ya cubre subdominios; amass solo se justifica para
      correlación pasiva más profunda
