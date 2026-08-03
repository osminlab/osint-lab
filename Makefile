LAB_DIR := $(shell pwd)
VENV    := $(LAB_DIR)/.venv
SCRIPTS := $(LAB_DIR)/scripts
VAULT   := $(LAB_DIR)/vault

# Los scripts Python se re-lanzan solos dentro del venv si existe (lib/paths.py),
# así que basta con un intérprete de arranque: el del venv si está, si no el del sistema.
PYTHON := $(shell test -x $(VENV)/bin/python3 && echo $(VENV)/bin/python3 || command -v python3)

.PHONY: help setup init audit audit-local audit-secrets audit-network audit-identity \
        report verify clean clean-tools

help:
	@echo ""
	@echo "  osint-lab — auditoría defensiva de huella digital"
	@echo ""
	@echo "  Preparación"
	@echo "    make setup           Dependencias del sistema, venv y herramientas OSINT"
	@echo "    make init            Crea vault/ y la config local desde la plantilla"
	@echo ""
	@echo "  Auditoría"
	@echo "    make audit           Todos los módulos + reporte consolidado"
	@echo "    make audit-local     Puertos, Docker, .env, permisos SSH, grupos"
	@echo "    make audit-secrets   Secretos en repos, historial Git y nube"
	@echo "    make audit-network   DNS, SPF/DMARC, WHOIS, exposición de servicios"
	@echo "    make audit-identity  Usernames, GitHub, brechas de datos"
	@echo "    make report          Reporte .md + .html desde los últimos scans"
	@echo ""
	@echo "  Higiene"
	@echo "    make verify          Comprueba que nada sensible es rastreable por git"
	@echo "    make clean           Borra scans y reportes del vault"
	@echo "    make clean-tools     Borra las herramientas clonadas"
	@echo ""

setup:
	@bash $(LAB_DIR)/setup.sh

init:
	@bash $(SCRIPTS)/init_vault.sh

audit: audit-local audit-secrets audit-network audit-identity report
	@echo ""
	@echo "✓ Auditoría completa. Reportes en $(VAULT)/reports/"

audit-local:
	@bash $(SCRIPTS)/audit_local.sh

audit-secrets:
	@bash $(SCRIPTS)/audit_secrets.sh

audit-network:
	@bash $(SCRIPTS)/audit_network.sh

audit-identity:
	@$(PYTHON) $(SCRIPTS)/audit_identity.py

report:
	@$(PYTHON) $(SCRIPTS)/report_generator.py

verify:
	@bash $(SCRIPTS)/verify_hygiene.sh

# El vault entero nunca se borra automáticamente: contiene auditorías manuales y
# configuración que no se puede regenerar. Solo se limpian las salidas de scans.
clean:
	@echo "Limpiando scans y reportes del vault..."
	@rm -f $(VAULT)/scans/*.json $(VAULT)/reports/*.md $(VAULT)/reports/*.html
	@echo "✓ Limpio (auditorías manuales y config intactas)"

clean-tools:
	@echo "Borrando herramientas clonadas..."
	@find $(LAB_DIR)/tools -mindepth 1 -not -name '.gitkeep' -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ tools/ vacío — recuperar con: make setup"
