# ============================================
# WazuhBOTS — Makefile
# Quick commands for common operations
# ============================================

.PHONY: help setup deploy stop start restart status health logs
.PHONY: ingest reset clean nuke

# Auto-detect Podman or Docker
ifeq ($(shell command -v podman-compose 2>/dev/null),)
  ifeq ($(shell command -v podman 2>/dev/null && podman compose version >/dev/null 2>&1 && echo ok),ok)
    COMPOSE = podman compose
  else
    COMPOSE = docker compose
  endif
else
  COMPOSE = podman-compose
endif
COMPOSE_FILE = docker-compose.yml

# Default target
help: ## Show this help message
	@echo ""
	@echo "  🐺 WazuhBOTS — Boss of the SOC"
	@echo "  ================================"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ============================================
# DEPLOYMENT
# ============================================

setup: ## Run full setup (first time)
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

deploy: ## Deploy all services
	@$(COMPOSE) -f $(COMPOSE_FILE) up -d --build
	@echo "Waiting for services..."
	@sleep 15
	@$(MAKE) health

stop: ## Stop all services
	@$(COMPOSE) -f $(COMPOSE_FILE) stop

start: ## Start all services
	@$(COMPOSE) -f $(COMPOSE_FILE) start

restart: ## Restart all services
	@$(COMPOSE) -f $(COMPOSE_FILE) restart

down: ## Stop and remove containers (keeps volumes)
	@$(COMPOSE) -f $(COMPOSE_FILE) down

# ============================================
# MONITORING
# ============================================

status: ## Show container status
	@$(COMPOSE) -f $(COMPOSE_FILE) ps

health: ## Run health checks
	@chmod +x scripts/health_check.sh
	@./scripts/health_check.sh

logs: ## Tail logs from all services
	@$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=50

logs-manager: ## Tail Wazuh Manager logs
	@$(COMPOSE) -f $(COMPOSE_FILE) logs -f wazuh-manager

logs-ctfd: ## Tail CTFd logs
	@$(COMPOSE) -f $(COMPOSE_FILE) logs -f ctfd

# ============================================
# DATA MANAGEMENT
# ============================================

ingest: ## Ingest all datasets into Wazuh Indexer
	@python3 scripts/ingest_datasets.py --all

ingest-scenario1: ## Ingest Scenario 1 (Dark Harvest)
	@python3 scripts/ingest_datasets.py --scenario scenario1_dark_harvest

ingest-scenario3: ## Ingest Scenario 3 (Ghost in the Shell)
	@python3 scripts/ingest_datasets.py --scenario scenario3_ghost_shell

export: ## Export datasets from Wazuh Indexer
	@chmod +x scripts/export_datasets.sh
	@./scripts/export_datasets.sh

# ============================================
# COMPETITION
# ============================================

flags: ## Generate and load CTFd flags
	@python3 scripts/generate_flags.py

reset: ## Reset competition (scores, submissions)
	@chmod +x scripts/reset_environment.sh
	@./scripts/reset_environment.sh

# ============================================
# CLEANUP
# ============================================

clean: ## Remove containers and networks (keeps volumes)
	@$(COMPOSE) -f $(COMPOSE_FILE) down --remove-orphans

nuke: ## DANGER: Remove everything including volumes
	@echo "WARNING: This will delete ALL data including datasets!"
	@read -p "Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ] || exit 1
	@$(COMPOSE) -f $(COMPOSE_FILE) down -v --remove-orphans
	@echo "All data removed."
