# ─────────────────────────────────────────────────────────────────────────────
# xVulnv2 — Makefile
# CLI-driven orchestration for the benchmark vulnerability lab.
#
# Usage:
#   make build                        Build server + CLI tool
#   make run                          Build and start the application
#   make reset                        Reset database to seed state (CLI)
#   make scan SCANNER=my-scanner      Start a scan session (custom header value)
#   make scan-stop SCANNER=my-scanner Stop a scan session
#   make report SCANNER=my-scanner    Generate HTML pentest report
#   make clean                        Remove binaries, reports, and database
#   make help                         Show this help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: build run reset scan scan-stop report clean help

# ─── Configuration ─────────────────────────────────────────────────────────────

APP_NAME     := xvulnv2
CLI_NAME     := xvulnctl
CLI_PKG      := ./cmd/xvulnctl
DB_PATH      ?= ./restaurant.db

# Scanner ID validation pattern: alphanumeric, hyphens, underscores, 1-64 chars
SCANNER_RE   := ^[a-zA-Z0-9_-]{1,64}$$

# ─── Default ───────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

# ─── Build ─────────────────────────────────────────────────────────────────────

build: ## Build server binary and CLI tool
	@echo "🔨 Building $(APP_NAME)..."
	@go build -o $(APP_NAME) .
	@echo "🔨 Building $(CLI_NAME)..."
	@go build -o $(CLI_NAME) $(CLI_PKG)
	@echo "✅ Build complete"

# ─── Run ───────────────────────────────────────────────────────────────────────

run: build ## Build and start the application
	@echo "🚀 Starting $(APP_NAME)..."
	@./$(APP_NAME)

# ─── Reset ─────────────────────────────────────────────────────────────────────

reset: build ## Reset database to seed state (via CLI, not HTTP)
	@echo "🔄 Resetting database..."
	@DB_PATH=$(DB_PATH) ./$(CLI_NAME) reset

# ─── Scan ──────────────────────────────────────────────────────────────────────

scan: build ## Start a scan session (requires SCANNER=<custom_header>)
ifndef SCANNER
	$(error ❌ SCANNER is required. Usage: make scan SCANNER=my-scanner-v1)
endif
	@if ! echo "$(SCANNER)" | grep -qE '$(SCANNER_RE)'; then \
		echo "❌ Invalid SCANNER value '$(SCANNER)' — must match [a-zA-Z0-9_-]{1,64}"; \
		exit 1; \
	fi
	@DB_PATH=$(DB_PATH) ./$(CLI_NAME) scan start --scanner=$(SCANNER)

scan-stop: build ## Stop a scan session (requires SCANNER=<custom_header>)
ifndef SCANNER
	$(error ❌ SCANNER is required. Usage: make scan-stop SCANNER=my-scanner-v1)
endif
	@if ! echo "$(SCANNER)" | grep -qE '$(SCANNER_RE)'; then \
		echo "❌ Invalid SCANNER value '$(SCANNER)' — must match [a-zA-Z0-9_-]{1,64}"; \
		exit 1; \
	fi
	@DB_PATH=$(DB_PATH) ./$(CLI_NAME) scan stop --scanner=$(SCANNER)

# ─── Report ────────────────────────────────────────────────────────────────────

report: build ## Generate HTML pentest report (requires SCANNER=<custom_header>)
ifndef SCANNER
	$(error ❌ SCANNER is required. Usage: make report SCANNER=my-scanner-v1)
endif
	@if ! echo "$(SCANNER)" | grep -qE '$(SCANNER_RE)'; then \
		echo "❌ Invalid SCANNER value '$(SCANNER)' — must match [a-zA-Z0-9_-]{1,64}"; \
		exit 1; \
	fi
	@DB_PATH=$(DB_PATH) ./$(CLI_NAME) report generate --scanner=$(SCANNER)

# ─── Clean ─────────────────────────────────────────────────────────────────────

clean: ## Remove binaries, reports, and database
	@echo "🧹 Cleaning up..."
	@rm -f $(APP_NAME) $(CLI_NAME)
	@rm -rf reports/
	@rm -f restaurant.db restaurant.db-shm restaurant.db-wal
	@echo "✅ Clean complete"

# ─── Help ──────────────────────────────────────────────────────────────────────

help: ## Show available targets
	@echo ""
	@echo "  xVulnv2 — Benchmark Vulnerability Lab"
	@echo "  ═══════════════════════════════════════"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Examples:"
	@echo "    make run"
	@echo "    make reset"
	@echo "    make scan SCANNER=zap-run-001"
	@echo "    make report SCANNER=zap-run-001"
	@echo ""
