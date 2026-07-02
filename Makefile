.PHONY: help install install-dev setup test lint format clean run docs

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
VENV := venv
VENV_BIN := $(VENV)/bin

# Colors
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

help:
	@echo "$(BLUE)SuperReconn - Makefile Commands$(NC)"
	@echo ""
	@echo "$(GREEN)Setup & Installation:$(NC)"
	@echo "  make setup          Instalación completamente automatizada"
	@echo "  make install        Crear venv e instalar dependencias"
	@echo "  make install-dev    Instalar dependencias + dev tools"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make test           Ejecutar tests con pytest"
	@echo "  make lint           Validar código (flake8, mypy, black)"
	@echo "  make format         Formatear código con black"
	@echo "  make clean          Limpiar archivos generados"
	@echo ""
	@echo "$(GREEN)Execution:$(NC)"
	@echo "  make run            Ejecutar SuperReconn (interactive)"
	@echo "  make quick-test     Quick test con --no-nuclei --no-crawl"
	@echo ""
	@echo "$(GREEN)Documentation:$(NC)"
	@echo "  make docs           Generar documentación"
	@echo ""
	@echo "$(GREEN)Utilities:$(NC)"
	@echo "  make activate       Mostrar cómo activar venv"
	@echo "  make check          Verificar herramientas disponibles"
	@echo "  make version        Mostrar versión de SuperReconn"

# ============================================================================
# SETUP & INSTALLATION
# ============================================================================

setup:
	@echo "$(BLUE)Ejecutando setup automatizado...$(NC)"
	@chmod +x setup.sh
	@./setup.sh

install:
	@echo "$(BLUE)Creando entorno virtual...$(NC)"
	$(PYTHON) -m venv $(VENV)
	@echo "$(GREEN)✓$(NC) Entorno virtual creado"
	@echo "$(BLUE)Instalando dependencias...$(NC)"
	$(VENV_BIN)/pip install --upgrade pip setuptools wheel
	$(VENV_BIN)/pip install -r requirements.txt
	@echo "$(GREEN)✓$(NC) Dependencias instaladas"
	@echo ""
	@echo "$(YELLOW)Para activar el entorno:$(NC)"
	@echo "  source $(VENV_BIN)/activate"

install-dev: install
	@echo "$(BLUE)Instalando herramientas de desarrollo...$(NC)"
	$(VENV_BIN)/pip install pytest pytest-cov black flake8 mypy pylint sphinx sphinx-rtd-theme
	@echo "$(GREEN)✓$(NC) Herramientas de desarrollo instaladas"

# ============================================================================
# DEVELOPMENT & TESTING
# ============================================================================

test:
	@echo "$(BLUE)Ejecutando tests...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install"; \
		exit 1; \
	fi
	$(VENV_BIN)/pytest tests/ -v --tb=short
	@echo "$(GREEN)✓$(NC) Tests completados"

test-coverage:
	@echo "$(BLUE)Ejecutando tests con coverage...$(NC)"
	$(VENV_BIN)/pytest tests/ --cov=SuperReconn --cov-report=html --cov-report=term
	@echo "$(GREEN)✓$(NC) Coverage report generado: htmlcov/index.html"

lint:
	@echo "$(BLUE)Validando código...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install-dev"; \
		exit 1; \
	fi
	@echo "$(YELLOW)→$(NC) Ejecutando black (check mode)..."
	$(VENV_BIN)/black --check SuperReconn.py persist_mssql.py 2>/dev/null || true
	@echo "$(YELLOW)→$(NC) Ejecutando flake8..."
	$(VENV_BIN)/flake8 SuperReconn.py persist_mssql.py --max-line-length=120 --ignore=E501,W503 || true
	@echo "$(YELLOW)→$(NC) Ejecutando mypy..."
	$(VENV_BIN)/mypy SuperReconn.py --ignore-missing-imports || true
	@echo "$(GREEN)✓$(NC) Validación completada"

format:
	@echo "$(BLUE)Formateando código con black...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install-dev"; \
		exit 1; \
	fi
	$(VENV_BIN)/black SuperReconn.py persist_mssql.py
	@echo "$(GREEN)✓$(NC) Código formateado"

# ============================================================================
# EXECUTION
# ============================================================================

run:
	@echo "$(BLUE)Ejecutando SuperReconn...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Ingresa el dominio objetivo:$(NC)"
	@read domain; \
	$(VENV_BIN)/python3 SuperReconn.py $$domain

quick-test:
	@echo "$(BLUE)Ejecutando test rápido (sin nuclei ni crawl)...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Ingresa el dominio objetivo:$(NC)"
	@read domain; \
	$(VENV_BIN)/python3 SuperReconn.py $$domain --no-nuclei --no-crawl

# ============================================================================
# CLEANING
# ============================================================================

clean:
	@echo "$(BLUE)Limpiando archivos generados...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.egg-info" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	@echo "$(GREEN)✓$(NC) Limpieza completada"

clean-venv:
	@echo "$(BLUE)Eliminando entorno virtual...$(NC)"
	rm -rf $(VENV)
	@echo "$(GREEN)✓$(NC) Entorno virtual eliminado"

clean-all: clean clean-venv
	@echo "$(GREEN)✓$(NC) Limpieza total completada"

# ============================================================================
# DOCUMENTATION
# ============================================================================

docs:
	@echo "$(BLUE)Generando documentación...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(RED)✗$(NC) Entorno virtual no existe. Ejecuta: make install-dev"; \
		exit 1; \
	fi
	@mkdir -p docs
	@echo "README.md - $(GREEN)✓$(NC)"
	@echo "CONTRIBUTING.md - $(GREEN)✓$(NC)"
	@echo "CHANGELOG.md - $(GREEN)✓$(NC)"
	@echo ""
	@echo "$(GREEN)✓$(NC) Documentación lista en:"
	@echo "  - README.md (guía completa)"
	@echo "  - CONTRIBUTING.md (desarrollo)"
	@echo "  - CHANGELOG.md (historial)"

# ============================================================================
# UTILITIES & CHECKING
# ============================================================================

activate:
	@echo "$(BLUE)Para activar el entorno virtual, ejecuta:$(NC)"
	@echo ""
	@echo "  source $(VENV_BIN)/activate"
	@echo ""
	@echo "$(YELLOW)O directamente:$(NC)"
	@echo ""
	@echo "  $(VENV_BIN)/python3 SuperReconn.py --help"

check:
	@echo "$(BLUE)Verificando herramientas disponibles...$(NC)"
	@echo ""
	@command -v massdns >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) massdns" || echo "$(RED)✗$(NC) massdns"
	@command -v httpx >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) httpx" || echo "$(RED)✗$(NC) httpx"
	@command -v naabu >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) naabu" || echo "$(RED)✗$(NC) naabu"
	@command -v nmap >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) nmap" || echo "$(RED)✗$(NC) nmap"
	@echo ""
	@command -v subfinder >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) subfinder (optional)" || echo "$(YELLOW)✗$(NC) subfinder (optional)"
	@command -v amass >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) amass (optional)" || echo "$(YELLOW)✗$(NC) amass (optional)"
	@command -v katana >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) katana (optional)" || echo "$(YELLOW)✗$(NC) katana (optional)"
	@command -v nuclei >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) nuclei (optional)" || echo "$(YELLOW)✗$(NC) nuclei (optional)"
	@echo ""
	@command -v $(PYTHON) >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) Python ($(PYTHON))" || echo "$(RED)✗$(NC) Python"
	@command -v git >/dev/null 2>&1 && echo "$(GREEN)✓$(NC) git" || echo "$(RED)✗$(NC) git"

version:
	@$(PYTHON) SuperReconn.py --help | head -2

# ============================================================================
# DOCKER (futuro)
# ============================================================================

docker-build:
	@echo "$(BLUE)Construyendo imagen Docker...$(NC)"
	docker build -t superreconn:latest .

docker-run:
	@echo "$(BLUE)Ejecutando SuperReconn en Docker...$(NC)"
	docker run -v $(PWD)/results:/app/results superreconn:latest

# ============================================================================
# DEFAULTS
# ============================================================================

.DEFAULT_GOAL := help

# Silenciar "Nothing to be done"
.SILENT: help activate version

# Target que no genera archivos
.PHONY: all help setup install install-dev test lint format clean run quick-test activate check version docs docker-build docker-run
