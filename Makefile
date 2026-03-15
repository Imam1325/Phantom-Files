.PHONY: install build-image run validate prod-check bootstrap test test-unit test-integration test-slow lint fmt package clean help

VENV_DIR ?= .venv
PYTHON ?= python3
ifneq ($(wildcard $(VENV_DIR)/bin/python3),)
PYTHON := $(VENV_DIR)/bin/python3
endif

install:
	@echo "Installing Phantom package..."
	pip install -e .
	pip install pytest pytest-cov pytest-asyncio httpx ruff black
	@echo "Building forensic image..."
	$(MAKE) build-image

build-image:
	docker build -t phantom-forensics:v2 -f resources/docker/Dockerfile .

run:
	@echo "Starting Phantom Files Daemon v1.0.0..."
	PYTHONPATH=src $(PYTHON) -m phantom

validate:
	@echo "Validating Phantom configuration..."
	PYTHONPATH=src $(PYTHON) -m phantom.cli validate

prod-check:
	@echo "Running production readiness checks..."
	PYTHONPATH=src $(PYTHON) -m phantom.cli prod-check

bootstrap:
	@echo "Bootstrapping system prerequisites (requires sudo)..."
	PYTHONPATH=src $(PYTHON) -m phantom.cli bootstrap

test:
	@echo "Running tests..."
	PYTHONPATH=src $(PYTHON) -m pytest tests/ -q --tb=short

test-unit:
	@echo "Running unit tests..."
	PYTHONPATH=src $(PYTHON) -m pytest -m "unit" -q --tb=short

test-integration:
	@echo "Running integration tests..."
	PYTHONPATH=src $(PYTHON) -m pytest -m "integration" -q --tb=short

test-slow:
	@echo "Running slow tests..."
	PYTHONPATH=src $(PYTHON) -m pytest -m "slow" -q --tb=short

test-cov:
	@echo "Running tests with coverage..."
	PYTHONPATH=src $(PYTHON) -m pytest tests/ \
		--cov=phantom \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		-q --tb=short

lint:
	@echo "Running linters..."
	ruff check src/ tests/
	black --check src/ tests/

fmt:
	@echo "Formatting code..."
	black src/ tests/
	ruff check --fix src/ tests/

package-deb:
	@echo "Building .deb package..."
	nfpm package --packager deb

package-rpm:
	@echo "Building .rpm package..."
	nfpm package --packager rpm

package: package-deb package-rpm

clean:
	@echo "Cleaning artifacts..."
	rm -rf build dist *.egg-info htmlcov .coverage coverage.xml
	find . -name "__pycache__" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf /tmp/phantom_traps /tmp/phantom_logs /tmp/phantom_evidence

help:
	@echo "Phantom Files Daemon v1.0.0 — Makefile targets:"
	@echo ""
	@echo "  make install      Install package + dev dependencies"
	@echo "  make run          Start daemon"
	@echo "  make test         Run tests"
	@echo "  make test-unit    Run unit tests"
	@echo "  make test-integration Run integration tests"
	@echo "  make test-slow    Run slow tests"
	@echo "  make test-cov     Run tests with coverage report"
	@echo "  make lint         Run linters (ruff + black)"
	@echo "  make fmt          Auto-format code"
	@echo "  make validate     Validate config"
	@echo "  make prod-check   Run production readiness checklist"
	@echo "  make bootstrap    Create phantom user/groups/dirs (sudo)"
	@echo "  make package      Build .deb and .rpm packages (nfpm)"
	@echo "  make clean        Cleanup temporary files"
