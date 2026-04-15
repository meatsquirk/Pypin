.PHONY: help install install-dev test test-cov lint format typecheck clean docs all

# Default target
help:
	@echo "DCPP Python - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install package in editable mode"
	@echo "  make install-dev  Install with dev dependencies"
	@echo ""
	@echo "Quality:"
	@echo "  make lint         Run linter (ruff)"
	@echo "  make format       Format code (ruff)"
	@echo "  make typecheck    Run type checker (mypy)"
	@echo "  make test         Run tests"
	@echo "  make test-cov     Run tests with coverage"
	@echo ""
	@echo "Other:"
	@echo "  make clean        Remove build artifacts"
	@echo "  make all          Run all quality checks"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pip install ruff mypy pre-commit

# Testing
test:
	PYTHONPATH="src" python3 -m pytest tests/ -v

test-cov:
	PYTHONPATH="src" python3 -m pytest tests/ -v --cov=dcpp_python --cov-report=term-missing --cov-report=html

test-fast:
	PYTHONPATH="src" python3 -m pytest tests/ -v -x --tb=short

# Code quality
lint:
	python3 -m ruff check .

lint-fix:
	python3 -m ruff check --fix .

format:
	python3 -m ruff format .

format-check:
	python3 -m ruff format --check .

typecheck:
	python3 -m mypy src/dcpp_python --ignore-missing-imports

# Pre-commit
pre-commit-install:
	pre-commit install

pre-commit-run:
	pre-commit run --all-files

# Documentation
docs:
	@echo "Documentation build not yet configured"
	@echo "See docs/IMPROVEMENT_ROADMAP.md for plans"

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf dcpp.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Combined targets
all: lint format-check typecheck test
	@echo "All checks passed!"

ci: lint-fix format test-cov
	@echo "CI checks complete!"
