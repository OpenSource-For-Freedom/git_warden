# Git Warden -- common developer and operator commands.
# Cross-platform: GNU make on Linux/macOS and on Windows. On Windows, install
# make via Git Bash, scoop, or `choco install make`. Targets run from a clean
# checkout (PYTHONPATH=src), so `make install` is optional. Every recipe shells
# out only to Python, so there is no bash-vs-cmd dependency.
#
# Override the interpreter with `make PY=python ...` if your platform differs.

ifeq ($(OS),Windows_NT)
PY ?= python
else
PY ?= python3
endif

export PYTHONPATH := src
GW := $(PY) -m git_warden.cli

.DEFAULT_GOAL := help
.PHONY: help install test lint fmt check ingest hunt discover iocs review serve clean

help: ## List the available commands
	@$(PY) -c "import re,glob; [print(f'  {m.group(1):14}{m.group(2)}') for f in ['Makefile']+glob.glob('Makefile.local') for l in open(f) for m in [re.match(r'([a-zA-Z_-]+):.*?## (.*)', l)] if m]"

# --- Development ---
install: ## Install the package with dev tools (editable)
	$(PY) -m pip install -e ".[dev]"

test: ## Run the full test suite
	$(PY) -m pytest -q

lint: ## Check style with ruff
	$(PY) -m ruff check src tests gw.py

fmt: ## Auto-fix lint findings
	$(PY) -m ruff check --fix src tests gw.py

check: lint test ## Lint + test -- run before pushing

# --- Threat-intel pipeline ---
ingest: ## Pull feeds (OSM, MITRE, CISA, news) into the DB
	$(GW) ingest

hunt: ## Hunt GitHub for malicious repos (override with LIMIT=N)
	$(GW) hunt --scan --gold --limit $(or $(LIMIT),30)

discover: ## Mirror OSM IOCs into GitHub code search
	$(GW) discover

iocs: ## Show the aggregated IOC pivot set
	$(GW) iocs

review: ## List confirmed findings (override with ARGS="--reject owner/repo")
	$(GW) review $(or $(ARGS),--list)

serve: ## Serve the telemetry dashboard on http://127.0.0.1:8787
	$(GW) serve

clean: ## Remove caches and scratch logs
	$(PY) -c "import shutil,glob,os; [shutil.rmtree(p,ignore_errors=True) for p in glob.glob('**/__pycache__',recursive=True)+['.pytest_cache','.ruff_cache']]; [os.remove(f) for f in glob.glob('*.log')]"

# Local-only targets (e.g. OSM submit) live in an untracked Makefile.local that
# is .gitignored, so the public Makefile never references the submit feature.
-include Makefile.local
