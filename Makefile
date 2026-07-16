.PHONY: tests help install lint format tcheck commit-checks prepare gitleaks pypibuild pypipush container container-local
SHELL := /usr/bin/bash
.ONESHELL:

venv_activated=if [ -z $${VIRTUAL_ENV+x} ]; then printf "activating venv...\n" ; source .venv/bin/activate ; else printf "venv already activated\n"; fi

help:
	@printf "\ninstall\n\tinstall requirements\n"
	@printf "\nformat\n\tauto-format + fix imports with ruff\n"
	@printf "\nlint\n\tcheck formatting + lint with ruff (non-mutating)\n"
	@printf "\ntcheck\n\tstatic type checks with mypy\n"
	@printf "\ntests\n\tLaunch tests\n"
	@printf "\nprepare\n\tLaunch tests and commit-checks\n"
	@printf "\ncommit-checks\n\trun pre-commit checks on all files\n"
	@printf "\ngitleaks\n\tscan repo for leaked secrets\n"
	@printf "\npypibuild\n\tbuild package for pypi\n"
	@printf "\npypipush\n\tpush package to pypi\n"
	@printf "\ncontainer\n\tbuild + push multi-arch image to ghcr.io\n"
	@printf "\ncontainer-local\n\tbuild image for the local arch only (no push)\n"

install: .venv

.venv: .venv/touchfile

# All deps (incl. dev + the optional redis extra) come from pyproject.toml —
# no separate requirements*.txt to keep in sync.
.venv/touchfile: pyproject.toml
	test -d .venv || python3.14 -m venv .venv
	source .venv/bin/activate
	pip install -e ".[dev,redis]"
	touch .venv/touchfile

tests: .venv
	@$(venv_activated)
	pytest .

# ruff covers formatting + import sorting + linting (replaces black + isort).
format: .venv
	@$(venv_activated)
	ruff format .
	ruff check --fix .

lint: .venv
	@$(venv_activated)
	ruff format --check .
	ruff check .

tcheck: .venv
	@$(venv_activated)
	mypy .

gitleaks: .venv .git/hooks/pre-commit
	@$(venv_activated)
	pre-commit run gitleaks --all-files

.git/hooks/pre-commit: .venv
	@$(venv_activated)
	pre-commit install

commit-checks: .git/hooks/pre-commit
	@$(venv_activated)
	pre-commit run --all-files

prepare: tests commit-checks

# --- PyPI packaging -----------------------------------------------------
# Project name is `littlessollm` (pyproject.toml), so hatch emits
# dist/littlessollm-<version>.* (PEP 625 normalized, no separators to fold).
# Version is dynamic, read from littlessollm/__init__.py.
PKG_SOURCES := $(shell find littlessollm -type f -name '*.py')
VERSION := $(shell $(venv_activated) > /dev/null 2>&1 && hatch version 2>/dev/null || echo HATCH_NOT_FOUND)

dist/littlessollm-$(VERSION).tar.gz dist/littlessollm-$(VERSION)-py3-none-any.whl dist/.touchfile: $(PKG_SOURCES) pyproject.toml
	@printf "VERSION: $(VERSION)\n"
	@$(venv_activated)
	hatch build --clean
	@touch dist/.touchfile

pypibuild: dist/littlessollm-$(VERSION).tar.gz dist/littlessollm-$(VERSION)-py3-none-any.whl

dist/.touchfile_push: dist/littlessollm-$(VERSION).tar.gz dist/littlessollm-$(VERSION)-py3-none-any.whl
	@$(venv_activated)
	hatch publish -r main
	@touch dist/.touchfile_push

pypipush: dist/.touchfile_push

# --- Container image (ghcr.io) ------------------------------------------
# The multi-arch build + push is driven by repo_scripts/build-container-multiarch.sh,
# which logs in to ghcr.io and pushes ghcr.io/<owner>/littlessollm (config in
# repo_scripts/include.sh / include.local.sh). The image bundles littlessollm
# on top of upstream litellm — see Dockerfile.
container:
	./repo_scripts/build-container-multiarch.sh

container-local:
	./repo_scripts/build-container-multiarch.sh onlylocal
