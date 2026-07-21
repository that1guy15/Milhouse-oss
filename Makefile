ifneq ($(strip $(MAKEFILES)),)
$(error Milhouse gates refuse MAKEFILES preloads)
endif

override SHELL := /bin/sh
override .SHELLFLAGS := -eu -c
override PYTHON := python3
override UV := $(PYTHON) -I scripts/run_uv.py
override UV_RUN := $(UV) run --locked --all-groups --all-extras --exact

_MILHOUSE_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
_MILHOUSE_REPO_ROOT := $(patsubst %/,%,$(dir $(_MILHOUSE_MAKEFILE)))
ifneq ($(realpath $(CURDIR)),$(_MILHOUSE_REPO_ROOT))
$(error Milhouse Makefile must be run from its repository root)
endif

_MILHOUSE_SHORT_MAKEFLAGS := $(filter-out -%,$(firstword $(MAKEFLAGS)))
_MILHOUSE_UNSAFE_LONG_MAKEFLAGS := $(filter --dry-run --ignore-errors --just-print --question --touch,$(MAKEFLAGS))
ifneq ($(strip $(findstring i,$(_MILHOUSE_SHORT_MAKEFLAGS))$(findstring n,$(_MILHOUSE_SHORT_MAKEFLAGS))$(findstring q,$(_MILHOUSE_SHORT_MAKEFLAGS))$(findstring t,$(_MILHOUSE_SHORT_MAKEFLAGS))$(_MILHOUSE_UNSAFE_LONG_MAKEFLAGS)),)
$(error Milhouse gates refuse make dry-run, ignore-error, question, or touch modes)
endif

_MILHOUSE_TARGETS := setup lock lock-check format format-check lint type-check test test-coverage \
	repo-check docs-check workflow-check skill-check quality build package-check \
	artifact-smoke audit license-check private-identifier-check secret-scan \
	secret-scan-self-test

.PHONY: $(_MILHOUSE_TARGETS)
$(_MILHOUSE_TARGETS): override SHELL := /bin/sh
$(_MILHOUSE_TARGETS): override .SHELLFLAGS := -eu -c
$(_MILHOUSE_TARGETS): override PYTHON := python3
$(_MILHOUSE_TARGETS): override UV := $(PYTHON) -I scripts/run_uv.py
$(_MILHOUSE_TARGETS): override UV_RUN := $(UV) run --locked --all-groups --all-extras --exact

setup:
	./setup.sh

lock:
	$(UV) lock

lock-check:
	$(UV) lock --check

format:
	$(UV_RUN) ruff check --fix src tests scripts
	$(UV_RUN) ruff format src tests scripts

format-check:
	$(UV_RUN) ruff format --check src tests scripts

lint:
	$(UV_RUN) ruff check src tests scripts

type-check:
	$(UV_RUN) mypy

test:
	$(UV_RUN) python -m pytest

test-coverage:
	mkdir -p build
	$(UV_RUN) python -m pytest --cov --cov-branch \
		--cov-report=term-missing --cov-report=json:build/coverage.json
	$(UV_RUN) python scripts/check_coverage.py build/coverage.json \
		--line 90 --branch 85 \
		--critical 'src/milhouse/config/filesystem.py' \
		--critical 'src/milhouse/config/loader.py' \
		--critical 'src/milhouse/config/paths.py' \
		--critical 'src/milhouse/config/secrets.py' \
		--critical 'src/milhouse/resources/__init__.py' \
		--critical 'src/milhouse/core/canonical.py' \
		--critical 'src/milhouse/domain/identity.py' \
		--critical 'src/milhouse/domain/records.py' \
		--critical 'src/milhouse/privacy/allowlist.py' \
		--critical 'src/milhouse/privacy/pseudonym.py' \
		--critical 'src/milhouse/privacy/redact.py' \
		--critical 'src/milhouse/privacy/render.py' \
		--critical 'src/milhouse/privacy/sanitize.py' \
		--critical 'scripts/check_artifacts.py' \
		--critical 'scripts/check_coverage.py' \
		--critical 'scripts/check_dco.py' \
		--critical 'scripts/check_links.py' \
		--critical 'scripts/check_private_identifiers.py' \
		--critical 'scripts/gitleaks.py' \
		--critical 'scripts/prepare_environment.py' \
		--critical 'scripts/required_ci.py' \
		--critical 'scripts/run_make.py' \
		--critical 'scripts/run_uv.py' \
		--critical 'scripts/secret_scan.py' \
		--critical 'scripts/validate_config.py' \
		--critical 'scripts/validate_workflows.py' \
		--critical 'scripts/milhouse_tools/strict_data.py' \
		--critical-branch 95

repo-check:
	/bin/sh -n setup.sh
	$(UV_RUN) validate-pyproject pyproject.toml
	$(UV_RUN) python scripts/validate_config.py \
		--require-repository-policy \
		pyproject.toml config .github tests/fixtures src/milhouse/resources

docs-check:
	$(UV_RUN) python scripts/check_links.py --repo-root . --external \
		--max-external 50 --timeout 5 --max-redirects 3 .

workflow-check:
	$(UV_RUN) python scripts/validate_workflows.py --require-aggregate .github/workflows
	$(UV_RUN) zizmor --pedantic .github/workflows

skill-check:
	$(UV_RUN) python scripts/validate_skills.py

quality: lock-check format-check lint type-check repo-check docs-check workflow-check skill-check

build:
	rm -rf ./build ./dist ./src/milhouse_observability.egg-info
	$(UV_RUN) python -m build --no-isolation

package-check:
	$(UV_RUN) validate-pyproject pyproject.toml
	$(UV_RUN) twine check --strict dist/*
	$(UV_RUN) check-wheel-contents dist/*.whl
	$(UV_RUN) python scripts/check_artifacts.py --skip-install \
		--write-hashes build/artifact-sha256.txt

artifact-smoke: lock-check
	$(UV_RUN) python scripts/check_artifacts.py

audit:
	mkdir -p build
	$(UV) export --locked --all-groups --all-extras --no-emit-project \
		--no-header --format requirements.txt --output-file build/audit-requirements.txt --quiet
	$(UV_RUN) pip-audit --require-hashes --disable-pip -r build/audit-requirements.txt

license-check:
	mkdir -p build
	$(UV_RUN) pip-licenses --from=all --format=json --with-system \
		--output-file build/license-inventory.json
	$(UV_RUN) python scripts/check_licenses.py \
		--inventory build/license-inventory.json \
		--lock uv.lock --policy config/license-policy.toml

private-identifier-check:
	$(UV_RUN) python scripts/check_private_identifiers.py --repository .

secret-scan: private-identifier-check
	$(UV_RUN) python scripts/secret_scan.py tree --source .
	$(UV_RUN) python scripts/secret_scan.py history --source .

secret-scan-self-test:
	$(UV_RUN) python scripts/secret_scan.py self-test --source .
