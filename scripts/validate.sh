#!/usr/bin/env bash
# Jason Stys: fail-fast portable quality, synthetic assurance, contract and performance gates.
# Functions: none. Variables: PYTHONPATH imports local modules; all tests use fixtures or owned temp trees.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# END CODE MAP
set -euo pipefail
export PYTHONPATH=.
python -m ruff check .
python -m ruff format --check .
python -m mypy
python scripts/code_map.py --check
python scripts/file_guide.py --check
python -m pytest -q --cov=hardening --cov-report=term-missing --cov-report=json:out/coverage.json --junitxml=out/junit.xml -W error
python -m scripts.scenarios
python -m scripts.benchmark
