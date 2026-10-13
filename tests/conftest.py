"""Shared synthetic contract fixtures; tests never collect this PC's settings. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 13
# definition: policy — line 17
# END CODE MAP

from pathlib import Path

import pytest

from hardening.contracts import Policy, load_policy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy() -> Policy:
    """Load the actual authored policy rather than a test-only implementation of it."""
    return load_policy(ROOT / "policies/baseline.yml")
