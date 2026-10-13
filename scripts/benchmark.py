"""Measure bounded baseline evaluation throughput; results are not production capacity claims. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 23
# variable: policy — line 25
# variable: snapshot — line 26
# variable: clock — line 27
# variable: start — line 28
# variable: _ — line 29
# variable: passed — line 29
# variable: seconds — line 30
# variable: data — line 32
# END CODE MAP

import json
import platform
import time
from pathlib import Path

from hardening.contracts import load_policy, load_snapshot, timestamp
from hardening.engine import assess


def main() -> int:
    """Evaluate 10,000 five-control synthetic snapshots; exclude parsing/export, assert all 50,000 checks pass."""
    policy = load_policy(Path("policies/baseline.yml"))
    snapshot = load_snapshot(Path("examples/linux-healthy.json"))
    clock = timestamp("2026-10-13T14:00:00Z")
    start = time.perf_counter()
    passed = sum(assess(policy, snapshot, clock).summary()["PASS"] for _ in range(10000))
    seconds = time.perf_counter() - start
    assert passed == 50000
    data = {
        "python": platform.python_version(),
        "platform": platform.system(),
        "snapshots": 10000,
        "checks": passed,
        "seconds": round(seconds, 6),
        "snapshots_per_second": round(10000 / seconds, 2),
        "scope": "in-memory synthetic evaluation only; excludes collection, parsing, disk export",
    }
    print(json.dumps(data, indent=2))
    Path("out").mkdir(exist_ok=True)
    Path("out/benchmark.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
