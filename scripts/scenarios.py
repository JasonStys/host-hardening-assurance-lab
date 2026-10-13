"""Verify independent demo truth for pass, drift, missing/stale/future evidence and exceptions. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 21
# variable: policy — line 23
# variable: clock — line 24
# variable: platform — line 25
# variable: clean — line 26
# variable: bad — line 27
# variable: unknown — line 28
# variable: stale — line 33
# variable: waived — line 39
# END CODE MAP

from pathlib import Path

from hardening.contracts import load_exceptions, load_policy, load_snapshot, timestamp
from hardening.drift import compare
from hardening.engine import assess


def main() -> int:
    """Assert explicitly chosen expected counts; failing host fixtures are expected successful test cases."""
    policy = load_policy(Path("policies/baseline.yml"))
    clock = timestamp("2026-10-13T14:00:00Z")
    for platform in ("linux", "windows"):
        clean = assess(policy, load_snapshot(Path(f"examples/{platform}-healthy.json")), clock)
        bad = assess(policy, load_snapshot(Path(f"examples/{platform}-drifted.json")), clock)
        unknown = assess(policy, load_snapshot(Path(f"examples/{platform}-unknown.json")), clock)
        assert clean.summary()["PASS"] == 5
        assert bad.summary()["FAIL"] == 3
        assert unknown.summary()["UNKNOWN"] == 5
        assert compare(clean, bad)["regressions"] == 3
        stale = assess(
            policy,
            load_snapshot(Path(f"examples/{platform}-healthy.json")),
            timestamp("2026-10-15T00:00:00Z"),
        )
        assert stale.summary()["UNKNOWN"] == 5
    waived = assess(
        policy,
        load_snapshot(Path("examples/linux-drifted.json")),
        clock,
        load_exceptions(Path("examples/exceptions.json"), policy),
    )
    assert waived.summary()["FAIL"] == 2 and waived.summary()["EXCEPTED"] == 1
    print(
        "Independent scenarios passed: two platforms; healthy, drifted, unknown, stale and deviation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
