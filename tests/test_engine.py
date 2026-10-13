"""Baseline, independent oracle, property checks, freshness and exception-boundary tests. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CLOCK — line 95
# definition: test_platform_truth — line 99
# parameter: platform — line 99
# parameter: policy — line 99
# variable: expected — line 101
# variable: suffix — line 101
# variable: report — line 106
# variable: count — line 107
# variable: key — line 107
# definition: test_freshness_boundary — line 116
# parameter: age — line 116
# parameter: expected — line 116
# parameter: policy — line 116
# variable: snapshot — line 118
# variable: report — line 119
# variable: f — line 120
# definition: test_missing_and_unsupported_not_pass — line 125
# parameter: policy — line 125
# variable: data — line 127
# variable: report — line 130
# definition: test_exception_boundary — line 144
# parameter: clock — line 144
# parameter: policy — line 144
# parameter: status — line 144
# variable: snapshot — line 146
# variable: report — line 147
# definition: test_exception_scope_unknown_and_healthy — line 157
# parameter: policy — line 157
# variable: exceptions — line 159
# variable: snapshot — line 160
# variable: change — line 161
# variable: f — line 163
# definition: test_exception_start_inclusive — line 174
# parameter: policy — line 174
# variable: records — line 176
# variable: scoped — line 177
# variable: report — line 178
# definition: test_no_applicable_controls — line 184
# parameter: policy — line 184
# variable: c — line 186
# variable: limited — line 186
# definition: test_mode_mask_oracle — line 192
# parameter: mode — line 192
# variable: policy — line 196
# variable: data — line 197
# variable: finding — line 199
# definition: test_windows_boolean_oracle — line 218
# parameter: values — line 218
# variable: policy — line 222
# variable: data — line 223
# variable: key — line 224
# variable: value — line 224
# variable: expected — line 226
# variable: report — line 233
# variable: key — line 234
# variable: value — line 234
# definition: test_drift_classes — line 237
# parameter: policy — line 237
# variable: clean — line 239
# variable: bad — line 240
# variable: unknown — line 241
# variable: restored — line 246
# variable: c — line 247
# variable: c — line 249
# variable: waived — line 251
# definition: test_drift_evidence_change — line 260
# parameter: policy — line 260
# variable: data — line 262
# variable: clean — line 263
# variable: current — line 265
# definition: test_drift_incompatible — line 280
# parameter: field — line 280
# parameter: policy — line 280
# parameter: value — line 280
# variable: clean — line 282
# END CODE MAP

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hardening.contracts import Policy, load_exceptions, load_snapshot, snapshot_data, timestamp
from hardening.drift import compare
from hardening.engine import assess
from hardening.io import Rejected
from scripts.fixtures import healthy

CLOCK = timestamp("2026-10-13T14:00:00Z")


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_platform_truth(policy: Policy, platform: str) -> None:
    """Expected healthy/three-failure/all-unknown counts are authored separately from evaluator output."""
    for suffix, expected in [
        ("healthy", {"PASS": 5, "FAIL": 0, "UNKNOWN": 0}),
        ("drifted", {"PASS": 2, "FAIL": 3, "UNKNOWN": 0}),
        ("unknown", {"PASS": 0, "FAIL": 0, "UNKNOWN": 5}),
    ]:
        report = assess(policy, load_snapshot(Path(f"examples/{platform}-{suffix}.json")), CLOCK)
        for key, count in expected.items():
            assert report.summary()[key] == count
        assert report.exit_code() == (suffix != "healthy")
        assert report.data()["policy_digest"] == policy.digest


@pytest.mark.parametrize(
    "age,expected", [(-1, "UNKNOWN"), (0, "PASS"), (86400, "PASS"), (86401, "UNKNOWN")]
)
def test_freshness_boundary(policy: Policy, age: int, expected: str) -> None:
    """One second beyond freshness or any future timestamp is unknown; the exact age limit is inclusive."""
    snapshot = snapshot_data(healthy("linux"))
    report = assess(policy, snapshot, snapshot.observed_at + timedelta(seconds=age))
    assert {f.status for f in report.findings} == {expected}
    if expected == "UNKNOWN":
        assert report.summary()["observed_percent"] == 0


def test_missing_and_unsupported_not_pass(policy: Policy) -> None:
    """Missing and unsupported facts are independently unknown, and all remain in the scoring denominator."""
    data = healthy("windows")
    del data["facts"]["firewall.domain"]
    data["facts"]["firewall.public"].update(value=None, quality="unsupported")
    report = assess(policy, snapshot_data(data), CLOCK)
    assert report.summary()["UNKNOWN"] == 2
    assert report.summary()["observed_percent"] == 60
    assert report.summary()["weighted_pass_percent"] < 100


@pytest.mark.parametrize(
    "clock,status",
    [
        ("2026-10-12T23:59:59Z", "UNKNOWN"),
        ("2026-10-13T13:00:00Z", "EXCEPTED"),
        ("2026-10-14T00:00:00Z", "FAIL"),
    ],
)
def test_exception_boundary(policy: Policy, clock: str, status: str) -> None:
    """An active exception does not pass, future evidence is not waived, and expiry is exclusive."""
    snapshot = load_snapshot(Path("examples/linux-drifted.json"))
    report = assess(
        policy,
        snapshot,
        timestamp(clock),
        load_exceptions(Path("examples/exceptions.json"), policy),
    )
    assert report.findings[0].status == status
    assert report.exit_code() == 1


def test_exception_scope_unknown_and_healthy(policy: Policy) -> None:
    """Host mismatch, missing observations, wrong digest and already-passing evidence cannot be waived."""
    exceptions = load_exceptions(Path("examples/exceptions.json"), policy)
    snapshot = load_snapshot(Path("examples/linux-drifted.json"))
    for change in [replace(snapshot, host_id="other-host"), replace(snapshot, facts={})]:
        assert "EXCEPTED" not in {
            f.status for f in assess(policy, change, CLOCK, exceptions).findings
        }
    assert (
        assess(policy, snapshot, CLOCK, (replace(exceptions[0], policy_digest="other"),))
        .findings[0]
        .status
        == "FAIL"
    )
    assert assess(policy, snapshot_data(healthy("linux")), CLOCK, exceptions).summary()["PASS"] == 5


def test_exception_start_inclusive(policy: Policy) -> None:
    """Exact exception start time permits only the scoped observed failure."""
    records = load_exceptions(Path("examples/exceptions.json"), policy)
    scoped = (replace(records[0], starts_at=CLOCK),)
    report = assess(policy, load_snapshot(Path("examples/linux-drifted.json")), CLOCK, scoped)
    assert (
        report.findings[0].status == "EXCEPTED" and report.findings[0].exception_ticket == "LAB-101"
    )


def test_no_applicable_controls(policy: Policy) -> None:
    """A Linux-only policy does not produce a misleading zero-control successful Windows assessment."""
    limited = replace(policy, controls=tuple(c for c in policy.controls if c.platform == "linux"))
    with pytest.raises(Rejected):
        assess(limited, snapshot_data(healthy("windows")), CLOCK)


@given(st.integers(min_value=0, max_value=4095))
def test_mode_mask_oracle(mode: int) -> None:
    """Property oracle uses octal write bits independently of the evaluator's general mask operator."""
    from hardening.contracts import load_policy

    policy = load_policy(Path("policies/baseline.yml"))
    data = healthy("linux")
    data["facts"]["ssh.config_mode"]["value"] = mode
    finding = assess(policy, snapshot_data(data), CLOCK).findings[3]
    assert (finding.status == "PASS") == (not (mode & 0o020 or mode & 0o002))


@given(
    st.dictionaries(
        st.sampled_from(
            [
                "firewall.domain",
                "firewall.private",
                "firewall.public",
                "defender.realtime",
                "smb.smb1",
            ]
        ),
        st.booleans(),
        max_size=5,
    )
)
def test_windows_boolean_oracle(values: dict[str, bool]) -> None:
    """Compare every supplied boolean with an independent positive/negative expected fact map."""
    from hardening.contracts import load_policy

    policy = load_policy(Path("policies/baseline.yml"))
    data = healthy("windows")
    for key, value in values.items():
        data["facts"][key]["value"] = value
    expected = {
        "firewall.domain": True,
        "firewall.private": True,
        "firewall.public": True,
        "defender.realtime": True,
        "smb.smb1": False,
    }
    report = assess(policy, snapshot_data(data), CLOCK)
    assert report.summary()["FAIL"] == sum(value != expected[key] for key, value in values.items())


def test_drift_classes(policy: Policy) -> None:
    """Discriminate regression, restored baseline, evidence gaps/restoration and deviation changes."""
    clean = assess(policy, load_snapshot(Path("examples/linux-healthy.json")), CLOCK)
    bad = assess(policy, load_snapshot(Path("examples/linux-drifted.json")), CLOCK)
    unknown = assess(policy, load_snapshot(Path("examples/linux-unknown.json")), CLOCK)
    assert compare(clean, clean)["changes"] == []
    assert compare(clean, bad)["regressions"] == 3
    assert compare(bad, unknown)["evidence_gaps"] == 5
    # Same-time evidence replacements are allowed; reverse chronological evidence is not.
    restored = replace(clean, observed_at=unknown.observed_at)
    assert {c["kind"] for c in compare(unknown, restored)["changes"]} == {"evidence_restored"}
    assert {
        c["kind"] for c in compare(bad, replace(clean, observed_at=bad.observed_at))["changes"]
    } == {"baseline_restored"}
    waived = assess(
        policy,
        load_snapshot(Path("examples/linux-drifted.json")),
        CLOCK,
        load_exceptions(Path("examples/exceptions.json"), policy),
    )
    assert compare(bad, waived)["changes"][0]["kind"] == "deviation_change"


def test_drift_evidence_change(policy: Policy) -> None:
    """A changed observation still passing the mask is evidence change, not a fabricated regression."""
    data = healthy("linux")
    clean = assess(policy, snapshot_data(data), CLOCK)
    data["facts"]["ssh.config_mode"]["value"] = 384
    current = assess(policy, snapshot_data(data), CLOCK)
    assert compare(clean, current)["changes"][0]["kind"] == "evidence_change"


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_id", "other"),
        ("platform", "windows"),
        ("policy_digest", "other"),
        ("observed_at", "2020-01-01T00:00:00Z"),
        ("as_of", "2020-01-01T00:00:00Z"),
        ("findings", ()),
    ],
)
def test_drift_incompatible(policy: Policy, field: str, value: object) -> None:
    """Do not compare different identities, policy versions, reversed clocks or incompatible control sets."""
    clean = assess(policy, snapshot_data(deepcopy(healthy("linux"))), CLOCK)
    with pytest.raises(Rejected):
        compare(clean, replace(clean, **{field: value}))
