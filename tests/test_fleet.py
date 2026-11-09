"""Independent inventory completeness, policy grouping and owner workflow tests. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CLOCK — line 71
# definition: test_expected_inventory_not_just_supplied_hosts — line 74
# parameter: policy — line 74
# variable: hosts — line 76
# variable: snapshots — line 77
# variable: name — line 78
# variable: result — line 80
# variable: row — line 85
# variable: row — line 90
# definition: test_refresh_and_deviation_are_distinct — line 93
# parameter: policy — line 93
# variable: snapshot — line 95
# variable: hosts — line 96
# variable: result — line 97
# variable: deviation — line 102
# variable: row — line 102
# variable: stale — line 104
# variable: row — line 106
# definition: test_all_pass_and_no_evidence — line 109
# parameter: policy — line 109
# variable: snapshot — line 111
# variable: hosts — line 112
# definition: test_bad_scope_rejected — line 129
# parameter: change — line 129
# parameter: policy — line 129
# variable: snapshot — line 131
# variable: hosts — line 132
# variable: snapshots — line 133
# variable: snapshots — line 135
# variable: snapshots — line 137
# variable: hosts — line 139
# variable: hosts — line 141
# variable: policy — line 143
# variable: control — line 145
# variable: snapshots — line 148
# variable: hosts — line 150
# definition: test_inventory_contract — line 165
# parameter: tmp_path — line 165
# parameter: value — line 165
# variable: path — line 167
# definition: test_user_workflow_and_immutable_outputs — line 173
# parameter: capsys — line 174
# parameter: tmp_path — line 174
# variable: output — line 177
# variable: args — line 178
# variable: data — line 192
# variable: original — line 194
# variable: page — line 200
# definition: test_cli_snapshot_bound — line 207
# parameter: capsys — line 207
# variable: _ — line 217
# variable: part — line 217
# definition: test_extreme_future_clock_refused — line 225
# parameter: policy — line 225
# variable: snapshot — line 227
# END CODE MAP

import json
from dataclasses import replace
from pathlib import Path

import pytest

from hardening.cli import main
from hardening.contracts import Policy, load_exceptions, load_snapshot, timestamp
from hardening.fleet import Host, assess_fleet, inventory, publish
from hardening.io import Rejected

CLOCK = timestamp("2026-10-13T14:00:00Z")


def test_expected_inventory_not_just_supplied_hosts(policy: Policy) -> None:
    """A missing Linux host adds five unknown checks; unlike OS groups retain separate counts."""
    hosts = inventory(Path("examples/fleet-inventory.json"))
    snapshots = tuple(
        load_snapshot(Path(f"examples/{name}-healthy.json")) for name in ("linux", "windows")
    )
    result = assess_fleet(hosts, snapshots, policy, CLOCK)
    assert result["expected_hosts"] == 3 and result["assessed_hosts"] == 2
    assert result["counts"] == {"PASS": 10, "FAIL": 0, "UNKNOWN": 5, "EXCEPTED": 0}
    assert result["all_expected_controls_pass"] is False
    assert [
        (row["platform"], row["expected_hosts"], row["missing_hosts"]) for row in result["groups"]
    ] == [("linux", 2, 1), ("windows", 1, 0)]
    assert result["refresh_queue"][0]["owner"] == "Warehouse systems"
    assert result["refresh_queue"][0]["reason"] == "missing_host_snapshot"
    assert len(result["refresh_queue"][0]["control_ids"]) == 5
    assert {row["policy_digest"] for row in result["groups"]} == {policy.digest}


def test_refresh_and_deviation_are_distinct(policy: Policy) -> None:
    """Stale evidence needs recollection; baseline deviations and expiring exceptions need owner review."""
    snapshot = load_snapshot(Path("examples/linux-drifted.json"))
    hosts = (Host(snapshot.host_id, "linux", "Platform team"),)
    result = assess_fleet(
        hosts, (snapshot,), policy, CLOCK, load_exceptions(Path("examples/exceptions.json"), policy)
    )
    assert result["counts"] == {"PASS": 2, "FAIL": 2, "UNKNOWN": 0, "EXCEPTED": 1}
    assert not result["refresh_queue"]
    deviation = next(row for row in result["deviation_queue"] if row["status"] == "EXCEPTED")
    assert deviation["exception_detail"]["expires_at"] == "2026-10-14T00:00:00Z"
    stale = assess_fleet(hosts, (snapshot,), policy, timestamp("2026-10-21T14:00:00Z"))
    assert len(stale["refresh_queue"]) == 5 and not stale["deviation_queue"]
    assert {row["reason"] for row in stale["refresh_queue"]} == {"stale_evidence"}


def test_all_pass_and_no_evidence(policy: Policy) -> None:
    """The only all-pass result has complete passing expected evidence; empty supplied evidence is allowed."""
    snapshot = load_snapshot(Path("examples/linux-healthy.json"))
    hosts = (Host(snapshot.host_id, "linux", "Owner"),)
    assert assess_fleet(hosts, (snapshot,), policy, CLOCK)["all_expected_controls_pass"]
    assert assess_fleet(hosts, (), policy, CLOCK)["counts"]["UNKNOWN"] == 5


@pytest.mark.parametrize(
    "change",
    [
        "unexpected",
        "duplicate",
        "platform",
        "inventory-duplicate",
        "no-controls",
        "too-many",
        "empty",
    ],
)
def test_bad_scope_rejected(policy: Policy, change: str) -> None:
    """Wrong scope never selects a newest file, silently drops evidence or changes the expected denominator."""
    snapshot = load_snapshot(Path("examples/linux-healthy.json"))
    hosts = (Host(snapshot.host_id, "linux", "Owner"),)
    snapshots = (snapshot,)
    if change == "unexpected":
        snapshots = (replace(snapshot, host_id="other"),)
    elif change == "duplicate":
        snapshots = (snapshot, snapshot)
    elif change == "platform":
        hosts = (replace(hosts[0], platform="windows"),)
    elif change == "inventory-duplicate":
        hosts = hosts * 2
    elif change == "no-controls":
        policy = replace(
            policy,
            controls=tuple(control for control in policy.controls if control.platform == "windows"),
        )
    elif change == "too-many":
        snapshots = snapshots * 501
    else:
        hosts = ()
    with pytest.raises(Rejected):
        assess_fleet(hosts, snapshots, policy, CLOCK)


@pytest.mark.parametrize(
    "value",
    [
        {"schema": True, "hosts": []},
        {"schema": 1, "hosts": []},
        {"schema": 1, "hosts": [{}]},
        {"schema": 1, "hosts": [{"host_id": "a", "platform": "mac", "owner": "team"}]},
        {"schema": 1, "hosts": [{"host_id": "a", "platform": "linux", "owner": "team"}] * 2},
    ],
)
def test_inventory_contract(value: object, tmp_path: Path) -> None:
    """Strict bounded schema rejects ambiguity before any assessment or output."""
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(value))
    with pytest.raises(Rejected):
        inventory(path)


def test_user_workflow_and_immutable_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Owner runs an actual mixed fleet demo and opens an inert, searchable local queue."""
    output = tmp_path / "review"
    args = [
        "fleet",
        "--inventory",
        "examples/fleet-inventory.json",
        "--snapshot",
        "examples/linux-healthy.json",
        "--snapshot",
        "examples/windows-drifted.json",
        "--as-of",
        "2026-10-13T14:00:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["counts"] == {"PASS": 7, "FAIL": 3, "UNKNOWN": 5, "EXCEPTED": 0}
    original = (output / "fleet.json").read_bytes()
    assert main(args) == 2
    assert "rejected" in capsys.readouterr().err
    assert original == (output / "fleet.json").read_bytes()
    data["refresh_queue"][0]["owner"] = "<script>hostile()</script>"
    publish(data, tmp_path / "escaped")
    page = (tmp_path / "escaped/fleet.html").read_text()
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page and "Jason Stys" in page
    with pytest.raises(Rejected):
        publish(data, tmp_path / "absent-parent/new")


def test_cli_snapshot_bound(capsys: pytest.CaptureFixture[str]) -> None:
    """Refuse over-limit argument sets before trying to open user paths."""
    assert (
        main(
            [
                "fleet",
                "--inventory",
                "examples/fleet-inventory.json",
                "--as-of",
                "2026-10-13T14:00:00Z",
                *[part for _ in range(501) for part in ("--snapshot", "absent.json")],
            ]
        )
        == 2
    )
    assert "too many snapshots" in capsys.readouterr().err


def test_extreme_future_clock_refused(policy: Policy) -> None:
    """Calendar overflow is a sanitized rejection, never an unhandled crash or a false freshness claim."""
    snapshot = replace(
        load_snapshot(Path("examples/linux-healthy.json")),
        observed_at=timestamp("9999-12-31T23:59:59Z"),
    )
    with pytest.raises(Rejected, match="calendar"):
        assess_fleet((Host(snapshot.host_id, "linux", "Owner"),), (snapshot,), policy, CLOCK)
