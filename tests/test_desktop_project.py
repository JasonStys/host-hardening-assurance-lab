"""Real offline GUI adapters use existing baseline/drift/fleet core with independent fixture oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: state — line 72
# parameter: tmp_path — line 72
# variable: value — line 74
# definition: run_case — line 81
# parameter: name — line 81
# parameter: parameters — line 81
# parameter: state — line 81
# parameter: tmp_path — line 81
# variable: stage — line 83
# variable: files — line 85
# variable: kind — line 85
# variable: summary — line 85
# variable: identity — line 86
# definition: test_real_assessment_scoped_exception_plan_and_windows — line 90
# parameter: state — line 90
# parameter: tmp_path — line 90
# variable: files — line 92
# variable: identity — line 92
# variable: report — line 93
# variable: key — line 94
# variable: views — line 100
# variable: row — line 104
# variable: _ — line 106
# variable: windows — line 106
# definition: test_real_drift_and_inventory_missing_host_denominators — line 111
# parameter: state — line 111
# parameter: tmp_path — line 111
# variable: _ — line 113
# variable: files — line 113
# variable: drift — line 114
# variable: _ — line 117
# variable: fleet — line 117
# variable: result — line 118
# variable: views — line 126
# definition: test_custom_freshness_policy_and_clock_used_without_guessing — line 133
# parameter: state — line 133
# parameter: tmp_path — line 133
# variable: parameters — line 135
# variable: policy — line 136
# variable: content — line 137
# variable: content — line 140
# variable: count — line 140
# variable: _ — line 145
# variable: files — line 145
# variable: result — line 146
# definition: test_invalid_clock_scope_or_operation_is_not_replaced_by_a_fixture — line 160
# parameter: change — line 160
# parameter: state — line 160
# parameter: tmp_path — line 160
# variable: parameters — line 162
# definition: test_unsupported_scenario_duplicate_and_out_of_scope_fleet_rejected — line 168
# parameter: state — line 168
# parameter: tmp_path — line 168
# variable: parameters — line 172
# variable: linux — line 173
# variable: original — line 177
# variable: path — line 179
# END CODE MAP

import json

import pytest

from hardening import desktop_project as project
from hardening.desktop_state import Workspace
from hardening.io import Rejected


@pytest.fixture
def state(tmp_path):
    """Own only a new disposable profile; no test collects or modifies this computer's configuration."""
    value = Workspace(tmp_path / "state", project.PRODUCT, project.ROOT)
    try:
        yield value
    finally:
        value.close()


def run_case(state, tmp_path, name, parameters):
    """Run the real project adapter and retain its exact core-generated completed bundle."""
    stage = tmp_path / name
    stage.mkdir()
    kind, summary, files = project.analyze(state, parameters, stage)
    identity = state.save(kind, summary, parameters, files)
    return identity, files


def test_real_assessment_scoped_exception_plan_and_windows(state, tmp_path):
    """An active exception remains a deviation and the inert review plan is not a configuration action."""
    identity, files = run_case(state, tmp_path, "linux", project.scenario(project.SCENARIOS[0]))
    report = json.loads(files["report.json"])
    assert {key: report["summary"][key] for key in ("PASS", "FAIL", "UNKNOWN", "EXCEPTED")} == {
        "PASS": 2,
        "FAIL": 2,
        "UNKNOWN": 0,
        "EXCEPTED": 1,
    }
    views = project.views(files)
    assert len(views["Control findings"]) == 5
    assert len(views["Review plan (not applied)"]) == 3
    assert views["Evidence refresh needs"] == []
    assert all(project.cells(row)[0] == "lab-linux-01" for row in views["Control findings"])
    assert state.files(identity) == files
    _, windows = run_case(state, tmp_path, "windows", project.scenario(project.SCENARIOS[3]))
    assert json.loads(windows["report.json"])["platform"] == "windows"
    assert len(project.views(windows)["Control findings"]) == 5


def test_real_drift_and_inventory_missing_host_denominators(state, tmp_path):
    """Same-host drift has three known regressions; missing inventory evidence adds five UNKNOWN checks."""
    _, files = run_case(state, tmp_path, "drift", project.scenario(project.SCENARIOS[1]))
    drift = json.loads(files["drift.json"])
    assert drift["regressions"] == 3 and drift["evidence_gaps"] == 0
    assert len(project.views(files)["Same-host drift"]) == 3
    _, fleet = run_case(state, tmp_path, "fleet", project.scenario(project.SCENARIOS[2]))
    result = json.loads(fleet["fleet.json"])
    assert (result["expected_hosts"], result["assessed_hosts"], result["missing_hosts"]) == (
        3,
        2,
        1,
    )
    assert result["counts"] == {"PASS": 10, "FAIL": 0, "UNKNOWN": 5, "EXCEPTED": 0}
    assert result["all_expected_controls_pass"] is False
    views = project.views(fleet)
    assert len(views["Fleet control findings"]) == 10
    assert len(views["Evidence refresh queue"]) == 1
    assert views["Evidence refresh queue"][0]["owner"] == "Warehouse systems"
    assert views["Deviation review plan (not applied)"] == []


def test_custom_freshness_policy_and_clock_used_without_guessing(state, tmp_path):
    """A selected authored policy and explicit clock affect the actual engine, not a hardcoded demonstration."""
    parameters = project.scenario(project.SCENARIOS[0])
    policy = tmp_path / "strict.yml"
    content = (project.ROOT / "policies/baseline.yml").read_text()
    import re

    content, count = re.subn(r"max_age_seconds: \d+", "max_age_seconds: 60", content)
    assert count == 1
    policy.write_text(content)
    parameters["policy"] = str(policy)
    parameters["exceptions"] = ""
    _, files = run_case(state, tmp_path, "freshness", parameters)
    result = json.loads(files["report.json"])
    assert result["summary"]["UNKNOWN"] == 5 and result["summary"]["PASS"] == 0
    assert len(project.views(files)["Evidence refresh needs"]) == 5


@pytest.mark.parametrize(
    "change",
    [
        {"as_of": "2026-02-30T00:00:00Z"},
        {"snapshot": ""},
        {"mode": "apply-hardening"},
        {"mode": project.MODES[1], "before_as_of": "2026-10-14T00:00:00Z"},
    ],
)
def test_invalid_clock_scope_or_operation_is_not_replaced_by_a_fixture(state, tmp_path, change):
    """Invalid operator input cannot turn into a PASS, host collection or automatic application of guidance."""
    parameters = {**project.scenario(project.SCENARIOS[0]), **change}
    with pytest.raises(Rejected):
        run_case(state, tmp_path, "invalid", parameters)
    assert state.history() == []


def test_unsupported_scenario_duplicate_and_out_of_scope_fleet_rejected(state, tmp_path):
    """Expected inventory is the actual authority boundary; duplicate/unlisted snapshots never enter a report."""
    with pytest.raises(Rejected):
        project.scenario("unknown")
    parameters = project.scenario(project.SCENARIOS[2])
    linux = str(project.ROOT / "examples/linux-healthy.json")
    parameters["snapshot"] = linux + "\n" + linux
    with pytest.raises(Rejected):
        run_case(state, tmp_path, "duplicate", parameters)
    original = json.loads((project.ROOT / "examples/linux-healthy.json").read_bytes())
    original["host_id"] = "outside-declared-inventory"
    path = tmp_path / "outside.json"
    path.write_text(json.dumps(original))
    parameters["snapshot"] = str(path)
    with pytest.raises(Rejected):
        run_case(state, tmp_path, "outside", parameters)
    assert state.history() == []
