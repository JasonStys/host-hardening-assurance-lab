"""Actual offline host assessment, drift and inventory evidence review for the native app. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 77
# variable: PRODUCT — line 78
# variable: TITLE — line 79
# variable: PROFILE — line 80
# variable: VERSION — line 81
# variable: COLUMNS — line 82
# variable: RESOURCES — line 83
# variable: MODES — line 98
# variable: REVIEW_MODE — line 99
# variable: ACTIVE_FIELDS — line 100
# variable: FIELDS — line 105
# variable: SCENARIOS — line 114
# variable: HELP — line 120
# definition: scenario — line 123
# parameter: name — line 123
# variable: value — line 127
# variable: filename — line 143
# definition: analyze — line 150
# parameter: parameters — line 151
# parameter: stage — line 151
# parameter: state — line 151
# variable: mode — line 154
# variable: policy — line 155
# variable: exceptions — line 156
# variable: clock — line 159
# variable: paths — line 160
# variable: value — line 161
# variable: output — line 165
# variable: result — line 167
# variable: path — line 169
# variable: summary — line 175
# variable: report — line 179
# variable: counts — line 181
# variable: summary — line 182
# variable: before — line 184
# variable: drift — line 190
# variable: summary — line 198
# variable: path — line 206
# definition: views — line 210
# parameter: files — line 210
# variable: result — line 213
# variable: controls — line 214
# variable: host — line 216
# variable: finding — line 217
# variable: result — line 224
# variable: controls — line 225
# variable: finding — line 225
# variable: views — line 226
# variable: row — line 229
# variable: row — line 231
# variable: drift — line 234
# variable: views — line 235
# variable: row — line 236
# definition: cells — line 242
# parameter: row — line 242
# variable: control — line 244
# variable: identifiers — line 246
# variable: control — line 247
# END CODE MAP

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .contracts import load_exceptions, load_policy, load_snapshot, timestamp
from .desktop_state import Workspace
from .drift import compare
from .engine import assess
from .fleet import assess_fleet, inventory, publish
from .io import Rejected, canonical, json_value, read_bytes
from .report import export

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "host-hardening-assurance-lab"
TITLE = "Host Hardening Assurance Workbench"
PROFILE = "HostHardeningAssuranceLab"
VERSION = "1.1.0"
COLUMNS = ("Host", "Control / expected evidence", "Evidence reason", "Status / change")
RESOURCES = (
    "policies/baseline.yml",
    "hardening/schema.sql",
    "examples/exceptions.json",
    "examples/fleet-inventory.json",
    "examples/linux-drifted.json",
    "examples/linux-healthy.json",
    "examples/linux-unknown.json",
    "examples/windows-drifted.json",
    "examples/windows-healthy.json",
    "examples/windows-unknown.json",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
MODES = ("Assess one offline snapshot", "Compare same-host drift", "Review declared inventory")
REVIEW_MODE: str | None = None
ACTIVE_FIELDS = {
    MODES[0]: ("snapshot", "policy", "exceptions", "as_of"),
    MODES[1]: ("snapshot", "policy", "exceptions", "as_of", "before", "before_as_of"),
    MODES[2]: ("snapshot", "policy", "exceptions", "as_of", "inventory"),
}
FIELDS = (
    ("snapshot", "Authorized snapshot JSON (fleet: select multiple)", "files"),
    ("policy", "Reviewed baseline policy (YAML)", "file"),
    ("exceptions", "Scoped exceptions JSON (optional)", "file"),
    ("as_of", "Evaluation UTC: YYYY-MM-DDTHH:MM:SSZ", "text"),
    ("before", "Earlier snapshot JSON (drift only)", "file"),
    ("before_as_of", "Earlier evaluation UTC (drift only)", "text"),
    ("inventory", "Declared inventory JSON (fleet only)", "file"),
)
SCENARIOS = (
    "Fictional Linux deviations and scoped exception",
    "Fictional same-host drift",
    "Fictional fleet with missing host",
    "Fictional Windows review",
)
HELP = "This application only analyzes explicitly supplied offline snapshots and authored policies. It never invokes collectors, shell commands, cmdlets, remote discovery or settings changes. FAIL needs owner review; EXCEPTED is a deviation, not PASS. Missing/stale/unsupported/future evidence is UNKNOWN. Review guidance is an inert plan, never executed. Drift requires the same host/platform/policy and valid chronology. Fleet uses declared inventory, rejects duplicate/out-of-scope evidence and keeps missing hosts UNKNOWN. Policy weights and freshness are explicit. Prepared scenarios use fixed historical clocks; choose your actual evidence/clock for other work. State/exports are plaintext OS-owner data, not production identity, certification or proof of effective protection."


def scenario(name: str) -> dict[str, str]:
    """Prepare realistic fictional cases as normal inputs to the same controls/core used for authorized evidence."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared scenario")
    value = {
        "mode": MODES[0],
        "snapshot": str(ROOT / "examples/linux-drifted.json"),
        "policy": str(ROOT / "policies/baseline.yml"),
        "exceptions": str(ROOT / "examples/exceptions.json"),
        "as_of": "2026-10-13T14:00:00Z",
        "before": str(ROOT / "examples/linux-healthy.json"),
        "before_as_of": "2026-10-13T12:00:00Z",
        "inventory": str(ROOT / "examples/fleet-inventory.json"),
    }
    if name == SCENARIOS[1]:
        value["mode"], value["exceptions"] = MODES[1], ""
    elif name == SCENARIOS[2]:
        value["mode"], value["exceptions"] = MODES[2], ""
        value["snapshot"] = "\n".join(
            str(ROOT / "examples" / filename)
            for filename in ("linux-healthy.json", "windows-healthy.json")
        )
    elif name == SCENARIOS[3]:
        value["snapshot"], value["exceptions"] = str(ROOT / "examples/windows-drifted.json"), ""
    return value


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Invoke the real validated baseline/drift/fleet engine; no collector/enforcement module is called."""
    mode = parameters["mode"]
    policy = load_policy(Path(parameters["policy"]))
    exceptions = load_exceptions(
        Path(parameters["exceptions"]) if parameters["exceptions"].strip() else None, policy
    )
    clock = timestamp(parameters["as_of"])
    paths = tuple(
        Path(value.strip()) for value in parameters["snapshot"].splitlines() if value.strip()
    )
    if len(paths) > 500:
        raise Rejected("too many supplied snapshots")
    output = stage / "bundle"
    if mode == MODES[2]:
        result = assess_fleet(
            inventory(Path(parameters["inventory"])),
            tuple(load_snapshot(path) for path in paths),
            policy,
            clock,
            exceptions,
        )
        publish(result, output)
        summary = f"Expected {result['expected_hosts']}; assessed {result['assessed_hosts']}; missing {result['missing_hosts']}; UNKNOWN {result['counts']['UNKNOWN']}"
    elif mode in MODES[:2]:
        if len(paths) != 1:
            raise Rejected("single-host assessment/drift needs exactly one current snapshot")
        report = assess(policy, load_snapshot(paths[0]), clock, exceptions)
        export(report, output)
        counts = report.summary()
        summary = f"{report.host_id}: {counts['PASS']} PASS / {counts['FAIL']} FAIL / {counts['UNKNOWN']} UNKNOWN / {counts['EXCEPTED']} EXCEPTED"
        if mode == MODES[1]:
            before = assess(
                policy,
                load_snapshot(Path(parameters["before"])),
                timestamp(parameters["before_as_of"]),
                exceptions,
            )
            drift = compare(before, report)
            (output / "drift.json").write_bytes(canonical(drift))
            (output / "drift.html").write_text(
                '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><title>Offline host drift — Jason Stys</title><main><h1>Same-host drift review</h1><p>Created by Jason Stys. Review guidance only; no settings changed.</p><pre>'
                + html.escape(canonical(drift).decode())
                + "</pre></main></html>",
                encoding="utf-8",
            )
            summary += (
                f"; {drift['regressions']} regressions / {drift['evidence_gaps']} evidence gaps"
            )
    else:
        raise Rejected("unsupported desktop operation")
    return (
        mode,
        summary,
        {path.name: read_bytes(path, 32 * 1024 * 1024) for path in output.iterdir()},
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Display actual result statuses, refresh queue and inert review guidance with their original context."""
    if "fleet.json" in files:
        result = json_value(files["fleet.json"])
        controls = [
            {"host_id": host["assessment"]["host_id"], "owner": host["owner"], **finding}
            for host in result["hosts"]
            for finding in host["assessment"]["findings"]
        ]
        return {
            "Fleet control findings": controls,
            "Evidence refresh queue": result["refresh_queue"],
            "Deviation review plan (not applied)": result["deviation_queue"],
        }
    result = json_value(files["report.json"])
    controls = [{"host_id": result["host_id"], **finding} for finding in result["findings"]]
    views = {
        "Control findings": controls,
        "Review plan (not applied)": [
            row for row in controls if row["status"] in ("FAIL", "EXCEPTED")
        ],
        "Evidence refresh needs": [row for row in controls if row["status"] == "UNKNOWN"],
    }
    if "drift.json" in files:
        drift = json_value(files["drift.json"])
        views = {
            "Same-host drift": [{"host_id": result["host_id"], **row} for row in drift["changes"]],
            **views,
        }
    return views


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Show literal host/control/evidence/status fields without suggesting that guidance has been applied."""
    control = row.get("control_id")
    if control is None:
        identifiers = row.get("control_ids", [])
        control = f"{len(identifiers)} controls (inspect detail)" if identifiers else ""
    return (
        str(row.get("host_id", "")),
        str(control),
        str(row.get("reason", row.get("title", ""))),
        str(row.get("status", row.get("kind", "UNKNOWN"))),
    )
