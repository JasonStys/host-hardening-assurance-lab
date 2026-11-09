"""Expected-inventory assessment and owner-routed evidence refresh; read-only. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Host — line 85
# variable: host_id — line 88
# variable: platform — line 89
# variable: owner — line 90
# definition: inventory — line 93
# parameter: path — line 93
# variable: data — line 95
# variable: rows — line 97
# variable: hosts — line 100
# variable: seen — line 101
# variable: raw — line 102
# variable: row — line 103
# variable: host_id — line 104
# variable: platform — line 105
# parameter: host — line 110
# definition: assess_fleet — line 113
# parameter: hosts — line 114
# parameter: snapshots — line 115
# parameter: policy — line 116
# parameter: as_of — line 117
# parameter: exceptions — line 118
# variable: clock — line 121
# variable: expected — line 124
# variable: host — line 124
# variable: supplied — line 127
# variable: submitted — line 128
# variable: host — line 129
# variable: reports — line 133
# variable: refresh — line 134
# variable: deviations — line 135
# variable: groups — line 136
# parameter: item — line 137
# variable: host — line 137
# variable: control — line 138
# variable: controls — line 138
# variable: group — line 141
# variable: snapshot — line 156
# variable: control — line 164
# variable: report — line 171
# variable: due_at — line 173
# variable: status — line 177
# variable: finding — line 186
# variable: counts — line 200
# variable: group — line 201
# variable: status — line 202
# parameter: item — line 210
# variable: host — line 210
# variable: key — line 215
# variable: status — line 220
# definition: publish — line 226
# parameter: data — line 226
# parameter: directory — line 226
# variable: absolute — line 228
# variable: part — line 229
# variable: rows — line 231
# variable: key — line 235
# variable: row — line 238
# variable: output — line 240
# END CODE MAP

from __future__ import annotations

import html
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .contracts import (
    ExceptionRecord,
    Policy,
    Snapshot,
    integer,
    mapping,
    text,
    utc,
)
from .engine import assess
from .io import Rejected, canonical, json_value, read_bytes


@dataclass(frozen=True)
class Host:
    """Expected pseudonymous host, platform and accountable team; ownership is a local assertion."""

    host_id: str
    platform: str
    owner: str


def inventory(path: Path) -> tuple[Host, ...]:
    """Read 1..500 distinct declared hosts; no discovery, remote URLs or implicit host collection."""
    data = mapping(json_value(read_bytes(path, 262144)), {"schema", "hosts"})
    integer(data["schema"], 1, 1)
    rows = data["hosts"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise Rejected("inventory needs 1..500 hosts")
    hosts = []
    seen = set()
    for raw in rows:
        row = mapping(raw, {"host_id", "platform", "owner"})
        host_id = text(row["host_id"], token=True)
        platform = text(row["platform"])
        if platform not in ("linux", "windows") or host_id in seen:
            raise Rejected("duplicate host or unsupported platform")
        seen.add(host_id)
        hosts.append(Host(host_id, platform, text(row["owner"], 120)))
    return tuple(sorted(hosts, key=lambda host: host.host_id))


def assess_fleet(
    hosts: tuple[Host, ...],
    snapshots: tuple[Snapshot, ...],
    policy: Policy,
    as_of: datetime,
    exceptions: tuple[ExceptionRecord, ...] = (),
) -> dict[str, Any]:
    """Assess each expected host once; never pool unlike platforms or count absent evidence as PASS."""
    clock = utc(as_of)
    if not 1 <= len(hosts) <= 500 or len(snapshots) > 500:
        raise Rejected("fleet size outside contract")
    expected = {host.host_id: host for host in hosts}
    if len(expected) != len(hosts):
        raise Rejected("duplicate inventory host")
    supplied = {}
    for submitted in snapshots:
        host = expected.get(submitted.host_id)
        if host is None or host.platform != submitted.platform or submitted.host_id in supplied:
            raise Rejected("unexpected, duplicate or wrong-platform snapshot")
        supplied[submitted.host_id] = submitted
    reports = []
    refresh = []
    deviations = []
    groups: dict[str, dict[str, Any]] = {}
    for host in sorted(hosts, key=lambda item: item.host_id):
        controls = [control for control in policy.controls if control.platform == host.platform]
        if not controls:
            raise Rejected("no policy controls for expected platform")
        group = groups.setdefault(
            host.platform,
            {
                "platform": host.platform,
                "policy_digest": policy.digest,
                "expected_hosts": 0,
                "assessed_hosts": 0,
                "missing_hosts": 0,
                "PASS": 0,
                "FAIL": 0,
                "UNKNOWN": 0,
                "EXCEPTED": 0,
            },
        )
        group["expected_hosts"] += 1
        snapshot = supplied.get(host.host_id)
        if snapshot is None:
            group["missing_hosts"] += 1
            group["UNKNOWN"] += len(controls)
            refresh.append(
                {
                    "host_id": host.host_id,
                    "owner": host.owner,
                    "control_ids": [control.id for control in controls],
                    "reason": "missing_host_snapshot",
                    "evidence_due_at": clock,
                    "action": "Request an authorized read-only snapshot; no host was discovered.",
                }
            )
            continue
        report = assess(policy, snapshot, as_of, exceptions)
        try:
            due_at = utc(snapshot.observed_at + timedelta(seconds=policy.max_age_seconds))
        except OverflowError as error:
            raise Rejected("freshness boundary outside supported calendar") from error
        group["assessed_hosts"] += 1
        for status in ("PASS", "FAIL", "UNKNOWN", "EXCEPTED"):
            group[status] += report.summary()[status]
        reports.append(
            {
                "owner": host.owner,
                "assessment": report.data(),
                "evidence_due_at": due_at,
            }
        )
        for finding in report.findings:
            if finding.status == "UNKNOWN":
                refresh.append(
                    {
                        "host_id": host.host_id,
                        "owner": host.owner,
                        "control_ids": [finding.control_id],
                        "reason": finding.reason,
                        "evidence_due_at": due_at,
                        "action": finding.review,
                    }
                )
            elif finding.status in ("FAIL", "EXCEPTED"):
                deviations.append({"host_id": host.host_id, "owner": host.owner, **asdict(finding)})
    counts = {
        status: sum(group[status] for group in groups.values())
        for status in ("PASS", "FAIL", "UNKNOWN", "EXCEPTED")
    }
    return {
        "schema": 1,
        "kind": "expected_inventory_assessment",
        "as_of": clock,
        "policy_id": policy.id,
        "policy_digest": policy.digest,
        "inventory": [asdict(host) for host in sorted(hosts, key=lambda item: item.host_id)],
        "expected_hosts": len(hosts),
        "assessed_hosts": len(reports),
        "missing_hosts": len(hosts) - len(reports),
        "counts": counts,
        "groups": [groups[key] for key in sorted(groups)],
        "hosts": reports,
        "refresh_queue": refresh,
        "deviation_queue": deviations,
        "all_expected_controls_pass": not any(
            counts[status] for status in ("FAIL", "UNKNOWN", "EXCEPTED")
        ),
        "scope": "Declared inventory and selected baseline only; no discovery, enforcement or fleet security certification.",
    }


def publish(data: dict[str, Any], directory: Path) -> None:
    """Save a new private JSON/escaped HTML worklist; existing evidence is never overwritten."""
    absolute = directory.absolute()
    if any(part.is_symlink() or part.is_junction() for part in (absolute, *absolute.parents)):
        raise Rejected("output traverses a link")
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(row[key]))}</td>"
            for key in ("host_id", "owner", "control_ids", "reason", "evidence_due_at", "action")
        )
        + "</tr>"
        for row in data["refresh_queue"]
    )
    output = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>Expected host inventory — Jason Stys</title><main><h1>Host evidence refresh queue</h1>"
        "<p>Created by Jason Stys. Read-only review; owners are asserted, not authenticated.</p>"
        f"<p>Expected {data['expected_hosts']}; assessed {data['assessed_hosts']}; missing {data['missing_hosts']}.</p>"
        "<table><caption>Unknown evidence requiring refresh</caption><thead><tr><th>Host</th><th>Owner</th>"
        "<th>Controls</th><th>Reason</th><th>Freshness boundary</th><th>Next step</th></tr></thead>"
        f"<tbody>{rows}</tbody></table><details><summary>Full assessments and deviations</summary><pre>"
        f"{html.escape(canonical(data).decode())}</pre></details></main></html>"
    )
    try:
        absolute.mkdir(mode=0o700)
        (absolute / "fleet.json").write_bytes(canonical(data))
        (absolute / "fleet.html").write_text(output, encoding="utf-8", newline="\n")
    except OSError as error:
        raise Rejected("output unavailable or exists; partial output preserved") from error
