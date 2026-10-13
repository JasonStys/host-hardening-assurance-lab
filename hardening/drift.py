"""Evidence-aware baseline drift without comparing incompatible hosts/policies. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: compare — line 32
# parameter: after — line 32
# parameter: before — line 32
# variable: f — line 44
# variable: old — line 44
# variable: f — line 45
# variable: new — line 45
# variable: changes — line 48
# variable: key — line 49
# variable: current — line 50
# variable: previous — line 50
# variable: kind — line 68
# variable: kind — line 70
# variable: kind — line 72
# variable: kind — line 74
# variable: kind — line 76
# variable: c — line 94
# variable: c — line 95
# END CODE MAP

from __future__ import annotations

from typing import Any

from .contracts import timestamp
from .engine import Report
from .io import Rejected


def compare(before: Report, after: Report) -> dict[str, Any]:
    """Compare equal identity/policy reports with O(C log C) sorted output; unknown is not improvement."""
    if (before.host_id, before.platform, before.policy_digest) != (
        after.host_id,
        after.platform,
        after.policy_digest,
    ):
        raise Rejected("drift requires the same host, platform and exact policy")
    if timestamp(after.observed_at) < timestamp(before.observed_at) or timestamp(
        after.as_of
    ) < timestamp(before.as_of):
        raise Rejected("drift chronology is reversed")
    old = {f.control_id: f for f in before.findings}
    new = {f.control_id: f for f in after.findings}
    if old.keys() != new.keys():
        raise Rejected("control sets are incompatible")
    changes = []
    for key in sorted(old):
        previous, current = old[key], new[key]
        if (
            previous.status,
            previous.value,
            previous.reason,
            previous.source,
            previous.exception_ticket,
            previous.exception_detail,
        ) == (
            current.status,
            current.value,
            current.reason,
            current.source,
            current.exception_ticket,
            current.exception_detail,
        ):
            continue
        if "UNKNOWN" in (previous.status, current.status):
            kind = "evidence_gap" if current.status == "UNKNOWN" else "evidence_restored"
        elif current.status == "FAIL" and previous.status != "FAIL":
            kind = "regression"
        elif current.status == "PASS" and previous.status != "PASS":
            kind = "baseline_restored"
        elif "EXCEPTED" in (previous.status, current.status):
            kind = "deviation_change"
        else:
            kind = "evidence_change"
        changes.append(
            {
                "control_id": key,
                "kind": kind,
                "before": previous.status,
                "after": current.status,
                "before_value": previous.value,
                "after_value": current.value,
            }
        )
    return {
        "schema": 1,
        "host_id": after.host_id,
        "policy_digest": after.policy_digest,
        "before_snapshot": before.snapshot_digest,
        "after_snapshot": after.snapshot_digest,
        "changes": changes,
        "regressions": sum(c["kind"] == "regression" for c in changes),
        "evidence_gaps": sum(c["kind"] == "evidence_gap" for c in changes),
    }
