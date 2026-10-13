"""Deterministic typed assessment, freshness and expiring deviations. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: STATUSES — line 80
# definition: Finding — line 84
# variable: control_id — line 87
# variable: title — line 88
# variable: status — line 89
# variable: reason — line 90
# variable: value — line 91
# variable: expected — line 92
# variable: weight — line 93
# variable: source — line 94
# variable: review — line 95
# variable: exception_ticket — line 96
# variable: exception_detail — line 97
# definition: Report — line 101
# variable: host_id — line 104
# variable: platform — line 105
# variable: policy_id — line 106
# variable: policy_digest — line 107
# variable: snapshot_digest — line 108
# variable: observed_at — line 109
# variable: as_of — line 110
# variable: provenance — line 111
# variable: findings — line 112
# definition: summary — line 114
# parameter: self — line 114
# variable: counts — line 116
# variable: f — line 116
# variable: status — line 116
# variable: total — line 117
# variable: f — line 118
# variable: weight — line 118
# variable: f — line 126
# definition: data — line 132
# parameter: self — line 132
# definition: exit_code — line 136
# parameter: self — line 136
# variable: f — line 138
# definition: assess — line 141
# parameter: policy — line 142
# parameter: snapshot — line 143
# parameter: as_of — line 144
# parameter: exceptions — line 145
# variable: clock — line 148
# variable: c — line 149
# variable: relevant — line 149
# variable: age — line 152
# variable: time_reason — line 153
# variable: exception_map — line 156
# variable: e — line 157
# variable: findings — line 159
# variable: control — line 160
# variable: fact — line 161
# variable: value — line 162
# variable: reason — line 163
# variable: ticket — line 170
# variable: detail — line 171
# variable: status — line 173
# variable: matches — line 176
# variable: matches — line 178
# variable: reason — line 183
# variable: status — line 183
# variable: exception — line 186
# variable: reason — line 192
# variable: status — line 192
# variable: ticket — line 192
# variable: detail — line 193
# END CODE MAP

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .contracts import ExceptionRecord, Policy, Snapshot, utc
from .io import Rejected

STATUSES = ("PASS", "FAIL", "UNKNOWN", "EXCEPTED")


@dataclass(frozen=True)
class Finding:
    """Control result preserves evidence and expectation; an exception is not a successful check."""

    control_id: str
    title: str
    status: str
    reason: str
    value: str | int | bool | None
    expected: str | int | bool
    weight: int
    source: str
    review: str
    exception_ticket: str | None
    exception_detail: dict[str, str] | None


@dataclass(frozen=True)
class Report:
    """Evidence-bound host results with explicit denominator, coverage and conservative weighted pass rate."""

    host_id: str
    platform: str
    policy_id: str
    policy_digest: str
    snapshot_digest: str
    observed_at: str
    as_of: str
    provenance: str
    findings: tuple[Finding, ...]

    def summary(self) -> dict[str, int | float]:
        """Keep UNKNOWN/EXCEPTED in the denominator; do not inflate pass rates by ignoring them."""
        counts = {status: sum(f.status == status for f in self.findings) for status in STATUSES}
        total = len(self.findings)
        weight = sum(f.weight for f in self.findings)
        return {
            **counts,
            "total": total,
            "observed_percent": round(100 * (total - counts["UNKNOWN"]) / total, 2)
            if total
            else 0.0,
            "weighted_pass_percent": round(
                100 * sum(f.weight for f in self.findings if f.status == "PASS") / weight, 2
            )
            if weight
            else 0.0,
        }

    def data(self) -> dict[str, Any]:
        """Expose the deterministic machine-readable contract; no raw collector error messages are included."""
        return {"schema": 1, **asdict(self), "summary": self.summary()}

    def exit_code(self) -> int:
        """Exit 1 for any non-PASS (including approved deviations); report generation still succeeds."""
        return int(any(f.status != "PASS" for f in self.findings))


def assess(
    policy: Policy,
    snapshot: Snapshot,
    as_of: datetime,
    exceptions: tuple[ExceptionRecord, ...] = (),
) -> Report:
    """Evaluate one snapshot in O(facts+controls+exceptions); never execute policy expressions or remediation."""
    clock = utc(as_of)
    relevant = [c for c in policy.controls if c.platform == snapshot.platform]
    if not relevant:
        raise Rejected("no controls apply to this platform")
    age = (as_of - snapshot.observed_at).total_seconds()
    time_reason = (
        "future_evidence" if age < 0 else "stale_evidence" if age > policy.max_age_seconds else None
    )
    exception_map = {
        (e.host_id, e.control_id): e for e in exceptions if e.policy_digest == policy.digest
    }
    findings = []
    for control in relevant:
        fact = snapshot.facts.get(control.fact)
        value = fact.value if fact else None
        reason = time_reason or (
            "missing_evidence"
            if fact is None
            else fact.quality
            if fact.quality != "observed"
            else None
        )
        ticket = None
        detail = None
        if reason:
            status = "UNKNOWN"
        else:
            # Exact types were checked at the boundary: True is not accepted as integer 1.
            matches = value == control.expected
            if control.operator == "forbidden_bits":
                matches = (
                    isinstance(value, int)
                    and isinstance(control.expected, int)
                    and value & control.expected == 0
                )
            status, reason = (
                ("PASS", "matches_baseline") if matches else ("FAIL", "baseline_mismatch")
            )
            exception = exception_map.get((snapshot.host_id, control.id))
            if (
                status == "FAIL"
                and exception
                and exception.starts_at <= as_of < exception.expires_at
            ):
                status, reason, ticket = "EXCEPTED", "active_deviation", exception.ticket
                detail = {
                    "reason": exception.reason,
                    "approved_by": exception.approved_by,
                    "starts_at": utc(exception.starts_at),
                    "expires_at": utc(exception.expires_at),
                }
        findings.append(
            Finding(
                control.id,
                control.title,
                status,
                reason,
                value,
                control.expected,
                control.weight,
                fact.source if fact else "not_collected",
                control.review,
                ticket,
                detail,
            )
        )
    return Report(
        snapshot.host_id,
        snapshot.platform,
        policy.id,
        policy.digest,
        snapshot.digest,
        utc(snapshot.observed_at),
        clock,
        snapshot.kind,
        tuple(findings),
    )
