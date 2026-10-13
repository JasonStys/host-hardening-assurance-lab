"""Strict, bounded policy, snapshot and exception contracts. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: FACT_TYPES — line 119
# variable: QUALITY — line 135
# variable: TOKEN — line 136
# definition: mapping — line 139
# parameter: optional — line 139
# parameter: required — line 139
# parameter: value — line 139
# definition: text — line 150
# parameter: maximum — line 150
# parameter: token — line 150
# parameter: value — line 150
# variable: c — line 155
# definition: integer — line 163
# parameter: high — line 163
# parameter: low — line 163
# parameter: value — line 163
# definition: timestamp — line 170
# parameter: value — line 170
# definition: utc — line 180
# parameter: value — line 180
# definition: Control — line 188
# variable: id — line 191
# variable: platform — line 192
# variable: fact — line 193
# variable: operator — line 194
# variable: expected — line 195
# variable: weight — line 196
# variable: title — line 197
# variable: rationale — line 198
# variable: review — line 199
# definition: Policy — line 203
# variable: id — line 206
# variable: max_age_seconds — line 207
# variable: controls — line 208
# variable: digest — line 209
# definition: Fact — line 213
# variable: value — line 216
# variable: quality — line 217
# variable: source — line 218
# definition: Snapshot — line 222
# variable: host_id — line 225
# variable: platform — line 226
# variable: observed_at — line 227
# variable: kind — line 228
# variable: collector — line 229
# variable: facts — line 230
# variable: digest — line 231
# definition: ExceptionRecord — line 235
# variable: host_id — line 238
# variable: control_id — line 239
# variable: policy_digest — line 240
# variable: starts_at — line 241
# variable: expires_at — line 242
# variable: reason — line 243
# variable: approved_by — line 244
# variable: ticket — line 245
# definition: load_policy — line 248
# parameter: path — line 248
# variable: data — line 250
# variable: policy_id — line 254
# variable: max_age — line 255
# variable: controls — line 258
# variable: seen — line 259
# variable: raw — line 260
# variable: row — line 261
# variable: control_id — line 275
# variable: platform — line 279
# variable: fact — line 280
# variable: expected — line 283
# variable: operator — line 290
# definition: snapshot_data — line 311
# parameter: value — line 311
# variable: data — line 313
# variable: host_id — line 317
# variable: platform — line 318
# variable: kind — line 321
# variable: observed_at — line 324
# variable: collector — line 325
# variable: facts — line 328
# variable: key — line 329
# variable: raw — line 329
# variable: row — line 332
# variable: quality — line 333
# variable: fact_value — line 336
# definition: load_snapshot — line 358
# parameter: path — line 358
# definition: load_exceptions — line 363
# parameter: path — line 363
# parameter: policy — line 363
# variable: data — line 367
# variable: rows — line 369
# variable: seen — line 372
# variable: c — line 373
# variable: controls — line 373
# variable: records — line 374
# variable: raw — line 375
# variable: row — line 376
# variable: control_id — line 389
# variable: host_id — line 389
# variable: digest — line 390
# variable: scope — line 391
# variable: end — line 395
# variable: start — line 395
# END CODE MAP

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .io import Rejected, canonical, json_value, read_bytes, yaml_value

FACT_TYPES: dict[str, dict[str, type[str] | type[int] | type[bool]]] = {
    "linux": {
        "ssh.password_auth": str,
        "ssh.root_login": str,
        "ssh.keyboard_auth": str,
        "ssh.config_mode": int,
        "kernel.aslr": int,
    },
    "windows": {
        "firewall.domain": bool,
        "firewall.private": bool,
        "firewall.public": bool,
        "defender.realtime": bool,
        "smb.smb1": bool,
    },
}
QUALITY = {"observed", "unavailable", "unsupported", "permission_denied", "ambiguous"}
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def mapping(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    """Require exact string keys; value is decoded data, required/optional specify the contract."""
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - (optional or set())
    ):
        raise Rejected("missing or unexpected object fields")
    return value


def text(value: Any, maximum: int = 500, token: bool = False) -> str:
    """Validate bounded nonempty text; token=True restricts IDs, not prose or source descriptions."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise Rejected("invalid bounded text")
    if token and not TOKEN.fullmatch(value):
        raise Rejected("invalid identifier")
    return value


def integer(value: Any, low: int, high: int) -> int:
    """Require a real integer in [low, high]; Python bool is deliberately not accepted as int."""
    if type(value) is not int or not low <= value <= high:
        raise Rejected("integer outside contract")
    return value


def timestamp(value: Any) -> datetime:
    """Require second-precision RFC3339 UTC text; do not interpret timezone-naive dates locally."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise Rejected("timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise Rejected("invalid UTC timestamp") from error


def utc(value: datetime) -> str:
    """Serialize an aware UTC time without fractional seconds; reject timezone-naive calls."""
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise Rejected("evaluation clock must be aware UTC")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Control:
    """One typed check: ID, platform, fact, expectation, weight and explanatory review guidance."""

    id: str
    platform: str
    fact: str
    operator: str
    expected: str | int | bool
    weight: int
    title: str
    rationale: str
    review: str


@dataclass(frozen=True)
class Policy:
    """Versioned baseline; digest binds canonical semantics including freshness and all controls."""

    id: str
    max_age_seconds: int
    controls: tuple[Control, ...]
    digest: str


@dataclass(frozen=True)
class Fact:
    """Typed observation plus quality/provenance; non-observed facts always carry null value."""

    value: str | int | bool | None
    quality: str
    source: str


@dataclass(frozen=True)
class Snapshot:
    """Minimal pseudonymous host evidence; missing facts are allowed but never implied secure."""

    host_id: str
    platform: str
    observed_at: datetime
    kind: str
    collector: str
    facts: dict[str, Fact]
    digest: str


@dataclass(frozen=True)
class ExceptionRecord:
    """Exact host/control/policy scope with bounded validity and an asserted reviewer, not a signature."""

    host_id: str
    control_id: str
    policy_digest: str
    starts_at: datetime
    expires_at: datetime
    reason: str
    approved_by: str
    ticket: str


def load_policy(path: Path) -> Policy:
    """Read <=128 KiB of safe YAML; allow only registered facts/operators and <=100 controls."""
    data = mapping(
        yaml_value(read_bytes(path, 131072)), {"schema", "id", "max_age_seconds", "controls"}
    )
    integer(data["schema"], 1, 1)
    policy_id = text(data["id"], token=True)
    max_age = integer(data["max_age_seconds"], 60, 604800)
    if not isinstance(data["controls"], list) or not 1 <= len(data["controls"]) <= 100:
        raise Rejected("policy needs 1..100 controls")
    controls = []
    seen = set()
    for raw in data["controls"]:
        row = mapping(
            raw,
            {
                "id",
                "platform",
                "fact",
                "operator",
                "expected",
                "weight",
                "title",
                "rationale",
                "review",
            },
        )
        control_id = text(row["id"], token=True)
        if control_id in seen:
            raise Rejected("duplicate control ID")
        seen.add(control_id)
        platform = text(row["platform"])
        fact = text(row["fact"])
        if platform not in FACT_TYPES or fact not in FACT_TYPES[platform]:
            raise Rejected("unsupported platform or fact")
        expected = row["expected"]
        if type(expected) is not FACT_TYPES[platform][fact]:
            raise Rejected("expected value has wrong type")
        if isinstance(expected, str):
            text(expected, 80)
        elif type(expected) is int:
            integer(expected, 0, 4095)
        operator = row["operator"]
        if operator not in ("equals", "forbidden_bits") or (
            operator == "forbidden_bits" and fact != "ssh.config_mode"
        ):
            raise Rejected("unsupported operator")
        controls.append(
            Control(
                control_id,
                platform,
                fact,
                operator,
                expected,
                integer(row["weight"], 1, 10),
                text(row["title"], 120),
                text(row["rationale"]),
                text(row["review"]),
            )
        )
    return Policy(policy_id, max_age, tuple(controls), hashlib.sha256(canonical(data)).hexdigest())


def snapshot_data(value: Any) -> Snapshot:
    """Validate <=32 allowlisted facts, exact types and explicit collection origin; exclude extra private fields."""
    data = mapping(
        value, {"schema", "host_id", "platform", "observed_at", "kind", "collector", "facts"}
    )
    integer(data["schema"], 1, 1)
    host_id = text(data["host_id"], token=True)
    platform = text(data["platform"])
    if platform not in FACT_TYPES:
        raise Rejected("unsupported snapshot platform")
    kind = text(data["kind"])
    if kind not in ("synthetic", "authorized_read_only"):
        raise Rejected("unsupported provenance kind")
    observed_at = timestamp(data["observed_at"])
    collector = text(data["collector"], token=True)
    if not isinstance(data["facts"], dict) or len(data["facts"]) > 32:
        raise Rejected("invalid facts object")
    facts = {}
    for key, raw in data["facts"].items():
        if key not in FACT_TYPES[platform]:
            raise Rejected("unsupported fact key")
        row = mapping(raw, {"value", "quality", "source"})
        quality = text(row["quality"])
        if quality not in QUALITY:
            raise Rejected("unsupported fact quality")
        fact_value = row["value"]
        if quality == "observed":
            if type(fact_value) is not FACT_TYPES[platform][key]:
                raise Rejected("observed fact has wrong type")
            if isinstance(fact_value, str):
                text(fact_value, 80)
            elif type(fact_value) is int:
                integer(fact_value, 0, 4095)
        elif fact_value is not None:
            raise Rejected("unobserved fact must have null value")
        facts[key] = Fact(fact_value, quality, text(row["source"], 160))
    return Snapshot(
        host_id,
        platform,
        observed_at,
        kind,
        collector,
        facts,
        hashlib.sha256(canonical(data)).hexdigest(),
    )


def load_snapshot(path: Path) -> Snapshot:
    """Read a <=128 KiB regular JSON snapshot without executing content or accepting duplicate keys."""
    return snapshot_data(json_value(read_bytes(path, 131072)))


def load_exceptions(path: Path | None, policy: Policy) -> tuple[ExceptionRecord, ...]:
    """Load <=100 exact-scope deviations, reject duplicate scope, unknown controls and durations >90 days."""
    if path is None:
        return ()
    data = mapping(json_value(read_bytes(path, 131072)), {"schema", "exceptions"})
    integer(data["schema"], 1, 1)
    rows = data["exceptions"]
    if not isinstance(rows, list) or len(rows) > 100:
        raise Rejected("too many exceptions")
    seen = set()
    controls = {c.id for c in policy.controls}
    records = []
    for raw in rows:
        row = mapping(
            raw,
            {
                "host_id",
                "control_id",
                "policy_digest",
                "starts_at",
                "expires_at",
                "reason",
                "approved_by",
                "ticket",
            },
        )
        host_id, control_id = text(row["host_id"], token=True), text(row["control_id"], token=True)
        digest = row["policy_digest"]
        scope = (host_id, control_id)
        if scope in seen or control_id not in controls or digest != policy.digest:
            raise Rejected("duplicate, unknown or wrong-policy exception scope")
        seen.add(scope)
        start, end = timestamp(row["starts_at"]), timestamp(row["expires_at"])
        if not timedelta(0) < end - start <= timedelta(days=90):
            raise Rejected("exception lifetime must be positive and <=90 days")
        records.append(
            ExceptionRecord(
                host_id,
                control_id,
                digest,
                start,
                end,
                text(row["reason"]),
                text(row["approved_by"], 120),
                text(row["ticket"], token=True),
            )
        )
    return tuple(records)
