"""Strict contract rejection, semantic hashing and YAML/JSON misuse tests. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_integer_exact — line 80
# parameter: value — line 80
# definition: test_text_contract — line 87
# parameter: value — line 87
# definition: test_utc_only — line 103
# parameter: value — line 103
# definition: test_naive_clock — line 109
# definition: test_non_unicode_scalar_text — line 116
# parameter: value — line 116
# variable: data — line 120
# definition: test_exact_object — line 127
# parameter: value — line 127
# definition: test_bad_json — line 137
# parameter: content — line 137
# definition: test_bad_yaml — line 157
# parameter: content — line 157
# definition: test_bad_snapshot_top — line 175
# parameter: field — line 175
# parameter: value — line 175
# variable: data — line 177
# definition: test_bad_fact — line 194
# parameter: updates — line 194
# variable: data — line 196
# definition: test_bool_is_not_integer — line 202
# variable: bad — line 204
# variable: key — line 204
# variable: platform — line 204
# variable: data — line 209
# definition: test_digest_order_stability — line 215
# variable: data — line 217
# variable: reordered — line 218
# variable: altered — line 220
# definition: test_policy_rejection — line 241
# parameter: mutation — line 241
# parameter: tmp_path — line 241
# variable: data — line 243
# variable: control — line 244
# variable: path — line 267
# definition: test_exception_rejection — line 276
# parameter: mutation — line 276
# parameter: policy — line 276
# parameter: tmp_path — line 276
# variable: data — line 278
# variable: row — line 279
# variable: path — line 294
# definition: test_regular_bounded_files — line 300
# parameter: tmp_path — line 300
# variable: path — line 302
# variable: limit — line 305
# variable: target — line 305
# END CODE MAP

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from hardening.contracts import (
    Policy,
    integer,
    load_exceptions,
    load_policy,
    mapping,
    snapshot_data,
    text,
    timestamp,
    utc,
)
from hardening.io import Rejected, json_value, read_bytes, yaml_value
from scripts.fixtures import healthy


@pytest.mark.parametrize("value", [None, True, 1.0, "1", -1, 4096])
def test_integer_exact(value: Any) -> None:
    """Booleans, floats, strings and out-of-range integers cannot masquerade as evidence integers."""
    with pytest.raises(Rejected):
        integer(value, 0, 4095)


@pytest.mark.parametrize("value", [None, "", "a\nb", "a" * 501, "bad/id"])
def test_text_contract(value: Any) -> None:
    """Reject absent/oversized/control-character text and invalid token identifiers."""
    with pytest.raises(Rejected):
        text(value, token=True)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "2026-10-13",
        "2026-10-13T12:00:00",
        "2026-10-13T12:00:00+00:00",
        "2026-02-30T00:00:00Z",
    ],
)
def test_utc_only(value: Any) -> None:
    """Naive, offset-spelled and invalid dates do not silently become local evaluation clocks."""
    with pytest.raises(Rejected):
        timestamp(value)


def test_naive_clock() -> None:
    """Library callers must provide a UTC-aware datetime too."""
    with pytest.raises(Rejected):
        utc(datetime(2026, 1, 1))


@pytest.mark.parametrize("value", ["\ud800", "\udfff", "unsafe\x7f"])
def test_non_unicode_scalar_text(value: str) -> None:
    """Lone surrogate and DEL text cannot reach UTF-8 report writes, even from valid escaped JSON."""
    with pytest.raises(Rejected):
        text(value)
    data = healthy("linux")
    data["facts"]["ssh.password_auth"]["source"] = value
    with pytest.raises(Rejected):
        snapshot_data(data)


@pytest.mark.parametrize("value", [{}, {"a": 1, "extra": 2}, [], None])
def test_exact_object(value: Any) -> None:
    """Required fields and unknown fields cannot be ignored at the contract boundary."""
    with pytest.raises(Rejected):
        mapping(value, {"a"})


@pytest.mark.parametrize(
    "content",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b"\xff", b"{", b"[" * 1500],
)
def test_bad_json(content: bytes) -> None:
    """Duplicate keys, non-finite numeric values, malformed bytes and excessive recursion are refused."""
    with pytest.raises(Rejected):
        json_value(content)


@pytest.mark.parametrize(
    "content",
    [
        b"a: 1\na: 2",
        b"a: &x [1]\nb: *x",
        b"!!python/object:os.system {}",
        b"a: 1\n---\nb: 2",
        b"a: " + b"[" * 10 + b"1" + b"]" * 10,
        b"1: x",
        b"<<: x",
        b"\xff",
        b"",
    ],
)
def test_bad_yaml(content: bytes) -> None:
    """Safe loader also rejects duplicates, merge/complex keys, aliases, depth, unsafe tags and multiple docs."""
    with pytest.raises(Rejected):
        yaml_value(content)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True),
        ("platform", "macos"),
        ("kind", "signed"),
        ("host_id", "../../x"),
        ("collector", ""),
        ("facts", []),
        ("facts", {"private.hostname": {}}),
    ],
)
def test_bad_snapshot_top(field: str, value: Any) -> None:
    """Unsupported provenance/platform and non-allowlisted private evidence are rejected."""
    data = healthy("linux")
    data[field] = value
    with pytest.raises(Rejected):
        snapshot_data(data)


@pytest.mark.parametrize(
    "updates",
    [
        {"value": True},
        {"value": ""},
        {"quality": "unavailable"},
        {"quality": "invented"},
        {"source": ""},
        {"extra": 1},
    ],
)
def test_bad_fact(updates: dict[str, Any]) -> None:
    """A fact cannot claim a value with unobserved quality or acquire silent extra properties."""
    data = healthy("linux")
    data["facts"]["ssh.password_auth"].update(updates)
    with pytest.raises(Rejected):
        snapshot_data(data)


def test_bool_is_not_integer() -> None:
    """Both Windows boolean and Linux integer evidence retain exact types, not permissive coercion."""
    for platform, key, bad in [
        ("windows", "firewall.public", 1),
        ("linux", "kernel.aslr", True),
        ("linux", "kernel.aslr", 4096),
    ]:
        data = healthy(platform)
        data["facts"][key]["value"] = bad
        with pytest.raises(Rejected):
            snapshot_data(data)


def test_digest_order_stability() -> None:
    """Key reordering does not change the evidence digest; a real value change does."""
    data = healthy("linux")
    reordered = dict(reversed(list(data.items())))
    assert snapshot_data(data).digest == snapshot_data(reordered).digest
    altered = deepcopy(data)
    altered["facts"]["kernel.aslr"]["value"] = 1
    assert snapshot_data(data).digest != snapshot_data(altered).digest


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "empty",
        "too_many",
        "wrong_type",
        "unknown_fact",
        "operator",
        "bad_mask",
        "bad_weight",
        "bad_age",
        "bad_platform",
        "large_integer",
    ],
)
def test_policy_rejection(tmp_path: Path, mutation: str) -> None:
    """Every policy control is validated before evaluation, without expression or dynamic-code execution."""
    data = yaml.safe_load(Path("policies/baseline.yml").read_text())
    control = data["controls"][0]
    if mutation == "duplicate":
        data["controls"].append(deepcopy(control))
    elif mutation == "empty":
        data["controls"] = []
    elif mutation == "too_many":
        data["controls"] = [control] * 101
    elif mutation == "wrong_type":
        control["expected"] = False
    elif mutation == "unknown_fact":
        control["fact"] = "execute.command"
    elif mutation == "operator":
        control["operator"] = "eval"
    elif mutation == "bad_mask":
        control["operator"] = "forbidden_bits"
    elif mutation == "bad_weight":
        control["weight"] = 0
    elif mutation == "bad_age":
        data["max_age_seconds"] = 0
    elif mutation == "bad_platform":
        control["platform"] = "unsupported"
    else:
        data["controls"][4]["expected"] = 4096
    path = tmp_path / "policy.yml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(Rejected):
        load_policy(path)


@pytest.mark.parametrize(
    "mutation", ["duplicate", "scope", "digest", "end", "duration", "too_many", "nonlist"]
)
def test_exception_rejection(tmp_path: Path, policy: Policy, mutation: str) -> None:
    """Exceptions require exact policy and known control with a bounded positive validity window."""
    data = json.loads(Path("examples/exceptions.json").read_text())
    row = data["exceptions"][0]
    if mutation == "duplicate":
        data["exceptions"].append(deepcopy(row))
    elif mutation == "scope":
        row["control_id"] = "UNKNOWN"
    elif mutation == "digest":
        row["policy_digest"] = "0" * 64
    elif mutation == "end":
        row["expires_at"] = row["starts_at"]
    elif mutation == "duration":
        row["expires_at"] = "2027-10-14T00:00:00Z"
    elif mutation == "too_many":
        data["exceptions"] = [row] * 101
    else:
        data["exceptions"] = "invalid"
    path = tmp_path / "exceptions.json"
    path.write_text(json.dumps(data))
    with pytest.raises(Rejected):
        load_exceptions(path, policy)


def test_regular_bounded_files(tmp_path: Path) -> None:
    """Readers refuse directories, absent paths and oversize files instead of blocking on special paths."""
    path = tmp_path / "data"
    path.write_bytes(b"abc")
    assert read_bytes(path, 3) == b"abc"
    for target, limit in [(path, 2), (tmp_path, 10), (tmp_path / "absent", 10)]:
        with pytest.raises(Rejected):
            read_bytes(target, limit)
