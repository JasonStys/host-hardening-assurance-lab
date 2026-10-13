"""Generate reproducible fictional host evidence and scoped example exceptions. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 36
# definition: healthy — line 39
# parameter: platform — line 39
# variable: values — line 41
# variable: key — line 66
# variable: value — line 66
# definition: generate — line 71
# variable: files — line 73
# variable: platform — line 74
# variable: clean — line 75
# variable: changed — line 77
# variable: mutations — line 79
# variable: key — line 88
# variable: value — line 88
# variable: unknown — line 91
# variable: key — line 95
# variable: policy — line 98
# definition: main — line 117
# variable: directory — line 119
# variable: data — line 121
# variable: name — line 121
# END CODE MAP

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from hardening.collect import fact
from hardening.contracts import FACT_TYPES, load_policy
from hardening.io import canonical

ROOT = Path(__file__).resolve().parents[1]


def healthy(platform: str) -> dict[str, Any]:
    """Build independently chosen baseline values; these are synthetic configuration observations, not real host data."""
    values = (
        {
            "ssh.password_auth": "no",
            "ssh.root_login": "no",
            "ssh.keyboard_auth": "no",
            "ssh.config_mode": 420,
            "kernel.aslr": 2,
        }
        if platform == "linux"
        else {
            "firewall.domain": True,
            "firewall.private": True,
            "firewall.public": True,
            "defender.realtime": True,
            "smb.smb1": False,
        }
    )
    return {
        "schema": 1,
        "host_id": f"lab-{platform}-01",
        "platform": platform,
        "observed_at": "2026-10-13T12:00:00Z",
        "kind": "synthetic",
        "collector": "fictional-fixtures-v1",
        "facts": {
            key: fact(value, "observed", "synthetic:authored") for key, value in values.items()
        },
    }


def generate() -> dict[str, Any]:
    """Create healthy/drifted/unknown snapshots for both platforms; fixed date and exact policy exception scope."""
    files = {}
    for platform in FACT_TYPES:
        clean = healthy(platform)
        files[f"{platform}-healthy.json"] = clean
        changed = deepcopy(clean)
        changed["observed_at"] = "2026-10-13T13:00:00Z"
        mutations = (
            {
                "ssh.password_auth": "yes",
                "ssh.root_login": "prohibit-password",
                "ssh.config_mode": 438,
            }
            if platform == "linux"
            else {"firewall.public": False, "defender.realtime": False, "smb.smb1": True}
        )
        for key, value in mutations.items():
            changed["facts"][key]["value"] = value
        files[f"{platform}-drifted.json"] = changed
        unknown = deepcopy(clean)
        unknown["observed_at"] = "2026-10-13T14:00:00Z"
        unknown["facts"] = {
            key: fact(None, "permission_denied", "synthetic:restricted")
            for key in FACT_TYPES[platform]
        }
        files[f"{platform}-unknown.json"] = unknown
    policy = load_policy(ROOT / "policies/baseline.yml")
    files["exceptions.json"] = {
        "schema": 1,
        "exceptions": [
            {
                "host_id": "lab-linux-01",
                "control_id": "LNX-SSH-PASSWORD",
                "policy_digest": policy.digest,
                "starts_at": "2026-10-13T00:00:00Z",
                "expires_at": "2026-10-14T00:00:00Z",
                "reason": "Fictional migration window; actual approval is not established by this sample.",
                "approved_by": "Synthetic reviewer",
                "ticket": "LAB-101",
            }
        ],
    }
    return files


def main() -> int:
    """Write authored fixture JSON; this maintenance command never inspects a real host."""
    directory = ROOT / "examples"
    directory.mkdir(exist_ok=True)
    for name, data in generate().items():
        (directory / name).write_bytes(canonical(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
