"""Opt-in Linux file evidence collector with conservative SSH interpretation. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: SSH_KEYS — line 53
# variable: SSH_VALUES — line 58
# definition: fact — line 71
# parameter: quality — line 71
# parameter: source — line 71
# parameter: value — line 71
# definition: ssh_facts — line 76
# parameter: content — line 76
# variable: values — line 78
# variable: ambiguous — line 79
# variable: line — line 80
# variable: tokens — line 81
# variable: key — line 84
# variable: ambiguous — line 86
# variable: name — line 88
# variable: ambiguous — line 90
# variable: name — line 101
# definition: authorized_path — line 105
# parameter: relative — line 105
# parameter: root — line 105
# variable: path — line 107
# variable: part — line 108
# variable: component — line 111
# variable: path — line 112
# definition: collect_linux — line 118
# parameter: authorized — line 119
# parameter: host_id — line 119
# parameter: observed_at — line 119
# parameter: root — line 119
# parameter: synthetic — line 119
# variable: facts — line 127
# variable: key — line 127
# variable: ssh — line 128
# variable: content — line 130
# variable: aslr — line 138
# variable: value — line 140
# variable: data — line 145
# END CODE MAP

from __future__ import annotations

import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import FACT_TYPES, snapshot_data, text, utc
from .io import Rejected, read_bytes

SSH_KEYS = {
    "passwordauthentication": "ssh.password_auth",
    "permitrootlogin": "ssh.root_login",
    "kbdinteractiveauthentication": "ssh.keyboard_auth",
}
SSH_VALUES = {
    "ssh.password_auth": {"yes", "no"},
    "ssh.keyboard_auth": {"yes", "no"},
    "ssh.root_login": {
        "yes",
        "no",
        "prohibit-password",
        "without-password",
        "forced-commands-only",
    },
}


def fact(value: str | int | bool | None, quality: str, source: str) -> dict[str, Any]:
    """Construct minimal provenance without including raw files, hostnames or collector exception text."""
    return {"value": value, "quality": quality, "source": source}


def ssh_facts(content: str) -> dict[str, dict[str, Any]]:
    """Interpret only explicit global simple directives; Include/Match/alias/syntax uncertainty yields UNKNOWN."""
    values: dict[str, str] = {}
    ambiguous = False
    for line in content.splitlines():
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        key = tokens[0].lower()
        if key in ("include", "match", "challengeresponseauthentication"):
            ambiguous = True
        if key in SSH_KEYS:
            name = SSH_KEYS[key]
            if len(tokens) != 2 or tokens[1] not in SSH_VALUES[name]:
                ambiguous = True
            else:
                values.setdefault(name, tokens[1])  # OpenSSH global directives use the first value.
    return {
        name: fact(None, "ambiguous", "sshd_config:limited_parser")
        if ambiguous
        else fact(
            values.get(name),
            "observed" if name in values else "unavailable",
            "sshd_config:limited_parser",
        )
        for name in SSH_KEYS.values()
    }


def authorized_path(root: Path, relative: str) -> Path:
    """Refuse symlinks/junctions in every fixed collector path; root must be a trusted non-concurrent tree."""
    path = root.absolute()
    for part in (*path.parents, path):
        if part.is_symlink() or part.is_junction():
            raise Rejected("collector root traverses a link")
    for component in Path(relative).parts:
        path /= component
        if path.is_symlink() or path.is_junction():
            raise Rejected("collector evidence traverses a link")
    return path


def collect_linux(
    root: Path, host_id: str, observed_at: datetime, authorized: bool, synthetic: bool = False
) -> dict[str, Any]:
    """Read exactly SSH configuration/mode and ASLR; require acknowledgement even for fixture roots."""
    if not authorized:
        raise Rejected("explicit acknowledgement of an authorized host/tree is required")
    if not synthetic and sys.platform != "linux":
        raise Rejected("live Linux collection requires Linux; use an explicitly synthetic tree")
    text(host_id, token=True)
    facts = {key: fact(None, "unavailable", "linux:read_only") for key in FACT_TYPES["linux"]}
    ssh = authorized_path(root, "etc/ssh/sshd_config")
    try:
        content = read_bytes(ssh, 65536).decode("utf-8")
        facts.update(ssh_facts(content))
        facts["ssh.config_mode"] = fact(
            stat.S_IMODE(ssh.stat().st_mode), "observed", "sshd_config:mode"
        )
    except (Rejected, UnicodeError, OSError):
        # No guesses from errors: missing, inaccessible and malformed evidence remain unknown.
        pass
    aslr = authorized_path(root, "proc/sys/kernel/randomize_va_space")
    try:
        value = read_bytes(aslr, 64).decode("ascii").strip()
        if value in ("0", "1", "2"):
            facts["kernel.aslr"] = fact(int(value), "observed", "proc:randomize_va_space")
    except (Rejected, UnicodeError, OSError):
        pass
    data = {
        "schema": 1,
        "host_id": host_id,
        "platform": "linux",
        "observed_at": utc(observed_at),
        "kind": "synthetic" if synthetic else "authorized_read_only",
        "collector": "linux-files-v1",
        "facts": facts,
    }
    snapshot_data(data)
    return data
