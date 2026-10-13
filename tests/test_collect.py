"""Read-only collector fixture tests, SSH ambiguity and actual PowerShell synthetic execution. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CLOCK — line 70
# variable: SCRIPT — line 71
# definition: test_ssh_ambiguity — line 85
# parameter: content — line 85
# variable: result — line 87
# variable: f — line 90
# variable: f — line 91
# definition: test_ssh_first_value_and_missing — line 94
# variable: result — line 96
# definition: test_ssh_parser_total — line 105
# parameter: content — line 105
# variable: result — line 107
# variable: f — line 109
# definition: fixture_root — line 112
# parameter: directory — line 112
# variable: ssh — line 114
# variable: aslr — line 120
# definition: test_linux_fixture_collection — line 126
# parameter: tmp_path — line 126
# variable: root — line 128
# variable: data — line 129
# variable: snapshot — line 130
# definition: test_linux_invalid_or_missing — line 138
# parameter: content — line 138
# parameter: tmp_path — line 138
# variable: root — line 140
# variable: data — line 143
# definition: test_linux_bad_encoding — line 148
# parameter: tmp_path — line 148
# variable: root — line 150
# variable: data — line 152
# definition: test_collection_requires_ack — line 156
# parameter: tmp_path — line 156
# definition: test_collector_refuses_links — line 162
# parameter: tmp_path — line 162
# variable: target — line 164
# variable: link — line 166
# definition: test_powershell_synthetic — line 182
# parameter: fails — line 183
# parameter: passes — line 183
# parameter: policy — line 183
# parameter: scenario — line 183
# parameter: unknown — line 183
# variable: result — line 186
# variable: snapshot — line 206
# variable: report — line 207
# definition: test_powershell_no_ack — line 219
# variable: result — line 221
# definition: test_no_mutating_collector_commands — line 240
# variable: content — line 242
# variable: unsafe — line 243
# END CODE MAP

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hardening.collect import authorized_path, collect_linux, ssh_facts
from hardening.contracts import Policy, snapshot_data, timestamp
from hardening.engine import assess
from hardening.io import Rejected

CLOCK = timestamp("2026-10-13T14:00:00Z")
SCRIPT = Path("scripts/collect-windows.ps1").resolve()


@pytest.mark.parametrize(
    "content",
    [
        "Include /etc/ssh/*.conf",
        "Match User sample",
        "ChallengeResponseAuthentication no",
        "PasswordAuthentication NO",
        'PasswordAuthentication "no"',
        "PasswordAuthentication no extra",
    ],
)
def test_ssh_ambiguity(content: str) -> None:
    """Includes, conditional matches, legacy aliases, quoting and unknown syntax cannot imply a secure result."""
    result = ssh_facts(
        "PasswordAuthentication no\nPermitRootLogin no\nKbdInteractiveAuthentication no\n" + content
    )
    assert {f["quality"] for f in result.values()} == {"ambiguous"}
    assert all(f["value"] is None for f in result.values())


def test_ssh_first_value_and_missing() -> None:
    """First explicit global values win, keyword case is ignored, defaults are never invented."""
    result = ssh_facts(
        "# comment\n\nPASSWORDauthentication yes\nPasswordAuthentication no\nPermitRootLogin prohibit-password # note"
    )
    assert result["ssh.password_auth"]["value"] == "yes"
    assert result["ssh.root_login"]["value"] == "prohibit-password"
    assert result["ssh.keyboard_auth"]["quality"] == "unavailable"


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
def test_ssh_parser_total(content: str) -> None:
    """Arbitrary bounded configuration text cannot execute code or crash the limited parser."""
    result = ssh_facts(content)
    assert len(result) == 3
    assert all(f["quality"] in {"observed", "ambiguous", "unavailable"} for f in result.values())


def fixture_root(directory: Path) -> Path:
    """Create only an owned temporary tree, not actual /etc or /proc on any test worker."""
    ssh = directory / "etc/ssh/sshd_config"
    ssh.parent.mkdir(parents=True)
    ssh.write_text(
        "PasswordAuthentication no\nPermitRootLogin no\nKbdInteractiveAuthentication no\n"
    )
    ssh.chmod(0o644)
    aslr = directory / "proc/sys/kernel/randomize_va_space"
    aslr.parent.mkdir(parents=True)
    aslr.write_text("2\n")
    return directory


def test_linux_fixture_collection(tmp_path: Path) -> None:
    """Real file reads on a synthetic tree produce explicit observed provenance, never PC evidence."""
    root = fixture_root(tmp_path)
    data = collect_linux(root, "fictional-host", CLOCK, authorized=True, synthetic=True)
    snapshot = snapshot_data(data)
    assert snapshot.kind == "synthetic"
    assert snapshot.facts["kernel.aslr"].value == 2
    assert snapshot.facts["ssh.password_auth"].value == "no"
    assert type(snapshot.facts["ssh.config_mode"].value) is int


@pytest.mark.parametrize("content", ["invalid", "3", "-1", "\xff"])
def test_linux_invalid_or_missing(tmp_path: Path, content: str) -> None:
    """Invalid ASLR and missing SSH remain unknown; no inferred secure defaults."""
    root = fixture_root(tmp_path)
    (root / "etc/ssh/sshd_config").unlink()
    (root / "proc/sys/kernel/randomize_va_space").write_text(content)
    data = collect_linux(root, "fictional", CLOCK, True, synthetic=True)
    assert data["facts"]["kernel.aslr"]["quality"] == "unavailable"
    assert data["facts"]["ssh.config_mode"]["quality"] == "unavailable"


def test_linux_bad_encoding(tmp_path: Path) -> None:
    """Malformed SSH bytes are not partially interpreted; errors are not disclosed as raw content."""
    root = fixture_root(tmp_path)
    (root / "etc/ssh/sshd_config").write_bytes(b"\xff")
    data = collect_linux(root, "fictional", CLOCK, True, synthetic=True)
    assert data["facts"]["ssh.password_auth"]["value"] is None


def test_collection_requires_ack(tmp_path: Path) -> None:
    """No file read is attempted until the caller explicitly acknowledges the authorized tree."""
    with pytest.raises(Rejected):
        collect_linux(tmp_path, "fictional", CLOCK, False)


def test_collector_refuses_links(tmp_path: Path) -> None:
    """Follow neither file links nor linked parent directories; skip only if the OS denies link creation."""
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("OS does not grant test process symbolic-link creation")
    with pytest.raises(Rejected):
        authorized_path(link, "etc/ssh/sshd_config")


@pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell 7 is required for collector execution"
)
@pytest.mark.parametrize(
    "scenario,passes,fails,unknown",
    [("Healthy", 5, 0, 0), ("Drifted", 1, 4, 0), ("Unknown", 0, 0, 5)],
)
def test_powershell_synthetic(
    policy: Policy, scenario: str, passes: int, fails: int, unknown: int
) -> None:
    """Execute real collector script with synthetic mode, testing GPO enum ambiguity without querying this host."""
    result = subprocess.run(
        [
            shutil.which("pwsh") or "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-HostId",
            "fictional-windows",
            "-Synthetic",
            "-Scenario",
            scenario,
            "-ObservedAt",
            "2026-10-13T14:00:00Z",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    snapshot = snapshot_data(json.loads(result.stdout))
    report = assess(policy, snapshot, CLOCK)
    assert snapshot.kind == "synthetic"
    assert (report.summary()["PASS"], report.summary()["FAIL"], report.summary()["UNKNOWN"]) == (
        passes,
        fails,
        unknown,
    )


@pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell 7 is required for collector refusal test"
)
def test_powershell_no_ack() -> None:
    """Actual-host mode refuses before calling read-only host cmdlets if acknowledgement is absent."""
    result = subprocess.run(
        [
            shutil.which("pwsh") or "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-HostId",
            "fictional",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "AcknowledgeAuthorizedHost" in result.stderr
    assert "schema" not in result.stdout


def test_no_mutating_collector_commands() -> None:
    """Guard the literal collector command list and prohibit elevation, dynamic evaluation or settings writes."""
    content = SCRIPT.read_text()
    for unsafe in (
        "Set-NetFirewall",
        "Set-Mp",
        "Set-Smb",
        "Set-Item",
        "Invoke-Expression",
        "Start-Process",
        "-Verb RunAs",
        "Invoke-Command",
        "-CimSession",
    ):
        assert unsafe not in content
    assert "-PolicyStore ActiveStore" in content
