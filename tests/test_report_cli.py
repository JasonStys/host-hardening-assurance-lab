"""End-to-end CLI exits, inert exports, SQL persistence and path safety. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: CLOCK — line 63
# definition: test_report_bundle — line 66
# parameter: policy — line 66
# parameter: tmp_path — line 66
# variable: report — line 68
# variable: directory — line 69
# variable: data — line 71
# variable: connection — line 73
# definition: test_html_escape_and_csp — line 84
# parameter: policy — line 84
# variable: report — line 86
# variable: payload — line 87
# variable: finding — line 88
# variable: output — line 89
# definition: test_export_no_overwrite — line 97
# parameter: policy — line 97
# parameter: tmp_path — line 97
# variable: report — line 99
# variable: directory — line 100
# variable: original — line 102
# definition: test_export_link_parent — line 110
# parameter: policy — line 110
# parameter: tmp_path — line 110
# variable: link — line 112
# variable: report — line 117
# definition: test_cli_assess_exit — line 125
# parameter: capsys — line 125
# parameter: expected — line 125
# parameter: fixture — line 125
# variable: result — line 127
# variable: captured — line 136
# definition: test_cli_exports — line 145
# parameter: capsys — line 145
# parameter: tmp_path — line 145
# definition: test_cli_drift — line 166
# parameter: capsys — line 166
# definition: test_cli_collect_empty_tree — line 187
# parameter: capsys — line 187
# parameter: tmp_path — line 187
# variable: args — line 189
# definition: test_module_entrypoint — line 196
# variable: result — line 198
# END CODE MAP

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from hardening.cli import main
from hardening.contracts import Policy, load_snapshot, timestamp
from hardening.engine import assess
from hardening.io import Rejected
from hardening.report import export, render

CLOCK = timestamp("2026-10-13T14:00:00Z")


def test_report_bundle(policy: Policy, tmp_path: Path) -> None:
    """Persist the actual report through JSON and normalized STRICT SQLite, with no interpolated SQL values."""
    report = assess(policy, load_snapshot(Path("examples/linux-drifted.json")), CLOCK)
    directory = tmp_path / "report"
    export(report, directory)
    data = json.loads((directory / "report.json").read_text())
    assert data["summary"]["FAIL"] == 3
    with closing(sqlite3.connect(directory / "evidence.sqlite")) as connection, connection:
        assert (
            connection.execute("SELECT count(*) FROM finding WHERE status='FAIL'").fetchone()[0]
            == 3
        )
        assert connection.execute("SELECT host_id FROM assessment").fetchone()[0] == "lab-linux-01"
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE finding SET status='PASS_WITHOUT_PROOF'")
    assert "Jason Stys" in (directory / "report.html").read_text()


def test_html_escape_and_csp(policy: Policy) -> None:
    """Data cannot inject script/HTML; renderer contains no script, frame, remote asset or telemetry tags."""
    report = assess(policy, load_snapshot(Path("examples/linux-healthy.json")), CLOCK)
    payload = "<img src=x onerror=alert(1)><script>alert(1)</script>"
    finding = replace(report.findings[0], title=payload, source=payload, review=payload)
    output = render(replace(report, findings=(finding,)))
    assert "<script" not in output and "<img" not in output
    assert "&lt;script&gt;" in output
    assert "default-src &#x27;none&#x27;" in output
    assert "sha256-" in output
    assert "<iframe" not in output and "<form" not in output


def test_export_no_overwrite(policy: Policy, tmp_path: Path) -> None:
    """Existing evidence remains byte-identical after a refused export attempt."""
    report = assess(policy, load_snapshot(Path("examples/linux-healthy.json")), CLOCK)
    directory = tmp_path / "report"
    export(report, directory)
    original = (directory / "report.json").read_bytes()
    with pytest.raises(Rejected):
        export(report, directory)
    assert (directory / "report.json").read_bytes() == original
    with pytest.raises(Rejected):
        export(report, tmp_path / "missing-parent" / "report")


def test_export_link_parent(policy: Policy, tmp_path: Path) -> None:
    """Report export cannot traverse a symlinked ancestor into another directory."""
    link = tmp_path / "linked"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("OS does not grant test process symbolic-link creation")
    report = assess(policy, load_snapshot(Path("examples/linux-healthy.json")), CLOCK)
    with pytest.raises(Rejected):
        export(report, link / "report")


@pytest.mark.parametrize(
    "fixture,expected", [("healthy", 0), ("drifted", 1), ("unknown", 1), ("missing", 2)]
)
def test_cli_assess_exit(fixture: str, expected: int, capsys: pytest.CaptureFixture[str]) -> None:
    """Known-good/bad/unknown/invalid inputs use distinct machine-readable exits with sanitized errors."""
    result = main(
        [
            "assess",
            "--snapshot",
            f"examples/linux-{fixture}.json",
            "--as-of",
            "2026-10-13T14:00:00Z",
        ]
    )
    captured = capsys.readouterr()
    assert result == expected
    if expected != 2:
        assert json.loads(captured.out)["schema"] == 1
    else:
        assert "rejected" in captured.err
        assert captured.out == ""


def test_cli_exports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI writes reports even for failing posture; reports are useful evidence, not only success artifacts."""
    assert (
        main(
            [
                "assess",
                "--snapshot",
                "examples/linux-drifted.json",
                "--as-of",
                "2026-10-13T14:00:00Z",
                "--exceptions",
                "examples/exceptions.json",
                "--out",
                str(tmp_path / "export"),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["summary"]["EXCEPTED"] == 1


def test_cli_drift(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI assesses two snapshots with explicit clocks and reports independently expected regression count."""
    assert (
        main(
            [
                "drift",
                "--before",
                "examples/linux-healthy.json",
                "--snapshot",
                "examples/linux-drifted.json",
                "--before-as-of",
                "2026-10-13T12:00:00Z",
                "--as-of",
                "2026-10-13T14:00:00Z",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["regressions"] == 3


def test_cli_collect_empty_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Explicitly authorized empty fixture tree yields unavailable facts; absent acknowledgement refuses."""
    args = ["collect-linux", "--root", str(tmp_path), "--host-id", "fictional", "--synthetic-tree"]
    assert main(args) == 2
    capsys.readouterr()
    assert main([*args, "--ack-authorized-host"]) == 0
    assert json.loads(capsys.readouterr().out)["facts"]["kernel.aslr"]["value"] is None


def test_module_entrypoint() -> None:
    """Run the real module as users do, rather than merely calling its internal entry function."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hardening",
            "assess",
            "--snapshot",
            "examples/windows-healthy.json",
            "--as-of",
            "2026-10-13T14:00:00Z",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["PASS"] == 5
