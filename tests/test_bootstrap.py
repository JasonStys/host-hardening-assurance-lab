"""Offline portable worker archive checksum/path isolation tests. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: make_archive — line 35
# parameter: name — line 35
# parameter: path — line 35
# variable: archive — line 37
# variable: member — line 38
# definition: test_verified_archive — line 44
# parameter: tmp_path — line 44
# variable: archive — line 46
# variable: digest — line 47
# variable: directory — line 48
# definition: test_archive_tamper — line 54
# parameter: tmp_path — line 54
# variable: archive — line 56
# definition: test_archive_traversal — line 63
# parameter: tmp_path — line 63
# variable: archive — line 65
# variable: digest — line 66
# variable: directory — line 67
# definition: test_bootstrap_not_local — line 74
# parameter: monkeypatch — line 74
# END CODE MAP

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from scripts.install_pwsh import main, unpack_verified


def make_archive(path: Path, name: str) -> str:
    """Create a tiny synthetic archive without fetching or installing PowerShell on this PC."""
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = 4
        archive.addfile(member, io.BytesIO(b"test"))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_archive(tmp_path: Path) -> None:
    """Correct digest permits a regular member confined to the destination."""
    archive = tmp_path / "bundle.tar.gz"
    digest = make_archive(archive, "pwsh")
    directory = tmp_path / "bundle"
    directory.mkdir()
    unpack_verified(archive, digest, directory)
    assert (directory / "pwsh").read_bytes() == b"test"


def test_archive_tamper(tmp_path: Path) -> None:
    """Wrong digest refuses before extracting anything."""
    archive = tmp_path / "bundle.tar.gz"
    make_archive(archive, "pwsh")
    with pytest.raises(ValueError, match="checksum"):
        unpack_verified(archive, "0" * 64, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_archive_traversal(tmp_path: Path) -> None:
    """Even a digest-matching test archive cannot extract an upward-traversing path."""
    archive = tmp_path / "bundle.tar.gz"
    digest = make_archive(archive, "../escape")
    directory = tmp_path / "bundle"
    directory.mkdir()
    with pytest.raises(tarfile.FilterError):
        unpack_verified(archive, digest, directory)
    assert not (tmp_path / "escape").exists()


def test_bootstrap_not_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """Installer refuses outside GitHub's explicitly identified disposable-worker context."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(ValueError, match="disposable"):
        main()
