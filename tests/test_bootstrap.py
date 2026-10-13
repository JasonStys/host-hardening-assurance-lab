"""Offline portable worker archive checksum/path isolation tests. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: make_archive — line 75
# parameter: name — line 75
# parameter: path — line 75
# variable: archive — line 77
# variable: member — line 78
# definition: test_verified_archive — line 84
# parameter: tmp_path — line 84
# variable: archive — line 86
# variable: digest — line 87
# variable: directory — line 88
# definition: test_archive_tamper — line 94
# parameter: tmp_path — line 94
# variable: archive — line 96
# definition: test_archive_traversal — line 103
# parameter: tmp_path — line 103
# variable: archive — line 105
# variable: digest — line 106
# variable: directory — line 107
# definition: test_bootstrap_not_local — line 114
# parameter: monkeypatch — line 114
# definition: test_download_retries_transport — line 124
# parameter: failure — line 125
# parameter: monkeypatch — line 125
# parameter: tmp_path — line 125
# variable: fetch — line 128
# variable: pause — line 129
# variable: destination — line 132
# definition: test_download_retries_transient_http — line 141
# parameter: monkeypatch — line 142
# parameter: status — line 142
# parameter: tmp_path — line 142
# variable: fetch — line 145
# variable: destination — line 150
# definition: test_download_refuses_permanent_http — line 157
# parameter: monkeypatch — line 158
# parameter: status — line 158
# parameter: tmp_path — line 158
# variable: fetch — line 161
# definition: test_download_exhaustion — line 169
# parameter: monkeypatch — line 169
# parameter: tmp_path — line 169
# variable: fetch — line 171
# variable: pause — line 172
# variable: call — line 178
# definition: test_download_discards_partial — line 182
# parameter: monkeypatch — line 182
# parameter: tmp_path — line 182
# variable: interrupted — line 184
# variable: fetch — line 186
# variable: destination — line 189
# definition: test_download_size_limit — line 196
# parameter: monkeypatch — line 196
# parameter: tmp_path — line 196
# variable: fetch — line 198
# definition: test_download_refuses_existing — line 207
# parameter: tmp_path — line 207
# variable: destination — line 209
# END CODE MAP

import hashlib
import io
import tarfile
import urllib.error
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import install_pwsh
from scripts.install_pwsh import download_archive, main, unpack_verified


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


@pytest.mark.parametrize(
    "failure", [TimeoutError(), urllib.error.URLError("offline"), ConnectionError()]
)
def test_download_retries_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """A transient transport error retries a fresh bounded stream without network or actual sleeping."""
    fetch = Mock(side_effect=[failure, io.BytesIO(b"verified-later")])
    pause = Mock()
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    monkeypatch.setattr(install_pwsh.time, "sleep", pause)
    destination = tmp_path / "download.gz"
    download_archive("https://example.invalid/test", destination)
    assert destination.read_bytes() == b"verified-later"
    assert fetch.call_count == 2
    pause.assert_called_once_with(2)
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("status", [429, 503])
def test_download_retries_transient_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """Rate limiting and service unavailability retry, preserving the successful bytes exactly."""
    fetch = Mock(
        side_effect=[urllib.error.HTTPError("test", status, "test", {}, None), io.BytesIO(b"ok")]
    )
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    monkeypatch.setattr(install_pwsh.time, "sleep", Mock())
    destination = tmp_path / "download.gz"
    download_archive("https://example.invalid/test", destination)
    assert destination.read_bytes() == b"ok"
    assert fetch.call_count == 2


@pytest.mark.parametrize("status", [403, 404])
def test_download_refuses_permanent_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """Permission denial and a missing pinned release fail immediately rather than hiding bad configuration."""
    fetch = Mock(side_effect=urllib.error.HTTPError("test", status, "test", {}, None))
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    with pytest.raises(urllib.error.HTTPError):
        download_archive("https://example.invalid/test", tmp_path / "download.gz")
    assert fetch.call_count == 1
    assert not list(tmp_path.iterdir())


def test_download_exhaustion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhausted transient failures stop after three attempts and leave no partial archive."""
    fetch = Mock(side_effect=TimeoutError())
    pause = Mock()
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    monkeypatch.setattr(install_pwsh.time, "sleep", pause)
    with pytest.raises(TimeoutError):
        download_archive("https://example.invalid/test", tmp_path / "download.gz")
    assert fetch.call_count == 3
    assert [call.args for call in pause.call_args_list] == [(2,), (4,)]
    assert not list(tmp_path.iterdir())


def test_download_discards_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A mid-stream timeout cannot splice incomplete old bytes into a successful retry."""
    interrupted = io.BytesIO()
    monkeypatch.setattr(interrupted, "read", Mock(side_effect=[b"wrong-prefix", TimeoutError()]))
    fetch = Mock(side_effect=[interrupted, io.BytesIO(b"complete")])
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    monkeypatch.setattr(install_pwsh.time, "sleep", Mock())
    destination = tmp_path / "download.gz"
    download_archive("https://example.invalid/test", destination)
    assert destination.read_bytes() == b"complete"
    assert interrupted.closed
    assert list(tmp_path.iterdir()) == [destination]


def test_download_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An oversized stream is a validation failure, not retryable, and partial bytes are removed."""
    fetch = Mock(return_value=io.BytesIO(b"oversized"))
    monkeypatch.setattr(install_pwsh.urllib.request, "urlopen", fetch)
    monkeypatch.setattr(install_pwsh, "MAX_BYTES", 2)
    with pytest.raises(ValueError, match="size limit"):
        download_archive("https://example.invalid/test", tmp_path / "download.gz")
    assert fetch.call_count == 1
    assert not list(tmp_path.iterdir())


def test_download_refuses_existing(tmp_path: Path) -> None:
    """The bootstrap helper cannot overwrite an existing destination."""
    destination = tmp_path / "download.gz"
    destination.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="must be new"):
        download_archive("https://example.invalid/test", destination)
    assert destination.read_bytes() == b"preserve"
