"""Hash-verified portable PowerShell bootstrap for disposable macOS CI workers only. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 43
# variable: MAX_BYTES — line 44
# definition: download_archive — line 47
# parameter: destination — line 47
# parameter: url — line 47
# variable: attempt — line 51
# variable: partial — line 52
# variable: output — line 54
# variable: response — line 54
# variable: total — line 55
# variable: chunk — line 56
# variable: total — line 57
# definition: unpack_verified — line 76
# parameter: archive — line 76
# parameter: destination — line 76
# parameter: expected_digest — line 76
# variable: stream — line 80
# variable: members — line 81
# variable: m — line 82
# definition: main — line 87
# variable: architecture — line 91
# variable: lock — line 94
# variable: expected_url — line 95
# variable: directory — line 98
# variable: archive — line 99
# variable: bundle — line 101
# variable: output — line 105
# END CODE MAP

import hashlib
import json
import os
import platform
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 256 * 1024 * 1024


def download_archive(url: str, destination: Path) -> None:
    """Retry transient transport failures at most three times; never reuse partial bytes or bypass TLS."""
    if destination.exists():
        raise ValueError("download destination must be new")
    for attempt in range(1, 4):
        partial = destination.with_name(f"{destination.name}.attempt-{attempt}")
        try:
            with urllib.request.urlopen(url, timeout=60) as response, partial.open("xb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError("PowerShell download exceeds size limit")
                    output.write(chunk)
            partial.rename(destination)
            return
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == 3:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 3:
                raise
        finally:
            partial.unlink(missing_ok=True)
        print(f"Transient portable PowerShell download failure; retry {attempt + 1}/3")
        time.sleep(2**attempt)


def unpack_verified(archive: Path, expected_digest: str, destination: Path) -> None:
    """Verify archive bytes before safe-data extraction; reject traversal, devices and oversized expansion."""
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_digest:
        raise ValueError("PowerShell checksum mismatch; no archive content is executed")
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 1024 * 1024 * 1024:
            raise ValueError("PowerShell archive exceeds expansion limit")
        stream.extractall(destination, filter="data")


def main() -> int:
    """Install the fixed official architecture bundle under a new worker temp dir; never install system-wide."""
    if platform.system() != "Darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("bootstrap is only for disposable macOS GitHub Actions workers")
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64"}.get(platform.machine())
    if architecture is None:
        raise ValueError("unsupported macOS worker architecture")
    lock = json.loads((ROOT / "tools.lock.json").read_text())["tools"][f"pwsh-osx-{architecture}"]
    expected_url = f"https://github.com/PowerShell/PowerShell/releases/download/v{lock['version']}/powershell-{lock['version']}-osx-{architecture}.tar.gz"
    if lock["url"] != expected_url:
        raise ValueError("PowerShell source must be its pinned official release")
    directory = Path(tempfile.mkdtemp(prefix="assurance-pwsh-", dir=os.environ["RUNNER_TEMP"]))
    archive = directory / "powershell.tar.gz"
    download_archive(expected_url, archive)
    bundle = directory / "bundle"
    bundle.mkdir(mode=0o700)
    unpack_verified(archive, lock["sha256"], bundle)
    os.chmod(bundle / "pwsh", 0o700)
    with Path(os.environ["GITHUB_PATH"]).open("a", encoding="utf-8") as output:
        output.write(str(bundle) + "\n")
    print("Verified portable PowerShell bootstrap complete; no system-wide install or cache upload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
