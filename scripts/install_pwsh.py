"""Hash-verified portable PowerShell bootstrap for disposable macOS CI workers only. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 36
# variable: MAX_BYTES — line 37
# definition: unpack_verified — line 40
# parameter: archive — line 40
# parameter: destination — line 40
# parameter: expected_digest — line 40
# variable: stream — line 44
# variable: members — line 45
# variable: m — line 46
# definition: main — line 51
# variable: architecture — line 55
# variable: lock — line 58
# variable: expected_url — line 59
# variable: directory — line 62
# variable: archive — line 63
# variable: output — line 64
# variable: response — line 64
# variable: total — line 65
# variable: chunk — line 66
# variable: total — line 67
# variable: bundle — line 71
# variable: output — line 75
# END CODE MAP

import hashlib
import json
import os
import platform
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 256 * 1024 * 1024


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
    with urllib.request.urlopen(expected_url, timeout=60) as response, archive.open("xb") as output:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_BYTES:
                raise ValueError("PowerShell download exceeds size limit")
            output.write(chunk)
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
