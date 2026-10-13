"""Maintain an exhaustive tracked-file README inventory without exposing ignored host evidence. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 31
# variable: BEGIN — line 32
# variable: END — line 33
# variable: SPECIAL — line 34
# definition: description — line 59
# parameter: path — line 59
# variable: content — line 69
# variable: summary — line 70
# definition: label — line 77
# parameter: path — line 77
# definition: main — line 82
# variable: parser — line 84
# variable: args — line 86
# variable: files — line 87
# variable: rows — line 95
# variable: path — line 98
# variable: path — line 100
# variable: original — line 101
# variable: first — line 102
# variable: last — line 102
# variable: expected — line 103
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "<!-- BEGIN FILE GUIDE -->"
END = "<!-- END FILE GUIDE -->"
SPECIAL = {
    ".gitattributes": "Portable LF text handling; SQLite outputs are binary.",
    ".gitignore": "Keeps environments, keys, output reports and private host evidence out of Git.",
    "LICENSE": "MIT license for authored source and synthetic fixtures.",
    "pyproject.toml": "Runtime metadata, strict typing, lint and branch-inclusive coverage gates.",
    "requirements-runtime.in": "Minimal reviewed runtime dependency.",
    "requirements-runtime.lock": "Hash-locked portable runtime dependency graph.",
    "requirements-dev.in": "Reviewed direct validation and audit dependencies.",
    "requirements-dev.lock": "Complete hash-locked development dependency graph.",
    "tools.lock.json": "Official scanner release URLs and verified SHA-256 digests.",
    "policies/baseline.yml": "Ten authored Windows/Linux controls, weights, freshness and review guidance.",
    "hardening/schema.sql": "STRICT normalized SQLite report schema and status index.",
    "scripts/collect-windows.ps1": "Opt-in read-only cmdlet collector with host-isolated synthetic scenarios.",
    "scripts/check-powershell.ps1": "PowerShell syntax and read-only command AST allowlist gate.",
    "scripts/collect-linux.sh": "Quoted wrapper for opt-in read-only Linux file evidence collection.",
    "scripts/validate.sh": "Portable fail-fast quality, synthetic tests, scenario and benchmark gates.",
    ".github/workflows/ci.yml": "Four OS/Python validation lanes, ephemeral worker probe and security gates; no uploads/caches.",
    ".github/workflows/codeql.yml": "Least-privilege Python security-extended CodeQL analysis.",
    "examples/exceptions.json": "Explicit fictional host/control/policy deviation with one-day expiry.",
    "docs/reports/demo.html": "Escaped, inert synthetic Linux drift report; no real host evidence.",
    "docs/reports/demo.json": "Deterministic synthetic report with policy/snapshot digests and exception details.",
    "docs/reports/benchmark.json": "Measured local in-memory throughput with scope and environment, not a capacity guarantee.",
}


def description(path: str) -> str:
    """Require a meaningful purpose for every tracked file; unknown formats are errors rather than omissions."""
    if path in SPECIAL:
        return SPECIAL[path]
    if path.startswith("examples/") and path.endswith(".json"):
        return (
            "Fictional "
            + Path(path).stem.replace("-", " ")
            + " configuration evidence; no private host data."
        )
    content = (ROOT / path).read_text(encoding="utf-8")
    if path.endswith(".py") and (summary := ast.get_docstring(ast.parse(content))):
        return summary.splitlines()[0]
    if path.endswith(".md"):
        return content.splitlines()[0].lstrip("# ") + "."
    raise ValueError(f"Missing tracked-file summary: {path}")


def label(path: str) -> str:
    """Escape underscores for readable Markdown labels while leaving file-link targets unchanged."""
    return path.replace("_", "\\_")


def main() -> int:
    """Generate/check only README's marked inventory after intended source has been staged with Git."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if files == [""]:
        raise ValueError("Stage intended files before generating the guide")
    rows = ["| File | Purpose |", "| --- | --- |"]
    rows.extend(
        f"| [{label(path)}]({path}) | {description(path).replace('|', '/')} |"
        for path in sorted(files)
    )
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    first, last = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:first] + "\n\n" + "\n".join(rows) + "\n\n" + original[last:]
    if args.check:
        if expected != original:
            raise SystemExit("README file guide is stale; stage files and regenerate")
    else:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README inventory current: {len(files)} tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
