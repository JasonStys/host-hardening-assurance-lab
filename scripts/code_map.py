"""Generate/check exact Python symbol locations in file headers. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: BEGIN — line 64
# variable: END — line 65
# variable: ROOT — line 66
# definition: mapped — line 69
# parameter: source — line 69
# variable: start — line 72
# variable: finish — line 73
# variable: source — line 74
# variable: tree — line 75
# variable: first — line 76
# variable: insertion — line 77
# variable: records — line 84
# variable: node — line 85
# variable: count — line 92
# variable: header — line 93
# parameter: item — line 97
# variable: kind — line 97
# variable: line — line 97
# variable: name — line 97
# variable: lines — line 101
# definition: main — line 106
# variable: parser — line 108
# variable: arguments — line 110
# variable: stale — line 111
# variable: folder — line 112
# variable: path — line 113
# variable: original — line 114
# variable: expected — line 115
# variable: tree — line 117
# variable: node — line 118
# variable: path — line 129
# variable: original — line 130
# variable: expected — line 131
# definition: shell_mapped — line 140
# parameter: source — line 140
# parameter: suffix — line 140
# variable: start — line 143
# variable: finish — line 144
# variable: source — line 145
# variable: lines — line 146
# variable: insertion — line 147
# variable: insertion — line 149
# variable: records — line 150
# variable: line — line 151
# variable: number — line 151
# variable: name — line 154
# variable: name — line 156
# variable: count — line 158
# variable: header — line 159
# variable: kind — line 163
# variable: name — line 163
# variable: number — line 163
# END CODE MAP

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

BEGIN = "# BEGIN CODE MAP (generated; python scripts/code_map.py)"
END = "# END CODE MAP"
ROOT = Path(__file__).resolve().parents[1]


def mapped(source: str) -> str:
    """Build a self-consistent line map for definitions, parameters and assigned variables."""
    if "\n" + BEGIN + "\n" in source:
        start = source.index("\n" + BEGIN + "\n") + 1
        finish = source.index("\n" + END + "\n", start) + len(END) + 2
        source = source[:start] + source[finish:]
    tree = ast.parse(source)
    first = tree.body[0] if tree.body else None
    insertion = (
        first.end_lineno
        if isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
        else 0
    )
    records: set[tuple[str, str, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            records.add(("definition", node.name, node.lineno))
        elif isinstance(node, ast.arg):
            records.add(("parameter", node.arg, node.lineno))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            records.add(("variable", node.id, node.lineno))
    count = len(records) + 2
    header = (
        [BEGIN]
        + [
            f"# {kind}: {name} — line {line + count if line > insertion else line}"
            for kind, name, line in sorted(records, key=lambda item: (item[2], item[0], item[1]))
        ]
        + [END]
    )
    lines = source.splitlines(keepends=True)
    lines.insert(insertion or 0, "\n".join(header) + "\n")
    return "".join(lines)


def main() -> int:
    """Update authored Python files, or fail if --check finds stale maps or missing contracts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    stale = []
    for folder in ("hardening", "scripts", "tests"):
        for path in sorted((ROOT / folder).glob("*.py")):
            original = path.read_text(encoding="utf-8")
            expected = mapped(original)
            if arguments.check:
                tree = ast.parse(original)
                for node in ast.walk(tree):
                    if isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ) and not ast.get_docstring(node):
                        raise ValueError(
                            f"Missing function/class contract: {path.name}:{node.lineno}"
                        )
            if original != expected:
                stale.append(str(path.relative_to(ROOT)))
                if not arguments.check:
                    path.write_text(expected, encoding="utf-8", newline="\n")
    for path in [*(ROOT / "scripts").glob("*.ps1"), *(ROOT / "scripts").glob("*.sh")]:
        original = path.read_text(encoding="utf-8")
        expected = shell_mapped(original, path.suffix)
        if original != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not arguments.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return 1 if arguments.check and stale else 0


def shell_mapped(source: str, suffix: str) -> str:
    """Map shell/PowerShell functions and first variable locations without executing either language."""
    if "\n" + BEGIN + "\n" in source:
        start = source.index("\n" + BEGIN + "\n") + 1
        finish = source.index("\n" + END + "\n", start) + len(END) + 2
        source = source[:start] + source[finish:]
    lines = source.splitlines(keepends=True)
    insertion = 1 if source.startswith("#!") else 0
    while insertion < len(lines) and lines[insertion].startswith("#"):
        insertion += 1
    records = {}
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for name in re.findall(r"\$([A-Za-z_][A-Za-z_0-9]*)", line):
            records.setdefault(("variable", name), number)
        for name in re.findall(r"^function ([A-Za-z0-9_-]+)", line):
            records[("function", name)] = number
    count = len(records) + 2
    header = [
        BEGIN,
        *(
            f"# {kind}: {name} — line {number + count if number > insertion else number}"
            for (kind, name), number in records.items()
        ),
        END,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
