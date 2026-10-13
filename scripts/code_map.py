"""Generate/check exact Python, shell, SQL and YAML symbol positions in headers. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: BEGIN — line 73
# variable: END — line 74
# variable: ROOT — line 75
# definition: mapped — line 78
# parameter: source — line 78
# variable: start — line 81
# variable: finish — line 82
# variable: source — line 83
# variable: tree — line 84
# variable: first — line 85
# variable: insertion — line 86
# variable: records — line 93
# variable: node — line 94
# variable: count — line 101
# variable: header — line 102
# parameter: item — line 106
# variable: kind — line 106
# variable: line — line 106
# variable: name — line 106
# variable: lines — line 110
# definition: main — line 115
# variable: parser — line 117
# variable: arguments — line 119
# variable: stale — line 120
# variable: folder — line 121
# variable: path — line 122
# variable: original — line 123
# variable: expected — line 124
# variable: tree — line 126
# variable: node — line 127
# variable: path — line 138
# variable: original — line 145
# variable: expected — line 146
# definition: shell_mapped — line 155
# parameter: source — line 155
# parameter: suffix — line 155
# variable: prefix — line 157
# variable: begin — line 158
# variable: end — line 158
# variable: start — line 160
# variable: finish — line 161
# variable: source — line 162
# variable: lines — line 163
# variable: insertion — line 164
# variable: insertion — line 166
# variable: records — line 167
# variable: line — line 168
# variable: number — line 168
# variable: name — line 171
# variable: name — line 173
# variable: name — line 176
# variable: name — line 179
# variable: name — line 181
# variable: name — line 184
# variable: name — line 186
# variable: name — line 188
# variable: count — line 190
# variable: header — line 191
# variable: kind — line 195
# variable: name — line 195
# variable: number — line 195
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
    for path in [
        *(ROOT / "scripts").glob("*.ps1"),
        *(ROOT / "scripts").glob("*.sh"),
        *(ROOT / "policies").glob("*.yml"),
        *(ROOT / ".github/workflows").glob("*.yml"),
        ROOT / "hardening/schema.sql",
    ]:
        original = path.read_text(encoding="utf-8")
        expected = shell_mapped(original, path.suffix)
        if original != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not arguments.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return 1 if arguments.check and stale else 0


def shell_mapped(source: str, suffix: str) -> str:
    """Map shell symbols, SQL columns/tables and YAML parameters/controls/expressions without execution."""
    prefix = "--" if suffix == ".sql" else "#"
    begin, end = BEGIN.replace("#", prefix, 1), END.replace("#", prefix, 1)
    if "\n" + begin + "\n" in source:
        start = source.index("\n" + begin + "\n") + 1
        finish = source.index("\n" + end + "\n", start) + len(end) + 2
        source = source[:start] + source[finish:]
    lines = source.splitlines(keepends=True)
    insertion = 1 if source.startswith("#!") else 0
    while insertion < len(lines) and lines[insertion].startswith(prefix):
        insertion += 1
    records = {}
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith(prefix):
            continue
        for name in re.findall(r"\$([A-Za-z_][A-Za-z_0-9]*)", line):
            records.setdefault(("variable", name), number)
        for name in re.findall(r"^function ([A-Za-z0-9_-]+)", line):
            records[("function", name)] = number
        if suffix == ".sh":
            for name in re.findall(r"^(?:export )?([A-Za-z_][A-Za-z_0-9]*)=", line):
                records.setdefault(("variable", name), number)
        if suffix == ".sql":
            for name in re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*) (?:TEXT|INTEGER)\b", line):
                records.setdefault(("column", name), number)
            for name in re.findall(r"CREATE TABLE (\w+)", line):
                records[("table", name)] = number
        elif suffix == ".yml":
            for name in re.findall(r"^\s*(?:- )?([A-Za-z_][A-Za-z_0-9]*):", line):
                records.setdefault(("parameter", name), number)
            for name in re.findall(r"^\s*- id: ([A-Za-z0-9_-]+)", line):
                records[("control", name)] = number
            for name in re.findall(r"\$\{\{\s*([A-Za-z0-9_.]+)\s*\}\}", line):
                records.setdefault(("expression", name), number)
    count = len(records) + 2
    header = [
        begin,
        *(
            f"{prefix} {kind}: {name} — line {number + count if number > insertion else number}"
            for (kind, name), number in records.items()
        ),
        end,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
