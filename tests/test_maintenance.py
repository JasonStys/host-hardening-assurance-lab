"""Generated symbol-map, README escaping and fixture reproducibility regressions. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_python_map_idempotent — line 33
# variable: source — line 35
# variable: result — line 38
# variable: lines — line 40
# variable: line — line 41
# variable: name — line 41
# definition: test_shell_map_idempotent — line 46
# variable: source — line 48
# variable: result — line 49
# variable: bash — line 52
# definition: test_markdown_filename_escape — line 56
# definition: test_structured_maps — line 61
# variable: sql — line 63
# variable: result — line 64
# variable: yaml — line 67
# variable: result — line 68
# definition: test_fixtures_reproducible — line 73
# variable: data — line 75
# variable: name — line 75
# END CODE MAP

import re
from pathlib import Path

from hardening.io import canonical
from scripts.code_map import mapped, shell_mapped
from scripts.file_guide import label
from scripts.fixtures import generate


def test_python_map_idempotent() -> None:
    """Adding/regenerating a header neither shifts mappings again nor removes the module contract."""
    source = (
        '"""Example file contract."""\nx = 1\ndef f(arg):\n    """Return arg."""\n    return arg\n'
    )
    result = mapped(source)
    assert mapped(result) == result
    lines = result.splitlines()
    for name, line in re.findall(r"# definition: (\w+) — line (\d+)", result):
        assert lines[int(line) - 1].startswith(f"def {name}(")
    assert "# parameter: arg" in result


def test_shell_map_idempotent() -> None:
    """PowerShell variable/function positions stay exact and Bash shebang remains first."""
    source = "# Description\nparam([string]$Name)\nfunction Test-Example { param($Value) }\n"
    result = shell_mapped(source, ".ps1")
    assert shell_mapped(result, ".ps1") == result
    assert "# function: Test-Example" in result and "# variable: Name" in result
    bash = shell_mapped("#!/usr/bin/env bash\n# Contract\nset -eu\n", ".sh")
    assert bash.startswith("#!/usr/bin/env bash\n")


def test_markdown_filename_escape() -> None:
    """Double-underscore entrypoints must render as literal filenames rather than bold Markdown."""
    assert label("hardening/__main__.py") == "hardening/\\_\\_main\\_\\_.py"


def test_structured_maps() -> None:
    """SQL/YAML symbols get exact comment syntax and self-consistent line numbers without content execution."""
    sql = "-- Purpose\nCREATE TABLE finding (\n id INTEGER PRIMARY KEY, value TEXT\n);\n"
    result = shell_mapped(sql, ".sql")
    assert shell_mapped(result, ".sql") == result
    assert "-- table: finding" in result and "-- column: value" in result
    yaml = "# Purpose\nschema: 1\ncontrols:\n  - id: LNX-EXAMPLE\n"
    result = shell_mapped(yaml, ".yml")
    assert shell_mapped(result, ".yml") == result
    assert "# parameter: schema" in result and "# control: LNX-EXAMPLE" in result


def test_fixtures_reproducible() -> None:
    """Every tracked sample equals its generator, including exact canonical policy exception digest."""
    for name, data in generate().items():
        assert (Path("examples") / name).read_bytes() == canonical(data)
