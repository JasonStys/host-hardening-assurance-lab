"""Generated symbol-map, README escaping and fixture reproducibility regressions. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_python_map_idempotent — line 28
# variable: source — line 30
# variable: result — line 33
# variable: lines — line 35
# variable: line — line 36
# variable: name — line 36
# definition: test_shell_map_idempotent — line 41
# variable: source — line 43
# variable: result — line 44
# variable: bash — line 47
# definition: test_markdown_filename_escape — line 51
# definition: test_fixtures_reproducible — line 56
# variable: data — line 58
# variable: name — line 58
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


def test_fixtures_reproducible() -> None:
    """Every tracked sample equals its generator, including exact canonical policy exception digest."""
    for name, data in generate().items():
        assert (Path("examples") / name).read_bytes() == canonical(data)
