# Coding, comments and maintenance guidelines

Created by Jason Stys. Prefer small explicit modules, meaningful identifiers, dataclass contracts, exact types and readable control flow. Policy constants/limits make assumptions visible. Favor measured simplicity over premature optimization. Weighted scores are not security probabilities, and Big-O estimates supplement—not replace—timings.

Every Python file has a purpose docstring, function/class contract docstrings, typed parameters and a generated header mapping definitions, parameters and assigned variables to exact lines. PowerShell/Bash headers document purpose/parameters and generated symbol positions; PowerShell functions also contain help/parameter explanations. SQL/YAML headers map columns/tables and policy/workflow parameters/control IDs/expressions to exact positions. Use comments to label safety boundaries and non-obvious semantics, not repeat each statement. Run formatting **before** generating maps; CI rejects stale maps or missing Python function/class contracts.

```bash
python -m ruff check --fix .
python -m ruff format .
python scripts/code_map.py
git add <reviewed source files>
python scripts/file_guide.py
```

The README inventory is Git-backed and summarizes every tracked file. New unrecognized file types require an explicit summary. Generated headers and synthetic outputs are the only mechanical rewrites; source edits should remain focused and independently reviewable. Do not publish local environments or ignored private evidence.

Dependency maintenance: review direct `.in` pins, use `pip-tools==7.6.2` in an isolated maintainer environment to regenerate complete `--generate-hashes --allow-unsafe --strip-extras` locks, audit every transitive package, then rerun all platform CI. Runtime installation has only PyYAML; development tools are not production dependencies. Scanner locks constrain official release URL and SHA-256 before one regular binary is extracted. A compromised source/lock review remains a risk; hashes do not authenticate an unreviewed change.

Policy maintenance: review applicability and cited semantics, update tests/oracles, regenerate fictional exceptions to match the new semantic digest, and review intentional fixture differences. Never change expectations or ignore security advisories just to make CI green. New facts/operators require strict boundary validation, collection/privacy review, documentation and negative/property tests.

macOS hosted workers bootstrap a portable official PowerShell 7.6.6 bundle into a new worker temporary directory, verified against GitHub release SHA-256 for x64/arm64 before safe-data tar extraction. This is not a system-wide installation, user-PC install or persisted cache. Offline tests verify checksum and traversal refusal. Windows/Ubuntu workers use their preinstalled PowerShell.

Release practice: inspect source diff, secret scan staged/history content, verify exact main commit in both workflows, update measured reports, then repeat checks for the documentation commit. Do not add CI artifact/cache uploads without reviewing account storage and purpose. No release installer/privileged daemon is needed for this CLI lab.
