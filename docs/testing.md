# Risk-based validation and reproducibility

## Test strategy

The highest risks are false security confidence, unsafe collection, silently ignored evidence, mismatched host/policy comparisons, expired approvals and exposure/injection through reports. Tests emphasize those boundaries before throughput or cosmetic output.

| Layer | Representative coverage |
| --- | --- |
| Unit/contracts | Exact fields/types, bounds, identifiers, timestamps, duplicate JSON/YAML, unsafe tags, aliases, depth/nonfinite values |
| Independent oracle | Two platforms with 5 PASS, 3 known FAIL, all UNKNOWN; explicit expected mutation counts separate from implementation |
| Property-based | POSIX octal permission oracle, Windows boolean expectation map, arbitrary bounded SSH text |
| Boundaries | Freshness at limit/+1 second, future evidence, exact exception start/expiry, wrong host/policy, max duration, zero applicable checks |
| Drift | Regression/restoration/gap/deviation/evidence changes; wrong host/platform/policy/chronology/control set rejection |
| Collectors | Owned temporary Linux trees, SSH first-wins/Include/Match/alias/syntax uncertainty, PowerShell synthetic healthy/drift/unknown, no-ack refusal |
| Security | XSS escaping/CSP, parameterized SQLite with CHECK constraints, linked path refusal, overwrite preservation, read-only PowerShell AST command allowlist |
| Integration/E2E | Real `python -m hardening` subprocess, CLI exits/output, JSON/HTML/SQLite export, cross-platform PowerShell execution |
| Performance | 10,000 snapshots / 50,000 checks; in-memory elapsed time only; no flaky hardware-dependent throughput gate |
| CI/supply chain | Hash installation, Ruff, strict mypy, exact symbol maps, exhaustive README inventory, advisory/history/config scans, CodeQL |

Hypothesis uses its bounded default example count (100 per property here), with shrinking/replay of failures. This is not exhaustive fuzzing of all OS parsers. A source guard cannot independently prove scripts harmless; it complements command AST validation and human review.

## Reproduce

Install the development lock, then run `bash scripts/validate.sh` plus the PowerShell syntax guard. Native Windows equivalents (without Bash/activation) are:

```powershell
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m mypy
.venv\Scripts\python.exe scripts/code_map.py --check
.venv\Scripts\python.exe scripts/file_guide.py --check
.venv\Scripts\python.exe -m pytest -q --cov=hardening --cov-report=term-missing --cov-report=json:out/coverage.json --junitxml=out/junit.xml -W error
.venv\Scripts\python.exe -m scripts.scenarios
.venv\Scripts\python.exe -m scripts.benchmark
pwsh -NoProfile -File scripts/check-powershell.ps1
```

Core tests run with warnings as errors and minimum **90% branch-inclusive** coverage. PowerShell 7 absence explicitly skips its four execution tests, but CI separately requires PowerShell parsing on every OS, so no hosted lane silently omits the language. Symlink tests skip only where OS permission denies creating links; Linux/macOS CI must execute them. Every expected insecure sample is asserted by a test rather than masking CLI exit 1.

Actions matrix: Ubuntu Python 3.12 and 3.14; Windows/macOS Python 3.14. Windows also runs an explicitly acknowledged read-only disposable-worker collector and validates the normalized contract; no real-user host state is inspected or published. CI stores logs/job summaries only, not artifacts/caches.

## Measured evidence and gaps

See [validation report](reports/validation.md) for dated measured outcomes and exact commit/run links, and [benchmark](reports/benchmark.json) for environment/scope. Core coverage does not measure completeness of OS security controls; CLI module subprocess coverage may differ across coverage runtimes.

No real production host, full Windows domain/GPO deployment, multi-tenant service, encryption-at-rest service, full SSH parser or automatic remediation is tested/claimed. Windows permission/OS cmdlet variation and alternate antivirus remain operational review points. Hosted worker checks validate contracts, not security of every supported OS release.
