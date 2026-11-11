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
| Bootstrap resilience | Offline transport/HTTP retries, maximum attempts, partial-byte discard, size limits, permanent error/overwrite refusal and resource closure |

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

Actions matrix: Ubuntu Python 3.12 and 3.14; Windows/macOS 15 Intel Python 3.14. The explicit standard macOS Intel pool preserves all tests while avoiding the ARM64 capacity constraint observed in the initial follow-up run. Windows also runs an explicitly acknowledged read-only disposable-worker collector and validates the normalized contract; no real-user host state is inspected or published. CI stores logs/job summaries only, not artifacts/caches.

## Measured evidence and gaps

See [validation report](reports/validation.md) for dated measured outcomes and exact commit/run links, and [benchmark](reports/benchmark.json) for environment/scope. Core coverage does not measure completeness of OS security controls; CLI module subprocess coverage may differ across coverage runtimes.

No real production host, full Windows domain/GPO deployment, multi-tenant service, encryption-at-rest service, full SSH parser or automatic remediation is tested/claimed. Windows permission/OS cmdlet variation and alternate antivirus remain operational review points. Hosted worker checks validate contracts, not security of every supported OS release.


## Native workbench validation

New project-adapter tests call actual core functions and SQLite exports with independent known fixture oracles. Storage tests exercise one-owner profiles, unknown/incompatible state, safe paths, quotas, transactions, BLOB hashes, stale-confirmation rejection and non-reused run identities. Presentation-adapter tests replace only OS widgets/dialog acquisition while keeping core/storage/thread work real. An actual Windows frozen executable separately instantiates the same Tk widgets/mainloop and runs the actual controls against an explicitly synthetic profile; no result/API is mocked.

`python scripts/build_native.py` requires an isolated patched CPython3.14.10 build environment and exact native lock. `python scripts/test_native_app.py` tests the resulting EXE with no Python/Node on its child PATH and no provider/account environment, validates independent domain oracles and exact private export, checks normal owned-process disappearance and starts a second process to prove exact retained bundle hashes. Screenshots capture only its owned synthetic window. This is not independent OS accessibility automation, populated real-user upgrade or signing proof. Existing coverage, benchmark, property, cross-platform, security-extended CodeQL and dependency/secret/configuration/workflow gates remain mandatory. No artifact/cache uploads were added.

[Actual native candidate observations](reports/native-application-2026-11-10.md) are distinct from historical reports and pending hosted/release results. Do not infer a future CI pass from a local build.

[Native reader/lifecycle follow-up](reports/native-reader-boundary-2026-11-10.md) adds real opened-NUL rejection, an actual POSIX no-writer FIFO replacement child and packaged minimum-width/long-status lifecycle-control assertions. Windows FIFO skips remain explicit; all original analysis/coverage/security gates are retained.
