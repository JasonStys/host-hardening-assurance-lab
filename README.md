# Host Hardening Assurance Lab

[![Validate](https://github.com/JasonStys/host-hardening-assurance-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/host-hardening-assurance-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/JasonStys/host-hardening-assurance-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/host-hardening-assurance-lab/actions/workflows/codeql.yml)

Read-only Windows/Linux baseline assurance with policy-as-code, explicit evidence quality, drift detection and expiring deviations. Created by [Jason Stys](https://github.com/JasonStys) · [LinkedIn/contact](https://www.linkedin.com/in/jason-stys-31b30b351/).

This defensive portfolio project answers: **What do we actually know about this host's configuration, what changed, and what still needs review?** It never applies hardening changes. It is a small authored baseline, not a complete CIS/STIG benchmark, certification, authorization to operate, malware scanner or proof that a host is secure.

## Features

- Ten documented platform-specific controls: SSH authentication declarations, configuration write bits, Linux ASLR, Windows firewall ActiveStore profiles, Defender reported real-time protection and SMB server v1.
- Strict typed JSON evidence and safe YAML policies. Missing, unsupported, stale, future or ambiguous evidence is **UNKNOWN**, never a guessed PASS.
- Exact host/control/policy exceptions with reason, asserted reviewer, ticket and a maximum 90-day expiry. EXCEPTED remains a deviation, not a pass, and cannot hide unknown evidence.
- Deterministic assessments with explicit evaluation clocks, semantic policy/snapshot digests, conservative weighted pass rate and separately reported evidence coverage.
- Same-host/same-policy drift separates regressions, evidence gaps/restoration, deviations and changed-but-still-passing observations.
- New-directory-only JSON, offline HTML and indexed STRICT SQLite reports. Escaped text, no scripts/ads/analytics or automatic uploads.
- Opt-in read-only collectors: Python/Bash for Linux file evidence; PowerShell 7 for five allowlisted Windows cmdlet properties. Synthetic mode does not query the host.
- Cross-platform tests, property-based checks, measured benchmarks, hash-locked dependencies, history secret scanning and security-extended CodeQL.

## Safe five-minute demo

Python 3.12–3.14 with SQLite is required. Start in the repository root. No administrator rights, Docker, host collection or settings changes are needed.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements-runtime.lock
python -m hardening assess --snapshot examples/linux-healthy.json --as-of 2026-10-13T14:00:00Z
```

On Windows you can avoid activation and use `.venv\Scripts\python.exe` instead of `python`. Activation failures do not require weakening execution policy.

Create an output parent such as `out` yourself, then generate a new evidence directory:

```bash
python -m hardening assess --snapshot examples/linux-drifted.json --as-of 2026-10-13T14:00:00Z --exceptions examples/exceptions.json --out out/demo
python -m hardening drift --before examples/linux-healthy.json --before-as-of 2026-10-13T12:00:00Z --snapshot examples/linux-drifted.json --as-of 2026-10-13T14:00:00Z
```

The first returns **2 PASS / 2 FAIL / 1 EXCEPTED** and exit 1; the second detects **3 regressions** and exit 1. These are deliberately non-compliant fixtures, not failed software tests. Exit 0 means all applicable checks pass; 1 means at least one FAIL/UNKNOWN/EXCEPTED; 2 means input/output was rejected. `--out` must be new and its parent must exist; reruns never overwrite earlier evidence.

Open `out/demo/report.html` in a browser. A public-safe [sample HTML report](docs/reports/demo.html) and [machine-readable report](docs/reports/demo.json) are included. Their fixed date is intentional: evaluating these fixtures using today's clock later will correctly make them stale.

## Collector demonstration

```powershell
pwsh -NoProfile -File scripts/collect-windows.ps1 -HostId fictional-windows -Synthetic -Scenario Healthy -ObservedAt 2026-10-13T14:00:00Z
```

Linux collection requires both `--root` and `--ack-authorized-host`. Live mode requires Linux. `--synthetic-tree` labels a fixture tree explicitly; Windows synthetic mode works with PowerShell 7 on all three CI OSes. **Do not collect real configuration without the system owner's permission.** See the [runbook](docs/runbook.md) for authorized live collection, privacy and troubleshooting.

## Validation and design

```bash
python -m pip install --require-hashes -r requirements-dev.lock
bash scripts/validate.sh
pwsh -NoProfile -File scripts/check-powershell.ps1
```

Native Windows command equivalents and measured results are in [testing](docs/testing.md) and the [validation report](docs/reports/validation.md). Actions use logs/job summaries, with **no artifact/cache uploads**.

Start with [architecture/ADR](docs/architecture.md), [contracts and scoring](docs/contracts.md), [control applicability](docs/controls.md), [threat model](docs/security.md), [research](docs/research.md), and [development guidelines](docs/development.md). Reports concern selected configuration facts only, not network filtering effectiveness, effective SSH daemon state or overall host security.

## File guide

Every tracked file is summarized below. Python, shell, SQL and YAML headers include generated exact symbol positions, enforced in CI.

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Portable LF text handling; SQLite outputs are binary. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Four OS/Python validation lanes, ephemeral worker probe and security gates; no uploads/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Least-privilege Python security-extended CodeQL analysis. |
| [.gitignore](.gitignore) | Keeps environments, keys, output reports and private host evidence out of Git. |
| [LICENSE](LICENSE) | MIT license for authored source and synthetic fixtures. |
| [README.md](README.md) | Host Hardening Assurance Lab. |
| [SECURITY.md](SECURITY.md) | Security reporting and responsible use. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR-001: read-only evidence before enforcement. |
| [docs/contracts.md](docs/contracts.md) | Evidence contracts, scoring and drift. |
| [docs/controls.md](docs/controls.md) | Control applicability and honest limitations. |
| [docs/development.md](docs/development.md) | Coding, comments and maintenance guidelines. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured local in-memory throughput with scope and environment, not a capacity guarantee. |
| [docs/reports/demo.html](docs/reports/demo.html) | Escaped, inert synthetic Linux drift report; no real host evidence. |
| [docs/reports/demo.json](docs/reports/demo.json) | Deterministic synthetic report with policy/snapshot digests and exception details. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/review.md](docs/reports/review.md) | Author review and release checklist. |
| [docs/reports/validation.md](docs/reports/validation.md) | Validation results. |
| [docs/research.md](docs/research.md) | Primary-source research and design rationale. |
| [docs/runbook.md](docs/runbook.md) | Operator runbook and help. |
| [docs/security.md](docs/security.md) | Threat model, privacy and residual risk. |
| [docs/testing.md](docs/testing.md) | Risk-based validation and reproducibility. |
| [examples/exceptions.json](examples/exceptions.json) | Explicit fictional host/control/policy deviation with one-day expiry. |
| [examples/linux-drifted.json](examples/linux-drifted.json) | Fictional linux drifted configuration evidence; no private host data. |
| [examples/linux-healthy.json](examples/linux-healthy.json) | Fictional linux healthy configuration evidence; no private host data. |
| [examples/linux-unknown.json](examples/linux-unknown.json) | Fictional linux unknown configuration evidence; no private host data. |
| [examples/windows-drifted.json](examples/windows-drifted.json) | Fictional windows drifted configuration evidence; no private host data. |
| [examples/windows-healthy.json](examples/windows-healthy.json) | Fictional windows healthy configuration evidence; no private host data. |
| [examples/windows-unknown.json](examples/windows-unknown.json) | Fictional windows unknown configuration evidence; no private host data. |
| [hardening/\_\_init\_\_.py](hardening/__init__.py) | Read-only baseline assurance, not host configuration enforcement. Created by Jason Stys. |
| [hardening/\_\_main\_\_.py](hardening/__main__.py) | Invoke the documented CLI with python -m hardening. Created by Jason Stys. |
| [hardening/cli.py](hardening/cli.py) | Assessment/drift CLI and explicitly acknowledged read-only Linux collection. Created by Jason Stys. |
| [hardening/collect.py](hardening/collect.py) | Opt-in Linux file evidence collector with conservative SSH interpretation. Created by Jason Stys. |
| [hardening/contracts.py](hardening/contracts.py) | Strict, bounded policy, snapshot and exception contracts. Created by Jason Stys. |
| [hardening/drift.py](hardening/drift.py) | Evidence-aware baseline drift without comparing incompatible hosts/policies. Created by Jason Stys. |
| [hardening/engine.py](hardening/engine.py) | Deterministic typed assessment, freshness and expiring deviations. Created by Jason Stys. |
| [hardening/io.py](hardening/io.py) | Bounded regular-file, strict JSON and safe YAML readers. Created by Jason Stys. |
| [hardening/report.py](hardening/report.py) | New-directory-only JSON, inert HTML and parameterized SQLite evidence exports. Created by Jason Stys. |
| [hardening/schema.sql](hardening/schema.sql) | STRICT normalized SQLite report schema and status index. |
| [policies/baseline.yml](policies/baseline.yml) | Ten authored Windows/Linux controls, weights, freshness and review guidance. |
| [pyproject.toml](pyproject.toml) | Runtime metadata, strict typing, lint and branch-inclusive coverage gates. |
| [requirements-dev.in](requirements-dev.in) | Reviewed direct validation and audit dependencies. |
| [requirements-dev.lock](requirements-dev.lock) | Complete hash-locked development dependency graph. |
| [requirements-runtime.in](requirements-runtime.in) | Minimal reviewed runtime dependency. |
| [requirements-runtime.lock](requirements-runtime.lock) | Hash-locked portable runtime dependency graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Measure bounded baseline evaluation throughput; results are not production capacity claims. Jason Stys. |
| [scripts/check-powershell.ps1](scripts/check-powershell.ps1) | PowerShell syntax and read-only command AST allowlist gate. |
| [scripts/code\_map.py](scripts/code_map.py) | Generate/check exact Python, shell, SQL and YAML symbol positions in headers. Created by Jason Stys. |
| [scripts/collect-linux.sh](scripts/collect-linux.sh) | Quoted wrapper for opt-in read-only Linux file evidence collection. |
| [scripts/collect-windows.ps1](scripts/collect-windows.ps1) | Opt-in read-only cmdlet collector with host-isolated synthetic scenarios. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Maintain an exhaustive tracked-file README inventory without exposing ignored host evidence. Jason Stys. |
| [scripts/fixtures.py](scripts/fixtures.py) | Generate reproducible fictional host evidence and scoped example exceptions. Created by Jason Stys. |
| [scripts/install\_pwsh.py](scripts/install_pwsh.py) | Hash-verified portable PowerShell bootstrap for disposable macOS CI workers only. Jason Stys. |
| [scripts/scenarios.py](scripts/scenarios.py) | Verify independent demo truth for pass, drift, missing/stale/future evidence and exceptions. Jason Stys. |
| [scripts/summary.py](scripts/summary.py) | Small CI job summaries without uploading Actions artifacts or sensitive telemetry. Jason Stys. |
| [scripts/tools.py](scripts/tools.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate.sh](scripts/validate.sh) | Portable fail-fast quality, synthetic tests, scenario and benchmark gates. |
| [tests/conftest.py](tests/conftest.py) | Shared synthetic contract fixtures; tests never collect this PC's settings. Created by Jason Stys. |
| [tests/test\_bootstrap.py](tests/test_bootstrap.py) | Offline portable worker archive checksum/path isolation tests. Created by Jason Stys. |
| [tests/test\_collect.py](tests/test_collect.py) | Read-only collector fixture tests, SSH ambiguity and actual PowerShell synthetic execution. Jason Stys. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Strict contract rejection, semantic hashing and YAML/JSON misuse tests. Created by Jason Stys. |
| [tests/test\_engine.py](tests/test_engine.py) | Baseline, independent oracle, property checks, freshness and exception-boundary tests. Jason Stys. |
| [tests/test\_maintenance.py](tests/test_maintenance.py) | Generated symbol-map, README escaping and fixture reproducibility regressions. Created by Jason Stys. |
| [tests/test\_report\_cli.py](tests/test_report_cli.py) | End-to-end CLI exits, inert exports, SQL persistence and path safety. Created by Jason Stys. |
| [tools.lock.json](tools.lock.json) | Official scanner release URLs and verified SHA-256 digests. |

<!-- END FILE GUIDE -->
