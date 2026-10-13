# Validation results

Measured 2026-10-13. Author: Jason Stys. This is synthetic/read-only software validation, not independent penetration testing, production approval or a host-security certification.

## Local final-source checks

Measured functional source: `2c572604cc52011f5ef22a8d548441b940fbe916`. Windows / CPython 3.14.6, isolated hash-locked environment. The subsequent report-only commit does not change this measured functional source and must independently pass both workflows before handoff.

| Gate | Observed outcome |
| --- | --- |
| pytest with warnings as errors | 148 passed, 2 skipped, 0 failures/errors; 150 collected |
| Branch-inclusive core coverage | 97.54%; required >=90% |
| Ruff lint + formatting | Passed |
| Strict mypy | Passed; 9 core source files |
| Exact symbol maps | Passed for Python, PowerShell/Bash, SQL and YAML |
| README inventory | Passed; every one of 63 tracked files summarized |
| PowerShell parse/read-only AST allowlist | Passed |
| Independent scenarios | Both platforms: 5 healthy PASS, 3 drift FAIL, 5 UNKNOWN; Linux scoped deviation 2 FAIL/1 EXCEPTED |
| Locked dependency audit | No known vulnerabilities found |
| Staged secret scans | No leaks found, redacted output |
| Browser report exercise | Correct 2 PASS/2 FAIL/1 EXCEPTED; expanded review guidance, justification/reviewer/expiry and author/contact verified |

The two local skips are OS-denied symlink creation for collector/export path tests, not disabled assertions. All corresponding tests executed successfully on hosted runners in the initial run. PowerShell execution uses synthetic scenarios; no local PC security settings were read or changed. The only real-host probe is an explicitly authorized disposable GitHub Windows worker and retains no artifact.

## Hosted evidence

Initial implementation `109869a3a3d091a01643c8944b9a3d6a47a3925e`: [Validate](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38451425664) and [CodeQL](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38451425583) completed successfully. Every OS lane ran all 135 tests without skips with 98.16% branch-inclusive coverage.

Unicode/documentation follow-up `ebd3a95630379554576859d55a450d317c4fb948`: [Validate](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38452018053) had successful Linux/Windows/security lanes (139 tests, 98.16% coverage for completed OS lanes), but the macOS job never acquired a runner and the overall run failed. Its annotation explicitly reported hosted-worker acquisition failure and ARM64 capacity constraints. [CodeQL](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38452018064) succeeded. That infrastructure-failed attempt remains visible; no test failure or history deletion is concealed.

Runner-pool mitigation `6b5bd0d2a13831c28b0958f3b616bda025b2d4ac` selected the supported standard `macos-15-intel` pool. [Validate](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38454293082) again passed Ubuntu/Windows/security, but the assigned macOS worker's PowerShell download timed out before tests began. [CodeQL](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38454292617) passed. Bounded retry and offline failure-path tests were added without relaxing checksums, TLS or any gate.

Final functional source `2c572604cc52011f5ef22a8d548441b940fbe916`: [Validate](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38455447872) and [CodeQL](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38455447920) both completed successfully on 2026-10-13. All four quality lanes and the security job succeeded. Ubuntu Python 3.12/3.14, Windows Python 3.14 and macOS 15 Intel Python 3.14 each executed **150 passing tests, no skips, 98.16% branch-inclusive core coverage**. PowerShell parsing/command guards passed everywhere and the explicitly acknowledged Windows disposable-worker probe validated its contract. The macOS official portable bundle verified successfully; offline tests exercise transient retry paths without relying on live network faults.

Security gates include complete development/runtime lock auditing, hash-verified Gitleaks history scan, Trivy HIGH/CRITICAL vulnerability/misconfiguration checks, actionlint, ShellCheck and Python security-extended CodeQL. No advisory suppressions or weakened tests are used. Zero open code-scanning alerts were returned during review.

## Performance, storage and scope

The included [benchmark](benchmark.json) measured 10,000 synthetic five-control assessments / 50,000 checks in 0.195093 seconds (51,257.47 snapshots/second) on local Windows/Python 3.14.6 during initial validation. It excludes file parsing, live collection, export and network transport. Hardware/system-load variance is expected; this is not a production capacity or latency guarantee. CI reruns and logs the same bounded workload without a flaky speed threshold.

Fresh read-only inventory at 2026-10-13T19:32:46Z: 573,383,397 account-wide artifact bytes and 7,225,387,352 cache bytes under the separate cache allowance. GitHub's refreshed billing meter showed 0.5 GB / 0.5 GB included storage (100%). These are different measurements; byte totals are not used to invent billing percentages, and account-wide changes can come from other repositories' runs. This repository reports **0 artifacts, 0 artifact bytes, 0 caches and 0 cache bytes**. Workflows keep results in logs/job summaries only. No existing runs, artifacts or caches were deleted; future cleanup needs fresh approval.

Known limits: unsigned snapshots/deviation approvals, trusted-workspace filesystem races, unencrypted local files, limited SSH declaration parsing, selected rather than complete OS hardening controls, OS/cmdlet variation and author self-review. No production deployment, host enforcement, full CIS/STIG assessment or installer is claimed. See [threat model](../security.md) and [control applicability](../controls.md).
