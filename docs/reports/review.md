# Author review and release checklist

Review type: author self-review, not an independent security audit. Author: Jason Stys. Scope: typed contracts, deterministic assessment, minimal collectors, same-policy drift, local evidence reports and GitHub workflows.

Design review caught and fixed explicit database connection closure, preservation of deviation justification/reviewer/expiry in exports, refusal of live OS collection on mismatched platforms, lone Unicode surrogate/DEL rejection before UTF-8 exports, and literal rendering of double-underscore filenames in the README guide. No host hardening settings were changed to validate the project.

Release gates: complete contract/property/collector/CLI tests, warning-free validation, strict lint/types, current symbol/file maps, dependency audit, staged/history secret scans, high/critical configuration/dependency scan, workflow/shell syntax and security-extended CodeQL. Measured gate outcomes and remaining limitations belong in [validation](validation.md), not unsupported claims here.

Rollback: source can be reverted to a reviewed commit; the tool never changes host settings. Existing outputs are not overwritten, so evidence needs no automated destructive rollback. No production host/service deployment, schema migration of existing databases, billing change, artifact deletion or installer publication is part of this release. New output databases are standalone exports.

Residual risks: unsigned evidence/approval assertions, trusted-workspace path race assumption, unencrypted local outputs, OS/runtime/cmdlet variation, incomplete benchmark coverage and author—not independent—review. Acceptable for a clearly labeled synthetic/read-only portfolio lab, not sufficient for production authorization without further assessment.

## Debug record: hosted macOS runner acquisition

Expected: the full four-lane matrix runs for the Unicode/documentation follow-up. Actual: Ubuntu/Windows/security succeeded; the ARM64 macOS job remained unassigned and was canceled after provider acquisition attempts. Reproduction evidence: [run 38452018053](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38452018053), job 115485051486 had no runner name and an annotation reporting acquisition failure/capacity constraints.

Isolated cause: GitHub's macOS ARM64 hosted-worker capacity, not a failing application test. The same macOS source suite had already passed in the initial implementation; completed follow-up OS lanes ran 139 passing tests. Mitigation: use supported standard `macos-15-intel`, retain all tests/PowerShell/security gates and verify a fresh run. Prevention: explicit OS label, dual-architecture official PowerShell digests, bounded CI timeouts and transparent run evidence. No tests were relaxed, old results deleted, paid/larger runners selected or unrelated workflows altered.

## Debug record: bootstrap transport timeout

The Intel worker was acquired in [run 38454293082](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38454293082), but failed before quality tests: the official PowerShell download raised a socket timeout through `urllib.error.URLError`. Ubuntu/Windows/security and CodeQL passed. The one-shot bootstrap had no transient recovery. Fix: at most three transport/selected HTTP attempts, 2/4-second backoff, fresh partial files per attempt, unchanged TLS/byte/checksum guards, immediate permanent error refusal and HTTP resource closure. Eleven additional offline cases exercise success/retry/exhaustion/partial-read/size/overwrite paths with no network or sleeping. Warning-as-error tests caught HTTP error resource cleanup during development, which was fixed. Acceptance evidence: [run 38455447872](https://github.com/JasonStys/host-hardening-assurance-lab/actions/runs/38455447872) completed successfully, including all 150 tests on the macOS Intel worker and each other lane, security gates and successful verified bootstrap. CodeQL also passed. Previous infrastructure/transport failures remain visible in run history.
