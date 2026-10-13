# Author review and release checklist

Review type: author self-review, not an independent security audit. Author: Jason Stys. Scope: typed contracts, deterministic assessment, minimal collectors, same-policy drift, local evidence reports and GitHub workflows.

Design review caught and fixed explicit database connection closure, preservation of deviation justification/reviewer/expiry in exports, refusal of live OS collection on mismatched platforms, and literal rendering of double-underscore filenames in the README guide. No host hardening settings were changed to validate the project.

Release gates: complete contract/property/collector/CLI tests, warning-free validation, strict lint/types, current symbol/file maps, dependency audit, staged/history secret scans, high/critical configuration/dependency scan, workflow/shell syntax and security-extended CodeQL. Measured gate outcomes and remaining limitations belong in [validation](validation.md), not unsupported claims here.

Rollback: source can be reverted to a reviewed commit; the tool never changes host settings. Existing outputs are not overwritten, so evidence needs no automated destructive rollback. No production host/service deployment, schema migration of existing databases, billing change, artifact deletion or installer publication is part of this release. New output databases are standalone exports.

Residual risks: unsigned evidence/approval assertions, trusted-workspace path race assumption, unencrypted local outputs, OS/runtime/cmdlet variation, incomplete benchmark coverage and author—not independent—review. Acceptable for a clearly labeled synthetic/read-only portfolio lab, not sufficient for production authorization without further assessment.
