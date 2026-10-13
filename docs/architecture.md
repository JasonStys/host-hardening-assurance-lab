# Architecture and ADR-001: read-only evidence before enforcement

Accepted 2026-10-13. Project author/decision owner: Jason Stys.

## Context

Configuration drift is useful evidence for security operations and DevOps. A portfolio lab must show repeatable checks and honest uncertainty without changing the developer's host, requiring privileged deployment or distributing a copyrighted benchmark as an original work.

## Decision

Use Python for a deterministic cross-platform typed evaluator, YAML for an authored configurable baseline, JSON for normalized minimal evidence, PowerShell for native Windows read-only cmdlets, Bash for a quoted Linux wrapper, SQL for indexed evidence, and inert HTML for human review. Python is appropriate for parsing, orchestration and property tests; native shell tools gather OS-specific facts without embedding platform APIs in the evaluator. A systems language would add complexity without a measured bottleneck here.

```text
owned synthetic/authorized host evidence -> strict snapshot contract ----+
authored YAML baseline ------------------> strict policy contract ------+-> assess -> JSON / HTML / SQLite
exact scoped deviations -----------------> expiry/policy validation ----+
before/after assessment (same host + policy) ------------------------------> drift
```

`contracts` is the only untrusted-input-to-domain boundary. `engine` has no network, shell, file-write or dynamic-expression execution. `collect` reads three fixed Linux artifacts; the PowerShell collector selects five properties from three Get-* cmdlets. `report` writes only a new directory. `drift` compares domain reports, not unchecked user-provided reports. CLI errors are sanitized; configuration values are deliberately visible only in local reports/stdout.

## Options and trade-offs

| Option | Benefit | Cost / decision |
| --- | --- | --- |
| Read-only snapshots + small baseline | Repeatable, portable, safe to demonstrate | Accepted; does not prove effective runtime protection |
| Automatically enforce settings | Closes drift automatically | Rejected for this lab: risks access loss, MFA breakage and service outages |
| Full CIS/STIG platform benchmark | Broader assurance coverage | Deferred: platform/version profiles, licensing, independent validation and maintenance required |
| Generic policy expression interpreter | Flexible custom rules | Rejected: unnecessary execution surface; two typed operators cover scoped controls |
| Fleet agent/backend | Centralized collection/history | Deferred: transport identity, signatures, access control, encryption and operational support required |

## Consequences and complexity

Baseline checks are O(C + F + E) time and O(C + F + E) space for controls, facts and exceptions; bounded inputs limit C/E to 100 and facts to 32. Report summaries traverse C a constant number of times. Drift builds maps in O(C); sorted presentation is O(C log C). JSON/YAML parse cost is bounded by a 128 KiB input cap and restricted structure. SQLite has an index on status/control; per-assessment storage is O(C), with indexed lookup O(log C + results). Export/render are O(C + text length).

No claim is made that Big-O predicts real elapsed time or that an in-memory benchmark measures collection/serialization throughput. See measured [benchmark](reports/benchmark.json).

## Follow-up gates

Any future enforcement requires a separate accepted ADR, explicit owner approval, tested recovery access, staging, maintenance windows, compatibility tests and rollback. A central service additionally requires authenticated collection, tenant isolation, signed evidence and private transport. Neither is authorized or implemented here.
