# Expected inventory and evidence refresh

Created by Jason Stys. `fleet` helps platform owners and auditors answer which **expected** hosts have usable selected baseline evidence, who should refresh it, and which observed deviations need review. It reads files only. It does not discover machines, collect live facts, change configuration, or certify a fleet.

Declare 1–500 pseudonymous hosts in a schema-1 inventory (`examples/fleet-inventory.json`): `host_id`, `platform` (`linux`/`windows`), and an accountable `owner` team. Supply at most one explicit snapshot per host. A missing host remains in the denominator as one UNKNOWN per applicable control. Unexpected hosts, duplicate snapshots, duplicate IDs and mismatched platforms are rejected; there is no implicit newest-snapshot selection.

```bash
mkdir -p out
python -m hardening fleet --inventory examples/fleet-inventory.json --snapshot examples/linux-healthy.json --snapshot examples/windows-drifted.json --as-of 2026-10-13T14:00:00Z --out out/fleet-demo
```

The synthetic payments/dispatch/warehouse inventory intentionally yields **7 PASS, 3 FAIL and 5 UNKNOWN** across three expected hosts and two supplied snapshots. Exit 1 signals review is needed, while still saving `fleet.json` and `fleet.html`. The HTML provides an escaped offline evidence-refresh table and full assessment/deviation details. Exit 0 requires every expected selected control to pass; exit 2 rejects input/output. The output parent must exist and destination must be new.

Each run uses one explicitly chosen `--policy` (default `policies/baseline.yml`) and one evaluation clock. Counts are grouped by platform and exact semantic policy digest; no cross-platform weighted average is invented. Each assessed host retains its full original report, snapshot digest, collection provenance, policy digest and freshness boundary. Run different baselines separately instead of combining incomparable pass percentages.

The refresh queue routes missing, stale, future, denied, unsupported or ambiguous evidence to its declared owner, with the underlying reason and control guidance. Its freshness boundary is the snapshot timestamp plus the policy age limit; freshness is inclusive at that instant. A missing snapshot has no trustworthy collection timestamp, so its queue boundary is the explicit evaluation clock. Future evidence requires checking clock/source integrity, not assuming it is fresh. Queue actions are guidance for an authorized owner, not commands executed by the tool.

FAIL and EXCEPTED results appear in a separate deviation queue. Optional `--exceptions` uses the existing exact host/control/policy contract; active exception details include expiry for renewal or remediation review. An exception cannot conceal unknown evidence and is never counted as PASS. Team names and exception reviewers are local assertions, not authenticated identities. The inventory's completeness is the submitter's responsibility; undeclared hosts cannot be assessed.

Keep real inventories/reports private and outside Git. No report uploads, external assets, scripts or telemetry are added. JSON preserves original per-host assessment details; HTML is inert and escaped. Inputs remain bounded by the existing regular-file readers. Aggregation is O(hosts × controls + snapshots + exceptions per host); the declared bounds are 500 hosts and 100 policy controls. Existing single-host JSON/HTML/SQLite exports remain available through `assess`.
