# Threat model, privacy and residual risk

## Assets and boundaries

Assets: truthful assurance status, host configuration confidentiality, prior evidence integrity and source supply-chain integrity. Untrusted boundaries: file bytes, JSON/YAML values, user-selected paths and configuration text. Trusted boundary: reviewed source/schema, installed Python/PowerShell, owned non-concurrently modified workspace and authenticated operator. Core assessment/report generation is offline; dependency/scanner installation and CI advisory feeds require network access.

## Controls implemented

- No remote scanner, arbitrary subprocess from policy, dynamic SQL identifier, remediation execution, collection of credentials or configuration upload.
- Explicit collection acknowledgement; synthetic mode independent of actual host queries; live collectors restricted to their actual OS and fixed fields/paths.
- Bounded regular-file reads; final input symlink/junction refusal and OS no-follow where available. Collector/export paths reject linked ancestors too. No ownership/sandbox guarantee is implied.
- Exact JSON/YAML contracts, duplicate/merge/alias/unsafe-tag rejection, finite numbers, UTC clocks and exact bool/int distinctions.
- Missing/stale/future/ambiguous evidence cannot pass or be waived. Deviations bind to exact host/control/policy with expiry and are visibly non-PASS.
- Report outputs use a new private directory; SQLite uses trusted schema and bound values. Connections are explicitly closed; partial failures do not erase prior evidence.
- All HTML text is escaped. A hash-authorized static style and deny-by-default meta CSP prevent scripts, automatic connections, frames, objects and form submissions within the report. No ads, tracking, remote assets or executable report payloads are present. Contact links navigate only when clicked.
- Least-privilege SHA-pinned Actions, no checkout credential persistence, hashed dependency locks, advisory auditing, Git history secret scan, Trivy HIGH/CRITICAL gates, workflow/shell checks and CodeQL security-extended.

## Limits that matter

A compromised host/operator can lie in snapshots or forge local exception approvals. Digests identify semantics, **not authenticity**. Filesystem path checks are defense-in-depth, not a complete cross-platform race-proof sandbox. Use a trusted parent with no hostile concurrent writers. Windows directory mode 0700 is not a Windows ACL enforcement guarantee; use OS/organizational private storage controls. Input ancestors for explicitly selected policy/snapshot files are not all checked by the generic regular-file reader; do not use untrusted mounted workspaces.

SQLite/JSON/HTML are not encrypted. Anyone with access to local files/stdout can read configuration evidence. Git ignores are not a data-loss-prevention system and can be overridden. Do not force-add real snapshots, reports, credentials or sensitive source labels. The public samples are fictional only. CI worker probes are allowlisted, pseudonymous, disposable GitHub worker data with no retained artifact uploads.

A CSP meta tag cannot guarantee protection against a hostile browser, injected extension, altered report file or a host server that replaces content. If serving reports in a real web service, implement authenticated access, TLS, restrictive HTTP CSP including `frame-ancestors`, retention, logging/privacy policy and authorization before exposure. This repository is an offline CLI/evidence lab, not a secure multi-tenant application.

The small policy is not complete vulnerability/configuration scanning, actual filtering verification, effective SSH state, legal compliance or an ATO. Author self-review and synthetic/property tests are not independent penetration testing. No perfect security claim is made.

## Approval boundaries

This build does not change this PC, other repositories, Docker, account permissions or security settings. Hosting, fleet deployment, enforcement and GitHub Actions data deletion require separate authorization. Actions summaries are diagnostic evidence, not authorization to act on hosts. See [SECURITY.md](../SECURITY.md) for responsible reporting.
