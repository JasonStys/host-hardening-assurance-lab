# Host Hardening Assurance Lab handbook

By Jason Stys.

Assess declared multi-host snapshots against explicit hardening policies, inspect evidence freshness and prioritize refresh work. Assessment is read-only and does not change operating-system settings or claim a compliance certification.

Review expected host inventory, unknown missing evidence, policy/platform counts and owner refresh/deviation queues.

Prevents absent hosts or stale observations from inflating assurance results.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [fleet](fleet.md)
- [runbook](runbook.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [security](security.md)
- [testing](testing.md)

## Historical results and reproduction

The reviewed source is [`53068a5cdc70f733211910afd199bb1fd4fac85e`](https://github.com/JasonStys/host-hardening-assurance-lab/tree/53068a5cdc70f733211910afd199bb1fd4fac85e). The observed functional workflow baseline is `53068a5cdc70f733211910afd199bb1fd4fac85e`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/fleet-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/host-hardening-assurance-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Completeness of the declared host inventory is the operator's responsibility.
- Each run uses one exact baseline; unlike platform counts remain separate rather than a pooled assurance score.
- Owner/reviewer labels are local assertions, not authenticated approvals or a compliance certification.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
