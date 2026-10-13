# Evidence contracts, scoring and drift

All formats are version 1 and reject unknown fields. Inputs are regular files <=128 KiB. IDs use 1–80 ASCII alphanumeric/dot/underscore/hyphen characters and start alphanumeric. Text is bounded and forbids C0/DEL characters and lone Unicode surrogates. Timestamps are exactly second-precision UTC `YYYY-MM-DDTHH:MM:SSZ`; naive dates/offset spellings are refused. Canonical JSON (sorted keys, finite numbers) binds semantic policy/snapshot digests, not signatures.

## Policy

`schema`, `id`, `max_age_seconds` (60–604800), and 1–100 `controls`. Every control has unique `id`, `platform` (`linux`/`windows`), registered `fact`, `operator`, exact-type `expected`, `weight` (1–10), `title`, `rationale`, and `review`. `equals` performs typed equality; `forbidden_bits` is only available for `ssh.config_mode`. Decimal 18 is the POSIX octal 022 group/other-write mask. Booleans are never accepted as integers. No regex, shell or expression evaluation is available to policies.

Safe YAML rejects duplicate/merge/complex keys, anchors, aliases, multiple documents, unsafe tags and depth >8. YAML boolean/date inference is still subject to the exact domain types; quote SSH string values such as `'no'`.

## Snapshot

`schema`, pseudonymous `host_id`, `platform`, `observed_at`, `kind` (`synthetic`/`authorized_read_only`), `collector`, and `facts`. Only the five registered keys for each platform are allowed, preventing accidentally recording extra host IDs/credentials. Every fact has `value`, `quality`, and a bounded `source` label. Observed facts require the exact registered string/integer/boolean type. Every other quality (`unavailable`, `unsupported`, `permission_denied`, `ambiguous`) requires null. Missing facts are valid unknown evidence.

JSON rejects duplicate keys, non-finite/overflow numeric values and malformed/deep input. Unrecognized SSH values supplied in snapshots are mismatches, not automatically remapped to security-approved values. Collectors use their own narrower accepted value vocabulary.

## Result status

| Status | Meaning | Included in denominator? |
| --- | --- | --- |
| PASS | Fresh observed fact matches the selected baseline | Yes |
| FAIL | Fresh observed fact does not match | Yes |
| UNKNOWN | Missing, unsupported, inaccessible, ambiguous, stale or future evidence | Yes |
| EXCEPTED | Observed failure has an active exact-scope deviation | Yes; not a pass |

Freshness is inclusive at `max_age_seconds`; any future observation is unknown. A clock must be passed explicitly for assessment. Only the host's platform controls apply. A platform with no controls is rejected, not treated as an empty success.

`observed_percent = (applicable - UNKNOWN) / applicable * 100`. `weighted_pass_percent = sum(PASS weights) / sum(all applicable weights) * 100`. Zero controls are refused; the summary itself defensively supports zero denominators for library-created empty reports. These are configuration evidence metrics, not probabilities of compromise or compliance grades. Weight changes are policy changes and change the digest.

## Deviations

Exception document: `schema` and <=100 `exceptions`. Each record includes `host_id`, known `control_id`, exact `policy_digest`, `starts_at`, `expires_at`, `reason`, `approved_by`, `ticket`. Validity is positive and <=90 days; start inclusive, expiry exclusive. Duplicate host/control scopes and wrong-policy records are rejected. UNKNOWN cannot be waived. EXCEPTED exposes reason, asserted reviewer, validity and ticket in JSON/HTML/SQLite. Approval is an assertion in local data: this lab does not authenticate a reviewer or sign an exception. Protect the file using organizational approval/access controls before relying on it.

## Drift and output

Compare only same host/platform/exact policy/control set, with nondecreasing observation and evaluation timestamps. This avoids confusing policy changes with host regressions. Unknown transitions are `evidence_gap` or `evidence_restored`, never automatically labeled an improvement. Other kinds: `regression`, `baseline_restored`, `deviation_change`, `evidence_change`. Historical clocks should evaluate evidence at collection time, not make every old snapshot stale at the current time.

JSON includes schema, host/platform/policy identity, both digests, collection/evaluation clocks, origin, findings and summary. A finding retains control/title/status/reason/value/expectation/weight/source/review and optional exception detail. SQLite stores assessment identity (one row), per-control findings, JSON-encoded typed values and deviation detail. Foreign keys/status CHECK/STRICT typing and a status index protect/query local persistence. Inputs are bound SQL parameters; schema is trusted source.

Outputs are new directories under an existing trusted parent. A failed partial export remains for investigation; nothing is deleted or overwritten automatically. Stdout JSON/exit codes are stable integration surfaces: 0 all PASS, 1 any other status, 2 input/output rejection. Argparse usage errors also return 2. Drift returns 1 for regressions/evidence gaps or a non-PASS final assessment, even if an unchanged exception remains approved.
