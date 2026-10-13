-- Jason Stys: normalized, indexed assurance evidence; parameterized inserts in report.py.
-- Tables: assessment (identity/digests), finding (control result, evidence/review).
-- Columns and variables are documented in docs/contracts.md; no dynamic SQL identifiers.
PRAGMA foreign_keys = ON;
CREATE TABLE assessment (
  id INTEGER PRIMARY KEY CHECK(id=1),
  host_id TEXT NOT NULL, platform TEXT NOT NULL,
  policy_digest TEXT NOT NULL, snapshot_digest TEXT NOT NULL,
  observed_at TEXT NOT NULL, as_of TEXT NOT NULL
) STRICT;
CREATE TABLE finding (
  assessment_id INTEGER NOT NULL REFERENCES assessment(id),
  control_id TEXT NOT NULL, status TEXT NOT NULL
    CHECK(status IN ('PASS','FAIL','UNKNOWN','EXCEPTED')),
  value_json TEXT NOT NULL, expected_json TEXT NOT NULL,
  source TEXT NOT NULL, review TEXT NOT NULL, exception_json TEXT,
  PRIMARY KEY(assessment_id,control_id)
) STRICT;
CREATE INDEX finding_status ON finding(status,control_id);
