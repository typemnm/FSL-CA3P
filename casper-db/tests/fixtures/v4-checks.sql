CREATE TABLE IF NOT EXISTS checks (
    check_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    parameter TEXT NOT NULL,
    parameter_location TEXT NOT NULL DEFAULT 'unknown' CHECK (parameter_location IN ('query','body','path','header','cookie','fragment','unknown')),
    observed_at TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('confirmed', 'not_reproduced', 'inconclusive')),
    observation TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL CHECK (source IN ('synthetic', 'tool', 'manual')),
    review_status TEXT NOT NULL CHECK (review_status IN ('draft', 'reviewed')),
    reviewer TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS checks_case_time_idx ON checks(case_id, observed_at);
