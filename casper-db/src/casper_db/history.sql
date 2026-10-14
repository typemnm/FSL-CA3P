CREATE TABLE IF NOT EXISTS case_versions (
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    snapshot TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (case_id, revision)
);
