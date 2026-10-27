CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY NOT NULL,
    target_id TEXT NOT NULL,
    title TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    reported_on TEXT,
    vulnerability_url TEXT,
    severity TEXT CHECK (severity IN ('low','medium','high','critical') OR severity IS NULL),
    description TEXT,
    remediation TEXT NOT NULL DEFAULT '[]',
    prior_evidence TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')),
    parameter TEXT NOT NULL,
    parameter_location TEXT NOT NULL DEFAULT 'unknown' CHECK (parameter_location IN ('query','body','path','header','cookie','fragment','unknown')),
    preconditions TEXT NOT NULL,
    procedure TEXT NOT NULL,
    payload TEXT,
    success_condition TEXT NOT NULL,
    source_report TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'ready')),
    patch_status TEXT NOT NULL CHECK (patch_status IN ('unknown', 'unpatched', 'patched')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (status != 'ready' OR (payload IS NOT NULL AND length(trim(payload)) > 0))
);

CREATE INDEX IF NOT EXISTS cases_location_idx
    ON cases(target_id, endpoint, method, status);
