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
    parameter TEXT,
    parameter_location TEXT NOT NULL DEFAULT 'unknown' CHECK (parameter_location IN ('query','body','path','header','cookie','fragment','unknown')),
    preconditions TEXT NOT NULL,
    procedure TEXT NOT NULL,
    payload TEXT,
    success_condition TEXT NOT NULL,
    source_report TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'ready')),
    patch_status TEXT NOT NULL CHECK (patch_status IN ('unknown', 'unpatched', 'patched')),
    source TEXT NOT NULL DEFAULT 'unknown' CHECK (source IN ('synthetic','manual','imported','unknown')),
    not_applicable_fields TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(not_applicable_fields) AND json_type(not_applicable_fields) = 'array'),
    applicability_reason TEXT,
    route_template TEXT,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (json_array_length(not_applicable_fields) <= 2),
    CHECK (json_array_length(not_applicable_fields) = 0
           OR json_extract(not_applicable_fields, '$[0]') IN ('parameter', 'payload')),
    CHECK (json_array_length(not_applicable_fields) < 2
           OR (json_extract(not_applicable_fields, '$[1]') IN ('parameter', 'payload')
               AND json_extract(not_applicable_fields, '$[0]')
                   != json_extract(not_applicable_fields, '$[1]'))),
    CHECK (json_array_length(not_applicable_fields) = 0
           OR coalesce(length(trim(applicability_reason)), 0) > 0),
    CHECK (parameter IS NOT NULL
           OR json_extract(not_applicable_fields, '$[0]') IS 'parameter'
           OR json_extract(not_applicable_fields, '$[1]') IS 'parameter'),
    CHECK (NOT (json_extract(not_applicable_fields, '$[0]') IS 'parameter'
                OR json_extract(not_applicable_fields, '$[1]') IS 'parameter')
           OR (parameter IS NULL AND parameter_location = 'unknown')),
    CHECK (NOT (json_extract(not_applicable_fields, '$[0]') IS 'payload'
                OR json_extract(not_applicable_fields, '$[1]') IS 'payload') OR payload IS NULL),
    CHECK (status != 'ready' OR (payload IS NOT NULL AND length(trim(payload)) > 0)
           OR json_extract(not_applicable_fields, '$[0]') IS 'payload'
           OR json_extract(not_applicable_fields, '$[1]') IS 'payload')
);

CREATE INDEX IF NOT EXISTS cases_location_idx
    ON cases(target_id, endpoint, method, status);
