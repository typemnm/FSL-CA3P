CREATE TABLE IF NOT EXISTS attack_catalog_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attack_catalog_sources (
    source_ref TEXT NOT NULL, content_sha256 TEXT NOT NULL, schema_version TEXT NOT NULL,
    snapshot TEXT NOT NULL, imported_at TEXT NOT NULL,
    PRIMARY KEY (source_ref, content_sha256)
);
CREATE TABLE IF NOT EXISTS attack_patterns (
    pattern_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK (revision >= 1),
    content_sha256 TEXT NOT NULL, vulnerability_type TEXT NOT NULL,
    application TEXT NOT NULL, endpoint TEXT NOT NULL, cwe TEXT,
    source_ref TEXT NOT NULL, source_sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (pattern_id, revision), UNIQUE (pattern_id, content_sha256),
    FOREIGN KEY (source_ref, source_sha256)
        REFERENCES attack_catalog_sources(source_ref, content_sha256)
);
CREATE TABLE IF NOT EXISTS attack_payloads (
    pattern_id TEXT NOT NULL, pattern_revision INTEGER NOT NULL, payload_id TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (pattern_id, pattern_revision, payload_id),
    FOREIGN KEY (pattern_id, pattern_revision) REFERENCES attack_patterns(pattern_id, revision)
);
CREATE TABLE IF NOT EXISTS attack_verification_rules (
    rule_id TEXT PRIMARY KEY, pattern_id TEXT NOT NULL, pattern_revision INTEGER NOT NULL,
    payload_id TEXT NOT NULL, snapshot TEXT NOT NULL,
    FOREIGN KEY (pattern_id, pattern_revision, payload_id)
        REFERENCES attack_payloads(pattern_id, pattern_revision, payload_id)
);
CREATE TABLE IF NOT EXISTS attack_templates (
    template_id TEXT NOT NULL, version TEXT NOT NULL, pattern_id TEXT NOT NULL,
    pattern_revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL,
    snapshot TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (template_id, version),
    FOREIGN KEY (pattern_id, pattern_revision) REFERENCES attack_patterns(pattern_id, revision)
);
CREATE TABLE IF NOT EXISTS attack_template_rules (
    template_id TEXT NOT NULL, template_version TEXT NOT NULL, rule_id TEXT NOT NULL,
    PRIMARY KEY (template_id, template_version, rule_id),
    FOREIGN KEY (template_id, template_version) REFERENCES attack_templates(template_id, version),
    FOREIGN KEY (rule_id) REFERENCES attack_verification_rules(rule_id)
);
