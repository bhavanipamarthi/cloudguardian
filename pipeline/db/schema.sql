-- Consolidated CSPM findings database schema.
-- One row per Prowler finding, enriched with the CloudGuardian prioritization
-- score (severity x exposure x blast_radius) and misconfig catalogue linkage.

CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    check_id        TEXT NOT NULL,
    region          TEXT,
    resource_id     TEXT,
    resource_type   TEXT,
    severity        TEXT CHECK(severity IN ('critical','high','medium','low','informational')),
    status          TEXT CHECK(status IN ('FAIL','PASS','MANUAL')),
    misconfig_id    TEXT,               -- links to misconfig_catalogue.misconfig_id, NULL if not one of the tracked 8
    title           TEXT,
    severity_score  INTEGER,            -- numeric weight derived from severity
    exposure_score  INTEGER,            -- 0-10, internet-facing vs internal
    blast_radius    INTEGER,            -- 0-10, estimated downstream impact
    priority_score  REAL,               -- severity_score * exposure_score * blast_radius
    priority_rank   INTEGER,            -- 1 = highest priority
    ingested_at     TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS misconfig_catalogue (
    misconfig_id    TEXT PRIMARY KEY,   -- MC-01 .. MC-08
    title           TEXT NOT NULL,
    resource_type   TEXT,
    iso27001_control TEXT,
    remediation_type TEXT CHECK(remediation_type IN ('auto','human_approval')),
    status          TEXT CHECK(status IN ('remediated','pending','open'))
);

CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority_rank);
CREATE INDEX IF NOT EXISTS idx_findings_misconfig ON findings(misconfig_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
