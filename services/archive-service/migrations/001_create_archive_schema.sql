-- Archive Metadata Schema
-- See: docs/adr/004-archive-compliance-layer.md §114-165

BEGIN;

-- Create schema
CREATE SCHEMA IF NOT EXISTS archive_metadata;

-- Invoices table
CREATE TABLE archive_metadata.invoices (
  invoice_id UUID PRIMARY KEY,
  original_filename TEXT NOT NULL,
  sha512_hash CHAR(128) NOT NULL,
  content_length BIGINT NOT NULL,
  signature_status TEXT NOT NULL CHECK (signature_status IN ('VALID', 'PENDING', 'INVALID', 'EXPIRED')),
  signature_last_checked TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_invoices_created_at ON archive_metadata.invoices(created_at DESC);
CREATE INDEX idx_invoices_signature_status ON archive_metadata.invoices(signature_status);

-- Invoice submissions table (FINA confirmations)
CREATE TABLE archive_metadata.invoice_submissions (
  invoice_id UUID REFERENCES archive_metadata.invoices(invoice_id),
  channel TEXT NOT NULL CHECK (channel IN ('B2C', 'B2B')),
  confirmation_type TEXT NOT NULL CHECK (confirmation_type IN ('JIR', 'UUID')),
  confirmation_value TEXT NOT NULL,
  submission_timestamp TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (invoice_id, confirmation_type)
);

-- Storage locations table (hot/warm/cold tiers)
CREATE TABLE archive_metadata.storage_locations (
  invoice_id UUID REFERENCES archive_metadata.invoices(invoice_id),
  tier TEXT NOT NULL CHECK (tier IN ('HOT', 'WARM', 'COLD')),
  bucket TEXT NOT NULL,
  object_key TEXT NOT NULL,
  version_id TEXT,
  retention_mode TEXT NOT NULL CHECK (retention_mode IN ('COMPLIANCE', 'GOVERNANCE')),
  retention_until TIMESTAMPTZ NOT NULL,
  glacier_job_id TEXT,
  PRIMARY KEY (invoice_id, tier)
);

-- Signature integrity checks table
CREATE TABLE archive_metadata.signature_integrity_checks (
  check_id UUID PRIMARY KEY,
  invoice_id UUID REFERENCES archive_metadata.invoices(invoice_id),
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  result TEXT NOT NULL CHECK (result IN ('VALID', 'INVALID', 'REQUIRES_ATTENTION')),
  certificate_chain JSONB,
  validator_version TEXT,
  failure_reason TEXT
);

CREATE INDEX idx_signature_checks_invoice_date ON archive_metadata.signature_integrity_checks(invoice_id, checked_at DESC);

-- Audit events table (immutable, append-only)
CREATE TABLE archive_metadata.audit_events (
  event_id UUID PRIMARY KEY,
  invoice_id UUID,
  event_type TEXT NOT NULL,
  actor_id UUID,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('SERVICE', 'USER')),
  correlation_id UUID,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB
);

CREATE INDEX idx_audit_events_invoice_date ON archive_metadata.audit_events(invoice_id, occurred_at DESC);
CREATE INDEX idx_audit_events_metadata ON archive_metadata.audit_events USING GIN(metadata);

-- Row-level security for audit trail immutability
ALTER TABLE archive_metadata.audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_append_only ON archive_metadata.audit_events
  FOR INSERT TO archive_service WITH CHECK (true);

CREATE POLICY audit_read_only ON archive_metadata.audit_events
  FOR SELECT TO archive_service USING (true);

-- Prevent UPDATE/DELETE (no policies defined = operations denied)

COMMIT;
