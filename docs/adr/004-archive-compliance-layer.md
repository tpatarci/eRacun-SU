# ADR-004: Archive & Compliance Layer Architecture

**Status:** 🟢 Accepted
**Date:** 2025-11-12
**Deciders:** System Architect, Compliance Lead, Platform Engineering Lead
**Technical Story:** Implement the eRacun archive-service and supporting compliance workflows ahead of 2026 fiscalization mandate

---

## Context

Croatian Fiscalization Law (NN 89/25) requires eleven-year retention of original, signed XML invoices alongside full forensic audit trails. Existing pipeline services (ubl-transformer, fina-connector, as4-gateway-connector) currently forward processed documents to downstream consumers but lack a compliant archival subsystem. We must design a production-ready Archive & Compliance Layer that guarantees:

- WORM storage for original XML with preserved XMLDSig envelopes and qualified timestamps
- EU-only residency with redundant replicas and verifiable retention policies
- Monthly integrity verification across the full corpus with alerting on signature drift
- Structured audit trails that capture every access, mutation attempt, and verification event for eleven years
- Seamless integration with existing event-driven CQRS architecture and RabbitMQ message bus

Failure to deliver this subsystem before 2026-01-01 blocks regulatory approval and exposes the organization to substantial financial penalties and operational shutdown.

---

## Decision

We will implement a dedicated **Archive & Compliance Layer** composed of:

1. **Archive Service (new bounded context)** – Node.js/Express service exposing REST APIs and RabbitMQ consumers for ingesting invoice payloads, persisting metadata in PostgreSQL, and writing immutable objects to S3-compatible storage with WORM retention policies.
2. **Archive Verifier (scheduled workflow)** – Kubernetes CronJob analogue implemented via systemd timer + worker process executing monthly integrity validation against stored objects using the digital-signature-service for XMLDSig verification.
3. **Audit Index** – PostgreSQL schemas optimized for temporal queries and OpenTelemetry-compatible structured logging forwarded to the audit-logger service.
4. **Lifecycle Policies** – Automated hot/warm/cold tiering leveraging DigitalOcean Spaces Lifecycle rules and Glacier-class EU cold storage with encrypted replicas.

The design preserves CQRS patterns by accepting write commands via RabbitMQ (`ArchiveInvoiceCommand`) while exposing query APIs (`GetInvoiceByID`, `GetArchivedInvoicesByDateRange`, `GetAuditTrailForInvoice`) through idempotent REST endpoints. Observability, resilience, and compliance controls align with existing platform guardrails (ADR-003, CLAUDE.md §3, §6, §11).

---

## Architecture Overview

### Component Diagram (Textual)

- **Producers:** `ubl-transformer`, `fina-connector`, `as4-gateway-connector` publish `ArchiveInvoiceCommand` events to RabbitMQ exchange `archive.commands`.
- **Archive Service:** RabbitMQ consumer (`archive-service:ingest-worker`) persists invoice metadata in PostgreSQL (`archive_metadata` schema) and streams original XML to DigitalOcean Spaces bucket `eracun-archive-hot-eu` configured for WORM retention.
- **Lifecycle Manager:** Background worker applies tiering policies via S3 lifecycle API, moving objects to warm (`eracun-archive-warm-eu`) after 30 days and to cold storage (`eracun-archive-cold-eu`) after 12 months while preserving compliance metadata.
- **Archive Verifier:** Monthly job queries PostgreSQL for pending validations, downloads XML from respective tier, invokes digital-signature-service to validate signature chains, and writes results to `signature_integrity_checks` table plus emits alerts to Prometheus Alertmanager and audit-logger.
- **Consumers:** `compliance-reporting-service`, `admin-portal-api`, and `audit-logger` use REST API hosted by archive-service (`/v1/archive/...`) for retrieval and audit queries.

### Data Flow: Ingestion → Archive

1. Producer emits `ArchiveInvoiceCommand { invoice_id, original_xml, submission_channel, confirmation_reference, submission_timestamp }`.
2. Archive-service worker validates payload (schema, OIB checksum, signature integrity via digital-signature-service).
3. Worker computes SHA-512 hash + size, stores metadata in PostgreSQL within a serializable transaction (tables: `invoices`, `invoice_submissions`, `storage_locations`).
4. Original XML is streamed to S3 hot bucket using multipart upload with Object Lock (compliance mode) and server-side encryption (AES-256 SSE-S3) with additional client-side envelope encryption (age key from secrets vault).
5. Immutable pointer (bucket, key, version_id, retention_until) persisted; success triggers emission of `InvoiceArchivedEvent` and HTTP 202 ack back through message bus.

### Data Flow: Retrieval → Compliance Reporting

1. Consumer calls REST endpoint `GET /v1/archive/invoices/{invoice_id}` with OAuth2 token.
2. Archive-service authorizes request (RBAC) and queries PostgreSQL for metadata, verifying caller permissions.
3. Service returns metadata plus pre-signed URL scoped to time-limited (5 min) download if object resides in hot/warm tier; for cold tier, asynchronous restore job is triggered and `202 Accepted` with tracking ID is returned.
4. Access event logged in `audit_events` table and emitted to audit-logger via RabbitMQ `archive.audit` exchange.

---

## Interface Specifications

### RabbitMQ Contracts

- **Exchange:** `archive.commands` (type: topic) – publishers: ubl-transformer (`source=ubl`), fina-connector (`source=fina`), as4-gateway-connector (`source=as4`). Routing key `archive.command.invoice`.
- **Queue:** `archive-service.ingest` – single consumer with prefetch=10, retry via dead-letter exchange `archive.commands.dlq`.
- **Command Payload:**
  ```json
  {
    "invoice_id": "UUIDv7",
    "original_xml": "base64",
    "submission_channel": "B2C|B2B",
    "confirmation_reference": {
      "type": "JIR|UUID",
      "value": "string"
    },
    "submission_timestamp": "RFC3339"
  }
  ```
- **Event:** `InvoiceArchivedEvent` on exchange `archive.events`, routing key `archive.event.archived`, payload references invoice_id, storage pointer, hash, signature_status.

### REST API Contracts

- `GET /v1/archive/invoices/{invoice_id}` → 200 with metadata + optional presigned URL.
- `GET /v1/archive/invoices` → Filter by `start_date`, `end_date`, `invoice_type`, `signature_status`, paginated.
- `GET /v1/archive/invoices/{invoice_id}/audit` → Full audit timeline.
- `POST /v1/archive/invoices/{invoice_id}/validate` → Triggers on-demand revalidation (idempotent), returns current signature state.

### Database Access

- PostgreSQL schema `archive_metadata` with dedicated connection pool (max 30 connections, PGBouncer enforced) and row-level security for service-owned role.

---

## Failure Modes & Recovery Procedures

| Failure Mode | Detection | Mitigation | Recovery |
|--------------|-----------|-----------|----------|
| S3 object upload failure | Retryable errors surfaced via SDK metrics | Exponential backoff with jitter, circuit breaker after 5 consecutive failures | Queue message moved to DLQ; operator runbook triggers replay after storage health restored |
| PostgreSQL outage | Connection errors, health check failure | Circuit breaker & fail-fast response; queue backlog building monitored by Prometheus | Promote hot standby, re-point service via HAProxy; process backlog |
| Signature verification service unavailable | Timeout when invoking digital-signature-service | Graceful degradation: archive with status `PENDING_VERIFICATION`, enqueue follow-up job | Scheduled retry worker revalidates once dependency restored |
| Cold storage restore delay > SLA | Timer metrics from lifecycle job | Pre-restore caching for frequently accessed invoices; escalate to storage provider | Manual escalation + duplication to alternate EU cold tier |
| Tamper attempt (overwrite/delete) | S3 Object Lock prevents modifications; audit log anomalies | Alert triggered via CloudTrail-compatible logs ingested in audit-logger | Security team review, restore from replica if necessary |

Disaster recovery adheres to RTO ≤ 1h / RPO ≤ 5m by maintaining cross-region replica buckets and streaming PostgreSQL WAL to standby in EU-West.

---

## Data Model Specification

### PostgreSQL Schema (`archive_metadata`)

- `invoices`
  - `invoice_id UUID PRIMARY KEY`
  - `original_filename TEXT NOT NULL`
  - `sha512_hash CHAR(128) NOT NULL`
  - `content_length BIGINT NOT NULL`
  - `signature_status ENUM('VALID','PENDING','INVALID','EXPIRED') NOT NULL`
  - `signature_last_checked TIMESTAMPTZ`
  - `created_at TIMESTAMPTZ DEFAULT now()`
  - `retention_expires_at TIMESTAMPTZ NOT NULL`

- `invoice_submissions`
  - `invoice_id UUID REFERENCES invoices(invoice_id)`
  - `channel ENUM('B2C','B2B')`
  - `confirmation_type ENUM('JIR','UUID')`
  - `confirmation_value TEXT`
  - `submission_timestamp TIMESTAMPTZ`
  - `PRIMARY KEY(invoice_id, confirmation_type)`

- `storage_locations`
  - `invoice_id UUID REFERENCES invoices(invoice_id)`
  - `tier ENUM('HOT','WARM','COLD')`
  - `bucket TEXT`
  - `object_key TEXT`
  - `version_id TEXT`
  - `retention_mode ENUM('COMPLIANCE','GOVERNANCE')`
  - `retention_until TIMESTAMPTZ`
  - `glacier_job_id TEXT NULL`
  - `PRIMARY KEY(invoice_id, tier)`

- `signature_integrity_checks`
  - `check_id UUID PRIMARY KEY`
  - `invoice_id UUID REFERENCES invoices(invoice_id)`
  - `checked_at TIMESTAMPTZ`
  - `result ENUM('VALID','INVALID','REQUIRES_ATTENTION')`
  - `certificate_chain JSONB`
  - `validator_version TEXT`
  - `failure_reason TEXT`

- `audit_events`
  - `event_id UUID PRIMARY KEY`
  - `invoice_id UUID`
  - `event_type TEXT`
  - `actor_id UUID`
  - `actor_type ENUM('SERVICE','USER')`
  - `correlation_id UUID`
  - `occurred_at TIMESTAMPTZ`
  - `metadata JSONB`
  - Indexes: `(invoice_id, occurred_at DESC)`, GIN on `metadata`

### Object Storage Layout

- Buckets: `eracun-archive-hot-eu`, `eracun-archive-warm-eu`, `eracun-archive-cold-eu`
- Key format: `{year}/{month}/{day}/{invoice_id}/{sha512}.xml`
- Object Lock: Compliance mode, retention = 11 years + 30 days
- Replication: Cross-region replication to `eracun-archive-hot-eu-central` etc. with same retention policies
- Metadata tags: `invoice_id`, `jir_uuid`, `channel`, `hash`

---

## Storage Strategy

| Tier | Duration | Storage | Retrieval SLA | Notes |
|------|----------|---------|----------------|-------|
| Hot | 0-30 days | DigitalOcean Spaces Standard (EU-West) | <200 ms | Immediate access, supports frequent reads |
| Warm | 31-365 days | DigitalOcean Spaces Archive tier (EU-West) | ≤24 hours | Lifecycle transition automatically updates `storage_locations` |
| Cold | 366 days - 11 years | AWS S3 Glacier Deep Archive (eu-central-1) via Spaces partner | ≤48 hours | Object Lock + replicate metadata pointer; retrieval requires restore workflow |

Lifecycle policies managed via IaC module; retrieval from cold tier triggers asynchronous restore with progress tracked in PostgreSQL.

---

## Signature Preservation & Validation Strategy

- **Preservation:** Store original XML bytes exactly as received; prohibit whitespace normalization. Object metadata stores SHA-512 hash and XML canonicalization digest for verification.
- **Encryption:** Client-side envelope encryption ensures no plaintext leaves EU boundaries; keys rotated quarterly via cert-lifecycle-manager.
- **Monthly Validation:** systemd timer triggers `archive-verifier` worker; batch fetches 10k invoices per chunk, streams XML to digital-signature-service for XMLDSig validation, updates `signature_integrity_checks` and `invoices.signature_status`.
- **Expired Certificates:** Mark status `EXPIRED` but retain document; raise warning alert and log `REQUIRES_ATTENTION` event for compliance follow-up.
- **Corruption Handling:** If hash mismatch detected, object flagged `INVALID`, redundant replica cross-checked; automated restore from replica or offline backup; escalate via P0 runbook.

---

## Audit Trail Architecture

- **Events Logged:** ingestion, verification outcome, storage tier transitions, retrieval requests, export downloads, retention extension requests, deletion attempts.
- **Format:** JSON with fields `{event_id, invoice_id, actor_id, actor_type, action, timestamp, correlation_id, metadata}`.
- **Storage:** Append-only `audit_events` table + streaming to audit-logger via RabbitMQ `archive.audit`. Log retention matches invoice retention (11 years).
- **Querying:** Indexed views for `audit_events` enabling queries like `actor_id + date range`, accessible via `/v1/archive/invoices/{invoice_id}/audit` endpoint with pagination and correlation ID filters.
- **Immutability:** Database-level row security prevents UPDATE/DELETE; only INSERT allowed. Periodic export to WORM storage for secondary audit trail backup.

---

## Integration Points

### Inbound Producers

- `ubl-transformer` – after schema validation, publishes ArchiveInvoiceCommand with B2C/B2B flag.
- `fina-connector` – attaches JIR confirmation for B2C submissions.
- `as4-gateway-connector` – attaches UUID confirmation for B2B AS4 submissions.

### Outbound Consumers

- `compliance-reporting-service` – uses `/v1/archive/invoices` to assemble monthly e-reporting payloads.
- `admin-portal-api` – obtains original XML for customer self-service retrieval.
- `audit-logger` – receives audit events, cross-correlates with other services.

### Supporting Services

- `digital-signature-service` – synchronous validation dependency with circuit breaker.
- `cert-lifecycle-manager` – provides certificate trust bundles and key rotation schedule.
- `retry-scheduler` – replays DLQ messages and failed validation jobs.

---

## Observability & Security

- **Metrics:** Prometheus exporters track queue depth, upload latency, validation duration, tier transition counts.
- **Tracing:** OpenTelemetry spans across ingestion pipeline; correlation IDs propagate via RabbitMQ headers and HTTP.
- **Logging:** Structured JSON via Pino, forwarded to ELK stack; sensitive fields redacted per GDPR guidelines.
- **Access Control:** OAuth2 scopes (`archive.read`, `archive.write`, `archive.audit`) validated against central IAM; service-to-service auth via mTLS.
- **Secrets:** Managed through SOPS + age; decrypted at runtime via `decrypt-secrets.sh archive-service` per ADR-002.

---

## Consequences

- **Pros:** Meets regulatory mandates, integrates cleanly with existing architecture, provides deterministic retention and verification workflows.
- **Cons:** Additional complexity managing multi-tier storage and periodic validation workloads; increased cost due to redundant EU storage.
- **Follow-up:** Implement IaC modules for lifecycle policies; coordinate with infra team to provision buckets and PostgreSQL schema migrations.

---

## Open Questions / Risks

1. Exact EU regions for hot vs. cold tier replication (pending TBD.md decision).
2. Throughput of monthly validation for >10M invoices requires performance benchmarking; consider sharding workloads.
3. Evaluate need for customer-facing throttling on retrieval endpoints to prevent abuse.

