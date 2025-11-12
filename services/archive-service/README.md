# Archive Service

## Overview

The Archive Service provides the regulatory-compliant archive and audit interface for the eRacun invoice platform. It ingests original XML invoices via RabbitMQ commands, persists immutable metadata in PostgreSQL, stores WORM-protected objects in EU-only S3-compatible storage, and exposes REST APIs for retrieval, audit queries, and signature validation.

## Responsibilities

- Consume `ArchiveInvoiceCommand` messages from `archive.commands` exchange and persist invoices with idempotent processing.
- Store raw XML bytes in DigitalOcean Spaces (hot/warm tiers) and AWS Glacier Deep Archive (cold tier) with Object Lock (compliance mode).
- Maintain PostgreSQL schema `archive_metadata` containing invoice metadata, submission confirmations, storage pointers, signature check history, and audit events.
- Expose REST endpoints for invoice retrieval, range queries, on-demand validation, and audit timeline access with RBAC enforcement.
- Trigger monthly signature validation workflow and raise alerts when integrity drifts or certificates expire.

## Architecture

- **Runtime:** Node.js 20 LTS, Express.js, TypeScript with strict mode.
- **Persistence:** PostgreSQL (managed cluster) accessed via Prisma ORM, connection pool capped at 30 connections with PGBouncer.
- **Messaging:** RabbitMQ consumer using `archive-service.ingest` queue with manual acknowledgements and dead-letter exchange `archive.commands.dlq`.
- **Object Storage:** DigitalOcean Spaces buckets `eracun-archive-hot-eu`, `eracun-archive-warm-eu`; AWS S3 Glacier Deep Archive bucket `eracun-archive-cold-eu`. All buckets enforce Object Lock compliance mode, retention 11 years + 30 days.
- **Dependencies:**
  - `digital-signature-service` for XMLDSig validation
  - `cert-lifecycle-manager` for trust bundle distribution
  - `audit-logger` for downstream audit enrichment
  - `retry-scheduler` for DLQ replay and scheduled validations
- **Observability:** OpenTelemetry instrumentation, Prometheus metrics exporter, structured JSON logs (Pino), trace IDs propagated through RabbitMQ headers and HTTP responses.

## APIs

### RabbitMQ Command (Inbound)

```
Exchange: archive.commands (topic)
Routing Key: archive.command.invoice
Queue: archive-service.ingest
Payload:
{
  "invoice_id": "UUIDv7",
  "original_xml": "base64",
  "submission_channel": "B2C|B2B",
  "confirmation_reference": { "type": "JIR|UUID", "value": "string" },
  "submission_timestamp": "RFC3339"
}
```

### REST Endpoints (Outbound)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/archive/invoices/{invoice_id}` | Return invoice metadata and presigned URL (hot/warm tiers) or restore token (cold tier). |
| GET | `/v1/archive/invoices` | Filter invoices by date range, channel, signature status; paginated. |
| GET | `/v1/archive/invoices/{invoice_id}/audit` | Return chronological audit events for invoice lifecycle. |
| POST | `/v1/archive/invoices/{invoice_id}/validate` | Trigger idempotent revalidation and update signature status. |

All endpoints require OAuth2 scopes: `archive.read` for read operations, `archive.audit` for audit views, `archive.write` for validation triggers.

## Data Model

See ADR-004 for canonical schema. Database migrations live in `services/archive-service/migrations/` (to be created) and must enforce row-level security to prevent UPDATE/DELETE on audit tables.

## Configuration

Configuration is loaded via `/etc/eracun/services/archive-service.conf` with environment overrides:

```yaml
postgres:
  url: ${ARCHIVE_DATABASE_URL}
  pool_max: 30
rabbitmq:
  url: ${RABBITMQ_URL}
  queue: archive-service.ingest
storage:
  hot_bucket: eracun-archive-hot-eu
  warm_bucket: eracun-archive-warm-eu
  cold_bucket: eracun-archive-cold-eu
  client_side_key: ${ARCHIVE_ENVELOPE_KEY}
validation:
  monthly_window_days: 30
  chunk_size: 10000
observability:
  metrics_port: 9310
  tracing_endpoint: ${OTEL_EXPORTER_OTLP_ENDPOINT}
```

Secrets (database passwords, envelope keys) are managed through SOPS + age and decrypted by `decrypt-secrets.sh archive-service` during systemd unit startup (see ADR-002).

## Operations

- **Systemd Unit:** `archive-service.service` runs the HTTP API; `archive-ingest-worker.service` handles queue consumption; `archive-verifier.timer` triggers monthly validation job.
- **Runbooks:** Follow `docs/runbooks/archive-service.md` (to be authored) for incident response, including DLQ replay, object restore workflow, and audit integrity checks.
- **Backups:** PostgreSQL WAL streaming to standby; object storage replication to EU secondary regions. Restore procedures must preserve Object Lock compliance.

## Testing Strategy

- 70% unit coverage on domain logic (idempotency checks, payload validation, storage pointer calculations).
- 25% integration coverage via contract tests with localstack (S3), testcontainers (PostgreSQL, RabbitMQ).
- 5% end-to-end coverage simulating ingestion → archive → retrieval → validation flow.
- Chaos scenarios: simulate S3 outage, signature-service latency, and cold-tier restore delays; ensure circuit breakers and retries behave as designed.

## Compliance Notes

- Enforce ISO 7064 Mod 11,10 validation on OIB before archiving (see `docs/research/OIB_CHECKSUM.md`).
- Maintain linkage between invoices and FINA confirmations (JIR/UUID) for auditability.
- Audit events retained for eleven years, exported quarterly to WORM storage for secondary audit trail.
- Retrieval endpoints must redact PII per GDPR and log access reason codes for every request.

