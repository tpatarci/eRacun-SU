# 2025-11-15 – PENDING-008 Progress Report (FINA Certificates & Connectivity)

**Related blocker:** [PENDING-008](../pending/008-fina-integration-testing.md)

## 1. Summary

- Added explicit TLS client certificate loading for `fina-connector` so SOAP/AS4
  traffic can source decrypted files from `/etc/eracun/secrets/certificates/`.
- Created `secrets/certificates/` with SOPS workflow instructions; actual
  certificates are still missing pending NIAS-authenticated access to
  `cms.fina.hr`.
- Added unit coverage for `cert-lifecycle-manager`’s expiration monitor to prove
  alerts fire when demo/production certificates approach expiry.
- Unable to execute demo or production certificate requests, WSDL smoke tests,
  or mandated B2C/B2B fiscalization scenarios because the sandbox lacks access
  to the real FINA portals, SOPS age keys, and PostgreSQL/RabbitMQ infrastructure
  defined in deployment runbooks.

## 2. Certificate Acquisition Status

| Task | Status | Notes |
| --- | --- | --- |
| Demo certificate request via `cms.fina.hr` | Blocked | Requires NIAS credential + legal entity OIB. No external network access is allowed from this environment. |
| Demo certificate import into PostgreSQL (cert-lifecycle-manager) | Blocked | Depends on certificate file + password. Repository now has tests ensuring expiry monitoring works once data is present. |
| Production certificate order | Pending (target lead time 5–10 business days) | Application cannot be filed without external access/payment processing. Documentation updated to highlight dependency. |
| Encrypted backup under `secrets/certificates/` | Pending | SOPS tooling + age key unavailable here; README documents the exact commands Ops must run. |

## 3. Storage & Decryption Plan

1. Compliance/Ops retrieves demo `.p12` and production `.p12` packages.
2. Convert to PEM (`.crt` + `.key`) for services that require split files.
3. Encrypt each artifact via `sops --encrypt … > secrets/certificates/<name>.enc`.
4. Deployment units call `decrypt-secrets.sh` (per `deployment/systemd/README.md`)
   to materialize `/run/eracun/certificates/*.{crt,key}` with `0400` perms owned
   by the `eracun` user.
5. `fina-connector` and future AS4 components read paths provided via the new
   configuration module.

## 4. Configuration Updates

- `services/fina-connector/src/config.ts` now centralizes env loading and
  resolves TLS file paths (defaults: `/etc/eracun/secrets/certificates/fina-demo-client.{crt,key}`).
- `soap-client.ts` builds a pinned `https.Agent` with the decrypted cert/key,
  optional CA bundle, and key passphrase (read from env or file).
- These changes ensure mutual TLS can be activated immediately after Ops drop
  decrypted assets onto the target host (no code change required).

## 5. Expiry Monitoring Verification

A dedicated Jest suite exercises the expiration monitor:

- Confirms expired/1-day/7-day/30-day thresholds update metrics and trigger
  alerts.
- Validates that repository failures bubble up instead of silently hiding
  missing data.
- Metrics asserted: `certificates_expiring_count{days_until_expiry="1"}` and
  `certificate_expiration_alerts_total{severity="urgent"}`.

This provides confidence that once real certificates are stored in Postgres via
`cert-lifecycle-manager`, alerting will immediately cover demo and production
chains.

## 6. Connectivity & Fiscalization Tests

The following matrices outline required coverage; all entries remain **Blocked**
because the sandbox cannot reach `cistest.apis-it.hr:8449`, lacks valid
certificates, and cannot capture official JIR/UUID values.

### B2C (SOAP) Tests

| # | Scenario | Expected Output | Status |
| - | --- | --- | --- |
| 1 | Happy-path retail invoice | JIR issued in <5s | Blocked – no certificate |
| 2 | Duplicate invoice submission | Same JIR returned | Blocked |
| 3 | Invalid OIB | SOAP fault `s:003` | Blocked |
| 4 | VAT mismatch | Business error | Blocked |
| 5 | Payment on delivery | Correct PDV tags | Blocked |
| 6 | Currency rounding edge case | Rounding warning | Blocked |
| 7 | SOAP timeout recovery | DLQ replay + retry logs | Blocked |
| 8 | Certificate revoked | TLS failure + alert | Blocked |
| 9 | Offline queue flush | Messages drained to FINA | Blocked |
| 10 | Circuit breaker open/close | Metrics reflect transitions | Blocked |

### B2B (AS4) Tests

| # | Scenario | Expected Output | Status |
| - | --- | --- | --- |
| 1 | Submit invoice via AS4 AP | UUID confirmation | Blocked – AS4 gateway unavailable |
| 2 | Duplicate message detection | Replayed message rejected | Blocked |
| 3 | ebMS error handling | Proper signal message | Blocked |
| 4 | Receipt acknowledgement latency | ACK < 30s | Blocked |
| 5 | DLQ replay of AS4 UserMessage | Message delivered after retry | Blocked |

### Negative Scenarios to Re-run Once Certificates Exist

- Certificate revoked mid-session → expect TLS handshake failure + alert
  emission.
- SOAP timeout simulation → expect offline queue + retry telemetry.
- DLQ replay → ensure poison messages can be reprocessed without data loss.

## 7. Next Actions Before Lifting PENDING-008

1. Compliance obtains demo + production certificates and encrypts them using the
   documented workflow.
2. Import demo cert metadata into `cert-lifecycle-manager` (Postgres) and rerun
   expiry monitoring with live data.
3. Run SOAP smoke tests against `cistest.apis-it.hr:8449` using provided
   envelopes, capturing JIR confirmations.
4. Stand up AS4 access-point scaffolding and repeat 5 B2B UUID tests.
5. Capture detailed evidence (request/response logs, JIR/UUID IDs, DLQ replay
   proof) and attach to this report before requesting that Compliance lift
   PENDING-008.

Until those external steps are completed, the regulatory blocker must remain in
place.
