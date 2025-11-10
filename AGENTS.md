# AGENTS: eRacun Development Monorepo

## Scope
These instructions apply to **every file** in this repository. Follow them in addition to any more specific guidance that may exist in nested directories.

## 1. Mission & Regulatory Posture
- Treat this platform as a **mission-critical, production-grade** e-invoice system for Croatian businesses. Reliability targets are 99.999% uptime, strict zero-data-loss tolerance, and aggressive disaster recovery (RTO ≤ 1h, RPO ≤ 5m).
- **Regulatory compliance is non-negotiable.** All implementations must satisfy Croatian Fiskalizacija 2.0, EN 16931, UBL 2.1, and CIUS-HR requirements. Always cross-reference:
  - `CROATIAN_COMPLIANCE.md` for legal obligations, timelines, and penalties.
  - `docs/standards/UBL-2.1/`, `docs/standards/EN-16931/`, `docs/standards/CIUS-HR/`, and `docs/standards/KLASUS-2025/` for authoritative schemas, rules, and code lists.
  - `docs/research/OIB_CHECKSUM.md`, `docs/research/VAT_RULES_HR.md`, and `docs/research/XMLDSIG_GUIDE.md` for implementation-critical algorithms.
- Respect **11-year archival** mandates for XML + signatures, dual-channel submission (SOAP + AS4), 5-day fiscalization deadlines, and monthly e-reporting duties.

## 2. Architecture Guardrails
- Maintain the documented monorepo structure (`CLAUDE.md`, `docs/MONOREPO_STRUCTURE.md`, `docs/adr/003-system-decomposition-integration-architecture.md`). Services are small (≤2,500 LOC, target ~1,000), single-responsibility, and communicate via explicit contracts.
- Use **event-driven CQRS patterns**. Prefer asynchronous messaging; synchronous gRPC/RPC is reserved for explicitly listed scenarios. Enforce idempotency, deduplicated event handling, and circuit breakers for external calls.
- Shared libraries in `shared/` are extracted only after the pattern appears in ≥3 services and must document performance (see CLAUDE §2.3).
- Observe performance budgets (e.g., XSD validator p95 <50 ms, Schematron <500 ms, overall pipeline SLA ≤10 s B2C/≤5 s B2B) and resource caps (≤512 MB memory baseline, CPU 0.5 core, etc.).

## 3. Documentation & Single Source of Truth (SSOT)
- Never duplicate normative content from standards or compliance guides. **Reference the canonical files** listed above. Standards directories are immutable reference material—create new versioned folders instead of editing in place.
- Every service must own a `CLAUDE.md` derived from `TEMPLATE_CLAUDE.md`; replace placeholders, document dependencies, cite standards, and keep approval sections current.
- Keep `PENDING.md`, `docs/pending/*`, and `TBD.md` synchronized. Track implementation-ready blockers in PENDING, open questions in TBD, and reference outcomes in ADRs.
- Update ADRs when architectural decisions change. Follow the accepted strategies in ADR-001 (filesystem configuration) and ADR-002 (SOPS + age secrets) unless superseded by a newer ADR.

## 4. Quality, Testing & Tooling
- **100% automated test coverage is mandatory.** Tests must cover unit, integration, contract, load/performance, failure/chaos, and regression cases outlined in `TEMPLATE_CLAUDE.md` §7. Provide fixtures for valid, edge-case, invalid, and malicious inputs.
- Enforce static analysis, linting, type checks, security scans (e.g., Snyk/Trivy), and ensure Docker builds succeed when applicable.
- Message schemas MUST use Protocol Buffers (`docs/api-contracts/protobuf/README.md`). Maintain backward compatibility (no renumbering, use `reserved` slots, bump package version for breaking changes).
- Follow conventional commits (e.g., `feat:`, `fix:`, `docs:`) and reference PENDING/TBD IDs where relevant (`fix(pending-001): …`).

## 5. Configuration, Secrets & Deployment
- Configuration hierarchy: `/etc/eracun/platform.conf`, `/etc/eracun/services/<service>.conf`, `/etc/eracun/environment.conf` (YAML). Implement loaders respecting this precedence plus environment overrides.
- Secrets are stored encrypted with **SOPS + age** (`secrets/.sops.yaml`, ADR-002). Decrypt via `decrypt-secrets.sh` to tmpfs (`/run/eracun/`). Never commit plaintext secrets, private keys, or production age keys.
- Deployment targets DigitalOcean droplets orchestrated by systemd. Service units must:
  - Run as the non-root `eracun` user.
  - Use `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, and other hardening flags from `deployment/systemd/README.md`.
  - Execute `ExecStartPre=/usr/local/bin/decrypt-secrets.sh <service>` for secrets.
- Maintain infrastructure scripts, configs, and secrets templates in the designated directories; align with `docs/SSOT_AUDIT_TRAIL.md` expectations.

## 6. Compliance-Critical Implementations
- Validate OIBs using ISO 7064 Mod 11,10 (see research doc) before any submission.
- Enforce KPD (KLASUS) codes on **every** invoice line item; integrate registry checks with caching per standard guidance.
- Apply VAT rates, exemptions, reverse charge rules, and rounding tolerances per `VAT_RULES_HR.md`.
- Implement digital signatures using FINA X.509 certificates and XMLDSig as described in `XMLDSIG_GUIDE.md`; preserve JIR/ZKI values.

## 7. Observability, Resilience & Operations
- Deliver structured JSON logging with request IDs, trace context, and compliance metadata. Instrument OpenTelemetry spans and adhere to the alert catalog in ADR-003.
- Define runbooks, rollback steps, and failure modes for each service (`TEMPLATE_CLAUDE.md` §§11–12). Incident response must include audit trail updates.
- Monitor DLQs, retry behavior, and consensus validation thresholds. Design for graceful degradation and disaster recovery scenarios documented in CLAUDE §11.

## 8. Process Discipline
- Triaging cadence: review PENDING/TBD weekly, update decision logs, and keep audit artifacts current (see `docs/SSOT_AUDIT_TRAIL.md`).
- Any new standard, research, or compliance reference must be added under `docs/standards/` or `docs/research/` with authoritative sources and immutability policy.
- Before coding a new bounded context, ensure TODO checklist items are satisfied (service catalog, message catalog, dependency analysis) and ADR-003 sections remain consistent.

Adhering to these instructions is essential to preserve compliance, auditability, and architectural integrity of the eRacun platform.
