# TODO-007: Archive Service Implementation Tracker

**Owner:** Platform Engineering Lead  
**Created:** 2025-11-12  
**Last Updated:** 2025-11-12  
**Status:** 🚧 In Progress

## Milestones

| Milestone | Description | Target Date | Status | Notes |
|-----------|-------------|-------------|--------|-------|
| M1 | Approve ADR-004 architecture | 2025-11-15 | ✅ Completed | ADR-004 authored and accepted. |
| M2 | Provision infrastructure (PostgreSQL schema, Spaces buckets, IAM roles) | 2025-11-25 | 🚧 On Track | Awaiting infra change request #INF-231. |
| M3 | Implement archive-service ingestion worker + REST API | 2025-12-05 | ⏳ Planned | Development blocked until infra ready. |
| M4 | Integrate monthly signature validation workflow | 2025-12-12 | ⏳ Planned | Requires cron timer + digital-signature-service SLA confirmation. |
| M5 | Complete performance, chaos, and compliance testing | 2025-12-20 | ⏳ Planned | Test plan drafted; needs fixtures. |
| M6 | Production hardening & runbook sign-off | 2025-12-31 | ⏳ Planned | Coordinate with Ops & Compliance. |

## Action Items

1. Draft IaC module for Spaces lifecycle policies (owner: DevOps) – due 2025-11-18.  
2. Confirm EU regions for cold storage replica (owner: Compliance) – due 2025-11-16.  
3. Prepare PostgreSQL migration scripts for `archive_metadata` schema (owner: Backend Engineer) – due 2025-11-20.  
4. Define load test scenarios for 10M monthly validations (owner: QA Lead) – due 2025-11-22.  
5. Update audit-logger ingestion mapping to handle `archive.audit` stream (owner: Observability) – due 2025-11-19.

## Risks & Dependencies

- **R1:** Pending decision on cold storage region (see TBD-003) may delay bucket provisioning.  
- **R2:** DigitalOcean Spaces compliance-mode availability must be confirmed; fallback to AWS S3 with VPC endpoints if unavailable.  
- **R3:** Need confirmation from legal on acceptable retention buffer (>11 years).  
- **Dependency:** digital-signature-service latency under monthly validation load; track via performance benchmarks.

## Reporting

- Update project status dashboard weekly with progress against milestones.  
- Escalate blockers exceeding 48 hours to Steering Committee via `PENDING.md` entry.

