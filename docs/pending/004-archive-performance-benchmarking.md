# PENDING-004: Archive Service Performance Benchmarking

**Priority:** 🟡 P1 (High)
**Created:** 2025-11-12
**Estimated Effort:** 3-4 days
**Owner:** QA Lead + Platform Engineering Lead

---

## Problem Statement

The archive-service must handle monthly signature validation for up to 10 million invoices within a 1-hour window (278 validations/second sustained throughput). Current design assumes digital-signature-service can meet this throughput, but no benchmarks exist to verify this assumption.

**Consequences if not addressed:**
- Monthly validation jobs may exceed 1-hour SLA, causing operational delays
- Undetected performance bottlenecks may surface in production (post-2026-01-01)
- Circuit breaker thresholds may be misconfigured, causing false positives

---

## Scope

### What Needs Benchmarking

1. **digital-signature-service Throughput**
   - Single-threaded: Validations/second for XMLDSig + certificate chain verification
   - Multi-threaded: Optimal concurrency level (10, 50, 100, 500 parallel requests)
   - Resource consumption: CPU, memory, network bandwidth per validation

2. **archive-service Monthly Validation Workflow**
   - Database query performance: Fetch 10k invoice IDs per chunk
   - S3 retrieval latency: Download XML from hot/warm/cold tiers
   - End-to-end pipeline: Time to validate 10M invoices with realistic data

3. **PostgreSQL Index Performance**
   - Query: `SELECT invoice_id FROM invoices WHERE signature_last_checked < NOW() - INTERVAL '30 days' LIMIT 10000`
   - Index effectiveness: `idx_invoices_signature_status` + partial index on `signature_last_checked`
   - Write performance: Bulk `UPDATE invoices SET signature_status = ...` for 10k records

4. **S3 Multipart Upload Performance**
   - Throughput: Concurrent uploads (10, 50, 100 parallel operations)
   - Chunk size optimization: 5MB, 10MB, 25MB parts
   - Network bandwidth: DigitalOcean Spaces EU-West egress limits

---

## Open Questions Requiring Decisions

1. **Acceptable throughput degradation:** Is 2-hour validation window acceptable if 1-hour proves infeasible?
2. **Horizontal scaling strategy:** Should we deploy multiple archive-verifier workers?
3. **Caching strategy:** Should we cache certificate trust bundles to reduce digital-signature-service load?
4. **Cold tier pre-warming:** Should we pre-restore frequently accessed invoices from Glacier?

---

## Deliverables Required to Close

### Phase 1: Tool Setup (1 day)
- [ ] Set up performance testing environment (staging with production-like data volume)
- [ ] Generate 100k sample invoices with valid XMLDSig signatures
- [ ] Deploy digital-signature-service + archive-service to staging
- [ ] Configure Prometheus + Grafana dashboards for real-time metrics

### Phase 2: digital-signature-service Benchmarks (1 day)
- [ ] Benchmark single-threaded validation throughput
- [ ] Benchmark parallel validation (10, 50, 100, 500 concurrent requests)
- [ ] Measure resource consumption (CPU, memory, network)
- [ ] Identify optimal concurrency level (max throughput before degradation)
- [ ] Document results in `docs/benchmarks/digital-signature-service.md`

### Phase 3: archive-service Workflow Benchmarks (1.5 days)
- [ ] Benchmark database query performance (10k invoice IDs per chunk)
- [ ] Benchmark S3 retrieval latency (hot/warm/cold tiers)
- [ ] Benchmark end-to-end monthly validation (100k invoices)
- [ ] Extrapolate to 10M invoices: Can we meet 1-hour SLA?
- [ ] Document results in `docs/benchmarks/archive-service.md`

### Phase 4: Optimization (if needed, 0.5 days)
- [ ] If throughput <278/sec: Implement caching, horizontal scaling, or database optimizations
- [ ] Re-run benchmarks to verify improvements
- [ ] Update TODO-007 M4 milestone with optimizations required

### Phase 5: Production Readiness (0.5 days)
- [ ] Set Prometheus alerting thresholds based on benchmark results
- [ ] Update `docs/runbooks/archive-service.md` with performance expectations
- [ ] Document capacity planning guidelines (when to scale horizontally)

---

## What It Blocks

- **M4 Milestone (TODO-007):** Monthly signature validation workflow integration
- **Production Deployment (M6):** Cannot deploy without performance validation
- **Capacity Planning:** Cannot determine if single droplet sufficient or multi-node required

---

## Why Deferred

**Reason:** Infrastructure provisioning (M2) not yet complete. Cannot benchmark without staging environment and sample data.

**Higher Priority Work:**
- ADR-004 architecture design (completed)
- Service skeleton implementation (completed)
- Database schema migrations (in progress)

---

## Estimated Effort

**Total:** 3-4 days (1 QA engineer + 0.5 DevOps for environment setup)

**Breakdown:**
- Phase 1 (setup): 1 day
- Phase 2 (digital-signature-service): 1 day
- Phase 3 (archive-service): 1.5 days
- Phase 4 (optimization): 0.5 days (contingent)
- Phase 5 (production readiness): 0.5 days

---

## Dependencies

- **Infrastructure (M2):** Staging environment must be provisioned with PostgreSQL, RabbitMQ, Spaces
- **Sample Data:** 100k invoices with valid signatures (requires integration with cert-lifecycle-manager)
- **digital-signature-service:** Must be deployed and operational in staging

---

## Success Criteria

✅ **Benchmarks complete when:**
1. digital-signature-service throughput measured and documented
2. archive-service monthly validation tested with 100k invoices
3. Performance extrapolation confirms 10M invoices validated in <1 hour OR optimization plan documented
4. Prometheus alerting thresholds configured based on benchmark data
5. Runbook updated with performance expectations and troubleshooting steps

---

## References

- **ADR-004** §250: "Throughput of monthly validation for >10M invoices requires performance benchmarking"
- **TODO-007 M4:** "Integrate monthly signature validation workflow"
- **CLAUDE.md §10:** Performance budgets (archive retrieve <200ms p95)

---

**Created:** 2025-11-12
**Target Resolution:** Before M4 milestone (2025-12-12)
**Status:** Active
