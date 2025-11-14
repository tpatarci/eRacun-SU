# TASK 5: Performance Benchmarks Validation

## Task Priority
**HIGH** - System must handle expected load without degradation

## Objective
Validate that all services meet defined performance SLAs under realistic load conditions, ensuring the system can handle current requirements (10,000 invoices/hour) and scale toward future targets (100,000+ invoices/hour).

## Scope
Performance testing across:
- API response times (p50, p95, p99)
- Throughput capacity
- Resource utilization
- Queue processing rates
- Database query performance
- Memory and CPU limits

## Detailed Approach

### 1. Baseline Performance Measurement (Day 1)
**Single request benchmarks:**
```bash
# Measure individual endpoint response times
npm run benchmark:baseline

# Expected results:
# Document Upload: <50ms (p50), <200ms (p95)
# Validation Pipeline: <1s (p50), <3s (p95)
# XML Generation: <200ms (p50), <1s (p95)
# FINA Submission: <1s (p50), <3s (p95)
```

**Service-level metrics:**
```javascript
// Capture baseline metrics
const metrics = {
  documentUpload: { p50: 0, p95: 0, p99: 0 },
  validationPipeline: { p50: 0, p95: 0, p99: 0 },
  xmlGeneration: { p50: 0, p95: 0, p99: 0 },
  finaSubmission: { p50: 0, p95: 0, p99: 0 }
};
```

### 2. Load Testing - Current Target (Day 1-2)
**10,000 invoices/hour test:**
```bash
# Using k6 for load testing
k6 run --vus 50 --duration 1h scripts/load-test-current.js

# Monitor during test:
# - Response times
# - Error rates
# - Queue depths
# - Resource usage
```

**Validation checklist:**
- [ ] Sustained 2.8 invoices/second
- [ ] p95 response time <3s
- [ ] Error rate <0.1%
- [ ] CPU usage <70%
- [ ] Memory usage <80%
- [ ] Queue depth stable

### 3. Stress Testing - Future Target (Day 2)
**100,000 invoices/hour test:**
```bash
# Gradual ramp-up to find breaking point
k6 run --vus 500 --stage 10m:100 --stage 30m:500 scripts/stress-test.js

# Identify bottlenecks:
# - First service to fail
# - Resource exhaustion point
# - Queue overflow threshold
```

**Bottleneck analysis:**
- [ ] Database connection pool size
- [ ] Message queue throughput
- [ ] XML validation speed
- [ ] FINA API rate limits
- [ ] Network bandwidth
- [ ] Disk I/O limits

### 4. Resource Utilization Audit (Day 2-3)
**Per-service resource monitoring:**
```bash
# Monitor each service under load
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Verify limits enforced:
# Memory: 512MB baseline, 1GB burst
# CPU: 0.5 cores baseline, 2 cores burst
```

**Resource verification:**
- [ ] Memory limits configured
- [ ] CPU quotas set
- [ ] OOM killer behavior tested
- [ ] Disk I/O within limits (100 IOPS sustained)
- [ ] Network bandwidth adequate
- [ ] Swap usage minimal

### 5. Database Performance Testing (Day 3)
**Query performance analysis:**
```sql
-- Identify slow queries
SELECT query, mean_time, calls
FROM pg_stat_statements
WHERE mean_time > 100
ORDER BY mean_time DESC;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0;
```

**Database optimization checklist:**
- [ ] All queries <100ms (p95)
- [ ] Indexes used appropriately
- [ ] Connection pool sized correctly
- [ ] Vacuum/analyze scheduled
- [ ] Partitioning for large tables
- [ ] Query plans optimized

### 6. Queue Performance Validation (Day 3-4)
**Message throughput testing:**
```bash
# RabbitMQ performance
rabbitmqctl list_queues name messages_ready messages_unacknowledged

# Kafka performance
kafka-run-class kafka.tools.ConsumerPerformance \
  --topic invoice-events \
  --messages 100000 \
  --threads 10
```

**Queue metrics validation:**
- [ ] Message processing rate >100/sec
- [ ] Queue depth remains stable
- [ ] Consumer lag <1000ms
- [ ] Dead letter queue empty
- [ ] Memory usage sustainable
- [ ] Disk space adequate

### 7. Endurance Testing (Day 4)
**24-hour sustained load:**
```bash
# Run overnight at 80% capacity
k6 run --vus 40 --duration 24h scripts/endurance-test.js

# Monitor for:
# - Memory leaks
# - Performance degradation
# - Queue buildup
# - Log file growth
```

## Required Tools
- k6/vegeta for load testing
- Prometheus + Grafana for monitoring
- pprof for profiling
- PostgreSQL pg_stat_statements
- RabbitMQ management plugin
- System monitoring (htop, iotop, netstat)

## Pass/Fail Criteria

### MUST PASS (SLA requirements)
- ✅ Document upload <200ms (p95)
- ✅ Full validation <5s (p99)
- ✅ 10,000 invoices/hour sustained
- ✅ Error rate <0.1%
- ✅ No memory leaks over 24 hours

### RED FLAGS (Performance issues)
- ❌ SLA breaches under normal load
- ❌ Resource exhaustion <80% load
- ❌ Queue buildup during steady state
- ❌ Database queries >500ms
- ❌ Memory growth over time

## Deliverables
1. **Performance Test Report** - All metrics vs SLAs
2. **Bottleneck Analysis** - Identified constraints
3. **Scaling Recommendations** - Path to 100K/hour
4. **Resource Sizing Guide** - Optimal configuration
5. **Performance Dashboard** - Grafana dashboards

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 performance engineer
- **Prerequisites:** Production-like environment with data

## Risk Factors
- **High Risk:** Cannot meet 10K/hour target
- **High Risk:** FINA API throttling
- **Medium Risk:** Database becomes bottleneck
- **Medium Risk:** Message queue overflow
- **Low Risk:** Network latency variations

## Escalation Path
For performance issues:
1. Identify specific bottleneck
2. Review recent code changes
3. Analyze resource utilization
4. Consider vertical scaling (immediate)
5. Plan horizontal scaling (long-term)

## Performance Targets

### Current (Year 1)
- 10,000 invoices/hour
- 5 service instances
- Single droplet deployment

### Near-term (Year 2)
- 100,000 invoices/hour
- 50+ service instances
- Multi-droplet deployment

### Future (Year 3+)
- 1,000,000 invoices/hour
- Kubernetes orchestration
- Auto-scaling enabled

## Related Documentation
- @docs/ARCHITECTURE.md (Section 5: Performance Budgets)
- @docs/guides/performance-tuning.md
- @docs/benchmarks/baseline-metrics.json
- Grafana dashboards configuration
- k6 test scripts in scripts/performance/

## Performance Checklist
- [ ] JIT warming completed before tests
- [ ] Test data representative of production
- [ ] Network conditions realistic
- [ ] Background processes controlled
- [ ] Monitoring gaps identified
- [ ] Alerting thresholds configured
- [ ] Capacity planning documented
- [ ] Cost optimization considered
- [ ] Caching strategies implemented
- [ ] CDN configuration optimized

## Notes
Performance testing must simulate realistic Croatian invoice patterns including peak periods (end of month, end of quarter). The system must maintain performance during FINA maintenance windows by queuing and retrying submissions.