# Load Testing Suite

Performance and load testing for eRačun services using k6.

## Prerequisites

### Install k6

**macOS:**
```bash
brew install k6
```

**Linux:**
```bash
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

**Windows:**
```powershell
choco install k6
```

## Running Tests

### Quick Smoke Test (10 VUs, 1 minute)
```bash
k6 run --vus 10 --duration 1m tests/load/invoice-submission.js
```

### Standard Load Test (50 VUs, 10 minutes)
```bash
k6 run --vus 50 --duration 10m tests/load/invoice-submission.js
```

### Stress Test (200 VUs, 30 minutes)
```bash
k6 run --vus 200 --duration 30m tests/load/invoice-submission.js
```

### Custom Scenarios
```bash
# Custom VUs and duration
k6 run --vus 100 --duration 5m tests/load/invoice-submission.js

# Against staging environment
BASE_URL=https://staging.eracun.hr k6 run tests/load/invoice-submission.js

# With results export
k6 run --out json=results.json tests/load/invoice-submission.js
```

## Test Scenarios

### invoice-submission.js

Tests the invoice submission workflow with progressive load:

**Load Profile:**
1. **Ramp-up (2 min):** 0 → 50 users
2. **Sustained (10 min):** 50 users
3. **Peak ramp (2 min):** 50 → 100 users
4. **Sustained peak (10 min):** 100 users
5. **Spike (1 min):** 100 → 200 users
6. **Sustained spike (5 min):** 200 users
7. **Ramp-down (2 min):** 200 → 0 users

**Total Duration:** ~34 minutes

**Tests Performed:**
- Invoice submission (POST /api/v1/invoices)
- Idempotency verification (duplicate POST)
- Status retrieval (GET /api/v1/invoices/:id)
- Health checks (GET /api/v1/health)

**Performance Thresholds:**
- p95 response time: < 200ms
- p99 response time: < 500ms
- Error rate: < 1%
- Success rate: > 99%

## Interpreting Results

### Sample Output

```
✓ submission status is 202
✓ submission has invoiceId
✓ submission duration < 200ms
✓ idempotency returns same invoice ID

checks.........................: 99.85% ✓ 45892  ✗ 69
data_received..................: 128 MB 224 kB/s
data_sent......................: 98 MB  172 kB/s
http_req_blocked...............: avg=12.45ms  min=1µs   med=3µs    max=1.84s  p(90)=5µs    p(95)=6µs
http_req_connecting............: avg=4.12ms   min=0s    med=0s     max=1.23s  p(90)=0s     p(95)=0s
http_req_duration..............: avg=152.34ms min=8.74ms med=138ms max=2.91s  p(90)=245ms p(95)=298ms
  { expected_response:true }...: avg=152.34ms min=8.74ms med=138ms max=2.91s  p(90)=245ms p(95)=298ms
http_req_failed................: 0.15%  ✓ 69     ✗ 45823
http_req_receiving.............: avg=89.71µs  min=15µs  med=70µs   max=18.36ms p(90)=142µs p(95)=189µs
http_req_sending...............: avg=45.13µs  min=7µs   med=34µs   max=17.29ms p(90)=68µs  p(95)=93µs
http_req_tls_handshaking.......: avg=0s       min=0s    med=0s     max=0s     p(90)=0s    p(95)=0s
http_req_waiting...............: avg=152.21ms min=8.67ms med=137.87ms max=2.91s p(90)=244.82ms p(95)=297.89ms
http_reqs......................: 45892  80.33/s
iteration_duration.............: avg=2.45s    min=1.02s med=2.34s  max=8.12s  p(90)=3.67s p(95)=4.23s
iterations.....................: 11473  20.08/s
submission_duration............: avg=152.45ms min=12.34ms med=139ms max=2.82s p(90)=246ms p(95)=299ms
success_rate...................: 99.85% ✓ 11458  ✗ 15
vus............................: 1      min=1    max=200
vus_max........................: 200    min=200  max=200
```

### Key Metrics Explained

- **http_req_duration:** Time from request start to response end
  - **p(95):** 95% of requests completed within this time
  - **p(99):** 99% of requests completed within this time

- **http_req_failed:** Percentage of failed requests (4xx, 5xx)

- **success_rate:** Custom metric tracking successful submissions

- **submission_duration:** Time specifically for invoice submissions

- **http_reqs:** Total requests per second (throughput)

### Pass/Fail Criteria

✅ **PASS** if:
- p95 < 200ms
- p99 < 500ms
- Error rate < 1%
- Success rate > 99%

❌ **FAIL** if any threshold is exceeded

## Performance Targets

### invoice-gateway-api

| Metric | Target | Threshold |
|--------|--------|-----------|
| Document upload (p95) | < 150ms | < 200ms |
| Document upload (p99) | < 300ms | < 500ms |
| Status query (p95) | < 30ms | < 50ms |
| Throughput | 10,000/hour | 8,000/hour minimum |
| Error rate | < 0.1% | < 1% |

### Resource Utilization

Monitor these metrics during load tests:

```bash
# CPU usage
top -p $(pgrep -f invoice-gateway-api)

# Memory usage
ps aux | grep invoice-gateway-api

# Prometheus metrics
curl http://localhost:3000/metrics | grep -E "(cpu|memory|active_requests)"
```

## Grafana Dashboard

Monitor live metrics during load tests:

**Dashboard:** [k6 Load Test Metrics](http://grafana.eracun.internal/d/load-tests)

**Key Panels:**
- Request rate (req/s)
- Response time (p95, p99)
- Error rate
- Active VUs
- Resource utilization

## Troubleshooting

### High Error Rate

```bash
# Check service logs
sudo journalctl -u eracun-invoice-gateway-api -f

# Check resource limits
curl http://localhost:3000/metrics | grep -E "(active_requests|memory)"

# Verify dependencies
curl http://localhost:3000/api/v1/health
```

### Slow Response Times

```bash
# Check database connection pool
curl http://localhost:3000/metrics | grep db_connection_pool

# Review Jaeger traces
open http://jaeger.eracun.internal:16686

# Check for rate limiting
curl http://localhost:3000/metrics | grep rate_limited
```

### Connection Errors

```bash
# Check open connections
netstat -an | grep 3000 | grep ESTABLISHED | wc -l

# Increase system limits
ulimit -n 65536

# Check service status
systemctl status eracun-invoice-gateway-api
```

## CI/CD Integration

### GitLab CI

```yaml
performance-test:
  stage: test
  image: grafana/k6:latest
  script:
    - k6 run --out json=results.json tests/load/invoice-submission.js
  artifacts:
    reports:
      junit: results.json
  only:
    - main
    - staging
```

### GitHub Actions

```yaml
- name: Run k6 load test
  uses: grafana/k6-action@v0.3.0
  with:
    filename: tests/load/invoice-submission.js
    cloud: false
```

## Best Practices

1. **Always run smoke tests first** (10 VUs, 1 min)
2. **Monitor resource usage** during tests
3. **Run tests against staging** before production
4. **Gradually increase load** (don't spike immediately)
5. **Document baseline metrics** for comparison
6. **Review Grafana dashboards** during tests
7. **Analyze Jaeger traces** for bottlenecks

## References

- [k6 Documentation](https://k6.io/docs/)
- [Performance Testing Checklist](../../docs/guides/performance-testing.md)
- [Grafana Dashboards](http://grafana.eracun.internal)

---

**Last Updated:** 2025-11-14
**Maintained By:** Team 1 - Core Processing Pipeline
