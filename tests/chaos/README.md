# Chaos Testing for eRačun Services

**Purpose:** Validate system resilience under failure conditions and verify recovery mechanisms.

## Philosophy

Chaos engineering is the discipline of experimenting on a system to build confidence in its capability to withstand turbulent conditions in production.

**Goals:**
- Verify circuit breakers prevent cascading failures
- Validate retry mechanisms with exponential backoff
- Ensure graceful degradation when dependencies fail
- Test system recovery after infrastructure failures
- Identify weaknesses before they cause outages

---

## Prerequisites

### Tools Required

**Docker Compose** (for controlled dependency failures):
```bash
docker-compose --version  # Should be 2.0+
```

**Toxiproxy** (for network failure injection):
```bash
# Install toxiproxy
wget -O toxiproxy-2.5.0.tar.gz https://github.com/Shopify/toxiproxy/releases/download/v2.5.0/toxiproxy-server-linux-amd64
tar -xzf toxiproxy-2.5.0.tar.gz
sudo mv toxiproxy-server /usr/local/bin/
toxiproxy-server --version
```

**Pumba** (for Docker chaos):
```bash
# Docker chaos tool
docker pull gaiaadm/pumba
```

**Node.js** (for test runner):
```bash
node --version  # Should be 20.x+
```

---

## Chaos Scenarios

### Scenario 1: Database Connection Failure

**Hypothesis:** When PostgreSQL is unavailable, the service should:
1. Reject new requests with 503 Service Unavailable
2. Mark health check as unhealthy
3. Automatically reconnect when database recovers
4. Not crash or leak connections

**Failure Injection:**
```bash
# Stop PostgreSQL container
docker-compose stop postgres

# Wait for services to detect failure (circuit breaker opens)
sleep 10

# Verify services return 503
curl -i http://localhost:3000/api/v1/invoices

# Restart PostgreSQL
docker-compose start postgres

# Verify services recover automatically (circuit breaker closes)
sleep 30
curl -i http://localhost:3000/api/v1/health
```

**Expected Behavior:**
- Services return 503 while database is down
- Health endpoint shows `database: "unhealthy"`
- Services automatically reconnect within 30 seconds
- No connection leaks (check with `SELECT count(*) FROM pg_stat_activity`)
- Circuit breaker metrics show state transitions

**Run Test:**
```bash
npm run chaos:database
```

---

### Scenario 2: RabbitMQ Message Broker Failure

**Hypothesis:** When RabbitMQ is unavailable, the system should:
1. Queue messages locally or reject with proper error
2. Retry connection with exponential backoff
3. Reprocess messages after recovery
4. Not lose any messages (durability guarantee)

**Failure Injection:**
```bash
# Stop RabbitMQ
docker-compose stop rabbitmq

# Attempt invoice submission
curl -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -d @tests/fixtures/valid-invoice.xml

# Restart RabbitMQ
docker-compose start rabbitmq

# Verify queued messages are processed
sleep 30
```

**Expected Behavior:**
- Services return 503 or queue locally
- Retry attempts visible in logs (with exponential backoff)
- Messages processed after recovery
- Dead letter queue remains empty
- Circuit breaker prevents cascading failures

**Run Test:**
```bash
npm run chaos:rabbitmq
```

---

### Scenario 3: Network Latency and Packet Loss

**Hypothesis:** When network conditions degrade, the system should:
1. Respect timeouts and fail fast
2. Retry transient failures
3. Maintain throughput within acceptable limits
4. Not block indefinitely

**Failure Injection (using Toxiproxy):**
```bash
# Add 500ms latency to database connections
toxiproxy-cli toxic add \
  -n latency_downstream \
  -t latency \
  -a latency=500 \
  postgres-proxy

# Add 20% packet loss
toxiproxy-cli toxic add \
  -n packet_loss \
  -t down \
  -a loss=0.2 \
  postgres-proxy

# Run load test
k6 run --vus 10 --duration 2m tests/load/invoice-submission.js

# Remove toxics
toxiproxy-cli toxic remove -n latency_downstream postgres-proxy
toxiproxy-cli toxic remove -n packet_loss postgres-proxy
```

**Expected Behavior:**
- p95 response time increases but stays below timeout
- Error rate increases but stays below 10%
- Circuit breakers open to prevent cascading failures
- System recovers when toxics are removed
- No permanent degradation

**Run Test:**
```bash
npm run chaos:network
```

---

### Scenario 4: CPU Throttling

**Hypothesis:** Under CPU starvation, the system should:
1. Process requests slower but not fail
2. Reject new requests if queue is full
3. Health checks continue to respond
4. Recover when CPU is available again

**Failure Injection (using Pumba):**
```bash
# Limit invoice-gateway-api CPU to 20%
docker run -d --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gaiaadm/pumba pause \
  --duration 2m \
  --interval 5s \
  --duration 4s \
  invoice-gateway-api

# Run load test
k6 run --vus 50 --duration 2m tests/load/invoice-submission.js
```

**Expected Behavior:**
- Response times increase significantly
- Error rate stays below 5%
- Health checks continue responding (may be slow)
- Queue depths increase but don't overflow
- System recovers after CPU throttling stops

**Run Test:**
```bash
npm run chaos:cpu
```

---

### Scenario 5: Memory Pressure

**Hypothesis:** Under memory pressure, the system should:
1. Gracefully handle OOM (Out of Memory) conditions
2. systemd restarts service automatically
3. Service recovers without manual intervention
4. No data corruption or loss

**Failure Injection:**
```bash
# Set strict memory limit on container
docker update --memory 256m invoice-gateway-api

# Generate memory-intensive load (large invoices)
for i in {1..1000}; do
  curl -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(uuidgen)" \
    -d @tests/fixtures/large-invoice-5mb.xml &
done

# Monitor for OOM kill
docker logs -f invoice-gateway-api
```

**Expected Behavior:**
- Service OOM killed by Docker/systemd
- systemd automatically restarts service (`Restart=on-failure`)
- Service recovers within 30 seconds
- No messages lost (RabbitMQ requeues unacknowledged messages)
- Prometheus alerts fire for high memory usage

**Run Test:**
```bash
npm run chaos:memory
```

---

### Scenario 6: Cascading Service Failures

**Hypothesis:** When validation-coordinator fails, the system should:
1. Prevent cascade to invoice-orchestrator
2. Circuit breaker opens after threshold
3. Requests return 503 instead of hanging
4. System recovers when validation-coordinator restarts

**Failure Injection:**
```bash
# Stop validation-coordinator
systemctl stop eracun-validation-coordinator

# Continuously submit invoices
for i in {1..100}; do
  curl -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(uuidgen)" \
    -d @tests/fixtures/valid-invoice.xml
  sleep 0.5
done

# Observe circuit breaker opening
curl http://localhost:9101/metrics | grep circuit_breaker

# Restart validation-coordinator
systemctl start eracun-validation-coordinator

# Wait for circuit breaker to close (30s cooldown)
sleep 30
```

**Expected Behavior:**
- First ~3 requests fail and retry
- Circuit breaker opens after 50% failure rate
- Subsequent requests fail fast with 503
- invoice-orchestrator remains healthy
- Circuit breaker closes after service recovers

**Run Test:**
```bash
npm run chaos:cascade
```

---

### Scenario 7: Partial Network Partition (Split Brain)

**Hypothesis:** When network partition separates services, the system should:
1. Detect partition via health checks
2. Avoid processing same invoice twice
3. Maintain data consistency
4. Automatically recover when partition heals

**Failure Injection (using iptables):**
```bash
# Block traffic from invoice-orchestrator to validation-coordinator
sudo iptables -A OUTPUT -p tcp -d validation-coordinator-ip --dport 9103 -j DROP

# Submit invoice (will get stuck in orchestrator)
curl -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -H "X-Idempotency-Key: test-partition-001" \
  -d @tests/fixtures/valid-invoice.xml

# Wait for timeout
sleep 60

# Remove partition
sudo iptables -D OUTPUT -p tcp -d validation-coordinator-ip --dport 9103 -j DROP

# Verify invoice processed once (idempotency)
curl http://localhost:3000/api/v1/invoices/$(cat last-invoice-id.txt)
```

**Expected Behavior:**
- Request times out after configured duration (30s)
- Saga rolls back or retries
- No duplicate processing (idempotency key prevents)
- System recovers automatically
- Distributed tracing shows timeout

**Run Test:**
```bash
npm run chaos:partition
```

---

## Running All Chaos Tests

### Quick Smoke Test (5 minutes)
```bash
npm run chaos:smoke
```

Runs abbreviated versions of all scenarios.

### Full Chaos Suite (30 minutes)
```bash
npm run chaos:full
```

Runs all scenarios with extended durations.

### Continuous Chaos (background)
```bash
npm run chaos:continuous
```

Runs random chaos scenarios continuously (for staging environment).

---

## Test Infrastructure Setup

### Docker Compose with Toxiproxy

**docker-compose.chaos.yml:**
```yaml
version: '3.8'

services:
  toxiproxy:
    image: ghcr.io/shopify/toxiproxy:2.5.0
    ports:
      - "8474:8474"  # API
      - "5433:5433"  # Proxied PostgreSQL
      - "5673:5673"  # Proxied RabbitMQ
    networks:
      - eracun-test

  postgres-proxy:
    image: ghcr.io/shopify/toxiproxy:2.5.0
    environment:
      - PROXY_NAME=postgres-proxy
      - UPSTREAM=postgres:5432
      - LISTEN=0.0.0.0:5433

  rabbitmq-proxy:
    image: ghcr.io/shopify/toxiproxy:2.5.0
    environment:
      - PROXY_NAME=rabbitmq-proxy
      - UPSTREAM=rabbitmq:5672
      - LISTEN=0.0.0.0:5673

networks:
  eracun-test:
    driver: bridge
```

**Start:**
```bash
docker-compose -f docker-compose.chaos.yml up -d
```

---

## Metrics and Observability

### Key Metrics to Monitor

**Circuit Breaker State:**
```promql
circuit_breaker_state{service="invoice-orchestrator", dependency="validation-coordinator"}
```

**Retry Attempts:**
```promql
rate(retry_attempts_total{service="invoice-orchestrator"}[5m])
```

**Error Rate:**
```promql
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])
```

**Recovery Time:**
```promql
histogram_quantile(0.95, rate(service_recovery_duration_seconds_bucket[5m]))
```

### Grafana Dashboard

**Chaos Testing Dashboard:** `http://grafana.eracun.internal/d/chaos-testing`

**Panels:**
- Circuit breaker states (gauge)
- Retry attempts (counter)
- Error rates (graph)
- Service health status (status map)
- Resource utilization (CPU, memory, disk)

---

## Safety Guidelines

### ⚠️ NEVER Run Chaos Tests In Production

**Staging Only:**
- All chaos tests run in staging environment
- Production has chaos engineering disabled by default
- `CHAOS_ENABLED=false` in production config

### Prerequisites Before Running
- [ ] Ensure all services are healthy
- [ ] Verify backups are recent
- [ ] Notify team in Slack (#team-1-core-pipeline)
- [ ] Have rollback plan ready
- [ ] Monitor Grafana during tests

### Cleanup After Tests
```bash
# Reset all Docker containers
docker-compose -f docker-compose.chaos.yml down
docker-compose up -d

# Clear toxiproxy toxics
toxiproxy-cli toxic remove --all

# Reset iptables rules
sudo iptables -F

# Verify all services healthy
curl http://localhost:3000/api/v1/health
```

---

## Interpreting Results

### Pass Criteria

✅ **PASS** if:
- Circuit breakers open/close correctly
- Services recover within 60 seconds
- No data loss or corruption
- Error rate during failure < 10%
- Health checks continue responding

❌ **FAIL** if:
- Services crash and don't restart
- Circuit breakers never open (cascading failures)
- Data loss occurs
- Services don't recover automatically
- Memory leaks or connection leaks

### Example Report

```
Chaos Test Report - 2025-11-14

Scenario: Database Connection Failure
Status: ✅ PASS
Duration: 5m 23s

Metrics:
- Service downtime: 45s (expected: <60s)
- Circuit breaker opened: 12s (expected: <30s)
- Error rate during failure: 8.3% (threshold: <10%)
- Messages lost: 0 (expected: 0)
- Recovery time: 18s (expected: <60s)

Observations:
- Circuit breaker opened after 3 failed connection attempts
- Services returned 503 during database downtime
- Automatic reconnection successful
- No connection leaks detected

Recommendations:
- Reduce circuit breaker threshold to 2 attempts (faster failure detection)
- Add exponential backoff to reconnection attempts
```

---

## Integration with CI/CD

### GitLab CI/CD

```yaml
chaos-testing:
  stage: test
  only:
    - staging
  script:
    - npm run chaos:smoke
  allow_failure: true  # Don't block deployment on chaos failures
  artifacts:
    reports:
      junit: chaos-test-results.xml
```

### GitHub Actions

```yaml
- name: Run chaos tests
  if: github.ref == 'refs/heads/staging'
  run: |
    npm run chaos:smoke
  continue-on-error: true
```

---

## References

- [Principles of Chaos Engineering](https://principlesofchaos.org/)
- [Netflix Chaos Monkey](https://netflix.github.io/chaosmonkey/)
- [Toxiproxy Documentation](https://github.com/Shopify/toxiproxy)
- [Pumba Documentation](https://github.com/alexei-led/pumba)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)

---

**Last Updated:** 2025-11-14
**Maintained By:** Team 1 - Core Processing Pipeline
**Review Cadence:** After each major deployment
