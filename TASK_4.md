# TASK 4: Integration Endpoints Health Check

## Task Priority
**CRITICAL** - External integrations are mandatory for compliance

## Objective
Verify all internal and external integration endpoints are properly configured, tested, and resilient to failures. Focus on FINA integration, inter-service communication, and third-party APIs.

## Scope
Comprehensive integration testing covering:
- FINA Tax Authority endpoints (test and production)
- Inter-service messaging (RabbitMQ/Kafka)
- Database connections and pooling
- External API integrations
- Health check endpoints
- Circuit breaker functionality

## Detailed Approach

### 1. FINA Integration Validation (Day 1)
**Test environment connectivity:**
```bash
# Test FINA test endpoint
curl -X POST https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest \
  --cert /etc/eracun/certs/fina-demo.p12:password \
  --header "Content-Type: text/xml" \
  --data @test/fixtures/valid-invoice.xml \
  --write-out "\nHTTP Status: %{http_code}\nTime: %{time_total}s\n"
```

**Production readiness verification:**
- [ ] Test endpoint responding (cistest.apis-it.hr)
- [ ] Production endpoint DNS resolves (cis.porezna-uprava.hr)
- [ ] Demo certificates authenticate successfully
- [ ] SOAP envelope structure validated
- [ ] Response parsing working (JIR extraction)
- [ ] AS4 protocol configured for B2B

### 2. Message Bus Health Check (Day 1-2)
**RabbitMQ validation:**
```bash
# Check RabbitMQ cluster health
rabbitmqctl cluster_status
rabbitmqctl list_queues name messages consumers

# Test message publishing
npm run test:rabbitmq-publish

# Verify dead letter queues
rabbitmqctl list_queues name messages_dead_letter
```

**Kafka validation:**
```bash
# Check Kafka brokers
kafka-topics --bootstrap-server localhost:9092 --list

# Test event streaming
kafka-console-producer --topic invoice-events --bootstrap-server localhost:9092
kafka-console-consumer --topic invoice-events --from-beginning --bootstrap-server localhost:9092
```

**Message flow verification:**
- [ ] All queues created and accessible
- [ ] Consumer groups properly configured
- [ ] Dead letter queues operational
- [ ] Message TTL configured
- [ ] Acknowledgment modes correct
- [ ] Retry policies implemented

### 3. Database Connection Testing (Day 2)
**PostgreSQL health check:**
```bash
# Test connection pooling
psql -h localhost -U eracun -c "SELECT count(*) FROM pg_stat_activity;"

# Check PgBouncer status
psql -p 6432 -U pgbouncer -d pgbouncer -c "SHOW POOLS;"
psql -p 6432 -U pgbouncer -d pgbouncer -c "SHOW STATS;"
```

**Connection pool verification:**
- [ ] Pool size limits configured (20 per service)
- [ ] Connection timeout set (30s)
- [ ] Idle connection cleanup working
- [ ] Transaction timeout configured
- [ ] Prepared statements cached
- [ ] Connection retry logic tested

### 4. Inter-Service Communication (Day 2-3)
**gRPC health checks:**
```bash
# Test each gRPC service
grpc_health_probe -addr=localhost:50051 -service=SchemaValidator
grpc_health_probe -addr=localhost:50052 -service=AIValidation
```

**REST API validation:**
```bash
# Test all service health endpoints
for port in 3001 3002 3003 3004 3005; do
  echo "Testing service on port ${port}"
  curl -f http://localhost:${port}/health || echo "FAILED"
done
```

**Service mesh verification:**
- [ ] All services discoverable
- [ ] Health endpoints responding
- [ ] Load balancing working
- [ ] Request tracing propagated
- [ ] mTLS certificates valid
- [ ] Service versioning handled

### 5. Circuit Breaker Testing (Day 3)
**Failure simulation:**
```javascript
// Test circuit breaker opening
for (let i = 0; i < 10; i++) {
  try {
    await finaService.submit(invoice); // Will fail
  } catch (e) {
    console.log(`Attempt ${i}: ${e.message}`);
  }
}
// Circuit should open after 50% failure rate
```

**Circuit breaker verification:**
- [ ] Opens at configured threshold (50% failures)
- [ ] Half-open state after timeout (30s)
- [ ] Closes after successful requests
- [ ] Fallback responses working
- [ ] Metrics exported to Prometheus
- [ ] Alerts configured for open circuits

### 6. External Dependencies Audit (Day 3-4)
**Third-party API checks:**
- [ ] Croatian business registry API
- [ ] OIB validation service
- [ ] KPD classification service
- [ ] Email service provider
- [ ] SMS notification service
- [ ] Monitoring/alerting services

**For each dependency verify:**
- [ ] API keys/credentials configured
- [ ] Rate limits understood and handled
- [ ] Timeout configuration (5s default)
- [ ] Retry logic with backoff
- [ ] Error handling graceful
- [ ] Monitoring in place

## Required Tools
- curl/httpie for API testing
- grpc_health_probe for gRPC
- RabbitMQ management CLI
- Kafka CLI tools
- PostgreSQL client
- Network diagnostic tools
- Load testing tools (k6/vegeta)

## Pass/Fail Criteria

### MUST PASS (Integration requirements)
- ✅ FINA test endpoint connectivity confirmed
- ✅ All message queues operational
- ✅ Database connection pools healthy
- ✅ All service health checks passing
- ✅ Circuit breakers functioning correctly

### RED FLAGS (Integration failures)
- ❌ FINA endpoints unreachable
- ❌ Message queue backlogs >1000
- ❌ Database connection pool exhaustion
- ❌ Services failing health checks
- ❌ No retry/fallback mechanisms

## Deliverables
1. **Integration Test Report** - All endpoints with response times
2. **Dependency Matrix** - External services and their SLAs
3. **Circuit Breaker Dashboard** - Current states and metrics
4. **Performance Baseline** - Normal operation metrics
5. **Failure Playbook** - Response procedures for outages

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 senior engineer
- **Prerequisites:** All services deployed, test data available

## Risk Factors
- **Critical Risk:** FINA endpoint changes without notice
- **High Risk:** Message queue failures during peak
- **High Risk:** Database connection exhaustion
- **Medium Risk:** Third-party API rate limits
- **Low Risk:** Transient network issues

## Escalation Path
For integration failures:
1. Check service status dashboard
2. Review recent deployments
3. Contact external service providers if needed
4. Implement fallback procedures
5. Update incident log

## Integration SLAs
- **FINA Response:** <3s (p99)
- **Inter-service:** <50ms (p95)
- **Database queries:** <100ms (p95)
- **Message processing:** <1s (p95)
- **Health checks:** <100ms

## Related Documentation
- @docs/api-contracts/fina-integration.md
- @docs/ARCHITECTURE.md (Section 1: Service Communication)
- @docs/guides/rabbitmq-setup.md
- @docs/guides/circuit-breaker-patterns.md
- Service README files for API contracts

## Integration Checklist
- [ ] FINA WSDL imported and validated
- [ ] Message schemas versioned (Protocol Buffers)
- [ ] Database migrations up to date
- [ ] API rate limits configured
- [ ] Webhook endpoints secured (HMAC)
- [ ] Distributed tracing enabled
- [ ] Correlation IDs propagated
- [ ] Timeout budgets defined
- [ ] Graceful degradation tested
- [ ] Monitoring alerts configured

## Notes
Integration health is critical for system reliability. The system must handle FINA outages gracefully while maintaining compliance. All integrations must be tested under failure conditions to ensure resilience.