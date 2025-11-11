# Health Monitor Service - Operations Runbook

**Service:** health-monitor
**Purpose:** System-wide health monitoring for all 40 services and external dependencies
**Last Updated:** 2025-11-11

## Quick Start

### Deployment
```bash
# Deploy service files
sudo rsync -av dist/ /opt/eracun/services/health-monitor/dist/
sudo rsync -av config/ /opt/eracun/services/health-monitor/config/

# Configure environment
sudo cp .env.example /etc/eracun/health-monitor.env
sudo nano /etc/eracun/health-monitor.env

# Install systemd unit
sudo cp deployment/eracun-health-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable eracun-health-monitor
sudo systemctl start eracun-health-monitor
```

### Health Checks
```bash
# Service health
curl http://localhost:8084/health

# Dashboard data
curl http://localhost:8084/health/dashboard

# Metrics
curl http://localhost:8084/metrics
```

## Monitoring

### Key Metrics
- `service_health_status` - Service health (1=healthy, 0.5=degraded, 0=unhealthy)
- `health_check_success_total` - Successful checks
- `health_check_failures_total` - Failed checks
- `circuit_breaker_state` - Circuit breaker states
- `health_check_duration_seconds` - Check latency

### Alerts
- **P0:** Critical service unhealthy, circuit breaker open >5min
- **P1:** Critical service degraded, circuit breaker just opened

## Common Issues

### Issue: Health Monitor Down
**Impact:** No centralized health visibility
**Resolution:**
```bash
sudo systemctl restart eracun-health-monitor
sudo journalctl -u eracun-health-monitor -f
```

### Issue: Many Services Unhealthy
**Impact:** System-wide outage
**Resolution:** Page on-call (P0), check external dependencies first (RabbitMQ, PostgreSQL, Kafka)

### Issue: False Positive Alerts
**Mitigation:** Service requires 3 consecutive failures before marked UNHEALTHY

## API Endpoints

- `GET /health/dashboard` - All services status
- `GET /health/services/:name` - Specific service details
- `GET /health/external` - External dependency health
- `GET /health/circuit-breakers` - Circuit breaker states
- `GET /health/history/:service` - Historical health (24h)

## Configuration

**Service Registry:** `/opt/eracun/services/health-monitor/config/services.json`
- Contains all 40 services to monitor
- Update this file to add/remove services
- Restart service after changes

**Environment:** `/etc/eracun/health-monitor.env`
- Database URLs, Kafka brokers, RabbitMQ credentials
- Never commit secrets to git

## Troubleshooting

```bash
# View logs
sudo journalctl -u eracun-health-monitor -n 100

# Check service status
sudo systemctl status eracun-health-monitor

# Test manually
sudo -u eracun bash
cd /opt/eracun/services/health-monitor
source /etc/eracun/health-monitor.env
node dist/index.js
```

## Disaster Recovery

**RTO:** 5 minutes (restart service)
**RPO:** 0 (stateless, no data loss)

If health-monitor fails, individual services remain operational. External monitoring should detect health-monitor failure.
