# Docker Compose - Team 3 Services

Complete local development environment for Team 3 (External Integration & Compliance) services.

## Services Included

### Team 3 Services
1. **digital-signature-service** (Port 8088, Metrics 9096)
2. **fina-connector** (Port 3003, Metrics 9097)
3. **archive-service** (Port 3004, Metrics 9098)
4. **dead-letter-handler** (Port 3005, Metrics 9099)
5. **cert-lifecycle-manager** (Port 3006, Metrics 9100)
6. **porezna-connector** (Port 3007, Metrics 9101)
7. **reporting-service** (Port 3008, Metrics 9102)

### Infrastructure Services
- **PostgreSQL** (Port 5432) - Database for archive, dead-letter-handler
- **RabbitMQ** (Port 5672, Management 15672) - Message broker
- **Prometheus** (Port 9090) - Metrics collection
- **Grafana** (Port 3000) - Dashboards and visualization
- **Jaeger** (Port 16686) - Distributed tracing

## Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum (16GB recommended)
- 20GB free disk space

### Start All Services
```bash
docker-compose -f docker-compose.team3.yml up -d
```

### Start Specific Services
```bash
# Infrastructure only
docker-compose -f docker-compose.team3.yml up -d postgres rabbitmq prometheus grafana jaeger

# Team 3 services only
docker-compose -f docker-compose.team3.yml up -d digital-signature-service fina-connector
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.team3.yml logs -f

# Specific service
docker-compose -f docker-compose.team3.yml logs -f fina-connector
```

### Stop Services
```bash
docker-compose -f docker-compose.team3.yml down

# Stop and remove volumes (WARNING: deletes all data)
docker-compose -f docker-compose.team3.yml down -v
```

## Access Points

### Services
- Digital Signature Service: http://localhost:8088
- FINA Connector: http://localhost:3003
- Archive Service: http://localhost:3004
- Dead Letter Handler: http://localhost:3005
- Cert Lifecycle Manager: http://localhost:3006
- Porezna Connector: http://localhost:3007
- Reporting Service: http://localhost:3008

### Infrastructure
- RabbitMQ Management: http://localhost:15672 (user: eracun, password: eracun_password)
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (user: admin, password: admin)
- Jaeger UI: http://localhost:16686

### Metrics Endpoints
- Digital Signature Service: http://localhost:9096/metrics
- FINA Connector: http://localhost:9097/metrics
- Archive Service: http://localhost:9098/metrics
- Dead Letter Handler: http://localhost:9099/metrics
- Cert Lifecycle Manager: http://localhost:9100/metrics
- Porezna Connector: http://localhost:9101/metrics
- Reporting Service: http://localhost:9102/metrics

## Environment Variables

Create a `.env` file in the root directory:

```bash
# FINA Certificate
FINA_CERT_PASSWORD=your-cert-password

# HSM Configuration (for cert-lifecycle-manager)
HSM_PIN=1234

# Porezna API (optional, uses mock by default)
POREZNA_API_KEY=your-api-key
```

## Health Checks

All services include health checks. Check status:

```bash
docker-compose -f docker-compose.team3.yml ps
```

Healthy services show `(healthy)` status.

## Troubleshooting

### Service Won't Start
```bash
# Check logs
docker-compose -f docker-compose.team3.yml logs <service-name>

# Restart service
docker-compose -f docker-compose.team3.yml restart <service-name>
```

### Database Connection Issues
```bash
# Check PostgreSQL logs
docker-compose -f docker-compose.team3.yml logs postgres

# Connect to PostgreSQL
docker-compose -f docker-compose.team3.yml exec postgres psql -U eracun_user -d eracun
```

### RabbitMQ Issues
```bash
# Check RabbitMQ logs
docker-compose -f docker-compose.team3.yml logs rabbitmq

# Access management UI
open http://localhost:15672
```

### Clean Restart
```bash
# Stop all services
docker-compose -f docker-compose.team3.yml down

# Remove volumes (WARNING: deletes all data)
docker-compose -f docker-compose.team3.yml down -v

# Rebuild and start
docker-compose -f docker-compose.team3.yml up -d --build
```

## Development Workflow

### Building Services
```bash
# Build all services
docker-compose -f docker-compose.team3.yml build

# Build specific service
docker-compose -f docker-compose.team3.yml build fina-connector

# Build without cache
docker-compose -f docker-compose.team3.yml build --no-cache
```

### Running Tests
```bash
# Run tests inside container
docker-compose -f docker-compose.team3.yml exec fina-connector npm test

# Run tests with coverage
docker-compose -f docker-compose.team3.yml exec fina-connector npm run test:coverage
```

## Monitoring

### Prometheus Queries
1. Navigate to http://localhost:9090
2. Example queries:
   - `up{team="team-3"}` - Service health
   - `rate(batch_signature_total[5m])` - Batch signing rate
   - `circuit_breaker_open` - Circuit breaker status

### Grafana Dashboards
1. Navigate to http://localhost:3000
2. Login (admin/admin)
3. Dashboards should be auto-provisioned

### Jaeger Traces
1. Navigate to http://localhost:16686
2. Select service from dropdown
3. View distributed traces

## Performance Testing

See `scripts/k6/` for load testing scripts.

## Production Deployment

This docker-compose is for **development only**. For production:
- Use managed PostgreSQL (DigitalOcean Managed Database)
- Use managed RabbitMQ or Kafka
- Deploy services individually with systemd
- See `deployment/systemd/` for production configurations

## Support

For issues:
- Check service logs: `docker-compose logs <service>`
- Check health: `docker-compose ps`
- See RUNBOOK.md for common issues
