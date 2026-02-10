# Docker Compose Development Guide

## Overview

This guide explains how to use Docker Compose for local development of the eRačun platform. The Docker Compose setup provides a complete development environment with all infrastructure services and Team 3 application services.

## Architecture

### Infrastructure Services
- **PostgreSQL** - State database (port 5432)
- **RabbitMQ** - Message broker (ports 5672, 15672)
- **Redis** - Cache layer (port 6379)
- **Prometheus** - Metrics collection (port 9090)
- **Grafana** - Metrics visualization (port 3000)
- **Jaeger** - Distributed tracing (ports 16686, 14268)

### Team 3 Application Services
- **cert-lifecycle-manager** - Certificate management (HTTP: 3001, Metrics: 9101)
- **fina-connector** - FINA Tax Authority integration (HTTP: 3002, Metrics: 9102)
- **porezna-connector** - Porezna Uprava integration (HTTP: 3003, Metrics: 9103)
- **digital-signature-service** - XMLDSig signing (HTTP: 3004, Metrics: 9104)
- **archive-service** - 11-year document retention (HTTP: 3005, Metrics: 9105)
- **reporting-service** - Compliance reporting (HTTP: 3006, Metrics: 9106)
- **dead-letter-handler** - Failed message recovery (HTTP: 3007, Metrics: 9107)

## Quick Start

### 1. Start Infrastructure Only

For active development where you run services locally:

```bash
# Start only infrastructure services
docker-compose up -d postgres rabbitmq redis prometheus grafana jaeger

# View logs
docker-compose logs -f postgres rabbitmq

# Check status
docker-compose ps
```

### 2. Start Everything

To run all services in Docker:

```bash
# Start all services
docker-compose up -d

# View logs for specific service
docker-compose logs -f cert-lifecycle-manager

# View logs for all services
docker-compose logs -f

# Check health status
docker-compose ps
```

### 3. Start Specific Services

```bash
# Start only cert-lifecycle-manager and its dependencies
docker-compose up -d postgres jaeger cert-lifecycle-manager

# Start FINA connector with dependencies
docker-compose up -d postgres rabbitmq jaeger cert-lifecycle-manager fina-connector
```

## Common Operations

### Build Services

```bash
# Build all services
docker-compose build

# Build specific service
docker-compose build cert-lifecycle-manager

# Build with no cache (clean build)
docker-compose build --no-cache cert-lifecycle-manager

# Build in parallel
docker-compose build --parallel
```

### Stop and Remove

```bash
# Stop all services
docker-compose stop

# Stop specific service
docker-compose stop cert-lifecycle-manager

# Remove stopped containers
docker-compose down

# Remove containers and volumes (clean slate)
docker-compose down -v

# Remove containers, volumes, and images
docker-compose down -v --rmi all
```

### View Logs

```bash
# Follow logs for all services
docker-compose logs -f

# Follow logs for specific service
docker-compose logs -f fina-connector

# View last 100 lines
docker-compose logs --tail=100 cert-lifecycle-manager

# View logs since timestamp
docker-compose logs --since 2023-01-01T00:00:00 fina-connector
```

### Execute Commands

```bash
# Execute command in running container
docker-compose exec cert-lifecycle-manager sh

# Run one-off command
docker-compose run --rm cert-lifecycle-manager npm test

# Access PostgreSQL
docker-compose exec postgres psql -U eracun -d eracun

# Access RabbitMQ management CLI
docker-compose exec rabbitmq rabbitmqctl list_queues
```

### Restart Services

```bash
# Restart specific service
docker-compose restart cert-lifecycle-manager

# Restart after code changes (rebuild)
docker-compose up -d --build cert-lifecycle-manager

# Force recreate container
docker-compose up -d --force-recreate cert-lifecycle-manager
```

## Development Workflows

### Workflow 1: Local Development with Infrastructure

**Use Case**: Active development, fast feedback loop

```bash
# 1. Start infrastructure
docker-compose up -d postgres rabbitmq redis prometheus grafana jaeger

# 2. Run services locally
cd services/cert-lifecycle-manager
npm install
npm run dev

# 3. Stop infrastructure when done
docker-compose stop
```

**Advantages**:
- Fast hot-reload with ts-node or nodemon
- Direct debugging in IDE
- Immediate code changes
- Lower memory usage

### Workflow 2: Full Docker Development

**Use Case**: Integration testing, production-like environment

```bash
# 1. Build and start all services
docker-compose up -d --build

# 2. Make code changes
# Edit services/cert-lifecycle-manager/src/index.ts

# 3. Rebuild and restart
docker-compose up -d --build cert-lifecycle-manager

# 4. View logs
docker-compose logs -f cert-lifecycle-manager

# 5. Clean up
docker-compose down
```

**Advantages**:
- Production-like environment
- Full service-to-service integration
- Tests inter-service communication
- Validates Docker configuration

### Workflow 3: Hybrid Development

**Use Case**: Develop one service, use Docker for others

```bash
# 1. Start infrastructure + most services
docker-compose up -d

# 2. Stop service you're developing
docker-compose stop cert-lifecycle-manager

# 3. Run that service locally
cd services/cert-lifecycle-manager
npm run dev

# 4. Service can still communicate with others via localhost
# PostgreSQL: localhost:5432
# RabbitMQ: localhost:5672
# Redis: localhost:6379
```

**Advantages**:
- Best of both worlds
- Fast iteration on one service
- Integration with other services
- Flexible debugging

## Troubleshooting

### Service Won't Start

```bash
# Check logs for errors
docker-compose logs cert-lifecycle-manager

# Check if port is already in use
lsof -i :3001

# Rebuild with no cache
docker-compose build --no-cache cert-lifecycle-manager

# Remove and recreate container
docker-compose rm -f cert-lifecycle-manager
docker-compose up -d cert-lifecycle-manager
```

### Database Connection Errors

```bash
# Check if PostgreSQL is healthy
docker-compose ps postgres

# Test connection
docker-compose exec postgres pg_isready -U eracun

# View PostgreSQL logs
docker-compose logs postgres

# Reset database (WARNING: deletes all data)
docker-compose down -v
docker-compose up -d postgres
```

### RabbitMQ Issues

```bash
# Check RabbitMQ status
docker-compose exec rabbitmq rabbitmq-diagnostics status

# List queues
docker-compose exec rabbitmq rabbitmqctl list_queues

# Access management UI
# http://localhost:15672
# Username: eracun
# Password: dev_password_change_in_production

# Reset RabbitMQ (WARNING: deletes all messages)
docker-compose down -v
docker-compose up -d rabbitmq
```

### Out of Disk Space

```bash
# Check Docker disk usage
docker system df

# Remove unused containers, networks, images
docker system prune

# Remove all stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes (WARNING: data loss)
docker volume prune
```

### Slow Build Times

```bash
# Use BuildKit for faster builds
DOCKER_BUILDKIT=1 docker-compose build

# Build in parallel
docker-compose build --parallel

# Use .dockerignore to exclude unnecessary files
# Already configured in services/*/.dockerignore
```

### Memory Issues

```bash
# Check Docker memory usage
docker stats

# Limit service memory (add to docker-compose.yml)
# deploy:
#   resources:
#     limits:
#       memory: 512M

# Increase Docker Desktop memory limit
# Docker Desktop > Preferences > Resources > Memory
```

## Monitoring and Observability

### Prometheus Metrics

Access Prometheus at http://localhost:9090

**Example Queries**:
```promql
# HTTP request rate
rate(http_requests_total[5m])

# Service memory usage
container_memory_usage_bytes{name="eracun-cert-lifecycle-manager"}

# RabbitMQ queue depth
rabbitmq_queue_messages{queue="eracun.fina.submit"}
```

### Grafana Dashboards

Access Grafana at http://localhost:3000
- Username: admin
- Password: admin

**Pre-configured Dashboards**:
- Service Health Dashboard
- RabbitMQ Metrics
- PostgreSQL Performance
- Request Latency (p50, p95, p99)

### Jaeger Distributed Tracing

Access Jaeger UI at http://localhost:16686

**Use Cases**:
- Trace request flow across services
- Identify performance bottlenecks
- Debug inter-service communication
- Analyze error propagation

## Environment Variables

### Override Configuration

Create `.env` file in project root:

```bash
# .env
POSTGRES_PASSWORD=my_secure_password
RABBITMQ_DEFAULT_PASS=my_rabbitmq_password
LOG_LEVEL=info
```

### Service-Specific Configuration

Override in docker-compose.yml or use environment-specific compose files:

```bash
# docker-compose.override.yml
version: '3.8'

services:
  cert-lifecycle-manager:
    environment:
      LOG_LEVEL: trace
      RENEWAL_THRESHOLD_DAYS: 30
```

## Production Considerations

**⚠️ WARNING**: This docker-compose.yml is for **DEVELOPMENT ONLY**

**Do NOT use in production**:
- Hardcoded passwords (dev_password_change_in_production)
- No resource limits
- Debug logging enabled
- No secrets management
- Non-hardened configurations

**For production deployment**:
- Use systemd service units (see @docs/DEPLOYMENT_GUIDE.md)
- Use SOPS for secrets management (see @docs/SECURITY.md)
- Apply systemd hardening directives
- Use managed PostgreSQL (DigitalOcean Managed Database)
- Configure proper resource limits
- Enable TLS/mTLS for inter-service communication

## Performance Benchmarking

### Load Testing with docker-compose

```bash
# Start all services
docker-compose up -d

# Wait for services to be healthy
sleep 30

# Run k6 load test (if k6 is installed)
k6 run tests/load/fina-submission.js

# Monitor with Prometheus/Grafana
# http://localhost:3000
```

### Memory Profiling

```bash
# Monitor memory usage in real-time
docker stats

# Get memory usage for specific service
docker stats eracun-cert-lifecycle-manager --no-stream

# Check for memory leaks
docker-compose logs cert-lifecycle-manager | grep "heap"
```

## Clean Up

### Daily Development

```bash
# Stop services but keep volumes
docker-compose stop
```

### Weekly Clean Up

```bash
# Remove containers but keep volumes
docker-compose down
```

### Full Reset

```bash
# Remove everything (WARNING: data loss)
docker-compose down -v --rmi all

# Rebuild from scratch
docker-compose build --no-cache
docker-compose up -d
```

## Related Documentation

- **Deployment Guide**: @docs/DEPLOYMENT_GUIDE.md - Production systemd deployment
- **Security Standards**: @docs/SECURITY.md - systemd hardening
- **Development Standards**: @docs/DEVELOPMENT_STANDARDS.md - Testing requirements
- **Architecture**: @docs/ARCHITECTURE.md - Service boundaries
- **Team 3 Instructions**: @TEAM_3.md - Service responsibilities

## Support

**Common Issues**: Check troubleshooting section above
**Security Issues**: See @docs/SECURITY.md
**Performance Issues**: Check Prometheus/Grafana dashboards
**Questions**: Consult service-specific README.md files

---

**Version**: 1.0.0
**Last Updated**: 2025-11-14
**Owner**: Team 3 - External Integration & Compliance
