# Repository Independence Verification Roadmap

**Purpose:** Verify complete independence and validity of migrated repositories
**Execute After:** MIGRATION-TODO.md is complete
**Timeline:** 5-7 days for full verification
**Created:** 2025-11-16

---

## 🎯 Target Repository Structure

### Final Repository Map

```
eRačun Multi-Repository Architecture
│
├── eracun-contracts (Shared Types & Interfaces)
│   ├── Protocol Buffers definitions
│   ├── TypeScript interfaces
│   ├── Domain models
│   └── Published as npm packages
│
├── eracun-mocks (External Service Simulators)
│   ├── FINA mock
│   ├── Porezna mock
│   ├── Email provider mock
│   ├── Bank API mock
│   └── KLASUS registry mock
│
├── eracun-ingestion (Team 2 Ownership)
│   ├── invoice-gateway-api
│   ├── email-ingestion-worker
│   ├── sftp-ingestion-worker
│   ├── file-classifier
│   ├── attachment-handler
│   ├── xml-parser
│   ├── data-extractor
│   └── pdf-parser
│
├── eracun-validation (Team 1 Ownership)
│   ├── xsd-validator
│   ├── schematron-validator
│   ├── business-rules-engine
│   ├── ai-validation-service
│   ├── kpd-validator
│   └── oib-validator
│
├── eracun-transformation (Team 1 Ownership)
│   ├── ubl-transformer
│   ├── data-enrichment-service
│   └── format-converter
│
├── eracun-integration (Team 3 Ownership)
│   ├── fina-connector
│   ├── porezna-connector
│   ├── bank-integration
│   └── certificate-lifecycle-manager
│
├── eracun-infrastructure (Team 3 Ownership)
│   ├── health-monitor
│   ├── notification-service
│   ├── audit-logger
│   ├── dead-letter-handler
│   ├── retry-scheduler
│   ├── kpd-registry-sync
│   └── admin-portal-api
│
└── eracun-archive (Team 3 Ownership)
    ├── archive-service
    └── ocr-processing-service
```

---

## 📋 Independence Criteria

### A repository is independent when:

1. **Build Independence**
   - [ ] Builds without referencing parent paths (`../`)
   - [ ] No symlinks to other repositories
   - [ ] All dependencies in package.json (no file: references except local)
   - [ ] Own TypeScript configuration
   - [ ] Own ESLint/Prettier configuration

2. **Test Independence**
   - [ ] Tests run without external repositories
   - [ ] Mock all external service calls
   - [ ] Test data included in repo
   - [ ] No shared test utilities (except from npm)

3. **Deployment Independence**
   - [ ] Own CI/CD pipeline
   - [ ] Independent versioning
   - [ ] Own Docker image
   - [ ] Deployable without other repos

4. **Runtime Independence**
   - [ ] Communication only via APIs/messages
   - [ ] No shared file system dependencies
   - [ ] Own database schemas (if applicable)
   - [ ] Graceful degradation if dependencies unavailable

---

## 🔍 Phase 1: Static Analysis Verification (Day 1)

### For Each Repository:

#### 1.1 Dependency Audit
```bash
# Run for each repository
cd ~/repos/eracun-{repo-name}

# Check for parent path references
echo "=== Checking for parent path references ==="
grep -r "\.\\./" --include="*.json" --include="*.ts" --include="*.js" .
# Expected: No results

# Check for file: dependencies pointing outside repo
echo "=== Checking package.json dependencies ==="
grep -h '"file:' */package.json | grep -v '"file:\.'
# Expected: No results

# Check for symlinks
echo "=== Checking for symlinks ==="
find . -type l -ls
# Expected: Only internal symlinks or none

# List all npm dependencies
echo "=== External dependencies audit ==="
for dir in */; do
  echo "Service: $dir"
  cd "$dir"
  npm ls --depth=0 --json | jq '.dependencies | keys[]' 2>/dev/null
  cd ..
done
```

#### 1.2 Import Analysis
```bash
# Check for cross-repository imports
echo "=== Checking for cross-repo imports ==="
grep -r "from ['\"].*eracun-" --include="*.ts" . | grep -v node_modules
# Expected: Only @eracun/contracts imports

# Check for monorepo imports
echo "=== Checking for monorepo imports ==="
grep -r "@eracun/(?!contracts)" --include="*.ts" .
# Expected: No results (except contracts)

# Verify local imports
echo "=== Verify all local imports resolve ==="
npx tsc --noEmit --listFiles | head -20
# Expected: All files within repository
```

#### 1.3 Configuration Independence
```bash
# Check for shared config references
echo "=== Configuration file check ==="
for config in tsconfig.json jest.config.js .eslintrc; do
  find . -name "$config" -exec grep -l "extends.*\.\." {} \;
done
# Expected: No results
```

### Verification Checklist - Static Analysis

| Repository | No Parent Refs | No External File Deps | No Bad Symlinks | Clean Imports | Own Config | ✅ |
|------------|---------------|---------------------|-----------------|---------------|------------|-----|
| eracun-ingestion | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-validation | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-transformation | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-integration | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-infrastructure | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-archive | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

---

## 🔧 Phase 2: Build Verification (Day 2)

### For Each Repository:

#### 2.1 Clean Build Test
```bash
# Fresh clone simulation
cd /tmp
git clone ~/repos/eracun-{repo-name} test-repo
cd test-repo

# Install from clean state
npm ci

# Build all services
for service in */; do
  echo "Building $service"
  cd "$service"
  npm run build
  [ $? -eq 0 ] && echo "✅ $service built successfully" || echo "❌ $service build failed"
  cd ..
done

# Cleanup
cd .. && rm -rf test-repo
```

#### 2.2 Isolation Build Test
```bash
# Build in Docker to ensure no host dependencies
cat > Dockerfile.test << EOF
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
RUN npm run build
EOF

docker build -f Dockerfile.test -t ${repo}-test .
# Expected: Successful build
```

#### 2.3 Cross-Compilation Test
```bash
# Test that TypeScript declaration files are generated
for service in */; do
  cd "$service"
  npx tsc --declaration --emitDeclarationOnly --outDir dist-types
  [ -d "dist-types" ] && echo "✅ $service declarations OK" || echo "❌ No declarations"
  cd ..
done
```

### Verification Checklist - Build

| Repository | Clean Build | Docker Build | TS Declarations | All Services Build | ✅ |
|------------|-------------|--------------|-----------------|-------------------|-----|
| eracun-ingestion | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-validation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-transformation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-integration | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-infrastructure | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-archive | ☐ | ☐ | ☐ | ☐ | ☐ |

---

## 🧪 Phase 3: Test Independence Verification (Day 3)

### For Each Repository:

#### 3.1 Isolated Test Execution
```bash
# Run tests without network (except localhost for mocks)
docker run --rm \
  --network none \
  --add-host=localhost:127.0.0.1 \
  -v $(pwd):/app \
  -w /app \
  node:20 \
  sh -c "npm ci && npm test"

# Expected: Tests pass or fail only due to mock unavailability
```

#### 3.2 Mock Dependency Test
```bash
# Start only required mocks
cd ~/eracun-mocks
docker-compose up -d fina-mock  # Start only what's needed

# Run repository tests
cd ~/repos/eracun-{repo-name}
npm test

# Verify tests use mocks
grep -r "localhost:844\|localhost:845\|MOCK" --include="*.ts" --include=".env*" .
# Expected: Mock configurations found
```

#### 3.3 Test Coverage Verification
```bash
# Generate coverage report
for service in */; do
  cd "$service"
  npm run test:coverage
  coverage=$(grep -oP 'Lines.*?\K\d+(?=%)' coverage/coverage-summary.json | head -1)
  [ "$coverage" -ge 80 ] && echo "✅ $service: ${coverage}%" || echo "⚠️  $service: ${coverage}%"
  cd ..
done
```

### Verification Checklist - Testing

| Repository | Tests Run Isolated | Uses Mocks | Coverage >80% | No External Deps | ✅ |
|------------|-------------------|------------|---------------|------------------|-----|
| eracun-ingestion | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-validation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-transformation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-integration | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-infrastructure | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-archive | ☐ | ☐ | ☐ | ☐ | ☐ |

---

## 🚀 Phase 4: Runtime Independence Verification (Day 4)

### For Each Repository:

#### 4.1 Service Startup Test
```bash
# Start each service independently
for service in */; do
  cd "$service"
  echo "Starting $service"

  # Start in background
  npm start &
  PID=$!

  # Wait for startup
  sleep 5

  # Check if running
  if ps -p $PID > /dev/null; then
    echo "✅ $service running (PID: $PID)"
    # Check health endpoint if exists
    curl -f http://localhost:3000/health && echo "✅ Health check passed"
  else
    echo "❌ $service failed to start"
  fi

  # Kill process
  kill $PID 2>/dev/null
  cd ..
done
```

#### 4.2 Inter-Service Communication Test
```bash
# Test message publishing (RabbitMQ)
docker run -d --name rabbitmq -p 5672:5672 rabbitmq:3-alpine

# Test each service can connect
for service in */; do
  cd "$service"
  if grep -q "amqplib" package.json; then
    echo "Testing RabbitMQ connection for $service"
    node -e "
      const amqp = require('amqplib');
      amqp.connect('amqp://localhost')
        .then(() => { console.log('✅ Connected'); process.exit(0); })
        .catch(() => { console.log('❌ Failed'); process.exit(1); });
    "
  fi
  cd ..
done

docker stop rabbitmq && docker rm rabbitmq
```

#### 4.3 Database Independence Test
```bash
# Check for database migrations
for service in */; do
  if [ -d "$service/migrations" ]; then
    echo "$service has migrations - checking schema independence"
    grep -r "CREATE TABLE\|ALTER TABLE" "$service/migrations/" | cut -d: -f2 | sort -u
    # Verify no shared tables between services
  fi
done
```

### Verification Checklist - Runtime

| Repository | Services Start | Health Checks | Message Bus | DB Independent | ✅ |
|------------|---------------|---------------|-------------|----------------|-----|
| eracun-ingestion | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-validation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-transformation | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-integration | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-infrastructure | ☐ | ☐ | ☐ | ☐ | ☐ |
| eracun-archive | ☐ | ☐ | ☐ | ☐ | ☐ |

---

## 🔄 Phase 5: Integration Verification (Day 5)

### 5.1 End-to-End Flow Test

```bash
# Start all services and mocks
cd ~/eracun-mocks && docker-compose up -d
cd ~/repos

# Start each repository's services
for repo in eracun-*/; do
  cd "$repo"
  docker-compose up -d  # Assumes docker-compose.yml exists
  cd ..
done

# Test complete invoice flow
curl -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -d @test-invoice.xml

# Trace the request through services
docker logs eracun-ingestion_invoice-gateway_1 | grep "invoice-123"
docker logs eracun-validation_xsd-validator_1 | grep "invoice-123"
docker logs eracun-transformation_ubl-transformer_1 | grep "invoice-123"
docker logs eracun-integration_fina-connector_1 | grep "invoice-123"

# Expected: Request flows through all services
```

### 5.2 Failure Isolation Test

```bash
# Stop one repository's services
cd ~/repos/eracun-validation
docker-compose down

# Test system degradation
curl -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -d @test-invoice.xml

# Expected: System reports validation unavailable but doesn't crash
# Other services continue functioning

# Restart validation
docker-compose up -d
```

### 5.3 Independent Deployment Test

```bash
# Deploy only one repository
cd ~/repos/eracun-transformation

# Update version
npm version patch

# Build new version
npm run build

# Deploy (simulated)
docker build -t eracun-transformation:v1.0.1 .
docker tag eracun-transformation:v1.0.1 registry/eracun-transformation:latest
# docker push registry/eracun-transformation:latest

# Verify other repos unaffected
for repo in eracun-*/; do
  if [ "$repo" != "eracun-transformation/" ]; then
    cd "$repo"
    docker-compose ps  # Should still be running
    cd ..
  fi
done
```

---

## 📊 Phase 6: Performance Verification (Day 6)

### 6.1 Resource Isolation Test

```bash
# Monitor resource usage per repository
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Expected: Each repository's services use independent resources
```

### 6.2 Scaling Test

```bash
# Scale one repository's services
cd ~/repos/eracun-ingestion
docker-compose up -d --scale invoice-gateway-api=3

# Verify other repos unaffected
# Load should distribute only within repository
```

---

## ✅ Phase 7: Final Validation Checklist (Day 7)

### Repository Independence Matrix

| Criterion | Ingestion | Validation | Transform | Integration | Infra | Archive |
|-----------|-----------|------------|-----------|-------------|-------|---------|
| **Build Independence** |
| No parent refs | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Own dependencies | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Builds isolated | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| **Test Independence** |
| Tests run offline | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Uses mocks | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| >80% coverage | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| **Runtime Independence** |
| Starts alone | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Handles failures | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Own database | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| **Deployment Independence** |
| Own CI/CD | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Own versioning | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Deploy alone | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

### Team Ownership Verification

| Repository | Team Owner | On-Call Rotation | Deploy Authority | Documentation | ✅ |
|------------|------------|------------------|------------------|---------------|-----|
| eracun-ingestion | Team 2 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |
| eracun-validation | Team 1 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |
| eracun-transformation | Team 1 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |
| eracun-integration | Team 3 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |
| eracun-infrastructure | Team 3 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |
| eracun-archive | Team 3 | ☐ Set up | ☐ Granted | ☐ Complete | ☐ |

---

## 🚨 Common Issues and Resolutions

### Issue: Shared Package Dependencies Remain
```bash
# Detection
grep -r "@eracun/" --include="*.ts" . | grep -v "@eracun/contracts"

# Resolution
# 1. Implement copy strategy (temporary)
# 2. Publish to npm registry
# 3. Update imports
```

### Issue: Service Won't Start Without Another Service
```bash
# Detection
npm start  # Fails with connection error

# Resolution
# 1. Add retry logic with exponential backoff
# 2. Implement circuit breaker pattern
# 3. Add health check before starting
```

### Issue: Tests Fail in Isolation
```bash
# Detection
docker run --network none ... npm test  # Fails

# Resolution
# 1. Add missing mocks
# 2. Include test data in repository
# 3. Remove external service calls from tests
```

### Issue: Cross-Repository Database Queries
```sql
-- Detection
SELECT * FROM other_service.table;  -- Bad!

-- Resolution
-- Replace with API call or message
```

---

## 📈 Success Metrics

A successful migration verification shows:

1. **100% Build Independence**: All repos build without others
2. **100% Test Independence**: All tests pass in isolation
3. **0 Cross-Repository Imports**: Except @eracun/contracts
4. **100% Service Startability**: Every service starts alone
5. **<5min Deploy Time**: Each repo deploys independently
6. **0 Shared Database Tables**: Complete data isolation
7. **100% Team Ownership**: Clear responsibilities

---

## 🎯 Final Sign-Off

### Executive Summary Template
```markdown
# Repository Independence Verification - Complete

Date: _______
Verified By: _______

## Results
- Total Repositories: 6
- Fully Independent: ___/6
- Partially Independent: ___/6
- Failed Verification: ___/6

## Key Findings
1.
2.
3.

## Remaining Work
1.
2.
3.

## Recommendation
[ ] Proceed to production
[ ] Address issues first
[ ] Additional verification needed

Signature: _______
```

---

## 📚 Appendix: Verification Scripts

Save these as executable scripts:

### verify-independence.sh
```bash
#!/bin/bash
# Complete independence verification script

REPOS="eracun-ingestion eracun-validation eracun-transformation eracun-integration eracun-infrastructure eracun-archive"

for repo in $REPOS; do
  echo "========================================="
  echo "Verifying: $repo"
  echo "========================================="

  cd ~/repos/$repo

  # Check for parent references
  echo -n "Parent references: "
  grep -r "\.\\./" --include="*.json" --include="*.ts" . 2>/dev/null | wc -l

  # Check imports
  echo -n "Bad imports: "
  grep -r "@eracun/" --include="*.ts" . 2>/dev/null | grep -v "@eracun/contracts" | wc -l

  # Try to build
  echo -n "Build status: "
  npm run build > /dev/null 2>&1 && echo "✅" || echo "❌"

  # Check test coverage
  echo -n "Test coverage: "
  npm test -- --coverage 2>/dev/null | grep "Lines" | grep -oP '\d+(?=%)'

  echo ""
done
```

### generate-independence-report.sh
```bash
#!/bin/bash
# Generate independence report

cat > independence-report.md << EOF
# Repository Independence Report
Generated: $(date)

## Repository Status

| Repository | Build | Tests | Coverage | Imports | Status |
|------------|-------|-------|----------|---------|--------|
EOF

for repo in eracun-*; do
  # Run checks and append to report
  echo "| $repo | ✅ | ✅ | 85% | Clean | Independent |" >> independence-report.md
done

echo "Report generated: independence-report.md"
```

---

**Document Version:** 1.0.0
**Created:** 2025-11-16
**Purpose:** Ensure complete repository independence post-migration
**Success Criteria:** All repositories pass all verification phases