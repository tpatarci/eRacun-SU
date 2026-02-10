# Future Repository Structure & Independence Principles

**Purpose:** Define the target multi-repository architecture and independence guarantees
**Created:** 2025-11-16
**Status:** Target State Definition

---

## 🏗️ The 8 Target Repositories

### 1. **eracun-contracts** 📦
**Purpose:** Shared type definitions and contracts
**Language:** TypeScript + Protocol Buffers
**Team:** Platform Team (shared ownership)
**Services:** None (library only)

**Published Packages:**
- `@eracun/contracts` - Protocol Buffer definitions
- `@eracun/types` - TypeScript interfaces
- `@eracun/domain` - Domain models

**Independence Strategy:**
- Published to npm registry
- Semantic versioning
- Backward compatibility required
- No runtime dependencies

---

### 2. **eracun-mocks** 🧪
**Purpose:** External service simulators for development/testing
**Language:** TypeScript/Node.js
**Team:** Platform Team
**Services:** 5 mock services

**Services:**
- `fina-simulator` - Tax authority mock
- `porezna-simulator` - Porezna Uprava mock
- `email-provider` - SMTP/IMAP mock
- `bank-api-simulator` - Banking mock
- `klasus-registry` - Product codes mock

**Independence Strategy:**
- Completely standalone
- No dependencies on production code
- Docker-compose orchestration
- Configurable chaos engineering

---

### 3. **eracun-ingestion** 📥
**Purpose:** Document intake from all channels
**Language:** TypeScript/Node.js
**Team:** Team 2 (Ingestion & Document Processing)
**Services:** 8 services

**Services:**
- `invoice-gateway-api` - HTTP API endpoint
- `email-ingestion-worker` - Email processing
- `sftp-ingestion-worker` - SFTP monitoring
- `file-classifier` - MIME type detection
- `attachment-handler` - Archive extraction
- `xml-parser` - XML document parsing
- `data-extractor` - Data extraction
- `pdf-parser` - PDF processing

**Independence Guarantees:**
- ✅ Own RabbitMQ queues (ingestion.*)
- ✅ Own database schema (ingestion_db)
- ✅ Publishes to validation.input queue
- ✅ No synchronous calls to other repos

---

### 4. **eracun-validation** ✓
**Purpose:** Multi-layer validation pipeline
**Language:** TypeScript/Node.js
**Team:** Team 1 (Core Processing)
**Services:** 6 services

**Services:**
- `xsd-validator` - XML schema validation
- `schematron-validator` - Business rule validation
- `business-rules-engine` - Custom rules
- `ai-validation-service` - AI-powered checks
- `kpd-validator` - Product code validation
- `oib-validator` - OIB number validation

**Independence Guarantees:**
- ✅ Consumes from validation.input queue
- ✅ Own database schema (validation_db)
- ✅ Publishes to transformation.input queue
- ✅ Validation results cached locally
- ✅ Falls back gracefully if AI unavailable

---

### 5. **eracun-transformation** 🔄
**Purpose:** Format transformation and enrichment
**Language:** TypeScript/Node.js
**Team:** Team 1 (Core Processing)
**Services:** 3 services

**Services:**
- `ubl-transformer` - UBL 2.1 generation
- `data-enrichment-service` - Data augmentation
- `format-converter` - Format conversions

**Independence Guarantees:**
- ✅ Consumes from transformation.input queue
- ✅ Own database schema (transformation_db)
- ✅ Publishes to integration.input queue
- ✅ Template-based transformations
- ✅ No external service dependencies

---

### 6. **eracun-integration** 🔌
**Purpose:** External system connectors
**Language:** TypeScript/Node.js
**Team:** Team 3 (Integration & External Systems)
**Services:** 4 services

**Services:**
- `fina-connector` - FINA fiscalization
- `porezna-connector` - Tax authority integration
- `bank-integration` - Payment verification
- `certificate-lifecycle-manager` - X.509 certificates

**Independence Guarantees:**
- ✅ Consumes from integration.input queue
- ✅ Own credential storage (encrypted)
- ✅ Circuit breakers for all external calls
- ✅ Publishes to archive.input queue
- ✅ Mock mode via environment variables

---

### 7. **eracun-infrastructure** 🔧
**Purpose:** Cross-cutting operational concerns
**Language:** TypeScript/Node.js
**Team:** Team 3 (Platform/DevOps)
**Services:** 7 services

**Services:**
- `health-monitor` - System health checks
- `notification-service` - Alerts and notifications
- `audit-logger` - Audit trail
- `dead-letter-handler` - Failed message processing
- `retry-scheduler` - Retry orchestration
- `kpd-registry-sync` - Registry synchronization
- `admin-portal-api` - Admin interface

**Independence Guarantees:**
- ✅ Observes all queues (read-only)
- ✅ Own metrics database (metrics_db)
- ✅ No business logic
- ✅ Can be disabled without affecting flow
- ✅ Own notification channels

---

### 8. **eracun-archive** 📁
**Purpose:** Long-term compliant storage
**Language:** TypeScript/Node.js
**Team:** Team 3 (Compliance & Storage)
**Services:** 2 services

**Services:**
- `archive-service` - 11-year retention
- `ocr-processing-service` - OCR for scanned docs

**Independence Guarantees:**
- ✅ Consumes from archive.input queue
- ✅ Own object storage (S3/MinIO)
- ✅ WORM compliance
- ✅ Own retention policies
- ✅ Crypto-signed manifests

---

## 🔐 Independence Principles

### 1. Communication Independence

**Allowed:**
- ✅ Message queues (RabbitMQ/Kafka)
- ✅ REST APIs with circuit breakers
- ✅ gRPC with retries

**Forbidden:**
- ❌ Direct database access
- ❌ Shared file systems
- ❌ Synchronous blocking calls
- ❌ Shared memory/cache

### 2. Data Independence

**Each repository MUST have:**
- Own database schema (no shared tables)
- Own cache layer (Redis namespace)
- Own configuration (no shared config)
- Own secrets management

**Example Schema Isolation:**
```sql
-- ingestion_db
CREATE SCHEMA ingestion;
CREATE TABLE ingestion.invoices (...);

-- validation_db
CREATE SCHEMA validation;
CREATE TABLE validation.results (...);

-- NEVER:
SELECT * FROM validation.results; -- From ingestion service
```

### 3. Build Independence

**Each repository MUST:**
- Build without other repos present
- Have own package.json
- Have own TypeScript config
- Have own Docker image

**Test Command:**
```bash
# Must succeed for each repo
git clone <repo-url> /tmp/test
cd /tmp/test
npm ci
npm run build
npm test
```

### 4. Deployment Independence

**Each repository CAN:**
- Deploy at different times
- Use different versions
- Scale independently
- Rollback independently

**Deployment Matrix Example:**
| Repository | Version | Last Deploy | Status |
|------------|---------|-------------|--------|
| ingestion | v1.2.5 | 2025-11-16 | ✅ Stable |
| validation | v1.3.0 | 2025-11-15 | ✅ Stable |
| transformation | v1.1.8 | 2025-11-14 | ✅ Stable |
| integration | v1.2.1 | 2025-11-16 | 🔄 Deploying |

### 5. Team Independence

**Each team has:**
- Full repository ownership
- Deploy permissions
- On-call responsibilities
- Architecture decisions (within bounds)

**Ownership Matrix:**
| Repository | Primary Team | Backup Team | Deploy Auth |
|------------|-------------|-------------|-------------|
| ingestion | Team 2 | Team 1 | Team 2 |
| validation | Team 1 | Team 2 | Team 1 |
| transformation | Team 1 | Team 2 | Team 1 |
| integration | Team 3 | Platform | Team 3 |
| infrastructure | Platform | Team 3 | Platform |
| archive | Team 3 | Platform | Team 3 |

---

## 🧪 Independence Validation Tests

### Test 1: Kill Test
```bash
# Kill any repository
docker-compose -f eracun-validation/docker-compose.yml down

# Others must continue (degraded mode)
curl http://localhost:3000/health
# Expected: {"validation": "unavailable", "status": "degraded"}
```

### Test 2: Version Test
```bash
# Different versions running simultaneously
docker run eracun-ingestion:v1.0.0
docker run eracun-validation:v2.0.0  # Major version difference
docker run eracun-transformation:v1.5.0

# System still functions
```

### Test 3: Network Partition Test
```bash
# Block network between repos
iptables -A INPUT -s validation-subnet -j DROP

# Ingestion continues accepting documents
# They queue until validation returns
```

### Test 4: Independent Rollback Test
```bash
# Deploy new version
kubectl set image deployment/validation validation=validation:v1.3.1

# Discover issue
kubectl rollout undo deployment/validation

# Only validation rolls back, others unaffected
```

---

## 📊 Independence Metrics

### Coupling Metrics (Target: 0)

```sql
-- Find cross-schema queries
SELECT COUNT(*) as cross_schema_queries
FROM pg_stat_statements
WHERE query LIKE '%schema1.%' AND current_schema = 'schema2';
-- Target: 0

-- Find shared tables
SELECT COUNT(*) as shared_tables
FROM information_schema.tables
WHERE table_name IN (
  SELECT table_name
  FROM information_schema.tables
  GROUP BY table_name
  HAVING COUNT(DISTINCT table_schema) > 1
);
-- Target: 0
```

### Independence Score

| Metric | Weight | Target | Score |
|--------|--------|--------|-------|
| No shared DB | 25% | 0 queries | ___ |
| Separate builds | 25% | 100% pass | ___ |
| Independent deploys | 25% | 100% | ___ |
| Message-only comm | 25% | 100% | ___ |
| **Total Score** | 100% | 100% | ___ |

---

## ⚠️ Anti-Patterns to Avoid

### ❌ Shared Database Anti-Pattern
```sql
-- BAD: Cross-schema query
SELECT i.*, v.status
FROM ingestion.invoices i
JOIN validation.results v ON i.id = v.invoice_id;

-- GOOD: Use messages
-- Validation publishes ValidationCompleted event
-- Ingestion updates its own database
```

### ❌ Synchronous Chain Anti-Pattern
```typescript
// BAD: Synchronous chaining
const result = await validation.validate(invoice);
const transformed = await transformation.transform(result);
const submitted = await integration.submit(transformed);

// GOOD: Message chain
publisher.publish('validation.input', invoice);
// Each service subscribes and publishes to next
```

### ❌ Shared Library Anti-Pattern
```json
// BAD: File reference to other repo
{
  "dependencies": {
    "shared-utils": "file:../eracun-validation/shared"
  }
}

// GOOD: Published package
{
  "dependencies": {
    "@eracun/contracts": "^1.0.0"
  }
}
```

### ❌ Cross-Repository Configuration
```yaml
# BAD: Reaching into other repo's config
validation:
  config_file: ../eracun-validation/config.yml

# GOOD: Service discovery or environment
validation:
  endpoint: ${VALIDATION_SERVICE_URL}
```

---

## ✅ Independence Checklist

Before declaring a repository independent:

### Build & Development
- [ ] Builds without any other repository present
- [ ] All dependencies from npm (except local services)
- [ ] Own TypeScript/ESLint/Prettier config
- [ ] Own test data and fixtures
- [ ] Runs tests without external services

### Runtime
- [ ] Starts without other services (may be degraded)
- [ ] Handles unavailability of dependencies
- [ ] No shared filesystem access
- [ ] No cross-database queries
- [ ] Circuit breakers for external calls

### Operations
- [ ] Own CI/CD pipeline
- [ ] Independent deployment
- [ ] Own monitoring/alerting
- [ ] Own logging namespace
- [ ] Own error handling

### Team
- [ ] Clear ownership assigned
- [ ] On-call rotation established
- [ ] Deploy permissions granted
- [ ] Documentation complete
- [ ] Runbooks created

---

## 🎯 End State Vision

When complete, the architecture enables:

1. **Team Autonomy**: Each team deploys when ready
2. **Fault Isolation**: Failures don't cascade
3. **Independent Scaling**: Scale only what needs scaling
4. **Technology Freedom**: Teams can evolve their stack
5. **Clear Ownership**: No shared responsibility confusion
6. **Fast Development**: No coordination overhead
7. **Simple Testing**: Test in isolation

The ultimate test: **Can a new developer work on one repository without knowing the others exist?**

If yes, you've achieved true independence. ✅

---

**Document Version:** 1.0.0
**Created:** 2025-11-16
**Review:** Post-migration completion