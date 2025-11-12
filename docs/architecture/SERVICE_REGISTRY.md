# Service Registry

**Purpose:** Centralized catalog of all microservices in the eRacun monorepo
**Maintainer:** Platform Engineering Team
**Last Updated:** 2025-11-12

---

## Service Inventory

| Service | Port | Status | Bounded Context | Contract | Dependencies |
|---------|------|--------|-----------------|----------|--------------|
| **admin-portal-api** | 8080 | ✅ Active | Customer Portal (BFF) | REST | health-monitor, cert-lifecycle-manager, dead-letter-handler |
| **archive-service** | 9310 | 🚧 In Progress | Archive & Compliance | Proto (archive.proto) | digital-signature-service, cert-lifecycle-manager |
| **audit-logger** | 8085 | ✅ Active | Audit & Observability | Proto (audit.proto) | None (terminal service) |
| **cert-lifecycle-manager** | 9302 | ✅ Active | Certificate Management | REST | None (reads from PostgreSQL) |
| **dead-letter-handler** | 8086 | ✅ Active | Infrastructure | REST | RabbitMQ (consumes DLQ) |
| **digital-signature-service** | 9301 | ✅ Active | Cryptography | REST | cert-lifecycle-manager |
| **email-ingestion-worker** | N/A | ✅ Active | Ingestion | Proto (ingestion.proto) | file-classifier, pdf-parser |
| **fina-connector** | 9303 | ✅ Active | Fiscalization (B2C) | SOAP + RabbitMQ | digital-signature-service |
| **file-classifier** | N/A | ✅ Active | Parsing | Proto (parsing.proto) | None |
| **health-monitor** | 8084 | ✅ Active | Observability | REST | All services (queries health endpoints) |
| **iban-validator** | N/A | ✅ Active | Validation | Proto (validation.proto) | None |
| **kpd-registry-sync** | N/A | ✅ Active | Master Data Sync | Proto (kpd-lookup.proto) | Croatian Statistical Office API |
| **kpd-validator** | N/A | ✅ Active | Validation | Proto (validation.proto) | kpd-registry-sync |
| **notification-service** | 8087 | ✅ Active | Notifications | RabbitMQ | SMTP server |
| **oib-validator** | N/A | ✅ Active | Validation | Proto (validation.proto) | None |
| **pdf-parser** | N/A | ✅ Active | Parsing | Proto (parsing.proto) | None |
| **retry-scheduler** | 8088 | ✅ Active | Infrastructure | RabbitMQ | dead-letter-handler |
| **schematron-validator** | N/A | ✅ Active | Validation | Proto (validation.proto) | None |
| **xml-parser** | N/A | ✅ Active | Parsing | Proto (parsing.proto) | None |
| **xsd-validator** | N/A | ✅ Active | Validation | Proto (validation.proto) | UBL 2.1 XSD schemas |

---

## Service Types

### **Gateway Services** (External Entry Points)
- `admin-portal-api` - Customer-facing admin portal (BFF pattern)
- `invoice-gateway-api` - Public API for invoice submission (NOT YET IMPLEMENTED)

### **Processing Services** (Core Business Logic)
- `fina-connector` - FINA fiscalization (B2C)
- `as4-gateway-connector` - AS4 B2B exchange (NOT YET IMPLEMENTED)
- `ubl-transformer` - Transform to UBL 2.1 XML (NOT YET IMPLEMENTED)

### **Validation Services** (Bounded Context: Validation)
- `xsd-validator` - XSD schema validation
- `schematron-validator` - Croatian CIUS business rules
- `kpd-validator` - KPD product classification
- `oib-validator` - OIB tax number validation
- `iban-validator` - IBAN bank account validation

### **Parsing Services** (Bounded Context: Parsing)
- `email-ingestion-worker` - Email attachment extraction
- `pdf-parser` - PDF to structured data
- `xml-parser` - XML parsing
- `file-classifier` - File type detection

### **Infrastructure Services** (Platform)
- `health-monitor` - System health aggregation
- `audit-logger` - Immutable audit trail
- `retry-scheduler` - Failed message retry orchestration
- `dead-letter-handler` - DLQ management
- `notification-service` - Email/SMS notifications

### **Master Data Services**
- `kpd-registry-sync` - Croatian KPD registry synchronization
- `cert-lifecycle-manager` - FINA certificate management

### **Cryptography Services**
- `digital-signature-service` - XMLDSig signing/verification

### **Compliance Services**
- `archive-service` - 11-year invoice retention (IN PROGRESS)
- `compliance-reporting-service` - eIzvještavanje (NOT YET IMPLEMENTED)

---

## Service Communication Matrix

### **Message Bus (RabbitMQ)**

| Publisher | Exchange | Routing Key | Consumer | Message Type |
|-----------|----------|-------------|----------|--------------|
| email-ingestion-worker | parsing.commands | parsing.command.classify | file-classifier | Command |
| file-classifier | parsing.events | parsing.event.classified | pdf-parser, xml-parser | Event |
| xsd-validator | validation.events | validation.event.validated | schematron-validator | Event |
| fina-connector | fiscalization.events | fiscalization.event.submitted | archive-service | Event |
| ubl-transformer | archive.commands | archive.command.invoice | archive-service | Command |

### **Direct HTTP (Via API Gateway Only)**

| Client | Gateway Route | Backend Service | Protocol |
|--------|---------------|-----------------|----------|
| Admin UI | `/v1/health/*` | health-monitor | REST |
| Admin UI | `/v1/certificates/*` | cert-lifecycle-manager | REST |
| Admin UI | `/v1/dead-letters/*` | dead-letter-handler | REST |

**Note:** All direct service-to-service HTTP calls are being migrated to message bus per ADR-005.

---

## Service Dependencies

### **Zero-Dependency Services** (Leaf Nodes)
- file-classifier
- oib-validator
- iban-validator
- pdf-parser
- xml-parser
- audit-logger

### **High-Dependency Services** (Orchestrators)
- admin-portal-api (queries 3+ services) ⚠️ **Being migrated to message bus**
- health-monitor (queries all services)
- fina-connector (calls digital-signature-service)

---

## Service Lifecycle States

| State | Description | Example |
|-------|-------------|---------|
| ✅ **Active** | Deployed to production, handling traffic | fina-connector, health-monitor |
| 🚧 **In Progress** | Under active development | archive-service |
| 📋 **Planned** | Designed but not started | ubl-transformer, as4-gateway-connector |
| ⏸️ **Deferred** | Designed but low priority | compliance-reporting-service |
| 🗑️ **Deprecated** | Being phased out | (none yet) |

---

## Adding a New Service

**Checklist:**
1. [ ] Define proto contract in `docs/api-contracts/protobuf/{service}.proto`
2. [ ] Add entry to this SERVICE_REGISTRY.md
3. [ ] Document message contracts in `docs/message-contracts/`
4. [ ] Create service skeleton: `services/{service-name}/`
5. [ ] Add health endpoint: `GET /health`
6. [ ] Register health endpoint with health-monitor
7. [ ] Add Prometheus metrics exporter (port 9xxx)
8. [ ] Create systemd service unit: `deployment/systemd/{service}.service`
9. [ ] Run architecture compliance check: `scripts/check-architecture-compliance.sh`
10. [ ] Deploy to staging and verify

---

## Service Naming Conventions

**Pattern:** `{bounded-context}-{resource}-{action}`

**Examples:**
- `fina-connector` (bounded context: fiscalization, resource: fina, action: connect)
- `kpd-validator` (bounded context: validation, resource: kpd, action: validate)
- `cert-lifecycle-manager` (bounded context: certificates, resource: lifecycle, action: manage)

**Avoid:**
- Generic names (`processor`, `handler`, `service`)
- Technology names (`rabbitmq-consumer`, `postgres-writer`)
- Verb-only names (`validate`, `parse`, `transform`)

---

## Port Allocation

**Ranges:**
- **8000-8099:** Gateway services (external-facing)
- **8100-8199:** Infrastructure services
- **9000-9099:** Reserved (future use)
- **9100-9199:** Reserved (future use)
- **9200-9299:** Reserved (future use)
- **9300-9399:** Processing services (fiscalization, signatures, crypto)
- **9400-9499:** Validation services
- **9500-9599:** Parsing services
- **9600-9699:** Master data services
- **9700-9799:** Compliance services

**Prometheus Metrics Ports:** Same as service port (single HTTP server with `/metrics` endpoint)

---

## References

- **Architecture:** `docs/architecture/MONOREPO_COMPLIANCE_AUDIT.md`
- **Bounded Contexts:** `docs/adr/005-bounded-context-isolation.md`
- **Message Contracts:** `docs/message-contracts/README.md` (to be created)
- **API Contracts:** `docs/api-contracts/protobuf/`

---

**Maintainer:** Platform Engineering Team
**Review Cadence:** Monthly (add new services, update status)
