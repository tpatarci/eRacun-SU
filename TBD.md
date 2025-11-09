# TBD - To Be Determined

**Document Purpose:** Track unresolved architectural decisions, pending technical choices, and open questions requiring stakeholder input or further research.

**Review Frequency:** Weekly during initial development, monthly post-launch

---

## 1. TECHNOLOGY STACK DECISIONS

### 1.1 Programming Languages

**Status:** ⏳ Pending Decision

**Options:**
- **TypeScript/Node.js** - Fast development, rich ecosystem, async-native
- **Go** - Performance, low memory footprint, excellent concurrency
- **Rust** - Maximum performance, memory safety, zero-cost abstractions
- **Python** - ML/AI libraries, OCR tools, rapid prototyping

**Considerations:**
- Performance vs development velocity trade-off
- Team expertise availability
- Library ecosystem for Croatian tax regulations
- ML/AI framework integration requirements

**Decision Required By:** Sprint 1 Planning
**Stakeholders:** Technical Lead, Development Team

---

### 1.2 Database Selection

**Status:** ⏳ Pending Decision

**Primary Database Options:**
- **PostgreSQL** - ACID compliance, JSON support, mature tooling
- **MongoDB** - Flexible schema, document-oriented
- **CockroachDB** - Distributed SQL, horizontal scaling

**Time-Series Metrics:**
- **InfluxDB** - Purpose-built for metrics
- **TimescaleDB** - PostgreSQL extension for time-series

**Caching Layer:**
- **Redis** - In-memory cache, pub/sub
- **Memcached** - Simple key-value cache

**Considerations:**
- Strong consistency vs eventual consistency requirements
- Query patterns (document retrieval vs relational joins)
- Operational complexity vs managed services
- Cost at scale (DigitalOcean managed databases vs self-hosted)

**Decision Required By:** Sprint 2
**Stakeholders:** Database Administrator, Technical Lead

---

### 1.3 Message Bus Technology

**Status:** ⏳ Pending Decision

**Options:**
- **RabbitMQ** - Proven reliability, complex routing, management UI
- **NATS/NATS Streaming** - Lightweight, high performance, cloud-native
- **Apache Kafka** - Event sourcing, replay capability, high throughput
- **Redis Streams** - Simple, already in stack if using Redis

**Considerations:**
- Message durability guarantees required
- Throughput requirements (messages/second)
- Operational complexity vs features
- Cost (managed services vs self-hosted)

**Decision Required By:** Sprint 2
**Stakeholders:** Infrastructure Team, Technical Lead

---

### 1.4 Workflow Orchestration Engine

**Status:** ⏳ Pending Decision

**Options:**
- **Temporal** - Durable execution, complex workflows, battle-tested
- **Camunda** - BPMN-based, visual workflow designer
- **Apache Airflow** - Python-based, rich UI, strong community
- **Custom Saga Implementation** - Full control, lower overhead

**Considerations:**
- Workflow complexity (simple pipelines vs complex state machines)
- Long-running process requirements (hours/days)
- Debugging and observability needs
- Learning curve for team

**Decision Required By:** Sprint 3
**Stakeholders:** Technical Lead, DevOps Team

---

### 1.5 Service Mesh

**Status:** ⏳ Pending Decision

**Options:**
- **Istio** - Feature-rich, industry standard, steep learning curve
- **Linkerd** - Lightweight, simpler than Istio, good defaults
- **Consul Connect** - Service discovery + mesh, HashiCorp ecosystem
- **No Service Mesh** - Use libraries (sidecar-free)

**Considerations:**
- Operational overhead vs observability benefits
- mTLS requirements for inter-service communication
- Traffic management needs (canary, blue-green)
- Resource overhead (CPU/memory per sidecar proxy)

**Decision Required By:** Sprint 4
**Stakeholders:** DevOps Team, Security Team

---

## 2. INFRASTRUCTURE & DEPLOYMENT

### 2.1 Kubernetes Cluster Configuration

**Status:** ⏳ Pending Decision

**Questions:**
- Single cluster vs multi-cluster (staging/production)?
- Node pool sizing (how many nodes, what sizes)?
- Autoscaling strategy (HPA, VPA, cluster autoscaler)?
- Namespace strategy (per-service, per-environment)?
- Ingress controller (NGINX, Traefik, Kong)?

**Considerations:**
- Cost optimization (reserved instances, spot instances)
- Fault isolation (blast radius of failures)
- Compliance requirements (data residency, network isolation)

**Decision Required By:** Infrastructure Setup (Sprint 1)
**Stakeholders:** DevOps Team, Finance

---

### 2.2 Secrets Management

**Status:** ⏳ Pending Decision

**Options:**
- **HashiCorp Vault** - Industry standard, dynamic secrets, audit logs
- **Kubernetes Secrets** - Native, encrypted at rest (if configured)
- **DigitalOcean Secrets** - Managed service (if available)
- **SOPS (Secrets OPerationS)** - Encrypted in Git, GitOps-friendly

**Considerations:**
- Key rotation requirements
- Audit logging needs
- Integration complexity
- Cost (managed vs self-hosted)

**Decision Required By:** Before any production deployment
**Stakeholders:** Security Team, DevOps Team

---

### 2.3 Container Registry

**Status:** ⏳ Pending Decision

**Options:**
- **DigitalOcean Container Registry** - Integrated, simple
- **Docker Hub** - Public/private repos, familiar
- **GitHub Container Registry** - Integrated with CI/CD
- **Harbor** - Self-hosted, vulnerability scanning, replication

**Considerations:**
- Vulnerability scanning requirements
- Access control granularity
- Cost (bandwidth, storage)
- Integration with CI/CD pipeline

**Decision Required By:** CI/CD Setup (Sprint 1)
**Stakeholders:** DevOps Team

---

### 2.4 Infrastructure as Code Tool

**Status:** ⏳ Pending Decision

**Options:**
- **Terraform** - Multi-cloud, mature, HCL
- **Pulumi** - Real programming languages, type-safe
- **Ansible** - Configuration management, agentless
- **Kubernetes Operators** - Native K8s resource management

**Considerations:**
- Team familiarity
- State management (Terraform Cloud, S3 backend)
- Drift detection needs
- Testing/validation capabilities

**Decision Required By:** Infrastructure Setup (Sprint 1)
**Stakeholders:** DevOps Team

---

## 3. SERVICE BOUNDARIES & CONTRACTS

### 3.1 Exact Service Decomposition

**Status:** ⏳ Needs Refinement

**Open Questions:**
- Should OCR processing be one service or split by document type?
- Does AI validation need separate services per validation type?
- Should FINA/Porezna connectors share infrastructure or be fully isolated?
- Where does rate limiting live (API gateway, individual services)?
- Who owns authentication/authorization (dedicated service, library)?

**Considerations:**
- Deployment independence vs operational complexity
- Shared infrastructure for similar services
- Team ownership boundaries

**Decision Required By:** Sprint 1 Planning
**Stakeholders:** Technical Lead, Development Team

---

### 3.2 API Contract Standards

**Status:** ⏳ Pending Definition

**Questions:**
- REST vs gRPC for internal services?
- OpenAPI version (3.0 vs 3.1)?
- Versioning strategy (URL path, header, content negotiation)?
- Error response format (RFC 7807 Problem Details)?
- Pagination standards (cursor-based, offset-based)?
- Rate limiting headers (RateLimit-*, X-RateLimit-*)?

**Decision Required By:** Before first API implementation (Sprint 1)
**Stakeholders:** API Design Team, Frontend Team

---

### 3.3 Message Schema Evolution

**Status:** ⏳ Pending Definition

**Questions:**
- Protocol Buffers vs Avro vs JSON Schema?
- Schema registry (Confluent, Apicurio, custom)?
- Backward/forward compatibility requirements?
- Schema versioning strategy?
- Breaking change migration process?

**Decision Required By:** Before first message bus implementation (Sprint 2)
**Stakeholders:** Integration Team, Technical Lead

---

## 4. DATA MANAGEMENT

### 4.1 Document Storage Strategy

**Status:** ⏳ Pending Decision

**Questions:**
- Where to store original uploaded documents (S3-compatible object storage)?
- Where to store generated XML (database, object storage)?
- Retention policy (7 years legally required - archive to cold storage)?
- Encryption at rest (provider-managed keys, customer-managed)?
- Geographic replication (single region, multi-region)?

**Considerations:**
- Cost at scale (10,000s of documents monthly)
- Retrieval latency requirements
- Compliance (GDPR, Croatian data residency laws)

**Decision Required By:** Sprint 2
**Stakeholders:** Compliance Officer, Technical Lead

---

### 4.2 Data Residency & Compliance

**Status:** ⚠️ Critical - Requires Legal Review

**Questions:**
- Must all data stay in Croatia/EU?
- Can we use non-EU cloud services (subject to data transfer agreements)?
- GDPR implications for storing invoices (personal data)?
- Data subject access request (DSAR) implementation requirements?
- Right to erasure vs 7-year retention conflict resolution?

**Decision Required By:** Before production launch
**Stakeholders:** Legal Team, Compliance Officer, Data Protection Officer

---

### 4.3 Backup & Disaster Recovery Testing

**Status:** ⏳ Pending Implementation

**Questions:**
- Backup testing frequency (weekly, monthly)?
- Automated restore testing in CI/CD?
- Disaster recovery drill schedule (quarterly)?
- Failover region selection (if multi-region)?
- Recovery point objective (RPO) validation method?

**Decision Required By:** Before production launch
**Stakeholders:** DevOps Team, Operations Team

---

## 5. SECURITY & COMPLIANCE

### 5.1 Authentication & Authorization

**Status:** ⏳ Pending Decision

**Questions:**
- OAuth 2.0 provider (Auth0, Keycloak, custom)?
- API key strategy for B2B integrations?
- Service-to-service authentication (mTLS, JWT)?
- Role-Based Access Control (RBAC) model definition?
- Multi-tenancy isolation strategy?

**Decision Required By:** Sprint 2
**Stakeholders:** Security Team, Product Owner

---

### 5.2 Penetration Testing

**Status:** ⏳ Pending Planning

**Questions:**
- Internal vs external penetration testing?
- Frequency (annual, semi-annual)?
- Scope (infrastructure, applications, social engineering)?
- Bug bounty program consideration?

**Decision Required By:** 2 months before production launch
**Stakeholders:** Security Team, Finance

---

### 5.3 Compliance Certifications

**Status:** ⏳ Needs Research

**Questions:**
- Is ISO 27001 required/beneficial?
- SOC 2 Type II compliance needed for B2B trust?
- Croatian-specific certifications required?
- eIDAS compliance for digital signatures?

**Decision Required By:** 6 months before production launch
**Stakeholders:** Compliance Officer, Legal Team, Sales

---

## 6. PERFORMANCE & SCALABILITY

### 6.1 Load Testing Strategy

**Status:** ⏳ Pending Definition

**Questions:**
- Load testing tools (k6, Gatling, Locust)?
- Test scenarios (normal load, peak load, stress test)?
- Performance regression testing in CI/CD?
- Production-like test environment required?

**Decision Required By:** Sprint 3
**Stakeholders:** QA Team, DevOps Team

---

### 6.2 Caching Strategy

**Status:** ⏳ Pending Decision

**Questions:**
- What to cache (validation rules, tax rates, user sessions)?
- Cache invalidation strategy (TTL, event-based)?
- Distributed cache (Redis Cluster, Memcached)?
- Cache aside vs read-through patterns?

**Decision Required By:** Performance optimization phase (Sprint 5+)
**Stakeholders:** Technical Lead, Performance Engineer

---

### 6.3 Database Sharding/Partitioning

**Status:** ⏳ Future Consideration

**Questions:**
- Sharding key (customer ID, date range)?
- When to implement (at what scale)?
- Horizontal partitioning by date (time-series data)?

**Decision Required By:** When reaching 80% of database capacity
**Stakeholders:** Database Administrator, Technical Lead

---

## 7. OBSERVABILITY & MONITORING

### 7.1 Monitoring Stack

**Status:** ⏳ Pending Decision

**Options:**
- **Self-Hosted:** Prometheus + Grafana + Loki + Jaeger
- **Managed:** Datadog, New Relic, Honeycomb
- **Hybrid:** Prometheus + managed Grafana Cloud

**Considerations:**
- Cost (self-hosted ops overhead vs managed service cost)
- Data retention requirements
- Alert routing complexity

**Decision Required By:** Sprint 2
**Stakeholders:** DevOps Team, Finance

---

### 7.2 Log Retention Policy

**Status:** ⏳ Pending Definition

**Questions:**
- Hot storage duration (7 days, 30 days)?
- Archive to cold storage (S3 Glacier)?
- Total retention period (1 year, 7 years for audit)?
- Log sampling for high-volume services?

**Decision Required By:** Before production deployment
**Stakeholders:** Compliance Officer, DevOps Team

---

### 7.3 On-Call Rotation

**Status:** ⏳ Pending Planning

**Questions:**
- Team size for sustainable on-call rotation?
- Escalation path (L1 → L2 → L3)?
- On-call compensation/time off policy?
- Runbook quality standards?

**Decision Required By:** 1 month before production launch
**Stakeholders:** Engineering Manager, HR

---

## 8. AI/ML COMPONENTS

### 8.1 AI Validation Model Training

**Status:** ⏳ Needs Research

**Questions:**
- Training data sources (synthetic, anonymized production data)?
- Model retraining frequency (daily, weekly)?
- A/B testing framework for model improvements?
- Explainability requirements (black box vs interpretable models)?

**Decision Required By:** Sprint 4 (AI validation service)
**Stakeholders:** ML Engineer, Data Scientist

---

### 8.2 OCR Engine Selection

**Status:** ⏳ Pending Evaluation

**Options:**
- **Tesseract** - Open source, customizable
- **Google Cloud Vision** - Managed, high accuracy, cost per request
- **Azure Computer Vision** - Managed, good Croatian language support
- **ABBYY FineReader** - Premium, enterprise-grade

**Considerations:**
- Accuracy for Croatian text
- Invoice-specific layout understanding
- Cost at scale
- Data privacy (sending documents to third parties)

**Decision Required By:** Sprint 3 (OCR service)
**Stakeholders:** ML Engineer, Product Owner, Legal

---

### 8.3 Triple Redundancy Implementation

**Status:** ⏳ Needs Design

**Questions:**
- Run 3 independent AI models (diversity)?
- Run same model 3 times with different preprocessing?
- How to resolve 2-1 splits (tie-breaking strategy)?
- Performance overhead acceptable (3x compute cost)?
- Threshold for manual review (2/3 consensus vs 3/3)?

**Decision Required By:** Sprint 4
**Stakeholders:** ML Engineer, Technical Lead, Product Owner

---

## 9. BUSINESS LOGIC & CROATIAN REGULATIONS

### 9.1 Tax Calculation Rules

**Status:** ⚠️ Critical - Requires Domain Expert

**Questions:**
- Current VAT rates in Croatia (standard, reduced)?
- Special tax handling (reverse charge, exempt, zero-rated)?
- Cross-border invoicing rules (EU vs non-EU)?
- Tax rounding rules (per line item, per invoice)?

**Decision Required By:** Sprint 3 (business rules engine)
**Stakeholders:** Tax Consultant, Accountant, Product Owner

---

### 9.2 FINA e-Račun Integration Details

**Status:** ⚠️ Critical - Requires FINA Documentation

**Questions:**
- API endpoint URLs (test, production)?
- Authentication method (API key, OAuth, client certificate)?
- Rate limits imposed by FINA?
- Retry policy for failed submissions?
- Webhook setup for status updates?

**Decision Required By:** Sprint 5 (FINA connector)
**Stakeholders:** Integration Lead, FINA Technical Contact

---

### 9.3 Porezna (Tax Authority) Integration

**Status:** ⚠️ Critical - Requires Porezna Documentation

**Questions:**
- Is integration mandatory or optional reporting?
- API availability (or file-based submission)?
- Schema differences vs FINA e-Račun?
- Submission deadlines (real-time, daily batch)?

**Decision Required By:** Sprint 5 (Porezna connector)
**Stakeholders:** Integration Lead, Porezna Technical Contact

---

## 10. PRODUCT & BUSINESS

### 10.1 Pricing Model

**Status:** ⏳ Pending Business Decision

**Questions:**
- Per-invoice pricing vs monthly subscription?
- Volume discounts (tiered pricing)?
- Freemium tier for market penetration?
- API access pricing separate from web UI?

**Decision Required By:** Before beta launch
**Stakeholders:** Product Owner, Finance, Sales

---

### 10.2 Customer Onboarding Flow

**Status:** ⏳ Pending Product Design

**Questions:**
- Self-service signup vs assisted onboarding?
- Trial period duration (14 days, 30 days)?
- Email verification process?
- Company verification (Croatian business registry check)?

**Decision Required By:** Sprint 6 (customer portal)
**Stakeholders:** Product Owner, UX Designer

---

### 10.3 Support Model

**Status:** ⏳ Pending Business Decision

**Questions:**
- Email support only vs chat vs phone?
- SLA tiers (basic, premium, enterprise)?
- Support hours (business hours, 24/7)?
- Self-service knowledge base vs documentation?

**Decision Required By:** 1 month before beta launch
**Stakeholders:** Customer Success Lead, Product Owner

---

## 11. DEVELOPMENT PROCESS

### 11.1 Code Review Process

**Status:** ⏳ Pending Definition

**Questions:**
- Minimum reviewers (1, 2)?
- Required approvals from specific roles (security review)?
- Automated checks in PR (linting, tests, coverage)?
- Review SLA (24 hours, 48 hours)?

**Decision Required By:** Sprint 1
**Stakeholders:** Engineering Manager, Development Team

---

### 11.2 Release Cadence

**Status:** ⏳ Pending Definition

**Questions:**
- Sprint duration (1 week, 2 weeks)?
- Release train model (fixed schedule)?
- Hotfix process for critical bugs?
- Feature flag strategy for dark launches?

**Decision Required By:** Sprint 1
**Stakeholders:** Product Owner, Engineering Manager

---

### 11.3 Documentation Standards

**Status:** ⏳ Pending Definition

**Questions:**
- API documentation tool (Swagger UI, Redoc, Stoplight)?
- Architecture diagrams (C4 model, UML, informal)?
- ADR format (Markdown, dedicated tool)?
- Wiki vs docs-as-code (Git-versioned Markdown)?

**Decision Required By:** Sprint 1
**Stakeholders:** Technical Writer, Technical Lead

---

## 12. OPERATIONAL EXCELLENCE

### 12.1 Incident Management Process

**Status:** ⏳ Pending Definition

**Questions:**
- Incident tracking tool (PagerDuty, OpsGenie, Jira)?
- Blameless postmortem process?
- Incident severity definitions?
- Communication plan (status page, email notifications)?

**Decision Required By:** Before production launch
**Stakeholders:** Operations Team, Engineering Manager

---

### 12.2 Capacity Planning

**Status:** ⏳ Pending Definition

**Questions:**
- Usage forecasting methodology?
- Infrastructure provisioning lead time?
- Autoscaling thresholds?
- Budget allocation for unexpected growth?

**Decision Required By:** 2 months before production launch
**Stakeholders:** DevOps Team, Finance, Product Owner

---

### 12.3 Cost Optimization

**Status:** ⏳ Ongoing Concern

**Questions:**
- Reserved instances for predictable workloads?
- Spot instances for batch processing?
- Right-sizing services (CPU/memory allocation)?
- Cold storage for archived documents?
- CDN for static assets?

**Decision Required By:** Ongoing (monthly reviews)
**Stakeholders:** FinOps Team, DevOps Team

---

## 13. RISK MITIGATION

### 13.1 Vendor Lock-In Concerns

**Status:** ⏳ Needs Assessment

**Questions:**
- Abstraction layers for cloud provider APIs?
- Multi-cloud strategy (DigitalOcean + AWS/GCP backup)?
- Exit strategy if DigitalOcean acquired/service degraded?

**Decision Required By:** Architecture finalization (Sprint 2)
**Stakeholders:** Technical Lead, CTO

---

### 13.2 Key Person Dependencies

**Status:** ⏳ Needs Assessment

**Questions:**
- Knowledge sharing practices (pair programming, documentation)?
- Cross-training plan for critical services?
- Succession planning for key technical roles?

**Decision Required By:** Ongoing
**Stakeholders:** Engineering Manager, HR

---

### 13.3 Third-Party API Reliability

**Status:** ⏳ Needs Monitoring

**Questions:**
- What if FINA API goes down (queue for retry)?
- Fallback mechanisms for OCR services?
- SLA guarantees from third-party vendors?

**Decision Required By:** Before production dependencies introduced
**Stakeholders:** Integration Lead, Product Owner

---

## 14. FUTURE ENHANCEMENTS (NOT MVP)

### 14.1 Multi-Tenancy

**Status:** 🔮 Future Consideration

**Questions:**
- Database per tenant vs shared database with tenant_id?
- Kubernetes namespace per tenant?
- Custom domain support (white-labeling)?

**Decision Required By:** When first enterprise customer requests it
**Stakeholders:** Product Owner, Technical Lead

---

### 14.2 Mobile App

**Status:** 🔮 Future Consideration

**Questions:**
- Native (iOS/Android) vs cross-platform (React Native, Flutter)?
- Mobile-specific features (photo upload for invoices)?

**Decision Required By:** Post-launch product roadmap
**Stakeholders:** Product Owner, Mobile Team

---

### 14.3 Blockchain Audit Trail

**Status:** 🔮 Experimental

**Questions:**
- Regulatory interest in blockchain-based audit trails?
- Cost-benefit analysis of immutable ledger?
- Integration with existing audit log system?

**Decision Required By:** Research phase only
**Stakeholders:** CTO, Compliance Officer

---

## DECISION LOG

*As decisions are made, document them here with date and rationale, then remove from sections above.*

### Decided Items

*None yet - initial architecture phase*

---

**Last Updated:** 2025-11-09
**Review Cadence:** Weekly (during initial development)
**Document Owner:** Technical Lead
