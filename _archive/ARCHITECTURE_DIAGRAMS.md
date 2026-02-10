# Architecture Diagrams

**Visual Documentation of eRačun System Architecture**

---

## Table of Contents

1. [High-Level Repository Architecture](#high-level-repository-architecture)
2. [Service Communication Graph](#service-communication-graph)
3. [Message Queue Topology](#message-queue-topology)
4. [Validation Pipeline Flow](#validation-pipeline-flow)
5. [Full System Data Flow](#full-system-data-flow)
6. [Team Ownership Map](#team-ownership-map)
7. [External Dependencies](#external-dependencies)
8. [Deployment Architecture](#deployment-architecture)

---

## High-Level Repository Architecture

### 8 Independent Repositories

```mermaid
graph TB
    subgraph "Team 2 - Ingestion"
        INGESTION[eracun-ingestion<br/>Multi-Channel Intake<br/>7 services]
    end

    subgraph "Team 1 - Validation"
        VALIDATION[eracun-validation<br/>6-Layer Validation<br/>5 services]
    end

    subgraph "Team 1 - Transformation"
        TRANSFORMATION[eracun-transformation<br/>UBL 2.1 Generation<br/>1 service]
    end

    subgraph "Team 3 - Integration"
        INTEGRATION[eracun-integration<br/>FINA/Porezna/Digital Signature<br/>5 services]
    end

    subgraph "Team 3 - Archive"
        ARCHIVE[eracun-archive<br/>11-Year Retention<br/>2 services]
    end

    subgraph "Platform Team"
        INFRASTRUCTURE[eracun-infrastructure<br/>Cross-Cutting Services<br/>7 services]
        MOCKS[eracun-mocks<br/>Testing Infrastructure<br/>6 services]
        CONTRACTS[eracun-contracts<br/>Shared Schemas<br/>@eracun/contracts npm]
    end

    INGESTION -->|validation.input| VALIDATION
    VALIDATION -->|transformation.input| TRANSFORMATION
    TRANSFORMATION -->|integration.input| INTEGRATION
    INTEGRATION -->|archive.input| ARCHIVE

    INFRASTRUCTURE -.->|observes| INGESTION
    INFRASTRUCTURE -.->|observes| VALIDATION
    INFRASTRUCTURE -.->|observes| TRANSFORMATION
    INFRASTRUCTURE -.->|observes| INTEGRATION
    INFRASTRUCTURE -.->|observes| ARCHIVE

    CONTRACTS -.->|npm install| INGESTION
    CONTRACTS -.->|npm install| VALIDATION
    CONTRACTS -.->|npm install| TRANSFORMATION
    CONTRACTS -.->|npm install| INTEGRATION
    CONTRACTS -.->|npm install| ARCHIVE
    CONTRACTS -.->|npm install| INFRASTRUCTURE

    MOCKS -.->|test doubles| INGESTION
    MOCKS -.->|test doubles| VALIDATION
    MOCKS -.->|test doubles| TRANSFORMATION
    MOCKS -.->|test doubles| INTEGRATION

    style INGESTION fill:#e1f5ff
    style VALIDATION fill:#fff3e0
    style TRANSFORMATION fill:#f3e5f5
    style INTEGRATION fill:#e8f5e9
    style ARCHIVE fill:#fff9c4
    style INFRASTRUCTURE fill:#e0e0e0
    style MOCKS fill:#ffebee
    style CONTRACTS fill:#e8eaf6
```

---

## Service Communication Graph

### All 27 Services and Their Communication Paths

```mermaid
graph LR
    subgraph "INGESTION (eracun-ingestion)"
        GW[invoice-gateway-api<br/>HTTP/REST]
        EMAIL[email-ingestion-worker<br/>IMAP]
        SFTP[sftp-ingestion-worker<br/>SFTP]
        CLASSIFY[file-classifier]
        ATTACH[attachment-handler]
        XMLP[xml-parser]
        PDFP[pdf-parser]
    end

    subgraph "VALIDATION (eracun-validation)"
        COORD[validation-coordinator]
        XSD[xsd-validator]
        SCH[schematron-validator]
        OIB[oib-validator]
        KPD[kpd-validator]
        AI[ai-validation-service]
    end

    subgraph "TRANSFORMATION (eracun-transformation)"
        UBL[ubl-transformer]
    end

    subgraph "INTEGRATION (eracun-integration)"
        FINA[fina-connector]
        POREZNA[porezna-connector]
        DIGSIG[digital-signature-service]
        CERT[cert-lifecycle-manager]
        IBAN[iban-validator]
    end

    subgraph "ARCHIVE (eracun-archive)"
        ARCH[archive-service]
        OCR[ocr-processing-service]
    end

    subgraph "INFRASTRUCTURE (eracun-infrastructure)"
        HEALTH[health-monitor]
        NOTIF[notification-service]
        AUDIT[audit-logger]
        DLQ[dead-letter-handler]
        RETRY[retry-scheduler]
        KPD_SYNC[kpd-registry-sync]
        ADMIN[admin-portal-api]
    end

    GW -->|FileClassifiedEvent| CLASSIFY
    EMAIL -->|FileClassifiedEvent| CLASSIFY
    SFTP -->|FileClassifiedEvent| CLASSIFY
    CLASSIFY -->|XMLParseRequest| XMLP
    CLASSIFY -->|PDFParseRequest| PDFP
    CLASSIFY -->|AttachmentExtractRequest| ATTACH

    XMLP -->|ValidateInvoiceCommand| COORD
    PDFP -->|ValidateInvoiceCommand| COORD

    COORD -->|XSDValidateCommand| XSD
    XSD -->|SchematronValidateCommand| SCH
    SCH -->|OIBValidateCommand| OIB
    SCH -->|KPDValidateCommand| KPD
    KPD -->|AIValidateCommand| AI

    AI -->|TransformCommand| UBL
    UBL -->|SignatureRequest| DIGSIG
    DIGSIG -->|FINASubmitCommand| FINA
    DIGSIG -->|PoreznaSubmitCommand| POREZNA

    FINA -->|ArchiveCommand| ARCH
    POREZNA -->|ArchiveCommand| ARCH
    OCR -.->|OCR processing| ARCH

    HEALTH -.->|monitors| GW
    HEALTH -.->|monitors| COORD
    HEALTH -.->|monitors| UBL
    HEALTH -.->|monitors| FINA

    DLQ -.->|reprocesses| COORD
    RETRY -.->|schedules retry| FINA
    AUDIT -.->|logs| FINA
    NOTIF -.->|alerts| HEALTH

    style GW fill:#42a5f5
    style COORD fill:#ffa726
    style UBL fill:#ab47bc
    style FINA fill:#66bb6a
    style ARCH fill:#fff176
    style HEALTH fill:#bdbdbd
```

---

## Message Queue Topology

### RabbitMQ Queues and Routing

```mermaid
graph TB
    subgraph "Ingestion Queues"
        ING_IN[ingestion.input<br/>HTTP/Email/SFTP uploads]
        ING_CLASS[ingestion.classified<br/>File format detected]
    end

    subgraph "Validation Queues"
        VAL_IN[validation.input<br/>Start validation]
        VAL_XSD[validation.xsd.input]
        VAL_SCH[validation.schematron.input]
        VAL_OIB[validation.oib.input]
        VAL_KPD[validation.kpd.input]
        VAL_AI[validation.ai.input]
        VAL_OUT[validation.output<br/>Validation complete]
    end

    subgraph "Transformation Queue"
        TRANS_IN[transformation.input<br/>Generate UBL 2.1]
        TRANS_OUT[transformation.output<br/>UBL generated]
    end

    subgraph "Integration Queues"
        INT_IN[integration.input<br/>Sign + Submit]
        INT_FINA[integration.fina.input]
        INT_POREZNA[integration.porezna.input]
        INT_OUT[integration.output<br/>Submission complete]
    end

    subgraph "Archive Queue"
        ARCH_IN[archive.input<br/>Store 11 years]
    end

    subgraph "Infrastructure Queues"
        DLQ_QUEUE[dead-letter-queue<br/>Failed messages]
        RETRY_QUEUE[retry.scheduled<br/>Delayed retry]
        NOTIF_QUEUE[notification.requests<br/>Email/SMS/Webhook]
    end

    subgraph "Event Topics (Kafka)"
        EVENTS[audit.events<br/>Event sourcing]
    end

    ING_IN --> ING_CLASS
    ING_CLASS --> VAL_IN
    VAL_IN --> VAL_XSD
    VAL_XSD --> VAL_SCH
    VAL_SCH --> VAL_OIB
    VAL_SCH --> VAL_KPD
    VAL_KPD --> VAL_AI
    VAL_AI --> VAL_OUT
    VAL_OUT --> TRANS_IN
    TRANS_IN --> TRANS_OUT
    TRANS_OUT --> INT_IN
    INT_IN --> INT_FINA
    INT_IN --> INT_POREZNA
    INT_FINA --> INT_OUT
    INT_POREZNA --> INT_OUT
    INT_OUT --> ARCH_IN

    VAL_IN -.->|on failure| DLQ_QUEUE
    TRANS_IN -.->|on failure| DLQ_QUEUE
    INT_IN -.->|on failure| RETRY_QUEUE

    DLQ_QUEUE -.->|reprocess| VAL_IN
    RETRY_QUEUE -.->|delayed| INT_IN

    VAL_OUT -.->|publish event| EVENTS
    INT_OUT -.->|publish event| EVENTS
    ARCH_IN -.->|publish event| EVENTS

    EVENTS -.->|subscribe| NOTIF_QUEUE

    style ING_IN fill:#e1f5ff
    style VAL_IN fill:#fff3e0
    style TRANS_IN fill:#f3e5f5
    style INT_IN fill:#e8f5e9
    style ARCH_IN fill:#fff9c4
    style DLQ_QUEUE fill:#ffebee
    style EVENTS fill:#e8eaf6
```

---

## Validation Pipeline Flow

### 6-Layer Validation with Triple Redundancy

```mermaid
flowchart TD
    START([Invoice XML]) --> COORD[validation-coordinator<br/>Orchestrates validation]

    COORD --> LAYER1[Layer 1: XSD Validation<br/>xsd-validator]
    LAYER1 -->|PASS| LAYER2[Layer 2: Schematron<br/>schematron-validator<br/>Business rules]
    LAYER1 -->|FAIL| REJECT1[❌ Reject: Invalid XML]

    LAYER2 -->|PASS| PARALLEL{Parallel Validation}
    LAYER2 -->|FAIL| REJECT2[❌ Reject: Business rule violation]

    PARALLEL --> LAYER3A[Layer 3a: OIB Check<br/>oib-validator<br/>Croatian tax ID]
    PARALLEL --> LAYER3B[Layer 3b: KPD Check<br/>kpd-validator<br/>Product codes]

    LAYER3A -->|PASS| LAYER4[Layer 4: Semantic<br/>Cross-field validation]
    LAYER3A -->|FAIL| REJECT3A[❌ Reject: Invalid OIB]

    LAYER3B -->|PASS| LAYER4
    LAYER3B -->|FAIL| REJECT3B[❌ Reject: Invalid KPD]

    LAYER4 -->|PASS| LAYER5[Layer 5: AI Validation<br/>ai-validation-service<br/>Anomaly detection]
    LAYER4 -->|FAIL| REJECT4[❌ Reject: Semantic error]

    LAYER5 -->|PASS| LAYER6{Layer 6: Consensus<br/>Triple Redundancy}
    LAYER5 -->|FAIL or UNCERTAIN| MANUAL[⚠️ Manual Review Queue]

    LAYER6 -->|2/3 validators agree| ACCEPT[✅ Accept]
    LAYER6 -->|No consensus| MANUAL

    ACCEPT --> NEXT([transformation.input])

    MANUAL -->|Human decision| ACCEPT
    MANUAL -->|Human decision| FINAL_REJECT[❌ Final Reject]

    style COORD fill:#ffa726
    style LAYER1 fill:#42a5f5
    style LAYER2 fill:#66bb6a
    style LAYER3A fill:#ab47bc
    style LAYER3B fill:#ab47bc
    style LAYER4 fill:#26c6da
    style LAYER5 fill:#ff7043
    style LAYER6 fill:#9ccc65
    style ACCEPT fill:#4caf50
    style REJECT1 fill:#f44336
    style REJECT2 fill:#f44336
    style REJECT3A fill:#f44336
    style REJECT3B fill:#f44336
    style REJECT4 fill:#f44336
    style MANUAL fill:#ff9800
```

---

## Full System Data Flow

### End-to-End Invoice Processing

```mermaid
flowchart LR
    subgraph "External Input"
        HTTP[HTTP Upload]
        EMAIL[Email Attachment]
        SFTP_IN[SFTP Drop]
    end

    subgraph "Ingestion (Team 2)"
        GATEWAY[invoice-gateway-api]
        EMAIL_W[email-ingestion-worker]
        SFTP_W[sftp-ingestion-worker]
        PARSER[xml-parser / pdf-parser]
    end

    subgraph "Validation (Team 1)"
        VAL_PIPE[6-Layer Validation Pipeline<br/>XSD → Schematron → OIB/KPD → Semantic → AI → Consensus]
    end

    subgraph "Transformation (Team 1)"
        UBL_T[ubl-transformer<br/>Generate UBL 2.1 + Croatian CIUS]
    end

    subgraph "Integration (Team 3)"
        SIGN[digital-signature-service<br/>XMLDSig + Timestamp]
        FINA_S[fina-connector<br/>B2C Fiscalization]
        POREZNA_S[porezna-connector<br/>B2B/B2G Reporting]
    end

    subgraph "Archive (Team 3)"
        ARCHIVE_S[archive-service<br/>11-Year WORM Storage<br/>3 Replicas]
    end

    subgraph "Infrastructure (Platform)"
        MONITOR[health-monitor]
        AUDIT_L[audit-logger<br/>Immutable Log]
        NOTIF_S[notification-service]
    end

    subgraph "External Output"
        FINA_API[FINA API<br/>cis.porezna-uprava.hr]
        POREZNA_API[Porezna API<br/>Tax Authority]
        S3[S3 Archive<br/>3 Regions]
        USER[User Notifications<br/>Email/SMS/Webhook]
    end

    HTTP --> GATEWAY
    EMAIL --> EMAIL_W
    SFTP_IN --> SFTP_W

    GATEWAY --> PARSER
    EMAIL_W --> PARSER
    SFTP_W --> PARSER

    PARSER --> VAL_PIPE
    VAL_PIPE -->|✅ Valid| UBL_T
    VAL_PIPE -->|❌ Invalid| NOTIF_S

    UBL_T --> SIGN
    SIGN --> FINA_S
    SIGN --> POREZNA_S

    FINA_S -->|Submit| FINA_API
    POREZNA_S -->|Submit| POREZNA_API

    FINA_API -->|JIR confirmation| ARCHIVE_S
    POREZNA_API -->|UUID confirmation| ARCHIVE_S

    ARCHIVE_S -->|Store| S3

    MONITOR -.->|health checks| GATEWAY
    MONITOR -.->|health checks| VAL_PIPE
    MONITOR -.->|health checks| SIGN
    MONITOR -.->|health checks| FINA_S

    AUDIT_L -.->|log all events| PARSER
    AUDIT_L -.->|log all events| VAL_PIPE
    AUDIT_L -.->|log all events| FINA_S
    AUDIT_L -.->|log all events| ARCHIVE_S

    NOTIF_S --> USER

    style GATEWAY fill:#42a5f5
    style VAL_PIPE fill:#ffa726
    style UBL_T fill:#ab47bc
    style SIGN fill:#66bb6a
    style ARCHIVE_S fill:#fff176
    style MONITOR fill:#bdbdbd
    style FINA_API fill:#4caf50
    style S3 fill:#ffd54f
```

---

## Team Ownership Map

### 8 Repositories / 4 Teams

```mermaid
graph TB
    subgraph "Platform Team (4 members)"
        direction LR
        INFRA_REPO[eracun-infrastructure<br/>7 services]
        MOCKS_REPO[eracun-mocks<br/>6 services]
        CONTRACTS_REPO[eracun-contracts<br/>npm package]
    end

    subgraph "Team 1: Core Processing (5 members)"
        direction LR
        VAL_REPO[eracun-validation<br/>5 services]
        TRANS_REPO[eracun-transformation<br/>1 service]
    end

    subgraph "Team 2: Ingestion (5 members)"
        direction LR
        ING_REPO[eracun-ingestion<br/>7 services]
    end

    subgraph "Team 3: Integration & Archive (5 members)"
        direction LR
        INT_REPO[eracun-integration<br/>5 services]
        ARCH_REPO[eracun-archive<br/>2 services]
    end

    CONTRACTS_REPO -.->|npm dependency| VAL_REPO
    CONTRACTS_REPO -.->|npm dependency| TRANS_REPO
    CONTRACTS_REPO -.->|npm dependency| ING_REPO
    CONTRACTS_REPO -.->|npm dependency| INT_REPO
    CONTRACTS_REPO -.->|npm dependency| ARCH_REPO
    CONTRACTS_REPO -.->|npm dependency| INFRA_REPO

    MOCKS_REPO -.->|test doubles| VAL_REPO
    MOCKS_REPO -.->|test doubles| ING_REPO
    MOCKS_REPO -.->|test doubles| INT_REPO

    INFRA_REPO -.->|observability| VAL_REPO
    INFRA_REPO -.->|observability| ING_REPO
    INFRA_REPO -.->|observability| INT_REPO
    INFRA_REPO -.->|observability| ARCH_REPO

    style INFRA_REPO fill:#e0e0e0
    style MOCKS_REPO fill:#ffebee
    style CONTRACTS_REPO fill:#e8eaf6
    style VAL_REPO fill:#fff3e0
    style TRANS_REPO fill:#f3e5f5
    style ING_REPO fill:#e1f5ff
    style INT_REPO fill:#e8f5e9
    style ARCH_REPO fill:#fff9c4
```

---

## External Dependencies

### Third-Party Services and APIs

```mermaid
graph TB
    subgraph "eRačun System"
        SYSTEM[Invoice Processing<br/>Platform]
    end

    subgraph "Croatian Tax Authority"
        FINA[FINA API<br/>cis.porezna-uprava.hr<br/>SOAP]
        POREZNA[Porezna API<br/>Tax Reporting<br/>REST + OAuth2]
    end

    subgraph "Certificate Authorities"
        FINA_CA[FINA CA<br/>X.509 Certificates<br/>~40 EUR/5 years]
        AKD_CA[AKD CA<br/>Alternative CA]
    end

    subgraph "Data Registries"
        KLASUS[KLASUS Registry<br/>data.gov.hr<br/>Product codes]
        OIB_REG[OIB Registry<br/>Croatian tax IDs]
    end

    subgraph "Infrastructure Services"
        DO[DigitalOcean<br/>Droplets + Managed DB]
        S3[S3-Compatible Storage<br/>Archive (11 years)]
    end

    subgraph "Messaging & Observability"
        RABBIT[RabbitMQ<br/>Self-hosted]
        KAFKA[Kafka<br/>Self-hosted]
        PROM[Prometheus<br/>Self-hosted]
        GRAFANA[Grafana<br/>Self-hosted]
        JAEGER[Jaeger<br/>Self-hosted]
    end

    subgraph "Email Services"
        SMTP[SMTP Server<br/>Outbound notifications]
        IMAP[IMAP Server<br/>Email ingestion]
    end

    subgraph "Testing Services (MOCKS)"
        MOCK_FINA[fina-mock<br/>Local testing]
        MOCK_POREZNA[porezna-mock<br/>Local testing]
    end

    SYSTEM -->|Submit B2C| FINA
    SYSTEM -->|Submit B2B/B2G| POREZNA
    SYSTEM -->|Request cert| FINA_CA
    SYSTEM -->|Request cert| AKD_CA
    SYSTEM -->|Sync codes| KLASUS
    SYSTEM -->|Validate OIB| OIB_REG
    SYSTEM -->|Deploy| DO
    SYSTEM -->|Archive| S3
    SYSTEM -->|Messages| RABBIT
    SYSTEM -->|Events| KAFKA
    SYSTEM -->|Metrics| PROM
    SYSTEM -->|Dashboards| GRAFANA
    SYSTEM -->|Traces| JAEGER
    SYSTEM -->|Send email| SMTP
    SYSTEM -->|Receive email| IMAP

    SYSTEM -.->|local dev/test| MOCK_FINA
    SYSTEM -.->|local dev/test| MOCK_POREZNA

    style FINA fill:#4caf50
    style POREZNA fill:#66bb6a
    style FINA_CA fill:#ffa726
    style KLASUS fill:#42a5f5
    style DO fill:#0080ff
    style S3 fill:#ffd54f
    style MOCK_FINA fill:#ffebee
    style MOCK_POREZNA fill:#ffebee
```

---

## Deployment Architecture

### DigitalOcean Infrastructure

```mermaid
graph TB
    subgraph "DigitalOcean Cloud (EU Region)"
        subgraph "Droplet 1: Application Services"
            SVC1[invoice-gateway-api<br/>validation-coordinator<br/>ubl-transformer]
            SVC2[fina-connector<br/>porezna-connector]
            SVC3[archive-service]
        end

        subgraph "Droplet 2: Ingestion Workers"
            WORKERS[email-ingestion-worker<br/>sftp-ingestion-worker<br/>file-classifier]
        end

        subgraph "Droplet 3: Infrastructure Services"
            INFRA_SVC[health-monitor<br/>notification-service<br/>audit-logger<br/>dead-letter-handler]
        end

        subgraph "Managed Services"
            DB[(PostgreSQL 15<br/>Managed Database<br/>3 replicas)]
            REDIS[(Redis<br/>Cache)]
        end

        subgraph "Message Bus (Self-Hosted)"
            MQ[RabbitMQ Cluster<br/>3 nodes]
            KAFKA_C[Kafka<br/>3 brokers]
        end

        subgraph "Observability Stack"
            PROM_SRV[Prometheus]
            GRAF[Grafana]
            JAEGER_SRV[Jaeger]
            LOKI[Loki]
        end

        LB[Load Balancer<br/>nginx]
    end

    subgraph "External Storage"
        S3_PRIMARY[S3 Primary<br/>EU-West-1]
        S3_BACKUP1[S3 Replica<br/>EU-Central-1]
        S3_BACKUP2[S3 Replica<br/>EU-North-1]
    end

    subgraph "External APIs"
        FINA_EXT[FINA API]
        POREZNA_EXT[Porezna API]
    end

    INTERNET[Internet] --> LB
    LB --> SVC1
    LB --> SVC2

    SVC1 <--> DB
    SVC2 <--> DB
    SVC3 <--> DB
    WORKERS <--> DB

    SVC1 <--> REDIS
    SVC2 <--> REDIS
    WORKERS <--> REDIS

    SVC1 --> MQ
    SVC2 --> MQ
    SVC3 --> MQ
    WORKERS --> MQ
    INFRA_SVC --> MQ

    SVC1 --> KAFKA_C
    SVC2 --> KAFKA_C
    INFRA_SVC --> KAFKA_C

    SVC1 -.-> PROM_SRV
    SVC2 -.-> PROM_SRV
    SVC3 -.-> PROM_SRV
    WORKERS -.-> PROM_SRV
    INFRA_SVC -.-> PROM_SRV

    PROM_SRV --> GRAF

    SVC1 -.-> JAEGER_SRV
    SVC2 -.-> JAEGER_SRV
    SVC3 -.-> JAEGER_SRV

    INFRA_SVC --> LOKI

    SVC3 --> S3_PRIMARY
    S3_PRIMARY --> S3_BACKUP1
    S3_PRIMARY --> S3_BACKUP2

    SVC2 -->|SOAP/REST| FINA_EXT
    SVC2 -->|REST| POREZNA_EXT

    style LB fill:#42a5f5
    style DB fill:#4caf50
    style MQ fill:#ffa726
    style S3_PRIMARY fill:#ffd54f
    style FINA_EXT fill:#66bb6a
```

---

## Legend

### Diagram Conventions

- **Solid arrows (→)**: Direct message/command flow (synchronous or queued)
- **Dashed arrows (⇢)**: Observation/monitoring (non-blocking)
- **Dotted arrows (⋯>)**: Dependency (npm install, test doubles)
- **Blue boxes**: Ingestion services (Team 2)
- **Orange boxes**: Validation services (Team 1)
- **Purple boxes**: Transformation services (Team 1)
- **Green boxes**: Integration services (Team 3)
- **Yellow boxes**: Archive services (Team 3)
- **Gray boxes**: Infrastructure services (Platform Team)
- **Red boxes**: Mock services (Platform Team)
- **Indigo boxes**: Shared contracts (Platform Team)

---

**Generated:** 2025-11-17
**Version:** 1.0.0
**Maintained by:** Platform Team
**Review Cadence:** Monthly (as architecture evolves)
