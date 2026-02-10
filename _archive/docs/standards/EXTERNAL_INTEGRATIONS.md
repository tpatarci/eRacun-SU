# External System Integration Catalog

**Document Classification:** Technical Integration Specifications
**Purpose:** Authoritative catalog of all external systems with integration requirements
**Status:** Active
**Last Updated:** 2025-11-10

---

## 1. OVERVIEW

This document catalogs all external systems that the eRacun platform integrates with, including authentication requirements, rate limits, SLAs, error handling, and credential lifecycle management.

**External System Categories:**
1. **Tax Authority Services** - FINA Fiscalization API, AS4 Central Exchange
2. **Metadata Services** - AMS, MPS
3. **Classification Registries** - DZS KLASUS
4. **Certificate Authorities** - FINA, AKD
5. **Timestamp Authorities** - eIDAS-qualified TSAs

---

## 2. EXTERNAL SYSTEM CATALOG

### 2.1 FINA Fiscalization Service (B2C SOAP API)

**System Name:** Fiscalization Service for B2C Invoices
**Provider:** Croatian Tax Authority (Porezna uprava)
**Protocol:** SOAP 1.2 over HTTPS
**Use Case:** Submit B2C invoices and receive JIR (Unique Invoice Identifier)

#### Endpoints

| Environment | URL | Availability |
|-------------|-----|--------------|
| Production | `https://cis.porezna-uprava.hr:8449/FiskalizacijaService` | 1 Jan 2026 - ongoing |
| Test | `https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest` | 1 Sept 2025 - ongoing |

#### Authentication

**Type:** Application Digital Certificate (X.509)
**Transport Security:** 1-way TLS/SSL (server certificate validation only)
**Message Security:** XMLDSig envelope signature with FINA certificate

**Certificate Requirements:**
- **Issuer:** FINA or AKD
- **Type:** Application certificate for fiscalization
- **Format:** PKCS#12 (.p12)
- **Validity:** 5 years
- **Cost:** 39.82 EUR + VAT (production), FREE (demo)
- **Acquisition Time:** 5-10 business days

#### Operations

| Operation | Purpose | Request Timeout | Retry Policy |
|-----------|---------|-----------------|--------------|
| `racuni` | Submit invoice for fiscalization | 5s | 3 retries, exponential backoff (2s, 4s, 8s) |
| `echo` | Test service availability | 2s | No retry (health check) |
| `provjera` | Validate invoice (TEST ONLY) | 5s | No retry (validation check) |

#### WSDL Version

**Current:** 1.9 (active from 5 Nov 2025)
**Monitoring:** Check `https://cis.porezna-uprava.hr:8449/FiskalizacijaService?wsdl` for updates

#### Rate Limits

**Documented Limits:** None officially published
**Observed Behavior:** ~100 requests/second sustained (based on fiscal device testing)
**Recommended Client Limit:** 50 requests/second with token bucket algorithm
**Backpressure Strategy:** Queue locally, process with controlled rate

#### SLA

**Availability:** 99.9% (24/7 operation)
**Typical Response Time:** <2 seconds
**Maintenance Windows:** Announced via porezna.gov.hr (typically overnight, rare)

#### Error Codes

| Code | Description | Action |
|------|-------------|--------|
| `s:001` | Signature verification failed | Check certificate validity, regenerate signature |
| `s:002` | Expired certificate | Renew certificate immediately |
| `s:003` | Invalid XML structure | Validate against WSDL schema |
| `s:004` | Invalid OIB | Verify issuer/buyer OIB checksums |
| `s:005` | Duplicate invoice number | Check for resubmission, verify uniqueness |
| `s:999` | Internal server error | Retry with exponential backoff |

**Full Error Catalog:** See `docs/standards/fina-error-codes.md` (to be created)

#### Offline Fallback

**Regulatory Grace Period:** 48 hours
**Implementation:**
- Queue failed requests to PostgreSQL (`fiscalization_queue` table)
- Background worker retries every 5 minutes
- Alert if queue depth >100 or age >12 hours
- Manual intervention if >24 hours

#### Data Residency

**Servers Located:** Croatia (Tax Authority infrastructure)
**Data Processing:** Within EU
**GDPR Compliance:** Tax Authority acts as data controller

#### Integration Test Plan

**Test Scenarios:**
1. **Happy Path:** Submit valid B2C invoice, receive JIR
2. **Invalid Signature:** Submit with wrong certificate, verify rejection
3. **Expired Certificate:** Test error handling
4. **Duplicate Invoice:** Resubmit same invoice number, verify idempotency
5. **Network Timeout:** Simulate timeout, verify retry logic
6. **Malformed XML:** Submit invalid structure, verify error handling
7. **Echo Test:** Verify service availability check
8. **Load Test:** 100 concurrent requests, measure response times

**Test Data:** Use demo certificates and test OIBs provided by Tax Authority

**Success Criteria:**
- All scenarios pass
- Response times <5s p95
- Retry logic functions correctly
- No unhandled exceptions

---

### 2.2 AS4 Central Exchange (B2B Invoice Exchange)

**System Name:** AS4 Message Exchange Infrastructure
**Provider:** Croatian Tax Authority
**Protocol:** AS4 (OASIS ebMS 3.0)
**Use Case:** Exchange B2B/B2G invoices via four-corner model

#### Architecture

```
[Sender] → [Access Point 1] → [Central Exchange] → [Access Point 2] → [Recipient]
           (our system or      (Tax Authority)    (recipient's AP)
            intermediary)
```

#### Access Point Options

| Option | Provider | Type | Cost | Complexity | Control |
|--------|----------|------|------|------------|---------|
| Proprietary AP | Self-hosted | Custom | €0 (infra only) | High | Full |
| FINA eRačun | FINA | Managed | ~50-200 EUR/month | Low | Limited |
| ePoslovanje.hr | ePoslovanje | Managed | Variable | Low | Limited |
| Hrvatski Telekom | HT | Managed | Variable | Low | Limited |
| mStart | mStart | Managed | Variable | Low | Limited |

**Recommendation for eRacun Platform:** Start with **FINA eRačun** intermediary for faster time-to-market, migrate to proprietary AP in Phase 2 if volume justifies complexity.

#### Endpoints

**Production Central Exchange:** `https://[to-be-announced].porezna-uprava.hr/as4`
**Test Central Exchange:** `https://[to-be-announced].apis-it.hr/as4-test`

**Note:** Endpoints announced via Tax Authority technical bulletins (monitor `porezna.gov.hr`)

#### Authentication

**Type:** 2-way TLS (mutual TLS)
**Client Certificate:** Same FINA application certificate as SOAP API
**Server Certificate:** Tax Authority certificate (validate against Fina Root CA)

**AS4 Message Security:**
- **Transport:** TLS 1.2+ mandatory
- **Message Signature:** XMLDSig (same as invoice signature)
- **Message Encryption:** Optional (not required by regulation, recommended for sensitive data)
- **Non-Repudiation:** Signed delivery receipts (ebMS3 receipts)

#### Message Structure

**AS4 Envelope Headers:**
```xml
<eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <eb:UserMessage>
    <eb:MessageInfo>
      <eb:Timestamp>2026-01-15T10:30:00Z</eb:Timestamp>
      <eb:MessageId>uuid-...</eb:MessageId>
    </eb:MessageInfo>
    <eb:PartyInfo>
      <eb:From><eb:PartyId type="OIB">12345678901</eb:PartyId></eb:From>
      <eb:To><eb:PartyId type="OIB">98765432109</eb:PartyId></eb:To>
    </eb:PartyInfo>
    <eb:CollaborationInfo>
      <eb:Service>eInvoicing</eb:Service>
      <eb:Action>SendInvoice</eb:Action>
    </eb:CollaborationInfo>
  </eb:UserMessage>
</eb:Messaging>
```

**Payload:** UBL 2.1 XML invoice (attached as separate MIME part)

#### Rate Limits

**Documented Limits:** Not yet published
**Expected Capacity:** 1,000+ messages/second (based on European AS4 implementations)
**Client-Side Limit:** Implement 100 req/sec limit until production data available

#### SLA

**Availability:** 99.9% target (not yet contractual)
**Message Delivery Time:** <30 seconds end-to-end
**Retry Mechanism:** AS4 protocol includes automatic retries (configurable)

#### Error Handling

**AS4 Error Codes:**
- `EBMS:0001` - ValueNotRecognized (invalid header value)
- `EBMS:0002` - FeatureNotSupported
- `EBMS:0004` - ConnectionFailure
- `EBMS:0101` - FailedAuthentication (certificate issue)
- `EBMS:0102` - FailedDecryption
- `EBMS:0103` - PolicyNoncompliance (doesn't meet security requirements)

**Business-Level Errors:** Returned as invoice rejection messages (separate B2B flow)

#### Data Residency

**Central Exchange Location:** Croatia
**Access Point Location:** Varies by provider (FINA: Croatia, others: check SLA)

#### Certification Requirements (Proprietary AP)

**Authority:** Tax Authority Compliance Testing Portal
**Process:**
1. Register AP with Tax Authority
2. Complete technical profile questionnaire
3. Execute test scenarios with test partners
4. Submit evidence package
5. Receive compliance certificate

**Certification Scenarios:**
- Message send/receive
- Signature verification
- Error handling
- Receipt acknowledgment
- Performance benchmarks

**Timeline:** 2-4 weeks after completing tests

#### Integration Test Plan

**Test Scenarios:**
1. **Send Invoice:** Submit to test partner, verify delivery receipt
2. **Receive Invoice:** Accept incoming message, parse UBL payload
3. **Reject Invoice:** Send rejection message, verify received by sender
4. **Duplicate Detection:** Resubmit same MessageId, verify idempotent handling
5. **Invalid Signature:** Test signature verification failure
6. **Large Invoice:** 5MB XML payload, verify transmission
7. **Concurrent Messages:** 50 simultaneous sends, measure throughput

**Test Partners:** Tax Authority provides test OIBs and Access Points

**Success Criteria:**
- All messages delivered successfully
- Receipts received within 10 seconds
- No data corruption
- Error handling verified

---

### 2.3 AMS (Address Metadata Service)

**System Name:** Address of Metadata Services
**Provider:** Croatian Tax Authority
**Protocol:** REST (primary) and SOAP (legacy)
**Use Case:** Lookup recipient's Access Point endpoint and capabilities

#### Endpoints

| Environment | URL | Protocol |
|-------------|-----|----------|
| Production | `https://ams.porezna-uprava.hr/api/v1/lookup` | REST |
| Production (SOAP) | `https://ams.porezna-uprava.hr/soap/ams` | SOAP 1.2 |
| Test | `https://ams-test.apis-it.hr/api/v1/lookup` | REST |

#### Authentication

**Type:** API Key (for REST) or Client Certificate (for SOAP)
**API Key Acquisition:** Via ePorezna portal (FiskAplikacija configuration)
**Key Rotation:** 90 days (automated renewal via portal)

**Request Headers:**
```http
GET /api/v1/lookup?oib=12345678901 HTTP/1.1
Host: ams.porezna-uprava.hr
Authorization: Bearer {api_key}
Accept: application/json
```

#### Operations

**REST Endpoint:**
```
GET /api/v1/lookup?oib={recipient_oib}
```

**Response Format:**
```json
{
  "oib": "12345678901",
  "name": "Example d.o.o.",
  "access_point": {
    "url": "https://ap.fina.hr/as4",
    "provider": "FINA eRačun",
    "capabilities": ["UBL-2.1", "CII-2.0"],
    "max_message_size_mb": 10
  },
  "status": "active",
  "last_updated": "2026-01-15T10:00:00Z"
}
```

**Error Responses:**
- `404 Not Found` - OIB not registered in AMS
- `401 Unauthorized` - Invalid API key
- `429 Too Many Requests` - Rate limit exceeded

#### Rate Limits

**Limit:** 1,000 requests/hour per API key
**Burst Limit:** 100 requests/minute
**Rate Limit Headers:**
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1641038400
```

**Client Strategy:** Cache responses for 24 hours (AMS data changes infrequently)

#### SLA

**Availability:** 99.5%
**Response Time:** <500ms p95
**Data Freshness:** Updated daily (new registrations, endpoint changes)

#### Caching Strategy

**Implementation:**
- Cache AMS responses in Redis (TTL: 24 hours)
- Cache key: `ams:oib:{oib_number}`
- Invalidation: Manual via admin API if recipient reports endpoint change
- Fallback: On cache miss, query AMS; on AMS failure, use last known value (if <7 days old)

#### Integration Test Plan

**Test Scenarios:**
1. **Lookup Valid OIB:** Verify response contains Access Point URL
2. **Lookup Invalid OIB:** Verify 404 response
3. **Expired API Key:** Test 401 handling
4. **Rate Limit Exceeded:** Verify 429 handling and backoff
5. **Cache Hit:** Verify Redis cache functioning
6. **Cache Miss:** Verify AMS query on cache expiry

**Success Criteria:**
- <500ms response time for cached lookups
- Correct error handling for all failure modes
- No unnecessary AMS queries (caching effective)

---

### 2.4 MPS (Metadata Service)

**System Name:** Metadata Service
**Provider:** Croatian Tax Authority
**Protocol:** SOAP over HTTPS
**Use Case:** Query detailed service capabilities and routing preferences

#### Endpoints

| Environment | URL |
|-------------|-----|
| Production | `https://mps.porezna-uprava.hr/MetadataService` |
| Test | `https://mps-test.apis-it.hr/MetadataService` |

#### Authentication

**Type:** 2-way TLS (mutual TLS)
**Client Certificate:** FINA application certificate
**Server Certificate:** Tax Authority certificate

#### Operations

**WSDL Operation:** `GetServiceMetadata`

**Request:**
```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetServiceMetadata xmlns="http://mps.porezna.hr/2025">
      <OIB>12345678901</OIB>
      <ServiceType>eInvoicing</ServiceType>
    </GetServiceMetadata>
  </soap:Body>
</soap:Envelope>
```

**Response:**
```xml
<ServiceMetadata>
  <OIB>12345678901</OIB>
  <SupportedDocuments>
    <Document type="UBL-Invoice-2.1" maxSize="10485760"/>
    <Document type="UBL-CreditNote-2.1" maxSize="10485760"/>
  </SupportedDocuments>
  <RoutingPreferences>
    <PreferredProtocol>AS4</PreferredProtocol>
    <SLA>
      <DeliveryTime>30s</DeliveryTime>
      <Availability>99.9%</Availability>
    </SLA>
  </RoutingPreferences>
  <TechnicalContact>
    <Email>support@example.hr</Email>
    <Phone>+385-1-1234567</Phone>
  </TechnicalContact>
</ServiceMetadata>
```

#### Rate Limits

**Limit:** 100 requests/hour per certificate
**Client Strategy:** Cache responses for 7 days (metadata changes rarely)

#### SLA

**Availability:** 99.0% (lower than AMS - less critical)
**Response Time:** <2 seconds

#### Use Cases

**When to Use MPS vs AMS:**
- **AMS:** Quick Access Point URL lookup (frequent operation)
- **MPS:** Detailed capability discovery (infrequent, typically during onboarding or debugging)

#### Integration Test Plan

**Test Scenarios:**
1. **Query Known OIB:** Verify metadata retrieval
2. **Query Unknown OIB:** Verify error response
3. **Invalid Certificate:** Test authentication failure
4. **Cache Validation:** Verify 7-day caching

**Success Criteria:**
- Successful metadata retrieval for test OIBs
- Proper error handling
- Minimal queries due to caching

---

### 2.5 DZS KLASUS Registry (KPD Classification)

**System Name:** KLASUS 2025 Product Classification Registry
**Provider:** State Statistical Office (Državni zavod za statistiku)
**Protocol:** Web Application + API (format TBD)
**Use Case:** Validate KPD product codes and retrieve descriptions

#### Endpoints

**Web Application:** `https://klasus.dzs.hr/` (search interface)
**API Endpoint:** Not yet published (expected Q4 2025)

**Note:** As of November 2025, DZS has not published a public API. Integration currently requires:
- Manual web searches
- Screen scraping (not recommended, terms of service violation risk)
- Static dataset download (if provided)

#### Authentication

**Web Application:** Public access (no authentication)
**API (future):** Expected to require registration and API key

#### Data Format

**KPD Code Structure:** Minimum 6 digits, hierarchical
```
62.01.0 - Computer programming activities
│└─┘ └─┘
│ │   └── Sub-category (level 3)
│ └────── Category (level 2)
└──────── Division (level 1)
```

**Example Lookup Response (anticipated API format):**
```json
{
  "code": "62.01.0",
  "description": "Computer programming activities",
  "description_hr": "Računalno programiranje",
  "division": "62",
  "division_name": "Computer programming, consultancy and related activities",
  "status": "active",
  "valid_from": "2025-01-01",
  "notes": ""
}
```

#### Integration Strategy (Current)

**Phase 1 (Until API Available):**
1. **Manual Pre-Population:**
   - Create internal KPD database table
   - Manually populate common codes for client products
   - Source: KLASUS web application searches
   - Update frequency: Monthly

2. **Validation:**
   - Validate against local database
   - Flag unknown codes for manual review
   - Email KPD@dzs.hr for clarification

3. **Database Schema:**
```sql
CREATE TABLE kpd_codes (
  code VARCHAR(10) PRIMARY KEY,
  description_en TEXT NOT NULL,
  description_hr TEXT NOT NULL,
  division VARCHAR(2) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  valid_from DATE NOT NULL,
  valid_to DATE,
  last_verified TIMESTAMP NOT NULL,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kpd_description ON kpd_codes USING GIN(to_tsvector('english', description_en));
CREATE INDEX idx_kpd_division ON kpd_codes(division);
```

**Phase 2 (When API Available):**
1. Integrate with official DZS API
2. Daily synchronization of KPD codes
3. Automatic validation against live registry
4. Deprecation notifications

#### Rate Limits

**Web Application:** No documented limits (respectful scraping: 1 req/second max)
**API (future):** TBD

#### Support Contact

**Email:** KPD@dzs.hr
**Response Time:** 3-5 business days (observed)
**Language:** Croatian (English support limited)

#### Data Update Frequency

**Official Updates:** Annual (KLASUS 2025 → KLASUS 2026 transition expected Jan 2027)
**Code Changes:** Rare mid-year (monitor DZS announcements)

#### Integration Test Plan

**Test Scenarios:**
1. **Valid Code Lookup:** Verify code "62.01.0" returns correct description
2. **Invalid Code Lookup:** Verify code "99.99.9" returns not found
3. **Database Sync:** Verify daily sync updates changed codes
4. **Performance:** Lookup 10,000 codes in <1 second (local database)

**Success Criteria:**
- 100% of client product codes mapped and validated
- <10ms local lookup time
- Zero invalid codes submitted to Tax Authority

---

### 2.6 FINA Certificate Authority

**System Name:** FINA Certificate Issuance and Management
**Provider:** FINA (Financijska agencija)
**Protocol:** HTTPS (web portal) + OSPD (electronic submission)
**Use Case:** Obtain and manage X.509 application certificates

#### Endpoints

**Certificate Portal:** `https://cms.fina.hr/`
**Support Phone:** 01 4404 707
**Support Email:** Available on FINA website (changes periodically)

#### Certificate Types

| Type | Purpose | Validity | Cost (EUR + VAT) |
|------|---------|----------|------------------|
| Production Application Certificate | B2C/B2B fiscalization | 5 years | 39.82 + VAT |
| Demo Application Certificate | Testing only | 1 year | FREE |
| Qualified Certificate for eSignature | NOT for fiscalization | Variable | Not applicable |

**⚠️ CRITICAL:** Only **Application Certificates for Fiscalization** are valid. Personal or company eSignature certificates will be rejected.

#### Certificate Acquisition Process

**Step 1: Prepare Documentation**

**Legal Entities (d.o.o., j.d.o.o.):**
- Application form (download from cms.fina.hr)
- Service agreement (2 signed copies)
- Copy of certificate administrator's ID
- Proof of payment (bank transfer confirmation)
- DZS business registry extract (not older than 6 months)

**Sole Traders (obrt):**
- Application form
- Service agreement
- Copy of administrator ID
- Proof of payment

**Step 2: Submit Documentation**

**Option A - Physical Submission:**
- Visit FINA registration office
- Bring original documents + copies
- Receive submission confirmation

**Option B - Electronic Submission:**
- Upload to OSPD portal
- Requires qualified eSignature (different certificate type)
- More complex, not recommended for first-time applicants

**Step 3: Payment**

**Bank Transfer Details:**
- Recipient: FINA
- Amount: 39.82 EUR + VAT = ~49.70 EUR total
- Payment reference: Application number (received after submission)
- IBAN: Provided on invoice

**Step 4: Processing**

**Timeline:** 5-10 business days
**Status Tracking:** CMS portal (login with NIAS credentials)
**Notification:** Email when certificate ready for download

**Step 5: Download and Installation**

**Download:**
- Login to cms.fina.hr
- Navigate to "My Certificates"
- Download .p12 file
- Set password (min 8 characters, mixed case, numbers, symbols)

**Installation:**
```bash
# Import into Java keystore
keytool -importkeystore \
  -srckeystore certificate.p12 \
  -srcstoretype PKCS12 \
  -destkeystore application.jks \
  -deststoretype JKS

# Verify import
keytool -list -v -keystore application.jks

# Extract certificate chain for verification
openssl pkcs12 -in certificate.p12 -out cert-chain.pem -nodes
```

**Storage Security:**
- Store .p12 in `/etc/eracun/secrets/` (NEVER in git)
- File permissions: 600 (owner read/write only)
- Encrypt with SOPS + age (see ADR-002)
- Backup to secure offline storage (encrypted USB, safe)

#### Certificate Lifecycle

**Activation:**
- Online via CMS portal after download
- Requires administrator authentication (NIAS)
- Certificate becomes active within 1 hour

**Renewal:**
- Start process 30 days before expiration
- Simplified renewal form (existing customer)
- Processing time: 3-5 business days
- Overlap period: Old certificate valid until new activated

**Revocation:**
- **Immediate notification required** if compromise suspected
- Contact FINA support: 01 4404 707
- Submit revocation request via CMS portal
- Takes effect within 24 hours
- **Legal obligation** - failure to report = liability for fraudulent use

**Monitoring:**
- Automated expiry check (daily cron job)
- Alert 60 days before expiration
- Alert 30 days before expiration (critical)
- Alert 7 days before expiration (emergency)

#### Certificate Validation

**PKI Hierarchy Verification:**
```bash
# Download FINA root CA
curl -O https://www.fina.hr/documents/fina-root-ca.crt

# Verify certificate chain
openssl verify -CAfile fina-root-ca.crt cert-chain.pem

# Expected output:
# cert-chain.pem: OK
```

**Certificate Properties:**
- **Subject:** CN=Company Name, OIB=12345678901, O=Company Name d.o.o., C=HR
- **Issuer:** CN=Fina RDC 2015 CA, O=FINA, C=HR
- **Key Usage:** Digital Signature, Non-Repudiation
- **Extended Key Usage:** 1.3.6.1.4.1.8072.2.1 (Fiscalization Application)
- **Signature Algorithm:** SHA256withRSA
- **Key Size:** 2048 bits (minimum)

#### Alternative: AKD Certificates

**Provider:** Agencija za komercijalnu djelatnost
**Website:** `https://www.akd.hr/`
**Differences:**
- Same technical specifications as FINA
- Different PKI hierarchy (AKD Root CA)
- Similar pricing
- Slightly different application process

**Recommendation:** Use FINA as primary (more established for fiscalization), AKD as backup if FINA unavailable.

#### Integration Test Plan

**Test Scenarios:**
1. **Certificate Loading:** Load .p12 file into application
2. **Signature Generation:** Sign test XML with certificate
3. **Signature Verification:** Verify signature against Fina Root CA
4. **Expiry Detection:** Verify expiry monitoring alerts
5. **Revocation Check:** Test OCSP/CRL validation
6. **Password Protection:** Verify password-protected keystore

**Success Criteria:**
- Certificate loads without errors
- Signatures validate correctly
- Expiry alerts trigger at correct intervals
- All security best practices followed

---

### 2.7 Qualified Timestamp Authority (TSA)

**System Name:** eIDAS-Qualified Time-Stamp Authority
**Provider:** Multiple EU-qualified providers
**Protocol:** RFC 3161 (Time-Stamp Protocol) over HTTPS
**Use Case:** Add qualified timestamps to B2B/B2G invoices

#### Requirement

**Mandatory For:**
- B2B invoices (mandatory qualified timestamp)
- B2G invoices (mandatory qualified timestamp)

**Not Required For:**
- B2C invoices (simple timestamp sufficient)

#### eIDAS-Qualified TSA Providers (Croatia & EU)

| Provider | Country | URL | Cost |
|----------|---------|-----|------|
| Infocert | Italy | `https://tsa.infocert.it` | ~€0.10/timestamp |
| Fina TSA | Croatia | TBD (launch expected 2026) | TBD |
| DigiStamp | Netherlands | `https://tsa.digistamp.com` | €0.05-0.15/timestamp |
| GlobalSign | Belgium | `https://tsa.globalsign.com` | Subscription-based |

**Note:** As of Nov 2025, Croatian providers have not launched eIDAS-qualified TSA. Use EU providers until local option available.

**Recommendation:** Use **Infocert** (established, Croatia-adjacent, reasonable pricing)

#### Protocol: RFC 3161

**Request Format:**
```http
POST /tsa HTTP/1.1
Host: tsa.infocert.it
Content-Type: application/timestamp-query
Content-Length: [length]

[DER-encoded TimeStampReq]
```

**TimeStampReq Structure:**
```asn1
TimeStampReq ::= SEQUENCE {
  version INTEGER,
  messageImprint MessageImprint,
  reqPolicy TSAPolicyId OPTIONAL,
  nonce INTEGER OPTIONAL,
  certReq BOOLEAN DEFAULT FALSE
}

MessageImprint ::= SEQUENCE {
  hashAlgorithm AlgorithmIdentifier,
  hashedMessage OCTET STRING
}
```

**Response Format:**
```asn1
TimeStampResp ::= SEQUENCE {
  status PKIStatusInfo,
  timeStampToken TimeStampToken OPTIONAL
}
```

**Implementation (Node.js example):**
```javascript
const crypto = require('crypto');
const axios = require('axios');
const asn1 = require('asn1.js');

async function getQualifiedTimestamp(xmlContent) {
  // 1. Hash the XML content
  const hash = crypto.createHash('sha256').update(xmlContent).digest();

  // 2. Create TimeStampReq (simplified)
  const tsReq = createTimeStampRequest(hash);

  // 3. Send to TSA
  const response = await axios.post('https://tsa.infocert.it', tsReq, {
    headers: { 'Content-Type': 'application/timestamp-query' },
    responseType: 'arraybuffer',
    timeout: 10000 // 10s timeout
  });

  // 4. Parse TimeStampResp
  const tsToken = parseTimeStampResponse(response.data);

  return tsToken; // Include in XMLDSig <ds:Object> element
}
```

#### Authentication

**Type:** None for public TSAs (Infocert, DigiStamp)
**Payment:** Pre-paid account or pay-per-timestamp API key

**Account Setup (Infocert):**
1. Register at `https://www.infocert.it/en/`
2. Purchase timestamp credits (minimum 1,000 timestamps)
3. Receive API credentials
4. Configure in application secrets

#### Rate Limits

**Infocert:** 100 requests/second (burst), 10,000/day (sustained)
**Backoff Strategy:** Exponential backoff on rate limit (retry after 1s, 2s, 4s)

#### SLA

**Availability:** 99.9% (Infocert contractual SLA)
**Response Time:** <1 second p95
**Timestamp Accuracy:** ±1 second (synchronized to UTC)

#### Error Handling

**TSA Status Codes:**
- `0` - Granted (success)
- `1` - Granted with modifications (acceptable)
- `2` - Rejection (permanent failure - investigate cause)
- `3` - Waiting (retry after delay)
- `4` - Revocation warning (rare)
- `5` - Revocation notification (rare)

**Client Actions:**
- Status 0-1: Proceed with timestamp
- Status 2: Log error, alert operator, manual intervention
- Status 3: Retry after 5 seconds (max 3 retries)
- Status 4-5: Alert operator immediately (rare, serious)

#### Cost Management

**Optimization Strategies:**
1. **Batch Invoices:** Single timestamp can cover multiple invoices (batch signature)
2. **Caching:** If invoice unchanged, reuse timestamp (within 1 hour)
3. **Tiered Pricing:** Negotiate volume discounts (>100,000 timestamps/year)

**Expected Volume:**
- Initial: 1,000 invoices/month = 1,000 timestamps = ~€100/month
- Target (12 months): 10,000 invoices/month = ~€1,000/month
- At scale (100K invoices/month): Negotiate to ~€0.02/timestamp = €2,000/month

#### Integration Test Plan

**Test Scenarios:**
1. **Request Timestamp:** Send hash, receive valid timestamp token
2. **Invalid Hash:** Send malformed hash, verify error handling
3. **Network Timeout:** Simulate timeout, verify retry logic
4. **Verify Timestamp:** Validate timestamp signature against TSA certificate
5. **Embed in XML:** Include timestamp in XMLDSig structure, verify schema compliance
6. **Rate Limit:** Send 150 req/sec, verify backoff behavior

**Success Criteria:**
- <2s end-to-end timestamp retrieval
- 100% valid timestamp tokens
- Proper error handling for all failure modes
- Cost within budget (monitor usage)

---

## 3. CREDENTIAL LIFECYCLE MANAGEMENT

### 3.1 Certificate Inventory

**All Certificates Used by eRacun Platform:**

| Certificate | Issuer | Purpose | Validity | Renewal Lead Time | Storage Location |
|-------------|--------|---------|----------|-------------------|------------------|
| FINA Application Cert (Prod) | FINA | B2C/B2B fiscalization | 5 years | 30 days | `/etc/eracun/secrets/fina-prod.p12.enc` |
| FINA Application Cert (Demo) | FINA | Testing | 1 year | 30 days | `/etc/eracun/secrets/fina-demo.p12.enc` |
| TLS Server Cert | Let's Encrypt | HTTPS for web services | 90 days | 30 days | `/etc/eracun/certs/server.pem` |
| TSA Client Account | Infocert | Timestamp requests | Subscription | 60 days | API key in `/etc/eracun/secrets/tsa.env.enc` |

**Storage Format:** All certificates encrypted with SOPS + age (see ADR-002)

### 3.2 Renewal Calendar

**Automated Monitoring:**

```bash
#!/bin/bash
# /usr/local/bin/check-certificate-expiry.sh
# Run daily via cron: 0 9 * * * /usr/local/bin/check-certificate-expiry.sh

CERT_PATH="/etc/eracun/secrets/fina-prod.p12"
PASSWORD=$(sops -d /etc/eracun/secrets/fina-prod.env.enc | grep CERT_PASSWORD | cut -d= -f2)

# Extract expiry date
EXPIRY=$(openssl pkcs12 -in "$CERT_PATH" -passin "pass:$PASSWORD" -nokeys | \
         openssl x509 -noout -enddate | cut -d= -f2)

EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_REMAINING=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

# Alert thresholds
if [ $DAYS_REMAINING -lt 7 ]; then
  # CRITICAL: 7 days or less
  curl -X POST https://alerts.eracun.hr/critical \
    -d "{\"alert\":\"Certificate expires in $DAYS_REMAINING days\",\"severity\":\"P0\"}"
elif [ $DAYS_REMAINING -lt 30 ]; then
  # WARNING: 30 days or less
  curl -X POST https://alerts.eracun.hr/warning \
    -d "{\"alert\":\"Certificate expires in $DAYS_REMAINING days\",\"severity\":\"P1\"}"
elif [ $DAYS_REMAINING -lt 60 ]; then
  # INFO: 60 days or less (start renewal process)
  curl -X POST https://alerts.eracun.hr/info \
    -d "{\"alert\":\"Certificate expires in $DAYS_REMAINING days - initiate renewal\",\"severity\":\"P2\"}"
fi
```

**systemd Timer:**
```ini
# /etc/systemd/system/eracun-cert-check.timer
[Unit]
Description=Daily certificate expiry check

[Timer]
OnCalendar=daily
OnCalendar=09:00
Persistent=true

[Install]
WantedBy=timers.target
```

### 3.3 Renewal Process

**FINA Certificate Renewal (Simplified Process for Existing Customers):**

**60 Days Before Expiry:**
1. Initiate renewal via CMS portal (cms.fina.hr)
2. Complete simplified renewal form (pre-filled customer data)
3. Update administrator ID if changed
4. Submit payment (same pricing as new certificate)

**30-40 Days Before Expiry:**
5. FINA processes renewal (3-5 business days)
6. Download new .p12 file from CMS portal
7. Set new password (DIFFERENT from old certificate)

**30 Days Before Expiry:**
8. Install new certificate alongside old (parallel operation)
9. Test new certificate in staging environment
10. Configure rotation: Primary=new, Fallback=old
11. Monitor for 48 hours

**7 Days Before Expiry:**
12. Switch primary to new certificate in production
13. Monitor for 24 hours
14. Verify old certificate still accepted (overlap period)

**After Expiry:**
15. Remove old certificate from keystore
16. Update documentation
17. Shred old .p12 file (secure deletion: `shred -n 5 -u old-cert.p12`)

### 3.4 Revocation Procedure

**When to Revoke:**
- Private key compromised or suspected compromise
- Certificate administrator left company (sole trader sold business)
- Certificate password disclosed to unauthorized party
- Device containing certificate stolen
- Forensic evidence of unauthorized use

**Immediate Actions (Within 1 Hour):**
1. Disable certificate in application (prevent further use)
2. Call FINA support: 01 4404 707 (verbal notification)
3. Submit written revocation request via CMS portal
4. Document incident (date, time, reason, actions taken)
5. Alert Tax Authority if fraudulent invoices may have been issued

**Within 24 Hours:**
6. FINA processes revocation (certificate added to CRL)
7. Obtain replacement certificate (emergency process: 1-2 days)
8. Install replacement certificate
9. Test fiscalization with replacement
10. Resume normal operations

**Within 7 Days:**
11. Complete incident report
12. Review access control procedures
13. Implement corrective actions
14. Update security training

**Legal Obligations:**
- Document compliance with revocation notification requirement
- Preserve audit trail (evidence of timely action)
- Cooperate with Tax Authority investigation if applicable

### 3.5 Backup and Recovery

**Certificate Backup Strategy:**

**Primary Backup:**
- Encrypted .p12 file stored in DigitalOcean Spaces (S3-compatible)
- Path: `s3://eracun-secrets-backup/certificates/fina-prod-{date}.p12.enc`
- Encryption: SOPS + age (same as production)
- Retention: Forever (until certificate expires + 11 years)

**Secondary Backup:**
- Encrypted USB drive stored in physical safe
- Updated monthly
- Verified quarterly (test decryption)

**Recovery Procedure:**

**Scenario: Production server failure, certificate lost**

1. Provision new server
2. Install age decryption key (from secure offline storage)
3. Download encrypted .p12 from DigitalOcean Spaces:
   ```bash
   aws s3 cp s3://eracun-secrets-backup/certificates/fina-prod-latest.p12.enc /tmp/
   ```
4. Decrypt with SOPS:
   ```bash
   sops -d /tmp/fina-prod-latest.p12.enc > /etc/eracun/secrets/fina-prod.p12
   chmod 600 /etc/eracun/secrets/fina-prod.p12
   ```
5. Verify certificate:
   ```bash
   openssl pkcs12 -info -in /etc/eracun/secrets/fina-prod.p12
   ```
6. Restart services:
   ```bash
   systemctl restart eracun-*.service
   ```
7. Test fiscalization (submit test invoice to TEST environment first)
8. Resume production operations

**Recovery Time Objective (RTO):** <2 hours
**Recovery Point Objective (RPO):** 0 (certificate is immutable, no data loss)

### 3.6 API Key Management

**TSA API Keys:**

**Rotation Schedule:** 90 days
**Storage:** `/etc/eracun/secrets/tsa.env.enc` (SOPS-encrypted)

**Format:**
```bash
# /etc/eracun/secrets/tsa.env (UNENCRYPTED - never store like this!)
TSA_URL=https://tsa.infocert.it
TSA_API_KEY=sk_live_abc123...xyz789
TSA_ACCOUNT_ID=12345
```

**Encrypted Version:**
```bash
sops -e /etc/eracun/secrets/tsa.env > /etc/eracun/secrets/tsa.env.enc
rm /etc/eracun/secrets/tsa.env  # Delete unencrypted
```

**Rotation Process:**
1. Generate new API key in TSA provider portal (keep old active)
2. Update `/etc/eracun/secrets/tsa.env.enc` with new key
3. Deploy to production (services reload automatically)
4. Monitor for 24 hours (ensure new key works)
5. Deactivate old key in TSA portal
6. Document rotation in changelog

**AMS API Keys:**

**Rotation Schedule:** 90 days (enforced by Tax Authority)
**Acquisition:** ePorezna portal → FiskAplikacija → API Keys
**Auto-Renewal:** Tax Authority sends email 14 days before expiry with renewal link

---

## 4. INTEGRATION TEST SPECIFICATIONS

### 4.1 End-to-End Test Scenarios

**Test Suite:** `tests/integration/external-systems.test.ts`

#### Test 1: B2C Fiscalization Flow

**Prerequisites:**
- Demo FINA certificate loaded
- Test environment configured

**Steps:**
1. Generate valid UBL 2.1 B2C invoice
2. Apply ZKI protective code
3. Sign with demo certificate
4. Submit to TEST SOAP endpoint
5. Receive JIR
6. Verify JIR format (UUID)
7. Verify response time <5s

**Success Criteria:**
- JIR received
- No errors in response
- Invoice archived with JIR

**Failure Scenarios:**
- Signature rejection → verify certificate validity
- Schema validation error → check XML structure
- Timeout → verify network connectivity

---

#### Test 2: B2B Invoice Exchange

**Prerequisites:**
- AS4 Access Point configured (or FINA eRačun account)
- Test partner OIB registered in AMS

**Steps:**
1. Generate valid UBL 2.1 B2B invoice
2. Apply digital signature + qualified timestamp
3. Wrap in AS4 envelope
4. Submit to own Access Point
5. Access Point routes to test partner
6. Receive delivery receipt
7. Verify receipt signature
8. Verify end-to-end time <30s

**Success Criteria:**
- Delivery receipt received
- Receipt signature valid
- Invoice delivered to test partner inbox
- No corruption (hash verification)

---

#### Test 3: AMS Lookup and Caching

**Steps:**
1. Clear Redis cache
2. Lookup test OIB via AMS API
3. Verify response contains Access Point URL
4. Measure response time (should be <500ms)
5. Repeat lookup (cache hit)
6. Verify response time <10ms (Redis cache)
7. Verify no second AMS API call (check logs)
8. Wait 24 hours + 1 minute
9. Repeat lookup (cache expired)
10. Verify AMS API called again

**Success Criteria:**
- Cache hit performance <10ms
- Cache miss performance <500ms
- Cache expiry functioning correctly

---

#### Test 4: KPD Validation

**Steps:**
1. Lookup valid KPD code "62.01.0" in local database
2. Verify description returned
3. Lookup invalid code "99.99.9"
4. Verify "not found" response
5. Create invoice with valid KPD
6. Submit to schematron validator
7. Verify no KPD-related errors
8. Create invoice with invalid KPD
9. Submit to schematron validator
10. Verify KPD error flagged

**Success Criteria:**
- Valid codes pass validation
- Invalid codes rejected
- Lookup time <10ms

---

#### Test 5: Certificate Expiry Monitoring

**Steps:**
1. Create test certificate expiring in 5 days
2. Run expiry check script
3. Verify CRITICAL alert sent
4. Create test certificate expiring in 25 days
5. Run expiry check script
6. Verify WARNING alert sent
7. Create test certificate expiring in 55 days
8. Run expiry check script
9. Verify INFO alert sent

**Success Criteria:**
- All alert thresholds trigger correctly
- Alerts contain correct expiry information
- Alert delivery confirmed (email/Slack)

---

#### Test 6: TSA Timestamp Retrieval

**Steps:**
1. Generate test XML content
2. Hash content (SHA-256)
3. Request timestamp from Infocert TSA
4. Receive timestamp token
5. Verify timestamp signature
6. Verify timestamp time is current (±5 seconds)
7. Embed timestamp in XMLDSig structure
8. Validate complete signed+timestamped document

**Success Criteria:**
- Timestamp received in <2s
- Signature valid
- Timestamp within acceptable range
- Document validates against Croatian CIUS

---

#### Test 7: Offline Fallback (B2C)

**Steps:**
1. Configure firewall to block FINA SOAP endpoint
2. Attempt to fiscalize invoice
3. Verify invoice queued locally (PostgreSQL)
4. Verify error logged (not exception)
5. Restore network connectivity
6. Wait for background worker cycle (5 minutes)
7. Verify queued invoice submitted successfully
8. Verify JIR received and stored
9. Verify queue cleared

**Success Criteria:**
- No data loss during outage
- Automatic recovery on network restore
- Alert sent to operator (network failure detected)
- Alert cleared when queue processed

---

#### Test 8: Rate Limit Handling (AMS)

**Steps:**
1. Configure AMS mock to return 429 after 100 requests
2. Send 150 AMS lookups in rapid succession
3. Verify first 100 succeed
4. Verify requests 101-150 trigger backoff
5. Verify exponential backoff (1s, 2s, 4s delays)
6. Verify eventual success after backoff
7. Verify no request dropped

**Success Criteria:**
- All 150 requests eventually succeed
- Backoff behavior correct
- No unhandled exceptions
- Rate limit logged (monitoring alert)

---

### 4.2 Performance Benchmarks

**Target Performance:**

| Operation | Target | Measurement Method |
|-----------|--------|-------------------|
| B2C Fiscalization (SOAP) | <5s p95 | Artillery load test, 100 concurrent |
| B2B Exchange (AS4) | <30s p95 | End-to-end delivery time |
| AMS Lookup (cache hit) | <10ms p95 | k6 load test, 1000 RPS |
| AMS Lookup (cache miss) | <500ms p95 | k6 load test, 100 RPS |
| KPD Validation | <10ms p95 | PostgreSQL query benchmark |
| TSA Timestamp | <2s p95 | Artillery load test, 50 concurrent |

**Load Test Configuration:**

```yaml
# artillery-fina-soap.yml
config:
  target: "https://cistest.apis-it.hr:8449"
  phases:
    - duration: 60
      arrivalRate: 10
      name: "Warm-up"
    - duration: 300
      arrivalRate: 100
      name: "Sustained load"
    - duration: 60
      arrivalRate: 200
      name: "Peak load"
  processor: "./test-helpers/soap-processor.js"

scenarios:
  - name: "Fiscalize B2C Invoice"
    flow:
      - post:
          url: "/FiskalizacijaServiceTest"
          headers:
            Content-Type: "text/xml; charset=utf-8"
            SOAPAction: "http://www.apis-it.hr/fin/2012/types/f73/racuni"
          body: "{{ generateSOAPRequest() }}"
          capture:
            - xpath:
                expression: "//tns:JIR"
                as: "jir"
```

**Run Test:**
```bash
artillery run artillery-fina-soap.yml --output report.json
artillery report report.json
```

### 4.3 Continuous Integration

**CI Pipeline Integration:**

```yaml
# .github/workflows/external-integration-tests.yml
name: External Integration Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  test-external-systems:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Decrypt demo certificates
        run: |
          echo "${{ secrets.AGE_SECRET_KEY }}" > /tmp/age-key.txt
          sops -d --age $(cat /tmp/age-key.txt) \
            secrets/fina-demo.p12.enc > /tmp/fina-demo.p12

      - name: Run external integration tests
        env:
          FINA_CERT_PATH: /tmp/fina-demo.p12
          FINA_CERT_PASSWORD: ${{ secrets.FINA_DEMO_PASSWORD }}
          AMS_API_KEY: ${{ secrets.AMS_TEST_API_KEY }}
          TSA_API_KEY: ${{ secrets.TSA_TEST_API_KEY }}
        run: npm run test:external

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: external-test-results
          path: test-results/

      - name: Notify on failure
        if: failure()
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: 'External integration tests failed'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

---

## 5. MONITORING AND ALERTING

### 5.1 External System Health Checks

**Health Check Endpoints (Internal Monitoring):**

```javascript
// services/health-monitor/external-systems.js

const healthChecks = {
  'fina-soap': {
    url: 'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest',
    method: 'POST',
    body: '<soap:Envelope>...</soap:Envelope>',  // echo operation
    timeout: 5000,
    interval: 60000,  // Check every 60 seconds
    alertThreshold: 3  // Alert after 3 consecutive failures
  },

  'ams-api': {
    url: 'https://ams-test.apis-it.hr/api/v1/health',
    method: 'GET',
    timeout: 2000,
    interval: 60000,
    alertThreshold: 3
  },

  'tsa-infocert': {
    url: 'https://tsa.infocert.it/health',
    method: 'GET',
    timeout: 3000,
    interval: 300000,  // Check every 5 minutes
    alertThreshold: 2
  }
};
```

**Prometheus Metrics:**

```javascript
const externalSystemUp = new Gauge({
  name: 'external_system_up',
  help: 'External system availability (1=up, 0=down)',
  labelNames: ['system']
});

const externalSystemResponseTime = new Histogram({
  name: 'external_system_response_seconds',
  help: 'External system response time',
  labelNames: ['system'],
  buckets: [0.1, 0.5, 1, 2, 5, 10]
});
```

**Alert Rules:**

```yaml
# prometheus/alerts/external-systems.yml

groups:
  - name: external_systems
    interval: 30s
    rules:
      - alert: FINASOAPDown
        expr: external_system_up{system="fina-soap"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "FINA SOAP API is unreachable"
          description: "Cannot fiscalize B2C invoices. Offline queue active."

      - alert: AMSAPIDown
        expr: external_system_up{system="ams-api"} == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "AMS API is unreachable"
          description: "Using cached Access Point lookups. Service degraded."

      - alert: TSADown
        expr: external_system_up{system="tsa-infocert"} == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "TSA service is unreachable"
          description: "Cannot timestamp B2B invoices. Queue active."

      - alert: ExternalSystemSlow
        expr: external_system_response_seconds{quantile="0.95"} > 5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "External system {{ $labels.system }} is slow"
          description: "p95 response time is {{ $value }}s (threshold: 5s)"
```

### 5.2 Credential Expiry Alerts

**Prometheus Exporter:**

```javascript
// services/health-monitor/certificate-expiry-exporter.js

const certificateExpiryDays = new Gauge({
  name: 'certificate_expiry_days',
  help: 'Days until certificate expiration',
  labelNames: ['certificate', 'issuer']
});

// Update every hour
setInterval(() => {
  const finaCert = loadCertificate('/etc/eracun/secrets/fina-prod.p12');
  const expiryDate = new Date(finaCert.validTo);
  const daysRemaining = Math.floor((expiryDate - Date.now()) / 86400000);

  certificateExpiryDays.set(
    { certificate: 'fina-prod', issuer: 'FINA' },
    daysRemaining
  );
}, 3600000);
```

**Alert Rules:**

```yaml
- alert: CertificateExpiringSoon
  expr: certificate_expiry_days < 30
  labels:
    severity: warning
  annotations:
    summary: "Certificate {{ $labels.certificate }} expires in {{ $value }} days"
    description: "Initiate renewal process immediately"

- alert: CertificateExpiringCritical
  expr: certificate_expiry_days < 7
  labels:
    severity: critical
  annotations:
    summary: "Certificate {{ $labels.certificate }} expires in {{ $value }} days"
    description: "URGENT: Certificate expiring soon. Service outage imminent."
```

---

## 6. COMPLIANCE VERIFICATION

### 6.1 Pre-Production Checklist

**Before Go-Live (1 Jan 2026):**

- [ ] FINA production certificate obtained and installed
- [ ] FINA demo certificate tested in TEST environment
- [ ] B2C SOAP API integration tested (all operations)
- [ ] AS4 Access Point selected and configured
- [ ] AMS API key obtained and tested
- [ ] MPS connectivity verified
- [ ] KPD database populated (all client products mapped)
- [ ] TSA account created and tested (Infocert or alternative)
- [ ] Certificate expiry monitoring operational
- [ ] Offline fallback queue tested (B2C)
- [ ] Load testing completed (meets performance budgets)
- [ ] All external system health checks enabled
- [ ] Alerting configured and tested (trigger test alerts)
- [ ] Credential backup and recovery tested
- [ ] Documentation complete (runbooks, integration specs)

### 6.2 Monthly Verification Tasks

**First Monday of Each Month:**

- [ ] Verify FINA certificate validity (not expired, not revoked)
- [ ] Check certificate expiry dates (all certificates)
- [ ] Review external system uptime metrics (>99%)
- [ ] Verify KPD database sync (no outdated codes)
- [ ] Test AMS cache invalidation (force lookup for sample OIBs)
- [ ] Verify TSA account balance (sufficient credits)
- [ ] Review API key rotation schedule (on track?)
- [ ] Test backup restore procedure (random certificate)
- [ ] Review external system error rates (<0.1% target)
- [ ] Update this document if external systems changed

---

## 7. CHANGE LOG

| Date | Change | Author |
|------|--------|--------|
| 2025-11-10 | Initial version | System Architect |

---

**Document Owner:** Technical Lead
**Review Cadence:** Monthly + after any external system change
**Distribution:** Development team, Operations, Compliance

---

*This document is authoritative for all external system integrations. Changes require review by Technical Lead and Compliance Team.*
