# TEAM 3: External Integration & Compliance

## Mission Statement
Build rock-solid integrations with Croatian regulatory systems (FINA, Porezna Uprava), implement comprehensive compliance validation, and establish system-wide monitoring. Create perfect mock implementations of government APIs to unblock all development.

## Team Composition
- 1 Senior Backend Engineer (Lead)
- 1 Integration Specialist
- 1 DevOps/SRE Engineer
- 1 QA/Compliance Engineer

## Assigned Bounded Contexts

### 1. fina-connector
**Purpose:** Integration with Croatian Tax Authority (FINA)
**Priority:** P0 - Critical for compliance

### 2. porezna-connector
**Purpose:** Integration with Porezna Uprava APIs
**Priority:** P0 - Critical for tax reporting

### 3. cert-lifecycle-manager
**Purpose:** X.509 certificate management for digital signing
**Priority:** P0 - Required for all submissions

### 4. digital-signature-service
**Purpose:** XMLDSig signing and verification
**Priority:** P0 - Legal requirement

### 5. archive-service
**Purpose:** 11-year compliant document storage
**Priority:** P1 - Required before production

### 6. reporting-service
**Purpose:** Generate compliance reports and analytics
**Priority:** P1 - Required for operations

### 7. dead-letter-handler
**Purpose:** Process failed messages and recovery
**Priority:** P1 - System reliability

---

## Blockers & Immediate Unblocking Actions

### 🔴 PENDING-006 – Architecture Compliance Remediation
- Create a temporary in-memory message bus adapter under `shared/messaging/` so every connector, certificate workflow, and reporting job already publishes/consumes messages instead of using direct HTTP calls.
- Wrap existing direct integrations with the adapter now; when the real bus topology lands we only swap the transport layer and keep the service contracts unchanged.
- Automate the guardrail locally by running `./scripts/check-architecture-compliance.sh` in CI and before every merge request; paste the report into the daily standup so other teams can consume the signal without waiting for a central fix.

### 🟡 PENDING-004 – Archive Throughput Benchmarking
- Spin up the local infra stack with `docker-compose up -d rabbitmq postgres prometheus grafana` and attach the archive-service + digital-signature-service to it so load testing is not blocked by staging capacity.
- Generate synthetic invoice corpora (≥100k docs) via the existing Faker-based builders already referenced in the mock services; persist them under `services/archive-service/fixtures/` for repeatable replay.
- Schedule nightly `k6` runs (use the provided script in this doc) against the local stack and log metrics to Prometheus/Grafana; update `docs/pending/004-archive-performance-benchmarking.md` with raw numbers even if the official environment is unavailable.

### External API & Certificate Dependencies
- Finalize the MockFINAService/MockPoreznaService and publish them as npm packages within the monorepo (`services/fina-connector/mocks` etc.) so Team 1/2 can point their integration tests to localhost without waiting for production API whitelisting.
- Maintain a shared mock certificate bundle (`shared/certificates/dev-root-ca.pem`) signed by the mock CA; circulate the PEM via git so no engineer is blocked waiting for credential provisioning.

### Cross-Team Feedback Loop
- Host a lightweight sandbox every evening by running `docker-compose up` plus `npm run dev` for all Team 3 services and exposing the mock endpoints on the shared dev network; publish the URLs + sample payloads in SHARED_CONTRACTS.md.
- Track any downstream dependency or schema change in SHARED_CONTRACTS.md immediately—never wait for blocker removal—and broadcast updates in the daily sync so all teams can continue coding against the mocks.

---

## External Dependencies & Perfect Mocking Strategy

### FINA API Mock Implementation

```typescript
// services/fina-connector/src/adapters/interfaces.ts
export interface IFINAClient {
  submitInvoice(invoice: SignedUBLInvoice): Promise<FINAResponse>;
  checkStatus(jir: string): Promise<StatusResponse>;
  validateCertificate(cert: X509Certificate): Promise<ValidationResult>;
  getCompanyInfo(oib: string): Promise<CompanyInfo>;
}

// services/fina-connector/src/adapters/mock-fina.ts
import {XMLBuilder, XMLParser} from 'fast-xml-parser';
import {createHash, createSign, createVerify} from 'crypto';

export class MockFINAService implements IFINAClient {
  private readonly responses: Map<string, FINAResponse> = new Map();
  private readonly certificateStore: MockCertificateStore;
  private readonly companyRegistry: MockCompanyRegistry;

  constructor() {
    this.certificateStore = new MockCertificateStore();
    this.companyRegistry = new MockCompanyRegistry();
    this.seedTestData();
  }

  async submitInvoice(invoice: SignedUBLInvoice): Promise<FINAResponse> {
    // Validate request structure
    this.validateSOAPEnvelope(invoice.soapEnvelope);

    // Verify digital signature
    const signatureValid = await this.verifyXMLSignature(invoice);
    if (!signatureValid) {
      return this.createErrorResponse('INVALID_SIGNATURE', 's005');
    }

    // Validate certificate
    const certValid = await this.validateCertificate(invoice.certificate);
    if (!certValid.valid) {
      return this.createErrorResponse('INVALID_CERTIFICATE', 's006');
    }

    // Business validations
    const validationResult = await this.performBusinessValidations(invoice);
    if (!validationResult.valid) {
      return this.createErrorResponse(validationResult.error, validationResult.code);
    }

    // Generate JIR (Jedinstveni Identifikator Računa)
    const jir = this.generateJIR(invoice);

    // Generate ZKI (Zaštitni Kod Izdavatelja)
    const zki = await this.generateZKI(invoice);

    // Simulate network delay
    await this.simulateNetworkDelay();

    // Create success response
    const response: FINAResponse = {
      success: true,
      jir,
      zki,
      timestamp: new Date().toISOString(),
      messageId: this.generateMessageId(),
      soapResponse: this.buildSOAPResponse(jir, zki),
      warnings: this.checkForWarnings(invoice)
    };

    // Store for status checking
    this.responses.set(jir, response);

    return response;
  }

  async checkStatus(jir: string): Promise<StatusResponse> {
    const response = this.responses.get(jir);
    if (!response) {
      return {
        found: false,
        status: 'NOT_FOUND',
        message: `JIR ${jir} not found in system`
      };
    }

    return {
      found: true,
      status: 'PROCESSED',
      jir: response.jir,
      timestamp: response.timestamp,
      details: {
        processed: true,
        archived: true,
        reportingComplete: true
      }
    };
  }

  async validateCertificate(cert: X509Certificate): Promise<ValidationResult> {
    // Mock certificate validation
    const certData = this.certificateStore.getCertificate(cert.serialNumber);

    if (!certData) {
      return {
        valid: false,
        error: 'UNKNOWN_CERTIFICATE',
        details: 'Certificate not issued by FINA'
      };
    }

    // Check expiry
    const now = new Date();
    if (now > certData.validTo) {
      return {
        valid: false,
        error: 'CERTIFICATE_EXPIRED',
        details: `Certificate expired on ${certData.validTo.toISOString()}`
      };
    }

    if (now < certData.validFrom) {
      return {
        valid: false,
        error: 'CERTIFICATE_NOT_YET_VALID',
        details: `Certificate valid from ${certData.validFrom.toISOString()}`
      };
    }

    // Check revocation (mock CRL check)
    if (certData.revoked) {
      return {
        valid: false,
        error: 'CERTIFICATE_REVOKED',
        details: 'Certificate has been revoked'
      };
    }

    return {
      valid: true,
      issuer: 'FINA Root CA',
      subject: certData.subject,
      validFrom: certData.validFrom,
      validTo: certData.validTo
    };
  }

  async getCompanyInfo(oib: string): Promise<CompanyInfo> {
    // Validate OIB format
    if (!this.isValidOIB(oib)) {
      throw new Error(`Invalid OIB format: ${oib}`);
    }

    // Return mock company data
    const company = this.companyRegistry.getCompany(oib);
    if (!company) {
      // Generate mock company for unknown OIBs
      return this.generateMockCompany(oib);
    }

    return company;
  }

  private async performBusinessValidations(invoice: SignedUBLInvoice): Promise<BusinessValidation> {
    const errors: string[] = [];

    // Validate OIB numbers
    if (!this.isValidOIB(invoice.supplierOIB)) {
      errors.push('Invalid supplier OIB');
    }

    if (!this.isValidOIB(invoice.buyerOIB)) {
      errors.push('Invalid buyer OIB');
    }

    // Validate VAT rates
    const validVATRates = [0, 5, 13, 25];
    for (const item of invoice.lineItems) {
      if (!validVATRates.includes(item.vatRate)) {
        errors.push(`Invalid VAT rate: ${item.vatRate}%`);
      }
    }

    // Validate KPD codes
    for (const item of invoice.lineItems) {
      if (!this.isValidKPDCode(item.kpdCode)) {
        errors.push(`Invalid KPD code: ${item.kpdCode}`);
      }
    }

    // Check for duplicate invoice numbers
    if (this.isDuplicateInvoiceNumber(invoice.invoiceNumber, invoice.supplierOIB)) {
      errors.push('Duplicate invoice number detected');
    }

    return {
      valid: errors.length === 0,
      errors,
      error: errors[0],
      code: this.mapErrorToCode(errors[0])
    };
  }

  private generateJIR(invoice: SignedUBLInvoice): string {
    // JIR format: UUID v4
    const uuid = this.generateUUID();
    return uuid.toUpperCase().replace(/-/g, '');
  }

  private async generateZKI(invoice: SignedUBLInvoice): Promise<string> {
    // ZKI = MD5(OIB + DateTime + InvoiceNumber + TotalAmount)
    const zkiSource =
      `${invoice.supplierOIB}` +
      `${invoice.issueDateTime}` +
      `${invoice.invoiceNumber}` +
      `${invoice.totalAmount.toFixed(2)}`;

    const hash = createHash('md5');
    hash.update(zkiSource);
    return hash.digest('hex').toUpperCase();
  }

  private buildSOAPResponse(jir: string, zki: string): string {
    const response = {
      'soap:Envelope': {
        '@_xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
        '@_xmlns:fis': 'http://www.apis-it.hr/fin/2012/types/f73',
        'soap:Body': {
          'fis:RacunOdgovor': {
            'fis:Zaglavlje': {
              'fis:IdPoruke': this.generateMessageId(),
              'fis:DatumVrijeme': new Date().toISOString()
            },
            'fis:Jir': jir,
            'fis:Zki': zki
          }
        }
      }
    };

    const builder = new XMLBuilder({
      ignoreAttributes: false,
      format: true,
      suppressEmptyNode: true
    });

    return builder.build(response);
  }

  private isValidOIB(oib: string): boolean {
    if (!/^\d{11}$/.test(oib)) {
      return false;
    }

    // ISO 7064, MOD 11-10 check digit validation
    let a = 10;
    for (let i = 0; i < 10; i++) {
      a = ((a + parseInt(oib[i])) % 10 || 10) * 2 % 11;
    }
    return ((11 - a) % 10) === parseInt(oib[10]);
  }

  private isValidKPDCode(code: string): boolean {
    // KLASUS 2025 6-digit code validation
    if (!/^\d{6}$/.test(code)) {
      return false;
    }

    // Check against known valid prefixes
    const validPrefixes = ['01', '02', '03', '10', '11', '20', '45', '46', '47'];
    return validPrefixes.includes(code.substring(0, 2));
  }

  private async verifyXMLSignature(invoice: SignedUBLInvoice): Promise<boolean> {
    // Mock signature verification
    // In production, this would use xml-crypto or similar

    // Simulate signature verification delay
    await this.simulateProcessing(50);

    // 98% success rate for valid signatures in mock
    return Math.random() < 0.98;
  }

  private generateMockCompany(oib: string): CompanyInfo {
    const cities = ['Zagreb', 'Split', 'Rijeka', 'Osijek', 'Zadar'];
    const streets = ['Ilica', 'Vukovarska', 'Frankopanska', 'Savska', 'Radnička'];

    return {
      oib,
      name: `Test Company ${oib.substring(0, 4)} d.o.o.`,
      address: {
        street: `${faker.helpers.arrayElement(streets)} ${faker.number.int({min: 1, max: 200})}`,
        city: faker.helpers.arrayElement(cities),
        postalCode: faker.number.int({min: 10000, max: 52000}).toString(),
        country: 'HR'
      },
      vatNumber: `HR${oib}`,
      active: true,
      registrationDate: faker.date.past({years: 10}),
      activityCodes: [
        faker.number.int({min: 100000, max: 999999}).toString()
      ]
    };
  }

  private seedTestData(): void {
    // Seed known test OIBs
    const testOIBs = [
      '12345678901', // Test company 1
      '98765432109', // Test company 2
      '11111111111', // Invalid (for testing)
    ];

    testOIBs.forEach(oib => {
      if (this.isValidOIB(oib)) {
        this.companyRegistry.addCompany(oib, this.generateMockCompany(oib));
      }
    });

    // Seed test certificates
    this.certificateStore.addCertificate({
      serialNumber: 'TEST-001',
      subject: 'CN=Test Company 1, O=Test d.o.o., C=HR',
      issuer: 'CN=FINA Demo CA, O=FINA, C=HR',
      validFrom: new Date('2024-01-01'),
      validTo: new Date('2026-12-31'),
      revoked: false
    });
  }

  private simulateNetworkDelay(): Promise<void> {
    // Realistic network delay: 100-500ms
    const delay = 100 + Math.random() * 400;
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  private simulateProcessing(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  private generateMessageId(): string {
    return this.generateUUID();
  }
}

// services/porezna-connector/src/adapters/mock-porezna.ts
export class MockPoreznaService implements IPoreznaClient {
  async submitReport(report: TaxReport): Promise<PoreznaResponse> {
    // Validate report structure
    if (!this.validateReport(report)) {
      return {
        success: false,
        error: 'INVALID_REPORT_STRUCTURE',
        details: 'Report does not conform to schema'
      };
    }

    // Simulate processing
    await this.simulateProcessing();

    // Generate confirmation
    const confirmationNumber = this.generateConfirmationNumber();

    return {
      success: true,
      confirmationNumber,
      timestamp: new Date().toISOString(),
      nextReportingDate: this.calculateNextReportingDate(),
      status: 'ACCEPTED'
    };
  }

  async getVATRates(): Promise<VATRate[]> {
    // Return current Croatian VAT rates
    return [
      {rate: 25, category: 'STANDARD', description: 'Standard rate'},
      {rate: 13, category: 'REDUCED', description: 'Reduced rate - tourism'},
      {rate: 5, category: 'SUPER_REDUCED', description: 'Super reduced rate'},
      {rate: 0, category: 'EXEMPT', description: 'Exempt from VAT'}
    ];
  }

  async validateVATNumber(vatNumber: string): Promise<VATValidation> {
    // Croatian VAT number format: HR + 11 digits (OIB)
    const match = vatNumber.match(/^HR(\d{11})$/);
    if (!match) {
      return {
        valid: false,
        error: 'Invalid VAT number format'
      };
    }

    const oib = match[1];
    if (!this.isValidOIB(oib)) {
      return {
        valid: false,
        error: 'Invalid OIB check digit'
      };
    }

    return {
      valid: true,
      companyName: `Company ${oib.substring(0, 4)}`,
      address: 'Zagreb, Croatia',
      active: true
    };
  }

  private validateReport(report: TaxReport): boolean {
    // Basic validation
    return !!(
      report.period &&
      report.supplierOIB &&
      report.totalAmount !== undefined &&
      report.vatAmount !== undefined
    );
  }

  private generateConfirmationNumber(): string {
    const year = new Date().getFullYear();
    const random = Math.floor(Math.random() * 1000000);
    return `PU-${year}-${random.toString().padStart(6, '0')}`;
  }

  private calculateNextReportingDate(): string {
    const next = new Date();
    next.setMonth(next.getMonth() + 1);
    next.setDate(20); // 20th of next month
    return next.toISOString().split('T')[0];
  }

  private simulateProcessing(): Promise<void> {
    return new Promise(resolve =>
      setTimeout(resolve, 200 + Math.random() * 300)
    );
  }

  private isValidOIB(oib: string): boolean {
    // Same OIB validation as FINA
    if (!/^\d{11}$/.test(oib)) {
      return false;
    }

    let a = 10;
    for (let i = 0; i < 10; i++) {
      a = ((a + parseInt(oib[i])) % 10 || 10) * 2 % 11;
    }
    return ((11 - a) % 10) === parseInt(oib[10]);
  }
}
```

### Digital Signature Mock Implementation

```typescript
// services/digital-signature-service/src/adapters/mock-signer.ts
import {createSign, createVerify, generateKeyPairSync} from 'crypto';
import {DOMParser, XMLSerializer} from '@xmldom/xmldom';
import * as xpath from 'xpath';

export class MockXMLSigner implements IXMLSigner {
  private readonly keyPair: KeyPair;
  private readonly certificate: MockCertificate;

  constructor() {
    // Generate mock RSA key pair for testing
    this.keyPair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    this.certificate = this.generateMockCertificate();
  }

  async signXML(xml: string, options: SigningOptions): Promise<SignedXML> {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');

    // Create signature element
    const signature = this.createSignatureElement(doc, options);

    // Calculate digest
    const digest = await this.calculateDigest(xml);

    // Sign the digest
    const signatureValue = await this.signDigest(digest);

    // Add signature to document
    this.addSignatureToDocument(doc, signature, signatureValue);

    const signedXML = new XMLSerializer().serializeToString(doc);

    return {
      xml: signedXML,
      signature: signatureValue,
      certificate: this.certificate.pem,
      timestamp: new Date().toISOString(),
      algorithm: 'RSA-SHA256'
    };
  }

  async verifyXMLSignature(signedXML: string): Promise<VerificationResult> {
    try {
      const doc = new DOMParser().parseFromString(signedXML, 'text/xml');

      // Extract signature value
      const signatureNode = xpath.select(
        '//*[local-name()="SignatureValue"]',
        doc
      )[0];

      if (!signatureNode) {
        return {
          valid: false,
          error: 'No signature found in document'
        };
      }

      const signatureValue = signatureNode.textContent;

      // Extract signed info
      const signedInfoNode = xpath.select(
        '//*[local-name()="SignedInfo"]',
        doc
      )[0];

      if (!signedInfoNode) {
        return {
          valid: false,
          error: 'No SignedInfo element found'
        };
      }

      // Canonicalize signed info
      const canonicalSignedInfo = this.canonicalize(signedInfoNode);

      // Verify signature
      const verifier = createVerify('RSA-SHA256');
      verifier.update(canonicalSignedInfo);

      const valid = verifier.verify(
        this.keyPair.publicKey,
        Buffer.from(signatureValue, 'base64')
      );

      return {
        valid,
        signer: this.certificate.subject,
        timestamp: new Date().toISOString(),
        algorithm: 'RSA-SHA256'
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }

  private createSignatureElement(doc: Document, options: SigningOptions): Element {
    const signature = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature'
    );

    // SignedInfo
    const signedInfo = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'SignedInfo'
    );

    // CanonicalizationMethod
    const canonMethod = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'CanonicalizationMethod'
    );
    canonMethod.setAttribute(
      'Algorithm',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    );
    signedInfo.appendChild(canonMethod);

    // SignatureMethod
    const sigMethod = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'SignatureMethod'
    );
    sigMethod.setAttribute(
      'Algorithm',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    );
    signedInfo.appendChild(sigMethod);

    // Reference
    const reference = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Reference'
    );
    reference.setAttribute('URI', options.referenceUri || '');

    // Transforms
    const transforms = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Transforms'
    );

    const transform = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Transform'
    );
    transform.setAttribute(
      'Algorithm',
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
    );
    transforms.appendChild(transform);
    reference.appendChild(transforms);

    // DigestMethod
    const digestMethod = doc.createElementNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'DigestMethod'
    );
    digestMethod.setAttribute(
      'Algorithm',
      'http://www.w3.org/2001/04/xmlenc#sha256'
    );
    reference.appendChild(digestMethod);

    signedInfo.appendChild(reference);
    signature.appendChild(signedInfo);

    return signature;
  }

  private async calculateDigest(data: string): Promise<string> {
    const hash = createHash('sha256');
    hash.update(data);
    return hash.digest('base64');
  }

  private async signDigest(digest: string): Promise<string> {
    const signer = createSign('RSA-SHA256');
    signer.update(digest);
    return signer.sign(this.keyPair.privateKey, 'base64');
  }

  private canonicalize(node: Node): string {
    // Simplified canonicalization for mock
    // In production, use proper XML canonicalization
    return new XMLSerializer().serializeToString(node);
  }

  private generateMockCertificate(): MockCertificate {
    return {
      subject: 'CN=Test Company, O=Test d.o.o., C=HR',
      issuer: 'CN=Mock CA, O=Mock Authority, C=HR',
      serialNumber: 'MOCK-' + Date.now(),
      validFrom: new Date(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      pem: this.generateMockPEM()
    };
  }

  private generateMockPEM(): string {
    // Generate mock certificate PEM
    return `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAMOCK...mock...certificate...data
-----END CERTIFICATE-----`;
  }
}
```

---

## Implementation Roadmap

### Week 1: Mock Infrastructure & Core Services
**Owner:** Senior Backend Engineer + Integration Specialist

#### Day 1-2: Perfect Mock Implementations
- [ ] MockFINAService with complete SOAP/XML handling
- [ ] MockPoreznaService with tax reporting simulation
- [ ] MockXMLSigner with XMLDSig implementation
- [ ] MockCertificateStore with X.509 handling
- [ ] Test data generators for all Croatian formats

#### Day 3-4: fina-connector Service
- [ ] SOAP client implementation with mock fallback
- [ ] Request/response XML transformation
- [ ] JIR/ZKI generation and validation
- [ ] Certificate-based authentication
- [ ] Circuit breaker for resilience

#### Day 5: porezna-connector Service
- [ ] REST API client implementation
- [ ] Tax report generation
- [ ] VAT validation service
- [ ] Monthly reporting automation
- [ ] Error handling and retries

### Week 2: Security & Compliance Services
**Owner:** Integration Specialist + DevOps Engineer

#### Day 6-7: cert-lifecycle-manager
- [ ] Certificate storage and retrieval
- [ ] Automated renewal workflow (30 days before expiry)
- [ ] CRL/OCSP validation
- [ ] HSM integration preparation (mock HSM)
- [ ] Certificate monitoring and alerting

#### Day 8-9: digital-signature-service
- [ ] XMLDSig enveloped signature implementation
- [ ] Batch signing for high throughput
- [ ] Signature verification service
- [ ] Timestamp server integration (mock TSA)
- [ ] Performance optimization for 278 sig/sec target

#### Day 10: archive-service
- [ ] PostgreSQL schema for 11-year retention
- [ ] WORM simulation in development
- [ ] Monthly signature validation workflow
- [ ] Compression and encryption
- [ ] Retrieval API with audit logging

### Week 3: Monitoring & Operational Services
**Owner:** DevOps Engineer + Full Team

#### Day 11-12: reporting-service
- [ ] Compliance report generation
- [ ] Analytics dashboard data preparation
- [ ] CSV/Excel export functionality
- [ ] Scheduled report automation
- [ ] Email delivery integration

#### Day 13: dead-letter-handler
- [ ] DLQ monitoring and alerting
- [ ] Manual retry interface
- [ ] Poison message detection
- [ ] Recovery workflow automation
- [ ] Metrics and dashboards

#### Day 14: Integration & Remediation
- [ ] Fix architecture violations (PENDING-006)
- [ ] Remove direct HTTP calls
- [ ] Implement message bus for all inter-service communication
- [ ] Add compliance checking scripts
- [ ] Setup pre-commit hooks

#### Day 15: Production Preparation
- [ ] systemd hardening for all services
- [ ] Secrets management with SOPS
- [ ] Monitoring and alerting setup
- [ ] Complete documentation
- [ ] Disaster recovery procedures

---

## Testing Strategy

### Compliance Testing

```typescript
// services/fina-connector/tests/integration/compliance.test.ts
describe('FINA Compliance Tests', () => {
  let finaService: IFINAClient;
  let mockFina: MockFINAService;

  beforeAll(() => {
    // Use mock in test, real in staging
    const useMock = process.env.USE_MOCK_FINA === 'true';
    finaService = useMock ? new MockFINAService() : new RealFINAClient();
  });

  describe('Croatian Fiscalization 2.0 Requirements', () => {
    it('should generate valid JIR for B2C transactions', async () => {
      const invoice = InvoiceBuilder.createB2C()
        .withSupplierOIB('12345678901')
        .withBuyerOIB('98765432109')
        .withVATRate(25)
        .withKPDCode('469011')
        .build();

      const signed = await digitalSignatureService.sign(invoice);
      const response = await finaService.submitInvoice(signed);

      expect(response.success).toBe(true);
      expect(response.jir).toMatch(/^[A-Z0-9]{32}$/);
      expect(response.zki).toMatch(/^[A-F0-9]{32}$/);
    });

    it('should validate Croatian OIB correctly', async () => {
      const validOIBs = [
        '12345678901',  // Valid test OIB
        '69435151530',  // Real valid OIB (public)
      ];

      for (const oib of validOIBs) {
        const company = await finaService.getCompanyInfo(oib);
        expect(company.oib).toBe(oib);
        expect(company.vatNumber).toBe(`HR${oib}`);
      }
    });

    it('should reject invalid KPD codes', async () => {
      const invoice = InvoiceBuilder.createValid()
        .withKPDCode('999999') // Invalid code
        .build();

      const signed = await digitalSignatureService.sign(invoice);
      const response = await finaService.submitInvoice(signed);

      expect(response.success).toBe(false);
      expect(response.error).toContain('KPD');
    });

    it('should handle certificate validation correctly', async () => {
      const cert = {
        serialNumber: 'TEST-001',
        pem: mockCertificatePEM
      };

      const validation = await finaService.validateCertificate(cert);
      expect(validation.valid).toBe(true);
      expect(validation.issuer).toContain('FINA');
    });
  });

  describe('Performance Requirements', () => {
    it('should handle 100 concurrent submissions', async () => {
      const invoices = Array.from({length: 100}, () =>
        InvoiceBuilder.createValid().build()
      );

      const startTime = Date.now();

      const results = await Promise.all(
        invoices.map(inv =>
          digitalSignatureService.sign(inv)
            .then(signed => finaService.submitInvoice(signed))
        )
      );

      const duration = Date.now() - startTime;

      expect(results.filter(r => r.success)).toHaveLength(100);
      expect(duration).toBeLessThan(10000); // Under 10 seconds
    });
  });
});
```

### Security Testing

```typescript
// services/digital-signature-service/tests/security/xmldsig.test.ts
describe('XML Digital Signature Security', () => {
  let signer: IXMLSigner;

  beforeEach(() => {
    signer = new MockXMLSigner();
  });

  describe('Signature Integrity', () => {
    it('should detect tampering with signed content', async () => {
      const xml = '<Invoice><Amount>1000</Amount></Invoice>';
      const signed = await signer.signXML(xml, {referenceUri: ''});

      // Tamper with the amount
      const tampered = signed.xml.replace('>1000<', '>2000<');

      const verification = await signer.verifyXMLSignature(tampered);
      expect(verification.valid).toBe(false);
    });

    it('should prevent XML signature wrapping attacks', async () => {
      const xml = generateInvoiceXML();
      const signed = await signer.signXML(xml, {referenceUri: '#invoice'});

      // Attempt signature wrapping attack
      const attacked = attemptSignatureWrapping(signed.xml);

      const verification = await signer.verifyXMLSignature(attacked);
      expect(verification.valid).toBe(false);
    });

    it('should validate certificate chain', async () => {
      const untrustedSigner = new MockXMLSigner({
        certificate: generateSelfSignedCert()
      });

      const xml = '<Invoice/>';
      const signed = await untrustedSigner.signXML(xml);

      const verification = await verifyWithTrustStore(signed);
      expect(verification.trusted).toBe(false);
    });
  });

  describe('Performance', () => {
    it('should achieve 278 signatures/second throughput', async () => {
      const documents = Array.from({length: 278}, () =>
        generateInvoiceXML()
      );

      const startTime = Date.now();

      await Promise.all(
        documents.map(doc =>
          signer.signXML(doc, {referenceUri: ''})
        )
      );

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThanOrEqual(1000);
    });
  });
});
```

### Chaos Testing

```typescript
// services/tests/chaos/external-failures.test.ts
describe('External Service Failure Scenarios', () => {
  let chaosMonkey: ChaosMonkey;

  beforeEach(() => {
    chaosMonkey = new ChaosMonkey();
  });

  it('should handle FINA service outage gracefully', async () => {
    // Inject FINA failure
    chaosMonkey.breakService('fina', {
      type: 'CONNECTION_TIMEOUT',
      duration: 5000
    });

    const invoice = createTestInvoice();
    const result = await submitInvoicePipeline(invoice);

    expect(result.status).toBe('QUEUED_FOR_RETRY');
    expect(result.retryAfter).toBeGreaterThan(0);

    // Verify circuit breaker opened
    const health = await getServiceHealth('fina-connector');
    expect(health.circuitBreaker).toBe('OPEN');
  });

  it('should handle certificate expiry during processing', async () => {
    // Start with valid certificate
    const certManager = new CertLifecycleManager();
    await certManager.loadCertificate('valid-cert.p12');

    // Schedule certificate expiry
    chaosMonkey.scheduleCertExpiry(1000);

    // Submit invoices
    const promises = Array.from({length: 10}, () =>
      submitInvoicePipeline(createTestInvoice())
    );

    // Wait for expiry
    await delay(1500);

    const results = await Promise.allSettled(promises);

    // Some should succeed (before expiry), some should fail
    const succeeded = results.filter(r => r.status === 'fulfilled');
    const failed = results.filter(r => r.status === 'rejected');

    expect(succeeded.length).toBeGreaterThan(0);
    expect(failed.length).toBeGreaterThan(0);

    // Verify automatic renewal was triggered
    const newCert = await certManager.getCurrentCertificate();
    expect(newCert.serialNumber).not.toBe('valid-cert');
  });

  it('should handle database failure during archive', async () => {
    const archiveService = new ArchiveService();

    // Inject database failure after 50% of batch
    chaosMonkey.scheduleFailure('postgresql', {
      type: 'CONNECTION_LOST',
      afterOperations: 50
    });

    const documents = Array.from({length: 100}, () =>
      generateSignedInvoice()
    );

    const result = await archiveService.archiveBatch(documents);

    // Should have partial success with rollback
    expect(result.status).toBe('PARTIAL_FAILURE');
    expect(result.succeeded).toBe(50);
    expect(result.failed).toBe(50);
    expect(result.rollbackCompleted).toBe(true);
  });
});
```

---

## Performance Benchmarks

### Target Metrics
- FINA submission: <3s (p99)
- Digital signature generation: 278/sec sustained
- Archive write throughput: 1000 docs/sec
- Certificate validation: <100ms
- Monthly validation batch: <1 hour for 10M documents

### Load Testing

```javascript
// tests/load/fina-submission.js
import http from 'k6/http';
import {check} from 'k6';
import {Rate} from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
  scenarios: {
    constant_load: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 50,
    },
    spike_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      stages: [
        {duration: '2m', target: 10},
        {duration: '1m', target: 500}, // Spike
        {duration: '2m', target: 10},
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<3000'], // 99% under 3s
    errors: ['rate<0.01'], // Error rate under 1%
  },
};

export default function() {
  const invoice = generateMockInvoice();

  const params = {
    headers: {
      'Content-Type': 'application/xml',
      'X-Certificate': getMockCertificate(),
    },
  };

  const response = http.post(
    'http://localhost:3000/api/v1/fina/submit',
    invoice,
    params
  );

  const success = check(response, {
    'status is 200': (r) => r.status === 200,
    'has JIR': (r) => JSON.parse(r.body).jir !== undefined,
    'response time OK': (r) => r.timings.duration < 3000,
  });

  errorRate.add(!success);
}
```

---

## Deliverables

### Services (7 total)
- [ ] fina-connector (100% tested, mock + real)
- [ ] porezna-connector (100% tested, mock + real)
- [ ] cert-lifecycle-manager (100% tested)
- [ ] digital-signature-service (100% tested)
- [ ] archive-service (100% tested)
- [ ] reporting-service (100% tested)
- [ ] dead-letter-handler (100% tested)

### Mock Implementations
- [ ] Complete FINA API mock with SOAP/XML
- [ ] Complete Porezna API mock
- [ ] XMLDSig implementation
- [ ] Certificate store and validation
- [ ] Mock HSM for testing

### Compliance Artifacts
- [ ] Architecture compliance script
- [ ] Pre-commit hooks
- [ ] PENDING-006 remediation complete
- [ ] Security audit checklist
- [ ] Compliance test suite

### Documentation
- [ ] Integration guide for Croatian systems
- [ ] Certificate setup guide
- [ ] Disaster recovery procedures
- [ ] Compliance checklist
- [ ] Performance tuning guide

---

## Risk Mitigation

### Risk: Production API differences from mock
**Mitigation:**
- Contract tests that both mock and real must pass
- Staging environment with FINA test API
- Gradual rollout with monitoring
- Quick rollback capability

### Risk: Certificate management complexity
**Mitigation:**
- Automated renewal 30 days before expiry
- Multiple certificate support
- HSM for production keys
- Backup certificates ready

### Risk: 11-year archive reliability
**Mitigation:**
- Multiple backup strategies
- Monthly integrity checks
- Signature re-validation
- Geographic redundancy

### Risk: Regulatory changes
**Mitigation:**
- Modular validation rules
- Configuration-driven compliance
- Regular compliance reviews
- Croatian tax consultant on retainer

---

## Critical Success Factors

### Week 1 Deliverables
- [ ] All mock services operational and realistic
- [ ] FINA/Porezna connectors working with mocks
- [ ] Certificate management functional

### Week 2 Deliverables
- [ ] Digital signatures working at required throughput
- [ ] Archive service meeting retention requirements
- [ ] All security services operational

### Week 3 Deliverables
- [ ] Architecture violations fixed (PENDING-006)
- [ ] Full compliance test suite passing
- [ ] Production deployment ready
- [ ] Disaster recovery tested

---

## Communication

### Daily Sync
- 10:00 AM standup (15 min)
- Blockers and dependencies
- Integration points with other teams

### Weekly Deliverables
- Monday: Plan review
- Wednesday: Integration test with all teams
- Friday: Demo and metrics review

### Escalation Path
1. Team Lead
2. Technical Director
3. Compliance Officer (for regulatory issues)

---

**Document Version:** 1.0.0
**Created:** 2025-11-14
**Owner:** Team 3 Lead
**Compliance Review:** Required before production
