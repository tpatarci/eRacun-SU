import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express, { Application } from 'express';

// Mock all dependencies
jest.mock('../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn(),
  getPool: jest.fn().mockReturnValue({
    query: jest.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] }),
  }),
  closePool: jest.fn(),
}));

jest.mock('../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('../../src/jobs/invoice-submission', () => ({
  initializeInvoiceSubmission: jest.fn(),
  submitInvoiceForProcessing: jest.fn(),
  getInvoiceSubmissionService: jest.fn().mockReturnValue({
    shutdown: jest.fn().mockResolvedValue(undefined),
  }),
}));

import { healthCheck, healthCheckDb } from '../../src/api/routes/health.js';
import { validationMiddleware } from '../../src/api/middleware/validate.js';
import { invoiceSubmissionSchema } from '../../src/api/schemas.js';
import { requestIdMiddleware, errorHandler } from '../../src/api/app.js';

describe('Invoice Flow E2E Tests (Mocked)', () => {
  let app: Application;
  const mockInvoices: any[] = [];

  beforeEach(() => {
    jest.clearAllMocks();
    mockInvoices.length = 0;

    // Create Express app for testing
    app = express();
    app.use(express.json());
    app.use(requestIdMiddleware);

    // Setup routes
    app.get('/health', healthCheck);
    app.get('/health/db', healthCheckDb);
    app.post('/api/v1/invoices',
      validationMiddleware(invoiceSubmissionSchema),
      async (req: any, res: any, next) => {
        try {
          // Mock job submission
          const invoice = {
            id: '550e8400-e29b-41d4-a716-446655440000',
            oib: req.body.oib,
            invoiceNumber: req.body.invoiceNumber,
            status: 'queued',
          };
          mockInvoices.push(invoice);

          res.status(202).json({
            invoiceId: invoice.id,
            jobId: 'test-job-id',
            status: 'queued',
          });
        } catch (error) {
          next(error);
        }
      }
    );

    app.get('/api/v1/invoices/:id', (req: any, res: any) => {
      const invoice = mockInvoices.find((inv: any) => inv.id === req.params.id);
      if (!invoice) {
        res.status(404).json({
          code: 'NOT_FOUND',
          message: 'Invoice not found',
          requestId: req.id
        });
        return;
      }
      res.json(invoice);
    });

    app.get('/api/v1/invoices/:id/status', (req: any, res: any) => {
      const invoice = mockInvoices.find((inv: any) => inv.id === req.params.id);
      if (!invoice) {
        res.status(404).json({
          code: 'NOT_FOUND',
          message: 'Invoice not found',
          requestId: req.id
        });
        return;
      }
      res.json({
        id: invoice.id,
        status: invoice.status,
        jir: invoice.jir,
      });
    });

    app.use(errorHandler);
  });

  describe('Health Endpoints', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'ok',
        timestamp: expect.any(String),
        version: expect.any(String),
      });
    });

    it('should return database health status', async () => {
      const response = await request(app)
        .get('/health/db')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'ok',
      });
    });

    it('should generate and return request ID', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.headers['x-request-id']).toBeDefined();
      expect(response.headers['x-request-id']).toMatch(/^[a-f0-9-]+$/);
    });

    it('should use custom request ID if provided', async () => {
      const customId = 'my-custom-request-id-123';

      const response = await request(app)
        .get('/health')
        .set('X-Request-ID', customId)
        .expect(200);

      expect(response.headers['x-request-id']).toBe(customId);
    });
  });

  describe('Invoice Submission Flow', () => {
    const validInvoiceData = {
      oib: '12345678903',
      invoiceNumber: 'TEST-001',
      amount: '1250.00',
      paymentMethod: 'T',
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-02-09T10:30:00Z',
      originalXml: '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>TEST-001</ID></Invoice>',
      signedXml: '<SignedInvoice><SignatureValue>abc123</SignatureValue></SignedInvoice>',
    };

    it('should submit a valid invoice and return job ID', async () => {
      const response = await request(app)
        .post('/api/v1/invoices')
        .send(validInvoiceData)
        .expect(202);

      expect(response.body).toMatchObject({
        invoiceId: expect.any(String),
        jobId: 'test-job-id',
        status: 'queued',
      });
    });

    it('should reject invoice with invalid OIB (too short)', async () => {
      const invalidData = { ...validInvoiceData, oib: '123' };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
      expect(response.body.errors).toBeInstanceOf(Array);
    });

    it('should reject invoice with invalid OIB (non-numeric)', async () => {
      const invalidData = { ...validInvoiceData, oib: 'abcdefghijk' };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
    });

    it('should reject invoice with invalid payment method', async () => {
      const invalidData = { ...validInvoiceData, paymentMethod: 'X' };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
    });

    it('should reject invoice with zero amount', async () => {
      const invalidData = { ...validInvoiceData, amount: '0' };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
    });

    it('should reject invoice with invalid datetime format', async () => {
      const invalidData = { ...validInvoiceData, dateTime: '2024-01-01 10:00:00' };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
    });

    it('should accept invoice with VAT breakdown', async () => {
      const dataWithVat = {
        ...validInvoiceData,
        vatBreakdown: [
          { base: '1000.00', rate: '25.00', amount: '250.00' },
          { base: '500.00', rate: '13.00', amount: '65.00' },
        ],
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(dataWithVat)
        .expect(202);

      expect(response.body).toMatchObject({
        status: 'queued',
      });
    });

    it('should reject invoice with invalid VAT breakdown (negative base)', async () => {
      const invalidData = {
        ...validInvoiceData,
        vatBreakdown: [
          { base: '-100.00', rate: '25.00', amount: '250.00' },
        ],
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
    });

    it('should accept all valid payment methods', async () => {
      const validMethods = ['G', 'K', 'C', 'T', 'O'];

      for (const method of validMethods) {
        const data = { ...validInvoiceData, paymentMethod: method };

        await request(app)
          .post('/api/v1/invoices')
          .send(data)
          .expect(202);
      }
    });
  });

  describe('Invoice Retrieval Flow', () => {
    beforeEach(() => {
      // Add test invoice
      mockInvoices.push({
        id: '550e8400-e29b-41d4-a716-446655440000',
        oib: '98765432105',
        invoiceNumber: 'TEST-002',
        originalXml: '<test/>',
        signedXml: '<signed/>',
        status: 'completed',
        jir: 'JIR-12345',
        createdAt: new Date().toISOString(),
      });
    });

    it('should retrieve invoice by ID', async () => {
      const invoiceId = '550e8400-e29b-41d4-a716-446655440000';

      const response = await request(app)
        .get(`/api/v1/invoices/${invoiceId}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: invoiceId,
        oib: '98765432105',
        invoiceNumber: 'TEST-002',
        status: 'completed',
        jir: 'JIR-12345',
      });
    });

    it('should return 404 for non-existent invoice', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      const response = await request(app)
        .get(`/api/v1/invoices/${fakeId}`)
        .expect(404);

      expect(response.body).toMatchObject({
        code: 'NOT_FOUND',
        message: 'Invoice not found',
        requestId: expect.any(String),
      });
    });

    it('should retrieve invoice status only', async () => {
      const invoiceId = '550e8400-e29b-41d4-a716-446655440000';

      const response = await request(app)
        .get(`/api/v1/invoices/${invoiceId}/status`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: invoiceId,
        status: 'completed',
        jir: 'JIR-12345',
      });
      expect(response.body).not.toHaveProperty('originalXml');
      expect(response.body).not.toHaveProperty('signedXml');
    });
  });
});

// OIB Validation Integration Tests
describe('OIB Validation Integration', () => {
  const { validateOIB, validateOIBChecksum, generateValidOIB } = require('../../src/validation/oib-validator');

  it('should validate multiple valid OIBs', () => {
    const validOIBs = [
      '12345678903',  // Valid checksum
      '33392005961',  // Valid checksum
      '82276151223',  // Valid checksum (generated)
    ];

    const results = validOIBs.map(oib => validateOIB(oib));

    results.forEach((result, i) => {
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.oib).toBe(validOIBs[i]);
    });
  });

  it('should detect all types of invalid OIBs', () => {
    const invalidCases = [
      { oib: '12345678901', expectedError: 'checksum' },
      { oib: 'abcdefghijk', expectedError: 'digits' },
      { oib: '123456789', expectedError: '11 digits' },
      { oib: '123456789012', expectedError: '11 digits' },
      { oib: '', expectedError: 'required' },
    ];

    invalidCases.forEach(({ oib, expectedError }) => {
      const result = validateOIB(oib);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e: string) => e.toLowerCase().includes(expectedError))).toBe(true);
    });
  });

  it('should validate OIB checksum correctly', () => {
    expect(validateOIBChecksum('12345678903')).toBe(true);
    expect(validateOIBChecksum('33392005961')).toBe(true);
    expect(validateOIBChecksum('82276151223')).toBe(true);
    expect(validateOIBChecksum('12345678901')).toBe(false);
    expect(validateOIBChecksum('00000000000')).toBe(false);
  });

  it('should generate valid OIBs', () => {
    const generated = [
      generateValidOIB(),
      generateValidOIB('1234567890'),  // Must be 10 digits for prefix
      generateValidOIB('8885949490'),
    ];

    generated.forEach(oib => {
      expect(oib).toHaveLength(11);
      expect(/^\d+$/.test(oib)).toBe(true);
      expect(validateOIBChecksum(oib)).toBe(true);
    });
  });
});

// XMLDSig Integration Tests
describe('XMLDSig Integration', () => {
  const { signXMLDocument } = require('../../src/signing/xmldsig-signer');
  const { loadCertificateFromFile } = require('../../src/signing/certificate-parser');
  const { generateZKI } = require('../../src/signing/zki-generator');
  const path = require('path');

  it('should sign an XML invoice document', async () => {
    const cert = await loadCertificateFromFile(
      path.join(__dirname, '../fixtures/test-cert.p12'),
      'test123'
    );

    const unsignedXml = `
      <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
        <ID>TEST-001</ID>
        <IssueDate>2026-02-09</IssueDate>
        <AccountingSupplierParty>
          <Party>
            <PartyIdentification>
              <ID>12345678903</ID>
            </PartyIdentification>
          </Party>
        </AccountingSupplierParty>
        <LegalMonetaryTotal>
          <TaxInclusiveCurrencyAmount currencyID="EUR">1250.00</TaxInclusiveCurrencyAmount>
        </LegalMonetaryTotal>
      </Invoice>
    `;

    const signedXml = await signXMLDocument(unsignedXml, cert);

    expect(signedXml).toContain('SignatureValue');
    expect(signedXml).toContain('X509Certificate');
    expect(signedXml).toContain('TEST-001');
    expect(signedXml).toContain('DigestValue');
  });

  it('should generate ZKI code with correct format', async () => {
    const cert = await loadCertificateFromFile(
      path.join(__dirname, '../fixtures/test-cert.p12'),
      'test123'
    );

    const zki = await generateZKI({
      oib: '12345678903',
      issueDateTime: '2026-02-09T10:30:00Z',
      invoiceNumber: '1/PP1/1',
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '1250.00',
    }, cert);

    expect(zki).toBeDefined();
    expect(zki.length).toBeGreaterThan(0);
    expect(typeof zki).toBe('string');
    // ZKI should be hex string (MD5 hash + RSA signature)
    expect(/^[0-9a-fA-F]+$/.test(zki)).toBe(true);
  });

  it('should generate unique ZKI codes for different invoices', async () => {
    const cert = await loadCertificateFromFile(
      path.join(__dirname, '../fixtures/test-cert.p12'),
      'test123'
    );

    const zki1 = await generateZKI({
      oib: '12345678903',
      issueDateTime: '2026-02-09T10:30:00Z',
      invoiceNumber: '1/PP1/1',
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '1250.00',
    }, cert);

    const zki2 = await generateZKI({
      oib: '12345678903',
      issueDateTime: '2026-02-09T10:30:00Z',
      invoiceNumber: '2/PP1/1',  // Different invoice number
      businessPremises: 'PP1',
      cashRegister: '1',
      totalAmount: '2500.00',
    }, cert);

    // Different invoices should produce different ZKI codes
    expect(zki1).not.toBe(zki2);
  });
});

// Certificate Parser Integration Tests
describe('Certificate Parser Integration', () => {
  const { loadCertificateFromFile } = require('../../src/signing/certificate-parser');
  const path = require('path');

  it('should load certificate from PKCS#12 file', async () => {
    const cert = await loadCertificateFromFile(
      path.join(__dirname, '../fixtures/test-cert.p12'),
      'test123'
    );

    expect(cert).toBeDefined();
    expect(cert.privateKey).toBeDefined();
    expect(cert.certificatePEM).toBeDefined();
    expect(cert.privateKeyPEM).toBeDefined();
    expect(cert.info.subjectDN).toContain('CN=Test');
  });

  it('should parse certificate components', async () => {
    const cert = await loadCertificateFromFile(
      path.join(__dirname, '../fixtures/test-cert.p12'),
      'test123'
    );

    expect(cert.info.subjectDN).toBeDefined();
    expect(cert.info.issuer).toBeDefined();
    expect(cert.info.serialNumber).toBeDefined();
    expect(cert.info.notBefore).toBeInstanceOf(Date);
    expect(cert.info.notAfter).toBeInstanceOf(Date);
  });

  it('should throw error for wrong passphrase', async () => {
    await expect(
      loadCertificateFromFile(
        path.join(__dirname, '../fixtures/test-cert.p12'),
        'wrongpass'
      )
    ).rejects.toThrow();
  });

  it('should throw error for non-existent file', async () => {
    await expect(
      loadCertificateFromFile('/nonexistent/file.p12', 'test123')
    ).rejects.toThrow();
  });
});
