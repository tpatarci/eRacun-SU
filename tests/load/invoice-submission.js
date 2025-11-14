/**
 * k6 Load Test: Invoice Submission
 *
 * Tests the invoice-gateway-api under various load scenarios.
 *
 * Usage:
 *   k6 run tests/load/invoice-submission.js
 *   k6 run --vus 100 --duration 30m tests/load/invoice-submission.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
const submissionErrors = new Counter('submission_errors');
const submissionDuration = new Trend('submission_duration');
const validationDuration = new Trend('validation_duration');
const successRate = new Rate('success_rate');

// Test configuration
export const options = {
  stages: [
    // Ramp-up: 0 → 50 users over 2 minutes
    { duration: '2m', target: 50 },

    // Sustained load: 50 users for 10 minutes
    { duration: '10m', target: 50 },

    // Peak load: 50 → 100 users over 2 minutes
    { duration: '2m', target: 100 },

    // Sustained peak: 100 users for 10 minutes
    { duration: '10m', target: 100 },

    // Spike test: 100 → 200 users over 1 minute
    { duration: '1m', target: 200 },

    // Sustained spike: 200 users for 5 minutes
    { duration: '5m', target: 200 },

    // Ramp-down: 200 → 0 users over 2 minutes
    { duration: '2m', target: 0 },
  ],

  thresholds: {
    // 95% of requests must complete within 200ms
    'http_req_duration': ['p(95)<200'],

    // 99% of requests must complete within 500ms
    'http_req_duration': ['p(99)<500'],

    // Error rate must be below 1%
    'http_req_failed': ['rate<0.01'],

    // Success rate must be above 99%
    'success_rate': ['rate>0.99'],

    // Submission endpoint must be fast
    'submission_duration': ['p(95)<200', 'p(99)<500'],
  },
};

// Base URL (configurable via environment variable)
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// Sample valid UBL 2.1 invoice XML
const validInvoiceXML = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2">
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>
  <cbc:ID>INV-${Date.now()}</cbc:ID>
  <cbc:IssueDate>${new Date().toISOString().split('T')[0]}</cbc:IssueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>HR12345678903</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>HR98765432106</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">25.00</cbc:TaxAmount>
  </cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:TaxExclusiveAmount currencyID="EUR">100.00</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">125.00</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">125.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`;

/**
 * Main test scenario
 */
export default function () {
  const idempotencyKey = uuidv4();

  // Test 1: Submit invoice
  const submitRes = http.post(
    `${BASE_URL}/api/v1/invoices`,
    validInvoiceXML,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-Idempotency-Key': idempotencyKey,
      },
      tags: { name: 'SubmitInvoice' },
    }
  );

  // Check submission response
  const submitSuccess = check(submitRes, {
    'submission status is 202': (r) => r.status === 202,
    'submission has invoiceId': (r) => JSON.parse(r.body).invoiceId !== undefined,
    'submission has status': (r) => JSON.parse(r.body).status === 'QUEUED',
    'submission duration < 200ms': (r) => r.timings.duration < 200,
  });

  // Record metrics
  successRate.add(submitSuccess);
  submissionDuration.add(submitRes.timings.duration);

  if (!submitSuccess) {
    submissionErrors.add(1);
    console.error(`Submission failed: ${submitRes.status} ${submitRes.body}`);
  }

  // Extract invoice ID for status check
  let invoiceId;
  if (submitRes.status === 202) {
    invoiceId = JSON.parse(submitRes.body).invoiceId;
  }

  // Test 2: Idempotency check (should return same response)
  const idempotencyRes = http.post(
    `${BASE_URL}/api/v1/invoices`,
    validInvoiceXML,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-Idempotency-Key': idempotencyKey,
      },
      tags: { name: 'IdempotencyCheck' },
    }
  );

  check(idempotencyRes, {
    'idempotency returns same invoice ID': (r) =>
      invoiceId && JSON.parse(r.body).invoiceId === invoiceId,
    'idempotency is fast (<100ms)': (r) => r.timings.duration < 100,
  });

  // Test 3: Status check (if invoice was submitted)
  if (invoiceId) {
    sleep(0.5); // Wait 500ms for processing

    const statusRes = http.get(`${BASE_URL}/api/v1/invoices/${invoiceId}`, {
      tags: { name: 'GetStatus' },
    });

    check(statusRes, {
      'status check is 200': (r) => r.status === 200,
      'status has invoiceId': (r) => JSON.parse(r.body).invoiceId === invoiceId,
      'status is fast (<50ms)': (r) => r.timings.duration < 50,
    });
  }

  // Test 4: Health check (every 10th iteration)
  if (__ITER % 10 === 0) {
    const healthRes = http.get(`${BASE_URL}/api/v1/health`, {
      tags: { name: 'HealthCheck' },
    });

    check(healthRes, {
      'health check is UP': (r) => r.status === 200 && JSON.parse(r.body).status === 'UP',
      'health check is fast (<50ms)': (r) => r.timings.duration < 50,
    });
  }

  // Think time: simulate user behavior (random between 1-5 seconds)
  sleep(Math.random() * 4 + 1);
}

/**
 * Setup function - runs once before test
 */
export function setup() {
  console.log('🚀 Starting load test...');
  console.log(`📍 Base URL: ${BASE_URL}`);
  console.log(`👥 Max VUs: 200`);
  console.log(`⏱️  Duration: 34 minutes`);

  // Verify service is up
  const healthCheck = http.get(`${BASE_URL}/api/v1/health`);
  if (healthCheck.status !== 200) {
    throw new Error(`Service not available: ${healthCheck.status}`);
  }

  console.log('✅ Service is UP - starting load test');
  return { startTime: Date.now() };
}

/**
 * Teardown function - runs once after test
 */
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000 / 60;
  console.log(`✅ Load test completed in ${duration.toFixed(2)} minutes`);
}
