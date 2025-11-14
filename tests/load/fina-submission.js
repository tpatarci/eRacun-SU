/**
 * FINA Submission Load Test
 *
 * Tests the complete FINA fiscalization flow:
 * 1. Digital signature generation
 * 2. ZKI code calculation
 * 3. FINA CIS submission
 * 4. JIR retrieval
 *
 * Scenarios:
 * - Constant load: 100 req/s for 10 minutes
 * - Spike test: 10 -> 500 -> 10 req/s
 *
 * Thresholds:
 * - p(99) response time < 3s
 * - Error rate < 1%
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const finaSubmissionDuration = new Trend('fina_submission_duration');
const jirRetrievalCount = new Counter('jir_retrieval_total');
const signatureDuration = new Trend('signature_duration');

export const options = {
  scenarios: {
    constant_load: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 50,
      maxVUs: 200,
      startTime: '0s',
    },
    spike_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      startTime: '11m',
      stages: [
        { duration: '2m', target: 10 },
        { duration: '1m', target: 500 }, // Spike
        { duration: '2m', target: 10 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<3000'], // 99% under 3s
    errors: ['rate<0.01'], // Error rate under 1%
    fina_submission_duration: ['p(95)<2000'], // 95% under 2s
    signature_duration: ['p(99)<500'], // 99% signature under 500ms
  },
};

// Mock invoice XML generator
function generateMockInvoice() {
  const invoiceNumber = `2025/${Math.floor(Math.random() * 99999).toString().padStart(5, '0')}`;
  const oib = '12345678901';
  const amount = (Math.random() * 10000 + 100).toFixed(2);

  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>${invoiceNumber}</cbc:ID>
  <cbc:IssueDate>${new Date().toISOString().split('T')[0]}</cbc:IssueDate>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">${oib}</cbc:ID>
      </cac:PartyIdentification>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="EUR">${amount}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`;
}

export default function () {
  const baseUrl = __ENV.BASE_URL || 'http://localhost:8090';
  const invoice = generateMockInvoice();

  // Step 1: Sign invoice
  const signatureStart = Date.now();
  const signResponse = http.post(
    `${baseUrl}/api/v1/sign/ubl`,
    invoice,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-Request-ID': `load-test-${__VU}-${__ITER}`,
      },
    }
  );

  signatureDuration.add(Date.now() - signatureStart);

  const signatureSuccess = check(signResponse, {
    'signature: status is 200': (r) => r.status === 200,
    'signature: has signed XML': (r) => r.body && r.body.includes('Signature'),
    'signature: response time OK': (r) => r.timings.duration < 500,
  });

  if (!signatureSuccess) {
    errorRate.add(1);
    return;
  }

  // Step 2: Submit to FINA
  const finaStart = Date.now();
  const finaResponse = http.post(
    `${baseUrl}/api/v1/fina/submit`,
    signResponse.body,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-Request-ID': `load-test-${__VU}-${__ITER}`,
        'X-Certificate': 'TEST-001',
      },
    }
  );

  finaSubmissionDuration.add(Date.now() - finaStart);

  const finaSuccess = check(finaResponse, {
    'fina: status is 200': (r) => r.status === 200,
    'fina: has JIR': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.jir !== undefined && body.jir.length > 0;
      } catch {
        return false;
      }
    },
    'fina: has ZKI': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.zki !== undefined && body.zki.length > 0;
      } catch {
        return false;
      }
    },
    'fina: response time OK': (r) => r.timings.duration < 3000,
  });

  if (finaSuccess) {
    jirRetrievalCount.add(1);
  } else {
    errorRate.add(1);
  }

  sleep(0.1); // 100ms think time
}

export function handleSummary(data) {
  return {
    'tests/load/results/fina-submission-summary.json': JSON.stringify(data, null, 2),
  };
}
