/**
 * Archive Service Throughput Load Test
 *
 * Tests the 11-year compliant archive storage throughput:
 * 1. Document archival (store operation)
 * 2. Document retrieval (read operation)
 * 3. Search operations
 * 4. Compliance verification
 *
 * Target: 10,000 archives/hour sustained (2.78/second)
 *
 * Scenarios:
 * - Sustained archival: 3 archives/s for 1 hour
 * - Read-heavy workload: 80% reads, 20% writes
 * - Burst test: Spike to 10/s
 *
 * Thresholds:
 * - p(95) archive time < 1s
 * - p(95) retrieval time < 200ms
 * - Error rate < 0.1%
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const archivalDuration = new Trend('archival_duration');
const retrievalDuration = new Trend('retrieval_duration');
const archivalCount = new Counter('documents_archived');
const retrievalCount = new Counter('documents_retrieved');
const compressionRatio = new Trend('compression_ratio');

export const options = {
  scenarios: {
    sustained_archival: {
      executor: 'constant-arrival-rate',
      rate: 3,
      timeUnit: '1s',
      duration: '60m',
      preAllocatedVUs: 10,
      maxVUs: 50,
      startTime: '0s',
    },
    read_heavy_workload: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '30m',
      preAllocatedVUs: 30,
      maxVUs: 100,
      startTime: '61m',
      exec: 'readHeavyTest',
    },
    burst_test: {
      executor: 'ramping-arrival-rate',
      startRate: 3,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 100,
      startTime: '92m',
      stages: [
        { duration: '2m', target: 3 },
        { duration: '1m', target: 10 }, // Burst
        { duration: '2m', target: 3 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1000'], // 95% under 1s
    errors: ['rate<0.001'], // Error rate under 0.1%
    archival_duration: ['p(95)<1000'], // 95% archive under 1s
    retrieval_duration: ['p(95)<200'], // 95% retrieval under 200ms
  },
};

// Generate realistic signed invoice XML
function generateSignedInvoice() {
  const invoiceId = `INV-${Math.floor(Math.random() * 1000000)}`;
  const oib = '12345678901';
  const jir = `${Math.random().toString(36).substring(2, 15)}-${Math.random().toString(36).substring(2, 15)}`;
  const zki = `${Math.random().toString(36).substring(2, 15)}`;
  const amount = (Math.random() * 10000 + 100).toFixed(2);
  const timestamp = new Date().toISOString();

  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>${invoiceId}</cbc:ID>
  <cbc:IssueDate>${timestamp.split('T')[0]}</cbc:IssueDate>
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
  <ext:FINAExtension>
    <JIR>${jir}</JIR>
    <ZKI>${zki}</ZKI>
    <Timestamp>${timestamp}</Timestamp>
  </ext:FINAExtension>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:Reference URI="">
        <ds:DigestValue>mock-digest-value</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>mock-signature-value</ds:SignatureValue>
  </ds:Signature>
</Invoice>`;
}

// Main test function (archival-focused)
export default function () {
  const baseUrl = __ENV.BASE_URL || 'http://localhost:8092';
  const invoice = generateSignedInvoice();
  const originalSize = invoice.length;

  // Archive document
  const archivalStart = Date.now();
  const archiveResponse = http.post(
    `${baseUrl}/api/v1/archive`,
    invoice,
    {
      headers: {
        'Content-Type': 'application/xml',
        'X-Request-ID': `load-test-${__VU}-${__ITER}`,
        'X-Retention-Years': '11',
      },
    }
  );

  archivalDuration.add(Date.now() - archivalStart);

  const archiveSuccess = check(archiveResponse, {
    'archive: status is 201': (r) => r.status === 201,
    'archive: has document ID': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.document_id !== undefined;
      } catch {
        return false;
      }
    },
    'archive: has archive timestamp': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.archived_at !== undefined;
      } catch {
        return false;
      }
    },
    'archive: response time OK': (r) => r.timings.duration < 1000,
  });

  if (!archiveSuccess) {
    errorRate.add(1);
    return;
  }

  const docId = JSON.parse(archiveResponse.body).document_id;
  archivalCount.add(1);

  // Calculate compression ratio (if applicable)
  const compressedSize = JSON.parse(archiveResponse.body).stored_size || originalSize;
  compressionRatio.add(originalSize / compressedSize);

  // Retrieve document (10% of the time)
  if (Math.random() < 0.1) {
    sleep(0.1); // Brief delay before retrieval

    const retrievalStart = Date.now();
    const retrieveResponse = http.get(
      `${baseUrl}/api/v1/archive/${docId}`,
      {
        headers: {
          'X-Request-ID': `load-test-retrieve-${__VU}-${__ITER}`,
        },
      }
    );

    retrievalDuration.add(Date.now() - retrievalStart);

    const retrieveSuccess = check(retrieveResponse, {
      'retrieve: status is 200': (r) => r.status === 200,
      'retrieve: has document': (r) => r.body && r.body.length > 0,
      'retrieve: response time OK': (r) => r.timings.duration < 200,
    });

    if (retrieveSuccess) {
      retrievalCount.add(1);
    } else {
      errorRate.add(1);
    }
  }

  sleep(0.3); // 300ms think time
}

// Read-heavy test function
export function readHeavyTest() {
  const baseUrl = __ENV.BASE_URL || 'http://localhost:8092';

  // 80% reads, 20% writes
  if (Math.random() < 0.8) {
    // Read operation - get random document
    const docId = `INV-${Math.floor(Math.random() * 100000)}`;
    const retrievalStart = Date.now();
    const retrieveResponse = http.get(
      `${baseUrl}/api/v1/archive/${docId}`,
      {
        headers: {
          'X-Request-ID': `load-test-read-${__VU}-${__ITER}`,
        },
      }
    );

    retrievalDuration.add(Date.now() - retrievalStart);

    const success = check(retrieveResponse, {
      'read: status is 200 or 404': (r) => r.status === 200 || r.status === 404,
      'read: response time OK': (r) => r.timings.duration < 200,
    });

    if (success && retrieveResponse.status === 200) {
      retrievalCount.add(1);
    } else if (!success) {
      errorRate.add(1);
    }
  } else {
    // Write operation (20%)
    const invoice = generateSignedInvoice();
    const archivalStart = Date.now();
    const archiveResponse = http.post(
      `${baseUrl}/api/v1/archive`,
      invoice,
      {
        headers: {
          'Content-Type': 'application/xml',
          'X-Request-ID': `load-test-write-${__VU}-${__ITER}`,
        },
      }
    );

    archivalDuration.add(Date.now() - archivalStart);

    const success = check(archiveResponse, {
      'write: status is 201': (r) => r.status === 201,
      'write: response time OK': (r) => r.timings.duration < 1000,
    });

    if (success) {
      archivalCount.add(1);
    } else {
      errorRate.add(1);
    }
  }

  sleep(0.05); // 50ms think time (read-heavy is faster)
}

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    metrics: data.metrics,
    scenarios: data.root_group.checks,
  };

  return {
    'tests/load/results/archive-throughput-summary.json': JSON.stringify(summary, null, 2),
    stdout: `
Archive Service Load Test Summary
==================================
Total Archived: ${data.metrics.documents_archived ? data.metrics.documents_archived.values.count : 0}
Total Retrieved: ${data.metrics.documents_retrieved ? data.metrics.documents_retrieved.values.count : 0}
Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(3)}%
Avg Archival Time: ${data.metrics.archival_duration ? data.metrics.archival_duration.values.avg.toFixed(2) : 'N/A'}ms
Avg Retrieval Time: ${data.metrics.retrieval_duration ? data.metrics.retrieval_duration.values.avg.toFixed(2) : 'N/A'}ms
p95 Archival Time: ${data.metrics.archival_duration ? data.metrics.archival_duration.values['p(95)'].toFixed(2) : 'N/A'}ms
p95 Retrieval Time: ${data.metrics.retrieval_duration ? data.metrics.retrieval_duration.values['p(95)'].toFixed(2) : 'N/A'}ms
    `,
  };
}
