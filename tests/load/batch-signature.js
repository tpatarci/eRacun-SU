/**
 * Digital Signature Batch Processing Load Test
 *
 * Tests the batch signature functionality:
 * 1. Batch submission (10-1000 invoices per batch)
 * 2. Parallel signature processing
 * 3. Throughput measurement
 * 4. Error handling in batches
 *
 * Target: 278 signatures/second (from TEAM_3 requirements)
 *
 * Scenarios:
 * - Small batches: 10 invoices/batch, 30 batches/min
 * - Medium batches: 100 invoices/batch, 3 batches/min
 * - Large batches: 500 invoices/batch, 1 batch/min
 *
 * Thresholds:
 * - Throughput >= 250 signatures/second
 * - p(95) batch time < 5s for 100 invoices
 * - Error rate < 0.1%
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const batchDuration = new Trend('batch_duration_ms');
const throughput = new Trend('signatures_per_second');
const totalSignatures = new Counter('total_signatures');
const batchSize = new Trend('batch_size');
const failedSignatures = new Counter('failed_signatures');

export const options = {
  scenarios: {
    small_batches: {
      executor: 'constant-arrival-rate',
      rate: 0.5, // 30 per minute
      timeUnit: '1s',
      duration: '20m',
      preAllocatedVUs: 5,
      maxVUs: 20,
      startTime: '0s',
      exec: 'smallBatchTest',
    },
    medium_batches: {
      executor: 'constant-arrival-rate',
      rate: 0.05, // 3 per minute
      timeUnit: '1s',
      duration: '20m',
      preAllocatedVUs: 3,
      maxVUs: 10,
      startTime: '21m',
      exec: 'mediumBatchTest',
    },
    large_batches: {
      executor: 'constant-arrival-rate',
      rate: 0.0167, // ~1 per minute
      timeUnit: '1s',
      duration: '20m',
      preAllocatedVUs: 2,
      maxVUs: 5,
      startTime: '42m',
      exec: 'largeBatchTest',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<10000'], // 95% under 10s (for large batches)
    errors: ['rate<0.001'], // Error rate under 0.1%
    signatures_per_second: ['avg>=250'], // Average throughput >= 250 sig/s
    batch_duration_ms: ['p(95)<5000'], // 95% of batches under 5s
  },
};

// Generate minimal UBL invoice XML
function generateInvoiceXML(index) {
  const invoiceNumber = `TEST-${Math.floor(Math.random() * 1000000)}-${index}`;
  const oib = '12345678901';
  const amount = (Math.random() * 1000 + 100).toFixed(2);

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

// Process batch signature
function processBatch(batchCount, concurrency) {
  const baseUrl = __ENV.BASE_URL || 'http://localhost:8088';

  // Generate batch of invoices
  const invoices = [];
  for (let i = 0; i < batchCount; i++) {
    invoices.push(generateInvoiceXML(i));
  }

  const payload = JSON.stringify({
    invoices: invoices,
    concurrency: concurrency,
    options: {
      algorithm: 'RSA-SHA256',
    },
  });

  const batchStart = Date.now();
  const response = http.post(
    `${baseUrl}/api/v1/sign/ubl/batch`,
    payload,
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `batch-test-${__VU}-${__ITER}`,
      },
      timeout: '60s', // Allow up to 60s for large batches
    }
  );

  const batchDurationMs = Date.now() - batchStart;
  batchDuration.add(batchDurationMs);
  batchSize.add(batchCount);

  const success = check(response, {
    'batch: status is 200': (r) => r.status === 200,
    'batch: has results': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.results && Array.isArray(body.results);
      } catch {
        return false;
      }
    },
    'batch: has throughput': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.throughput !== undefined && body.throughput > 0;
      } catch {
        return false;
      }
    },
  });

  if (success) {
    const body = JSON.parse(response.body);

    // Record metrics
    throughput.add(body.throughput);
    totalSignatures.add(body.successful);
    failedSignatures.add(body.failed);

    // Additional checks
    check(response, {
      'batch: all signatures successful': () => body.failed === 0,
      'batch: throughput target met': () => body.throughput >= 250,
      'batch: duration acceptable': () => body.duration_ms < (batchCount * 20), // Max 20ms per sig
    });
  } else {
    errorRate.add(1);
    failedSignatures.add(batchCount); // Count all as failed
  }

  return success;
}

// Small batch test (10 invoices)
export function smallBatchTest() {
  processBatch(10, 5);
  sleep(1); // 1s between batches
}

// Medium batch test (100 invoices)
export function mediumBatchTest() {
  processBatch(100, 10);
  sleep(5); // 5s between batches
}

// Large batch test (500 invoices)
export function largeBatchTest() {
  processBatch(500, 20);
  sleep(10); // 10s between batches
}

export function handleSummary(data) {
  const totalSigs = data.metrics.total_signatures ? data.metrics.total_signatures.values.count : 0;
  const failedSigs = data.metrics.failed_signatures ? data.metrics.failed_signatures.values.count : 0;
  const avgThroughput = data.metrics.signatures_per_second ? data.metrics.signatures_per_second.values.avg : 0;
  const avgBatchDuration = data.metrics.batch_duration_ms ? data.metrics.batch_duration_ms.values.avg : 0;
  const avgBatchSize = data.metrics.batch_size ? data.metrics.batch_size.values.avg : 0;

  const summary = {
    timestamp: new Date().toISOString(),
    total_signatures: totalSigs,
    failed_signatures: failedSigs,
    success_rate: ((totalSigs - failedSigs) / totalSigs * 100).toFixed(2),
    avg_throughput_per_second: avgThroughput.toFixed(2),
    avg_batch_duration_ms: avgBatchDuration.toFixed(2),
    avg_batch_size: avgBatchSize.toFixed(1),
    target_met: avgThroughput >= 250,
  };

  return {
    'tests/load/results/batch-signature-summary.json': JSON.stringify(summary, null, 2),
    stdout: `
Batch Signature Load Test Summary
==================================
Total Signatures: ${totalSigs}
Failed Signatures: ${failedSigs}
Success Rate: ${summary.success_rate}%
Average Throughput: ${summary.avg_throughput_per_second} signatures/second
Average Batch Duration: ${summary.avg_batch_duration_ms}ms
Average Batch Size: ${summary.avg_batch_size} invoices
Target Met (>=250 sig/s): ${summary.target_met ? 'YES ✅' : 'NO ❌'}
    `,
  };
}
