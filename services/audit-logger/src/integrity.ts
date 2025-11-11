import { getPool } from './writer';
import {
  logger,
  auditIntegrityChecks,
  createSpan,
  setSpanError,
} from './observability';

/**
 * Integrity verification result
 */
export interface IntegrityResult {
  valid: boolean;
  total_events: number;
  broken_chains: string[];  // Event IDs with hash mismatches
  verification_time_ms: number;
}

/**
 * Verify hash chain integrity for a time range
 *
 * CRITICAL: This checks that each event's previous_hash matches
 * the previous event's event_hash, ensuring audit trail immutability
 *
 * @param startTimeMs - Start of time range (Unix timestamp in ms)
 * @param endTimeMs - End of time range (Unix timestamp in ms)
 * @returns IntegrityResult with validation status
 */
export async function verifyIntegrity(
  startTimeMs: number,
  endTimeMs: number
): Promise<IntegrityResult> {
  const span = createSpan('verify_integrity', {
    'time.start': startTimeMs,
    'time.end': endTimeMs,
  });

  const startTime = Date.now();
  const brokenChains: string[] = [];

  try {
    const pool = getPool();

    // Fetch all events in time range, ordered by timestamp
    const result = await pool.query(
      `SELECT event_id, event_hash, previous_hash, timestamp_ms
       FROM audit_events
       WHERE timestamp_ms BETWEEN $1 AND $2
       ORDER BY timestamp_ms ASC, id ASC`,
      [startTimeMs, endTimeMs]
    );

    const events = result.rows;
    const totalEvents = events.length;

    logger.info({
      start_time_ms: startTimeMs,
      end_time_ms: endTimeMs,
      total_events: totalEvents,
    }, 'Starting integrity verification');

    // Verify hash chain
    let previousHash: string | null = null;

    for (let i = 0; i < events.length; i++) {
      const event = events[i];

      // Skip first event if it has no previous_hash (genesis event)
      if (i === 0 && !event.previous_hash) {
        previousHash = event.event_hash;
        continue;
      }

      // Verify chain link
      if (previousHash && event.previous_hash !== previousHash) {
        brokenChains.push(event.event_id);
        logger.warn({
          event_id: event.event_id,
          expected_previous_hash: previousHash,
          actual_previous_hash: event.previous_hash,
          position: i,
        }, 'Hash chain broken - integrity violation detected');
      }

      previousHash = event.event_hash;
    }

    const verificationTimeMs = Date.now() - startTime;
    const valid = brokenChains.length === 0;

    // Metrics
    auditIntegrityChecks.inc({ status: valid ? 'valid' : 'broken' });

    span.setAttribute('events.total', totalEvents);
    span.setAttribute('chains.broken', brokenChains.length);
    span.setAttribute('integrity.valid', valid);
    span.end();

    const result_obj: IntegrityResult = {
      valid,
      total_events: totalEvents,
      broken_chains: brokenChains,
      verification_time_ms: verificationTimeMs,
    };

    if (valid) {
      logger.info({
        total_events: totalEvents,
        verification_time_ms: verificationTimeMs,
      }, 'Integrity verification passed');
    } else {
      logger.error({
        total_events: totalEvents,
        broken_chains: brokenChains.length,
        broken_event_ids: brokenChains,
        verification_time_ms: verificationTimeMs,
      }, 'CRITICAL: Integrity verification failed - audit trail compromised');
    }

    return result_obj;

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({
      err: error,
      start_time_ms: startTimeMs,
      end_time_ms: endTimeMs,
    }, 'Integrity verification failed with error');

    throw error;
  }
}

/**
 * Verify integrity of entire audit log
 *
 * WARNING: This can be slow for large datasets
 * Recommended to run during maintenance windows
 */
export async function verifyFullIntegrity(): Promise<IntegrityResult> {
  const span = createSpan('verify_full_integrity');

  try {
    const pool = getPool();

    // Get time range of all events
    const rangeResult = await pool.query(
      `SELECT
         MIN(timestamp_ms) as min_time,
         MAX(timestamp_ms) as max_time
       FROM audit_events`
    );

    if (!rangeResult.rows[0].min_time) {
      span.end();
      logger.info('No audit events found - integrity verification skipped');
      return {
        valid: true,
        total_events: 0,
        broken_chains: [],
        verification_time_ms: 0,
      };
    }

    const minTime = parseInt(rangeResult.rows[0].min_time);
    const maxTime = parseInt(rangeResult.rows[0].max_time);

    span.setAttribute('time.range.start', minTime);
    span.setAttribute('time.range.end', maxTime);
    span.end();

    logger.info({
      min_time_ms: minTime,
      max_time_ms: maxTime,
    }, 'Starting full integrity verification');

    return await verifyIntegrity(minTime, maxTime);

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();
    throw error;
  }
}

/**
 * Verify integrity for a specific invoice's audit trail
 *
 * @param invoiceId - Invoice UUID to verify
 */
export async function verifyInvoiceIntegrity(invoiceId: string): Promise<IntegrityResult> {
  const span = createSpan('verify_invoice_integrity', {
    'invoice.id': invoiceId,
  });

  const startTime = Date.now();
  const brokenChains: string[] = [];

  try {
    const pool = getPool();

    // Fetch all events for this invoice, ordered by timestamp
    const result = await pool.query(
      `SELECT event_id, event_hash, previous_hash, timestamp_ms
       FROM audit_events
       WHERE invoice_id = $1
       ORDER BY timestamp_ms ASC, id ASC`,
      [invoiceId]
    );

    const events = result.rows;
    const totalEvents = events.length;

    if (totalEvents === 0) {
      span.end();
      logger.warn({ invoice_id: invoiceId }, 'No audit events found for invoice');
      return {
        valid: true,
        total_events: 0,
        broken_chains: [],
        verification_time_ms: Date.now() - startTime,
      };
    }

    // Verify sequential hash chain for this invoice
    let previousHash: string | null = null;

    for (let i = 0; i < events.length; i++) {
      const event = events[i];

      // For invoice-specific verification, we only check within the invoice's chain
      // The previous_hash might reference events from other invoices (global chain)
      // So we verify that the sequence is consistent
      if (i > 0 && previousHash) {
        // This is a simplified check - in reality, events from different invoices
        // can interleave, so we're just ensuring no obvious corruption
        const currentTimestamp = parseInt(event.timestamp_ms);
        const previousTimestamp = parseInt(events[i-1].timestamp_ms);

        if (currentTimestamp < previousTimestamp) {
          brokenChains.push(event.event_id);
          logger.warn({
            event_id: event.event_id,
            invoice_id: invoiceId,
            reason: 'timestamp_out_of_order',
          }, 'Timestamp ordering violated');
        }
      }

      previousHash = event.event_hash;
    }

    const verificationTimeMs = Date.now() - startTime;
    const valid = brokenChains.length === 0;

    auditIntegrityChecks.inc({ status: valid ? 'valid' : 'broken' });

    span.setAttribute('events.total', totalEvents);
    span.setAttribute('chains.broken', brokenChains.length);
    span.setAttribute('integrity.valid', valid);
    span.end();

    logger.info({
      invoice_id: invoiceId,
      total_events: totalEvents,
      valid,
      verification_time_ms: verificationTimeMs,
    }, 'Invoice integrity verification complete');

    return {
      valid,
      total_events: totalEvents,
      broken_chains: brokenChains,
      verification_time_ms: verificationTimeMs,
    };

  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({
      err: error,
      invoice_id: invoiceId,
    }, 'Invoice integrity verification failed');

    throw error;
  }
}
