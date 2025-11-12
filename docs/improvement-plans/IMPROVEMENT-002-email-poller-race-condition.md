# Improvement Plan: Fix Email Poller Race Condition Deadlock

**Priority:** 🔴 **CRITICAL**
**Service:** `services/email-ingestion-worker/`
**Issue ID:** 5.5
**Status:** Blocks Email Ingestion Permanently
**Effort Estimate:** 30 minutes
**Risk if Not Fixed:** Any transient IMAP error causes email polling to stop until service restart. No invoices ingested for hours/days.

---

## Problem Statement

The email poller uses a flag (`isPolling`) to prevent concurrent polls. However, **if an exception occurs during polling, the flag is never reset**, causing a permanent deadlock.

**Current Code** (lines 117-122, `services/email-ingestion-worker/src/email-poller.ts`):

```typescript
async poll(): Promise<void> {
  if (this.isPolling) {
    logger.debug('Poll already in progress, skipping');
    return;
  }

  this.isPolling = true;  // Flag set
  const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

  try {
    await this.imapClient.openMailbox(...);   // ← If this throws, flag never resets!
    // ... rest of polling logic
  } catch (err) {
    logger.error({...}, 'Email polling failed');
    // Flag left as TRUE - next poll() call will skip!
  }
}
```

### Failure Scenario

1. **t=0s:** Scheduled poll starts, sets `isPolling = true`
2. **t=0.5s:** IMAP server times out or returns error
3. **t=0.5s:** Exception caught, logged, but `isPolling` still `true`
4. **t=60s:** Next scheduled poll runs, sees `isPolling = true`, skips execution
5. **t=120s, 180s, ...:** All subsequent polls skip - **email ingestion dead**
6. **Until restart:** No emails are ingested, no invoices processed

### Impact

- **Severity:** CRITICAL
- **Duration:** Hours or days (until service restart)
- **Business Impact:** Customer invoices stuck in mailboxes, not processing
- **Detection:** Alert on "Poll already in progress" debug logs (may not be noticed)

---

## Root Cause Analysis

The `isPolling` flag is a **boolean semaphore without guarantee of reset**. Exception handling doesn't account for the flag.

This is a classic **lock release failure** pattern - should use try/finally to guarantee cleanup.

---

## Solution Design

### Pattern: Use try/finally for Guaranteed Cleanup

Replace boolean flag management with structured exception handling:

```typescript
async poll(): Promise<void> {
  if (this.isPolling) {
    logger.debug('Poll already in progress, skipping');
    return;
  }

  this.isPolling = true;
  const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

  try {
    // All polling logic here
    await this.imapClient.openMailbox(...);
    // ...
  } catch (err) {
    logger.error({...}, 'Email polling failed', err);
    // Don't rethrow - let next scheduled poll attempt again
  } finally {
    this.isPolling = false;  // ← GUARANTEED to execute
  }
}
```

### Enhanced Solution: Add Timeout Protection

While fixing the flag issue, also add a timeout to prevent hangs (see Issue 5.8):

```typescript
async poll(): Promise<void> {
  if (this.isPolling) {
    logger.debug('Poll already in progress, skipping');
    return;
  }

  this.isPolling = true;
  const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

  try {
    // Wrap entire poll operation with 30-second timeout
    await Promise.race([
      this.executePoll(),  // Main polling logic
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Poll timeout after 30s')), 30000)
      ),
    ]);
  } catch (err) {
    logger.error({ error: err }, 'Email polling failed');
    // Emit metric for alerting
    emailPollingErrors.inc({ error_type: err.code || 'unknown' });
  } finally {
    this.isPolling = false;  // Guaranteed execution
    endTimer({ status: 'completed' });
  }
}

private async executePoll(): Promise<void> {
  const connectionStatus = this.imapClient.getConnectionStatus();

  if (!connectionStatus) {
    logger.debug('IMAP not connected, attempting reconnect');
    await this.imapClient.connect();
  }

  const box = await this.imapClient.openMailbox(this.config.mailbox);
  const uids = await this.imapClient.getNewEmails(
    this.lastProcessedUid,
    this.config.batchSize
  );

  if (uids.length === 0) {
    logger.debug('No new emails');
    return;
  }

  logger.info({ count: uids.length }, 'Processing email batch');

  // Process emails in controlled parallel batches
  const batchSize = 3;
  for (let i = 0; i < uids.length; i += batchSize) {
    const batch = uids.slice(i, i + batchSize);

    await Promise.all(
      batch.map(uid => this.processEmail(uid).catch(err => {
        logger.error({ uid, error: err }, 'Failed to process email');
      }))
    );

    this.lastProcessedUid = Math.max(...batch);
  }
}
```

---

## Implementation Steps

### Step 1: Add Timeout Configuration

**File:** `services/email-ingestion-worker/src/config.ts`

Add to configuration:
```typescript
export interface EmailPollerConfig {
  // ... existing fields
  pollTimeoutMs: number;  // Default: 30000 (30 seconds)
}

// In default config:
export const DEFAULT_CONFIG: EmailPollerConfig = {
  // ...
  pollTimeoutMs: parseInt(process.env.EMAIL_POLL_TIMEOUT_MS ?? '30000'),
};
```

### Step 2: Add Monitoring Metrics

**File:** `services/email-ingestion-worker/src/metrics.ts`

Add:
```typescript
export const emailPollingErrors = new Counter({
  name: 'email_polling_errors_total',
  help: 'Total email polling errors by type',
  labelNames: ['error_type'],
});

export const emailPollingTimeouts = new Counter({
  name: 'email_polling_timeouts_total',
  help: 'Email polling operations that timed out',
});
```

### Step 3: Refactor Email Poller

**File:** `services/email-ingestion-worker/src/email-poller.ts`

Replace the existing `poll()` method:

```typescript
async poll(): Promise<void> {
  if (this.isPolling) {
    logger.debug('Poll already in progress, skipping');
    return;
  }

  this.isPolling = true;
  const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

  try {
    // Execute poll with timeout protection
    await Promise.race([
      this.executePoll(),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('Email poll timeout')),
          this.config.pollTimeoutMs
        )
      ),
    ]);
  } catch (err) {
    // Classify error for monitoring
    if (err.message.includes('timeout')) {
      emailPollingTimeouts.inc();
      logger.warn(
        { timeoutMs: this.config.pollTimeoutMs },
        'Email poll timed out'
      );
    } else {
      emailPollingErrors.inc({ error_type: err.code || 'unknown' });
      logger.error(
        { error: err, code: err.code },
        'Email polling failed'
      );
    }
    // Continue - next scheduled poll will retry
  } finally {
    this.isPolling = false;  // GUARANTEE: Always reset flag
    endTimer({ status: 'completed' });
  }
}

private async executePoll(): Promise<void> {
  // Extract polling logic into separate method for clarity
  const connectionStatus = this.imapClient.getConnectionStatus();

  if (!connectionStatus) {
    logger.debug('IMAP not connected, reconnecting');
    await this.imapClient.connect();
  }

  const box = await this.imapClient.openMailbox(this.config.mailbox);

  const uids = await this.imapClient.getNewEmails(
    this.lastProcessedUid,
    this.config.batchSize
  );

  if (uids.length === 0) {
    logger.debug('No new emails');
    return;
  }

  logger.info({ emailCount: uids.length }, 'Processing email batch');

  // Process in controlled parallel batches (max 3 concurrent)
  const concurrencyLimit = 3;
  for (let i = 0; i < uids.length; i += concurrencyLimit) {
    const batch = uids.slice(i, i + concurrencyLimit);

    await Promise.allSettled(
      batch.map(uid => this.processEmail(uid))
    );

    this.lastProcessedUid = Math.max(...batch);
  }
}
```

### Step 4: Add Tests

**File:** `services/email-ingestion-worker/src/email-poller.spec.ts`

```typescript
describe('EmailPoller', () => {
  let poller: EmailPoller;
  let mockIMAPClient: jest.Mocked<IMAPClient>;

  beforeEach(() => {
    mockIMAPClient = {
      getConnectionStatus: jest.fn().mockReturnValue(true),
      openMailbox: jest.fn(),
      getNewEmails: jest.fn().mockResolvedValue([]),
      // ...
    } as any;

    poller = new EmailPoller(mockIMAPClient, DEFAULT_CONFIG);
  });

  it('should reset isPolling flag even when openMailbox throws', async () => {
    mockIMAPClient.openMailbox.mockRejectedValueOnce(
      new Error('IMAP connection failed')
    );

    expect(poller['isPolling']).toBe(false);

    // Call poll - should catch error internally
    await poller.poll();

    // Flag MUST be reset despite error
    expect(poller['isPolling']).toBe(false);
  });

  it('should skip poll if already polling', async () => {
    poller['isPolling'] = true;

    mockIMAPClient.openMailbox.mockResolvedValueOnce({} as any);

    await poller.poll();

    // Should not call IMAP if already polling
    expect(mockIMAPClient.openMailbox).not.toHaveBeenCalled();
  });

  it('should timeout poll after configured duration', async () => {
    const config = { ...DEFAULT_CONFIG, pollTimeoutMs: 100 };
    poller = new EmailPoller(mockIMAPClient, config);

    // Mock openMailbox to hang forever
    mockIMAPClient.openMailbox.mockImplementationOnce(
      () => new Promise(resolve => {
        // Never resolves
      })
    );

    const startTime = Date.now();
    await poller.poll();
    const duration = Date.now() - startTime;

    // Should timeout around 100ms, definitely under 5 seconds
    expect(duration).toBeLessThan(5000);
    expect(poller['isPolling']).toBe(false);
  });

  it('should emit error metrics on failure', async () => {
    mockIMAPClient.openMailbox.mockRejectedValueOnce(
      new Error('Connection refused')
    );

    const incSpy = jest.spyOn(emailPollingErrors, 'inc');

    await poller.poll();

    // Error metric should be incremented
    expect(incSpy).toHaveBeenCalledWith({ error_type: 'unknown' });
  });
});
```

---

## Validation Checklist

- [ ] `isPolling` flag always reset in finally block
- [ ] Timeout prevents hanging indefinitely (30-second default)
- [ ] Error metrics emitted for monitoring
- [ ] Next scheduled poll executes even after error
- [ ] Tests verify flag reset on error
- [ ] Tests verify timeout behavior
- [ ] Integration test: Poll succeeds after temporary IMAP outage
- [ ] No changes to message format or external API

---

## Acceptance Criteria

✅ **Critical Fix:** isPolling flag guaranteed reset on any exception
✅ **Timeout Protection:** Poll operations timeout after 30 seconds (configurable)
✅ **Observability:** Error and timeout metrics available for alerting
✅ **Tests:** All edge cases covered (exception during poll, concurrent poll attempts, timeout)
✅ **Backward Compatible:** No API changes, existing callers unaffected

---

## Deployment Notes

**Rollout Strategy:**
1. Merge to main after code review
2. Deploy to staging first (no risk - only affects email ingestion)
3. Monitor `email_polling_errors_total` and `email_polling_timeouts_total` metrics
4. Verify in production that email batches are processed consistently
5. Can deploy immediately to production (no data migration needed)

**Alert Configuration (Add to Prometheus Alertmanager):**
```yaml
alert: EmailPollingDeadlock
expr: rate(email_polling_errors_total[5m]) > 0 AND on(job) rate(up[5m]) == 1
for: 5m
labels:
  severity: critical
annotations:
  summary: "Email polling errors detected (job={{ $labels.job }})"
  description: "Email ingestion may be deadlocked. Check email-ingestion-worker logs."
```

---

## Related Issues

- Issue 5.8: No timeout on polling (fixed in Step 3)
- Issue 5.9: IMAP event listeners not re-registered on reconnect (separate improvement)
- Issue 5.6: Sequential email processing prevents parallelization (enhanced in Step 3)

---

**Owner:** Codex
**Due Date:** Immediate (before next production deployment)
**Blocked By:** None
**Blocks:** Email ingestion pipeline stabilization

