# Improvement Plan: Fix IMAP Event Listener Memory Leak on Reconnection

**Priority:** 🔴 **CRITICAL**
**Service:** `services/email-ingestion-worker/`
**Issue ID:** 5.9
**Status:** Breaks Reconnection Logic
**Effort Estimate:** 1-2 hours
**Risk if Not Fixed:** IMAP reconnection fails silently - client never marked as ready after network outage. Email polling stops permanently until restart.

---

## Problem Statement

When IMAP connection drops and reconnects, the event listeners from the **old connection object** are never re-attached to the **new connection object**. The `ready` event never fires on the new connection.

**Current Code** (lines 100-134, `services/email-ingestion-worker/src/imap-client.ts`):

```typescript
class IMAPClient {
  private connection: Imap;

  async connect(): Promise<void> {
    this.connection = new Imap(this.config);  // Create NEW connection

    // Register event listeners (only on THIS instance)
    this.connection.once('ready', () => {
      logger.debug('IMAP connected and ready');
      this.isConnected = true;
      // ... open mailbox, etc
    });

    this.connection.once('error', (err) => {
      logger.error({...}, 'IMAP error', err);
      this.isConnected = false;
    });

    this.connection.once('end', () => {
      logger.info('IMAP connection ended');
      this.isConnected = false;
    });

    this.connection.openBox(this.config.mailbox, ...);
  }

  async reconnect(): Promise<void> {
    logger.info('Attempting IMAP reconnection');
    // If this calls connect() again with NEW Imap instance,
    // listeners are registered on the new instance ✓ (works)
    //
    // BUT if there's leftover reference to old this.connection,
    // or if 'end' event fires on old connection,
    // the 'ready' listener is on the WRONG object
    this.connection = new Imap(this.config);
    // Event listeners never re-registered!
  }
}
```

### Failure Scenario

1. **t=0s:** `connect()` called, creates Imap instance #1, registers listeners on #1
2. **t=30s:** Network glitch - 'end' event fires on instance #1, sets `isConnected = false`
3. **t=31s:** Email poller calls `reconnect()`
4. **t=31s:** `reconnect()` creates **new Imap instance #2** - `this.connection = new Imap(...)`
5. **t=31s:** ❌ **Event listeners still on instance #1**, not re-registered on instance #2
6. **t=32s:** Instance #2 connects and fires 'ready' event
7. **t=32s:** ❌ **'ready' listener never fires** (it's on instance #1)
8. **t=32s:** `isConnected` remains `false`
9. **t=60s:** Next poll attempt sees `isConnected = false`, tries to reconnect again
10. **Until restart:** Infinite reconnection loop, email polling stuck

### Impact

- **Severity:** CRITICAL
- **Root Cause:** Event listeners on stale connection objects
- **Duration:** Until service restart
- **Business Impact:** Email ingestion dead after any network outage
- **Hard to Debug:** No error thrown - just silently never connects

---

## Root Cause Analysis

The IMAP client uses `once()` (fires once) instead of `on()` (persistent listener). When creating a new Imap instance, the code forgets to re-register listeners.

### Why This Pattern Fails

```typescript
this.connection = new Imap(...);  // Old listeners not on this new object
this.connection.once('ready', ...);  // Only fires if not already fired

// If .once() fires during old connection setup, it won't fire again on new connection
```

The Node.js EventEmitter pattern requires each instance to have its own listeners.

---

## Solution Design

### Approach 1: Always Unregister Old Listeners (Recommended)

Before creating new connection, remove all listeners from old connection:

```typescript
private removeAllListeners(): void {
  if (this.connection) {
    // Remove all listeners from old connection
    this.connection.removeAllListeners('ready');
    this.connection.removeAllListeners('error');
    this.connection.removeAllListeners('end');
    this.connection.removeAllListeners('mail');
    this.connection.removeAllListeners('update');
  }
}

async connect(): Promise<void> {
  this.removeAllListeners();  // Clean up old listeners

  this.connection = new Imap(this.config);

  // Register listeners on NEW connection
  this.connection.once('ready', () => {
    logger.debug('IMAP connected and ready');
    this.isConnected = true;
    this.setupMailbox();
  });

  this.connection.on('error', (err) => {
    logger.error({...}, 'IMAP error', err);
    this.isConnected = false;
    this.handleConnectionError(err);
  });

  this.connection.once('end', () => {
    logger.info('IMAP connection ended');
    this.isConnected = false;
  });

  this.connection.openBox(this.config.mailbox, ...);
}

async reconnect(): Promise<void> {
  logger.info('Attempting IMAP reconnection');
  await this.connect();  // Calls connect() which cleans up old listeners
}
```

### Approach 2: Wrapper with Guaranteed Listener Registration

Use a method wrapper that ensures listeners are always properly registered:

```typescript
private registerEventListeners(): void {
  if (!this.connection) {
    throw new Error('Connection not initialized');
  }

  const connection = this.connection;

  // Defensive: Remove any existing listeners first
  connection.removeAllListeners('ready');
  connection.removeAllListeners('error');
  connection.removeAllListeners('end');

  // Register fresh listeners on current connection
  connection.once('ready', () => {
    logger.debug('IMAP ready', {
      connectionId: (connection as any).id,
      timestamp: new Date().toISOString(),
    });
    this.isConnected = true;
    this.setupMailbox().catch(err => {
      logger.error({...}, 'Failed to setup mailbox', err);
    });
  });

  connection.on('error', (err: Error) => {
    logger.error(
      { error: err, errorCode: (err as any).code },
      'IMAP error'
    );
    this.isConnected = false;
    // Emit metric for monitoring
    imapConnectionErrors.inc({ error: (err as any).code || 'unknown' });
  });

  connection.once('end', () => {
    logger.info('IMAP connection ended');
    this.isConnected = false;
    // Trigger automatic reconnection attempt
    this.scheduleReconnection();
  });

  // Optional: Monitor email arrivals
  connection.on('mail', (numNewEmails: number) => {
    logger.debug('Mail arrived', { count: numNewEmails });
    imapMailArrivals.inc({ count: numNewEmails });
  });
}

async connect(): Promise<void> {
  logger.info('Initiating IMAP connection');

  // Create new connection instance
  this.connection = new Imap(this.config);

  // Immediately register all event listeners on new instance
  this.registerEventListeners();

  try {
    await new Promise<void>((resolve, reject) => {
      // Timeout after 10 seconds if 'ready' never fires
      const timeout = setTimeout(
        () => reject(new Error('IMAP connection timeout')),
        10000
      );

      const originalReady = this.connection?.listeners('ready')[0];
      if (originalReady) {
        this.connection?.once('ready', () => {
          clearTimeout(timeout);
          resolve();
          // Re-attach original listener
          originalReady.call(this.connection);
        });
      } else {
        clearTimeout(timeout);
        reject(new Error('Failed to register ready listener'));
      }
    });
  } catch (err) {
    logger.error({...}, 'Failed to connect', err);
    this.isConnected = false;
    throw err;
  }
}

private scheduleReconnection(): void {
  if (!this.reconnectionScheduled) {
    this.reconnectionScheduled = true;
    setTimeout(() => {
      logger.info('Attempting automatic reconnection');
      this.connect().catch(err => {
        logger.error({...}, 'Reconnection failed', err);
        this.scheduleReconnection();
      });
      this.reconnectionScheduled = false;
    }, 5000);
  }
}
```

---

## Implementation Steps

### Step 1: Add Connection ID Tracking (for debugging)

**File:** `services/email-ingestion-worker/src/imap-client.ts`

Add:
```typescript
private connectionId: string = '';
private reconnectionScheduled: boolean = false;

private generateConnectionId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}
```

### Step 2: Implement Listener Cleanup & Re-registration

Replace the `connect()` and `reconnect()` methods:

```typescript
async connect(): Promise<void> {
  logger.info('Initiating IMAP connection', {
    previousConnectionId: this.connectionId,
  });

  // Generate unique ID for this connection attempt
  this.connectionId = this.generateConnectionId();

  // Create new connection instance
  this.connection = new Imap(this.config);

  // Immediately register all event listeners
  this.registerEventListeners();

  try {
    // Wait for 'ready' event with timeout
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('IMAP connection timeout after 10s'));
      }, 10000);

      const handleReady = () => {
        clearTimeout(timeout);
        this.connection?.removeListener('ready', handleReady);
        resolve();
      };

      this.connection?.once('ready', handleReady);
    });

    this.isConnected = true;
    logger.info('IMAP connection established', {
      connectionId: this.connectionId,
    });
  } catch (err) {
    logger.error(
      { error: err, connectionId: this.connectionId },
      'Failed to connect'
    );
    this.isConnected = false;
    this.connection?.end();  // Close failed connection
    throw err;
  }
}

async reconnect(): Promise<void> {
  logger.info('Attempting IMAP reconnection', {
    currentConnectionId: this.connectionId,
  });

  // Don't attempt reconnection if already trying
  if (this.reconnectionScheduled) {
    logger.debug('Reconnection already scheduled');
    return;
  }

  try {
    await this.connect();
    this.reconnectionScheduled = false;
  } catch (err) {
    logger.error({...}, 'Reconnection failed, will retry');
    // Schedule retry
    this.scheduleReconnection();
  }
}

private registerEventListeners(): void {
  if (!this.connection) {
    throw new Error('Connection not initialized');
  }

  const connectionId = this.connectionId;

  // Remove any stale listeners first
  this.connection.removeAllListeners('ready');
  this.connection.removeAllListeners('error');
  this.connection.removeAllListeners('end');
  this.connection.removeAllListeners('mail');

  // Ready event (fires once when connected)
  this.connection.once('ready', () => {
    logger.debug('IMAP ready', { connectionId });
    this.isConnected = true;
    this.setupMailbox().catch(err => {
      logger.error({ error: err, connectionId }, 'Failed to setup mailbox');
    });
  });

  // Error event (fires on errors)
  this.connection.on('error', (err: Error) => {
    logger.error(
      {
        error: err,
        code: (err as any).code,
        connectionId,
      },
      'IMAP error'
    );
    this.isConnected = false;
    imapConnectionErrors.inc({
      error_type: (err as any).code || 'unknown',
    });
  });

  // End event (fires when connection closes)
  this.connection.once('end', () => {
    logger.info('IMAP connection ended', { connectionId });
    this.isConnected = false;
    // Trigger automatic reconnection
    this.scheduleReconnection();
  });

  // Mail arrival event
  this.connection.on('mail', (numNewEmails: number) => {
    if (numNewEmails > 0) {
      logger.debug('Mail arrived', { count: numNewEmails, connectionId });
      imapMailArrivals.inc();
    }
  });
}

private scheduleReconnection(): void {
  if (this.reconnectionScheduled) {
    logger.debug('Reconnection already scheduled');
    return;
  }

  this.reconnectionScheduled = true;

  const delay = 5000;
  logger.info('Scheduling IMAP reconnection', { delayMs: delay });

  setTimeout(() => {
    this.reconnect().catch(err => {
      logger.error({...}, 'Reconnection attempt failed');
      // Will reschedule itself
    });
  }, delay);
}

private async setupMailbox(): Promise<void> {
  if (!this.connection) {
    throw new Error('Connection not available');
  }

  const mailbox = this.config.mailbox || 'INBOX';

  try {
    const box = await new Promise<any>((resolve, reject) => {
      this.connection?.openBox(mailbox, false, (err, box) => {
        if (err) reject(err);
        else resolve(box);
      });
    });

    logger.info('Mailbox opened', {
      mailbox,
      total: box.messages.total,
    });
  } catch (err) {
    logger.error({ error: err }, 'Failed to open mailbox');
    throw err;
  }
}
```

### Step 3: Add Metrics

**File:** `services/email-ingestion-worker/src/metrics.ts`

Add:
```typescript
export const imapConnectionErrors = new Counter({
  name: 'imap_connection_errors_total',
  help: 'IMAP connection errors by error type',
  labelNames: ['error_type'],
});

export const imapMailArrivals = new Counter({
  name: 'imap_mail_arrivals_total',
  help: 'Total emails received via IMAP',
});

export const imapReconnectionAttempts = new Counter({
  name: 'imap_reconnection_attempts_total',
  help: 'IMAP reconnection attempt count',
});
```

### Step 4: Add Tests

**File:** `services/email-ingestion-worker/src/imap-client.spec.ts`

```typescript
describe('IMAPClient', () => {
  let client: IMAPClient;
  let mockImap: jest.Mocked<Imap>;

  beforeEach(() => {
    mockImap = {
      openBox: jest.fn((mailbox, readOnly, cb) => cb(null, {})),
      end: jest.fn(),
      on: jest.fn(),
      once: jest.fn(),
      removeAllListeners: jest.fn().mockReturnThis(),
      removeListener: jest.fn().mockReturnThis(),
      listeners: jest.fn().mockReturnValue([]),
    } as any;

    client = new IMAPClient(DEFAULT_CONFIG);
    client['connection'] = mockImap;
  });

  it('should remove old listeners before registering new ones', () => {
    client['registerEventListeners']();

    expect(mockImap.removeAllListeners).toHaveBeenCalledWith('ready');
    expect(mockImap.removeAllListeners).toHaveBeenCalledWith('error');
    expect(mockImap.removeAllListeners).toHaveBeenCalledWith('end');
  });

  it('should register ready listener on new connection', () => {
    client['registerEventListeners']();

    expect(mockImap.once).toHaveBeenCalledWith('ready', expect.any(Function));
  });

  it('should schedule reconnection on connection end', () => {
    client['registerEventListeners']();

    // Get the 'end' listener
    const endListener = mockImap.once.mock.calls.find(
      call => call[0] === 'end'
    )?.[1] as Function;

    expect(endListener).toBeDefined();

    // Fire 'end' event
    endListener();

    // Should have scheduled reconnection
    expect(client['reconnectionScheduled']).toBe(true);
  });

  it('should handle connection timeout', async () => {
    mockImap.once.mockImplementation((event, callback) => {
      if (event === 'ready') {
        // Simulate timeout - never call ready callback
        setTimeout(() => {}, 20000);
      }
      return mockImap;
    });

    const connectPromise = client.connect();

    // Should reject after 10 seconds
    await expect(
      Promise.race([
        connectPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Test timeout')), 15000)
        ),
      ])
    ).rejects.toThrow('timeout');
  });

  it('should not schedule multiple reconnections', () => {
    client['reconnectionScheduled'] = true;

    client['scheduleReconnection']();

    // Should not schedule again
    expect(client['reconnectionScheduled']).toBe(true);
  });

  it('should use unique connection IDs for debugging', async () => {
    const id1 = client['generateConnectionId']();
    const id2 = client['generateConnectionId']();

    expect(id1).not.toBe(id2);
    expect(id1).toMatch(/^\d+-[a-z0-9]{9}$/);
  });
});
```

---

## Validation Checklist

- [ ] Event listeners removed from old connection before creating new one
- [ ] Event listeners registered on NEW connection object every time
- [ ] Connection ID unique per connection (for debugging)
- [ ] Timeout prevents hanging if 'ready' event never fires
- [ ] Automatic reconnection scheduled on connection end
- [ ] Metrics track connection errors and mail arrivals
- [ ] Tests verify listener re-registration after reconnection
- [ ] No changes to external API
- [ ] Integration test: Reconnection works after network outage

---

## Acceptance Criteria

✅ **Critical Fix:** Event listeners guaranteed on current connection object
✅ **Robustness:** Timeout prevents indefinite hanging (10 seconds)
✅ **Automatic Recovery:** Connection end triggers reconnection attempt
✅ **Debugging:** Connection IDs in logs help diagnose connection issues
✅ **Tests:** Listener re-registration verified in unit tests
✅ **Observability:** Metrics for connection errors and mail arrivals

---

## Deployment Notes

**Rollout Strategy:**
1. Merge to main after code review
2. Deploy to staging
3. Monitor `imap_connection_errors_total` and reconnection behavior
4. Verify that connection drops and recovery works smoothly
5. Deploy to production
6. Alert team if `imap_reconnection_attempts_total` spikes (indicates recurring connection issues)

---

## Related Issues

- Issue 5.5: Race condition deadlock (fixed in separate improvement)
- Issue 5.8: No timeout on polling (we add timeout here for connection establishment)
- Issue 5.6: Sequential email processing prevents parallelization

---

**Owner:** Codex
**Due Date:** Immediate (blocks email ingestion stability)
**Blocked By:** None
**Blocks:** Email ingestion pipeline reliability

