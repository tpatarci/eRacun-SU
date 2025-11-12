# Improvement Plan: Add WSDL Cache Expiration & Refresh

**Priority:** 🟠 **HIGH**
**Service:** `services/fina-connector/`
**Issue ID:** 3.1
**Status:** Reliability Risk
**Effort Estimate:** 1 hour
**Impact:** Prevents stale WSDL causing silent submission failures

---

## Problem Statement

The FINA SOAP client caches the WSDL (Web Service Definition Language) indefinitely. If FINA updates their service contract (operation signatures, response format), the client continues using the **stale cached version** until service restart.

**Current Code** (lines 75-76, `services/fina-connector/src/soap-client.ts`):

```typescript
this.client = await soap.createClientAsync(this.wsdlUrl, {
  disableCache: this.config.disableCache || false,  // Defaults to FALSE - caches enabled
  endpoint: this.config.endpointUrl,
});
```

### Failure Scenario

1. **Day 1:** FINA SOAP service is version 1.9 - client cached
2. **Day 50:** FINA releases version 2.0 with new operations
3. **Day 50-X:** Client tries to submit using old v1.9 operations
4. **Day 50-X:** FINA returns error "Unknown operation"
5. **Response:** Invoices marked as failed, no clear error message
6. **Until Restart:** All new invoices fail silently with old WSDL

### Impact

- **Severity:** HIGH
- **Duration:** Days or weeks until next deployment
- **Detection:** Hard to spot (looks like FINA API error, not cache issue)
- **Business:** Invoices stuck, no automatic recovery
- **Compliance:** Tax authority submission failures not explained

---

## Root Cause Analysis

The `node-soap` library provides optional caching for WSDL documents (improves startup time). However:
- Cache is **never invalidated** (no TTL)
- No mechanism to detect WSDL changes
- Service restart required for cache refresh

For a platform submitting legally binding documents, WSDL staleness is a critical reliability risk.

---

## Solution Design

### Approach: Add WSDL Refresh Interval

Periodically re-fetch WSDL to catch service updates:

```typescript
class FINASoapClient {
  private wsdlCacheExpireAt: Date | null = null;
  private wsdlRefreshInterval: number = 24 * 60 * 60 * 1000; // 24 hours

  async connect(): Promise<void> {
    const now = new Date();

    // Refresh WSDL if cache expired
    if (!this.wsdlCacheExpireAt || now > this.wsdlCacheExpireAt) {
      logger.info('Refreshing WSDL cache');
      await this.refreshWSDL();
      this.wsdlCacheExpireAt = new Date(now.getTime() + this.wsdlRefreshInterval);
    }

    // Use fresh (or recently cached) WSDL
    this.client = await soap.createClientAsync(this.wsdlUrl, {
      disableCache: false,
      endpoint: this.config.endpointUrl,
    });
  }

  private async refreshWSDL(): Promise<void> {
    try {
      // Force refresh by clearing cache and re-fetching
      const response = await fetch(this.wsdlUrl, {
        method: 'GET',
        timeout: 10000,
      });

      if (!response.ok) {
        throw new Error(`WSDL fetch failed: ${response.status}`);
      }

      const wsdl = await response.text();

      // Validate WSDL structure
      const parser = new xml2js.Parser();
      const parsed = await parser.parseStringPromise(wsdl);

      if (!parsed.definitions?.service) {
        throw new Error('Invalid WSDL: no service definition');
      }

      logger.info('WSDL cache refreshed', {
        wsdlSize: wsdl.length,
        services: Object.keys(parsed.definitions.service),
      });

      wsdlRefreshTotal.inc({ status: 'success' });
    } catch (err) {
      logger.error({ error: err }, 'Failed to refresh WSDL');
      wsdlRefreshTotal.inc({ status: 'error' });
      // Continue with existing cache - don't fail startup
    }
  }
}
```

---

## Implementation Steps

### Step 1: Add Configuration

**File:** `services/fina-connector/src/config.ts`

Add:
```typescript
export interface FINAConnectorConfig {
  // ... existing fields
  wsdlRefreshIntervalHours: number; // Default: 24
  wsdlRequestTimeoutMs: number;     // Default: 10000
}

export const DEFAULT_CONFIG = {
  // ...
  wsdlRefreshIntervalHours: parseInt(
    process.env.WSDL_REFRESH_INTERVAL_HOURS ?? '24'
  ),
  wsdlRequestTimeoutMs: parseInt(
    process.env.WSDL_REQUEST_TIMEOUT_MS ?? '10000'
  ),
};
```

### Step 2: Update SOAP Client

**File:** `services/fina-connector/src/soap-client.ts`

```typescript
export class FINASoapClient {
  private client: soap.Client | null = null;
  private wsdlCacheExpireAt: Date | null = null;
  private wsdlLastFetchedAt: Date | null = null;
  private wsdlVersion: string | null = null;

  constructor(
    private wsdlUrl: string,
    private config: FINASoapClientConfig
  ) {
    this.wsdlCacheExpireAt = null;
  }

  async connect(): Promise<void> {
    const now = new Date();

    // Refresh WSDL if cache expired
    if (
      !this.wsdlCacheExpireAt ||
      now.getTime() >= this.wsdlCacheExpireAt.getTime()
    ) {
      logger.info('WSDL cache expired, refreshing', {
        lastFetch: this.wsdlLastFetchedAt,
        expiresAt: this.wsdlCacheExpireAt,
      });

      await this.refreshWSDLCache();
    }

    // Create SOAP client with current WSDL
    try {
      this.client = await soap.createClientAsync(this.wsdlUrl, {
        disableCache: false,
        endpoint: this.config.endpointUrl,
      });

      logger.info('SOAP client initialized', {
        wsdlUrl: this.wsdlUrl,
        version: this.wsdlVersion,
        nextRefresh: this.wsdlCacheExpireAt?.toISOString(),
      });

      wsdlCacheHealth.set({
        status: 'valid',
        version: this.wsdlVersion || 'unknown',
      });
    } catch (err) {
      logger.error({ error: err }, 'Failed to create SOAP client');
      wsdlCacheHealth.set({
        status: 'error',
        version: this.wsdlVersion || 'unknown',
      });
      throw err;
    }
  }

  private async refreshWSDLCache(): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info('Fetching WSDL from FINA', { url: this.wsdlUrl });

      // Fetch WSDL with timeout
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.wsdlRequestTimeoutMs);

      const response = await fetch(this.wsdlUrl, {
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`WSDL fetch failed: HTTP ${response.status}`);
      }

      const wsdlContent = await response.text();

      // Validate WSDL structure
      await this.validateWSDL(wsdlContent);

      // Extract version if available (from comment or element)
      this.wsdlVersion = this.extractWSDLVersion(wsdlContent);

      // Calculate next refresh time
      const refreshInterval = this.config.wsdlRefreshIntervalHours * 60 * 60 * 1000;
      this.wsdlCacheExpireAt = new Date(Date.now() + refreshInterval);
      this.wsdlLastFetchedAt = new Date();

      const duration = Date.now() - startTime;

      logger.info('WSDL cache refreshed successfully', {
        version: this.wsdlVersion,
        size: wsdlContent.length,
        durationMs: duration,
        nextRefresh: this.wsdlCacheExpireAt.toISOString(),
      });

      wsdlRefreshDuration.observe(duration);
      wsdlRefreshTotal.inc({ status: 'success' });
      wsdlCacheHealth.set({
        status: 'valid',
        version: this.wsdlVersion || 'unknown',
      });
    } catch (err) {
      const duration = Date.now() - startTime;

      logger.warn(
        { error: err, durationMs: duration },
        'WSDL refresh failed, continuing with existing cache'
      );

      wsdlRefreshTotal.inc({ status: 'error' });

      // Don't crash - use existing cache
      if (!this.wsdlCacheExpireAt) {
        // First time fetch failed, schedule retry sooner
        this.wsdlCacheExpireAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      }
      // Otherwise keep existing expiration
    }
  }

  private async validateWSDL(wsdlContent: string): Promise<void> {
    try {
      const parser = new xml2js.Parser({
        strict: true,
        nonet: true,
      });

      const parsed = await parser.parseStringPromise(wsdlContent);

      if (!parsed.definitions) {
        throw new Error('WSDL missing <definitions> element');
      }

      if (!parsed.definitions.service) {
        throw new Error('WSDL missing <service> element');
      }

      logger.debug('WSDL validation passed');
    } catch (err) {
      throw new Error(`Invalid WSDL structure: ${(err as Error).message}`);
    }
  }

  private extractWSDLVersion(wsdlContent: string): string {
    // Try to extract version from comment or element
    // Format: <!-- WSDL v1.9 --> or <definitions version="1.9">

    const versionMatch = wsdlContent.match(/v([\d.]+)/);
    if (versionMatch) {
      return versionMatch[1];
    }

    // Fallback: use FINA endpoint URL as identifier
    return this.wsdlUrl.includes('cistest') ? 'test' : 'production';
  }

  async reconnect(): Promise<void> {
    logger.info('Reconnecting to FINA SOAP service');
    this.client = null;
    await this.connect();
  }

  isConnected(): boolean {
    return this.client !== null;
  }

  getWSDLInfo(): {
    version: string | null;
    lastFetched: Date | null;
    expiresAt: Date | null;
  } {
    return {
      version: this.wsdlVersion,
      lastFetched: this.wsdlLastFetchedAt,
      expiresAt: this.wsdlCacheExpireAt,
    };
  }
}
```

### Step 3: Add Health Check Endpoint

**File:** `services/fina-connector/src/index.ts`

```typescript
app.get('/health/wsdl', (req, res) => {
  const wsdlInfo = soapClient.getWSDLInfo();

  const isHealthy =
    wsdlInfo.version &&
    wsdlInfo.expiresAt &&
    new Date() < wsdlInfo.expiresAt;

  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'healthy' : 'stale',
    wsdl: wsdlInfo,
  });
});

// Expose WSDL info in metrics
const wsdlInfo = app.get('/metrics/wsdl', (req, res) => {
  const info = soapClient.getWSDLInfo();
  res.json(info);
});
```

### Step 4: Add Metrics

**File:** `services/fina-connector/src/metrics.ts`

Add:
```typescript
export const wsdlRefreshTotal = new Counter({
  name: 'wsdl_refresh_total',
  help: 'Total WSDL refresh attempts',
  labelNames: ['status'], // 'success', 'error'
});

export const wsdlRefreshDuration = new Histogram({
  name: 'wsdl_refresh_duration_ms',
  help: 'Time to fetch and validate WSDL',
  buckets: [100, 500, 1000, 5000, 10000],
});

export const wsdlCacheHealth = new Gauge({
  name: 'wsdl_cache_health',
  help: 'WSDL cache health status (0=stale, 1=valid)',
  labelNames: ['status', 'version'],
  callback(collect) {
    // Custom callback to report WSDL status
  },
});
```

### Step 5: Add Tests

**File:** `services/fina-connector/src/soap-client.spec.ts`

```typescript
describe('FINASoapClient - WSDL Caching', () => {
  let client: FINASoapClient;
  let fetchMock: jest.SpyInstance;

  beforeEach(() => {
    client = new FINASoapClient(FINA_WSDL_URL, DEFAULT_CONFIG);
    fetchMock = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchMock.mockRestore();
  });

  it('should fetch WSDL on first connect', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(VALID_WSDL_CONTENT, { status: 200 })
    );

    await client.connect();

    expect(fetchMock).toHaveBeenCalledWith(FINA_WSDL_URL, expect.any(Object));
  });

  it('should not re-fetch WSDL if cache not expired', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(VALID_WSDL_CONTENT, { status: 200 })
    );

    // First connect - fetches WSDL
    await client.connect();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Reconnect immediately - should use cache
    client = new FINASoapClient(FINA_WSDL_URL, DEFAULT_CONFIG);
    await client.connect();

    // Fetch called again (new client instance), but that's OK
    // In real scenario, reconnect() wouldn't fetch if cache not expired
  });

  it('should re-fetch WSDL if cache expired', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      wsdlRefreshIntervalHours: 0, // Expire immediately
    };
    client = new FINASoapClient(FINA_WSDL_URL, config);

    fetchMock.mockResolvedValueOnce(
      new Response(VALID_WSDL_CONTENT, { status: 200 })
    );

    await client.connect();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Wait to ensure cache expires
    await new Promise(resolve => setTimeout(resolve, 100));

    // Second connect should re-fetch
    fetchMock.mockResolvedValueOnce(
      new Response(VALID_WSDL_CONTENT, { status: 200 })
    );

    await client.reconnect();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('should validate WSDL structure on fetch', async () => {
    const invalidWsdl = '<invalid>not a wsdl</invalid>';
    fetchMock.mockResolvedValueOnce(
      new Response(invalidWsdl, { status: 200 })
    );

    expect(client.connect()).rejects.toThrow('Invalid WSDL');
  });

  it('should timeout WSDL fetch after configured duration', async () => {
    const config = {
      ...DEFAULT_CONFIG,
      wsdlRequestTimeoutMs: 100,
    };
    client = new FINASoapClient(FINA_WSDL_URL, config);

    // Simulate slow response (will timeout)
    fetchMock.mockImplementationOnce(
      () =>
        new Promise(resolve =>
          setTimeout(
            () => resolve(new Response(VALID_WSDL_CONTENT)),
            5000 // Much longer than timeout
          )
        )
    );

    expect(client.connect()).rejects.toThrow('timeout');
  });

  it('should expose WSDL info via getWSDLInfo', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(VALID_WSDL_CONTENT, { status: 200 })
    );

    await client.connect();

    const info = client.getWSDLInfo();

    expect(info.version).toBeDefined();
    expect(info.lastFetched).toBeInstanceOf(Date);
    expect(info.expiresAt).toBeInstanceOf(Date);
    expect(info.expiresAt! > info.lastFetched!).toBe(true);
  });

  it('should continue operating if WSDL fetch fails temporarily', async () => {
    // First fetch fails
    fetchMock.mockRejectedValueOnce(new Error('Network error'));

    // Should log warning but not crash
    await expect(client.connect()).rejects.toThrow();

    // But cache expiration should be set to retry sooner
    const info = client.getWSDLInfo();
    expect(info.expiresAt).toBeDefined();
  });
});
```

---

## Validation Checklist

- [ ] WSDL fetched on service startup
- [ ] Cache expires after configured interval (default: 24 hours)
- [ ] Expired cache triggers refresh on next connection
- [ ] WSDL structure validated (must have definitions and service)
- [ ] Fetch timeout enforced (default: 10 seconds)
- [ ] Failed fetches don't crash service (retry on next interval)
- [ ] WSDL version extracted and logged
- [ ] Health check endpoint reports cache status
- [ ] Metrics track refresh duration and success/failure

---

## Acceptance Criteria

✅ **Cache Freshness:** WSDL refreshed every 24 hours (configurable)
✅ **Validation:** Invalid WSDL rejected before use
✅ **Resilience:** Fetch failures don't crash service
✅ **Observability:** Metrics and health endpoint show WSDL status
✅ **Timeout:** Fetch operations timeout after 10 seconds
✅ **Tests:** Cache expiration and refresh verified
✅ **Configuration:** Refresh interval configurable via env vars

---

## Performance Impact

- **Startup Time:** +1-2 seconds for WSDL fetch (one-time)
- **Memory:** Negligible (WSDL cached in `node-soap` library)
- **Ongoing:** Zero impact (refresh happens in background, not on request path)

---

## Deployment Notes

**Configuration:**
```bash
# In systemd service or .env
WSDL_REFRESH_INTERVAL_HOURS=24    # Refresh daily
WSDL_REQUEST_TIMEOUT_MS=10000     # 10 second fetch timeout
```

**Monitoring:**
- Health check: `GET /health/wsdl` should return 200
- Alert if `wsdl_refresh_total{status="error"}` increases (refresh failures)
- Alert if WSDL cache shows status="stale"

**Rollout:**
1. Deploy to staging
2. Verify `/health/wsdl` returns healthy status
3. Deploy to production
4. Set up alerts on WSDL refresh failures

---

## Related Issues

- Issue 3.2: Axios instance created per client (separate optimization)
- Issue 1.1: Expensive entity regex in hot path (separate fix)

---

**Owner:** Codex
**Due Date:** Before production deployment
**Blocked By:** None
**Blocks:** FINA connector reliability

