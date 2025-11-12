/**
 * Unit Tests - Backoff Calculation
 *
 * Tests exponential backoff with jitter to ensure:
 * - Correct exponential growth
 * - Max delay cap is enforced
 * - Jitter prevents thundering herd
 */

import { calculateNextRetryDelay, calculateNextRetryTime, getRetrySchedule } from '../../src/backoff';

describe('Backoff Calculation', () => {
  describe('calculateNextRetryDelay', () => {
    beforeEach(() => {
      // Set deterministic environment for testing
      process.env.BASE_DELAY_MS = '2000';
      process.env.MAX_DELAY_MS = '60000';
    });

    it('should calculate correct delay for retry attempt 0', () => {
      const delay = calculateNextRetryDelay(0);

      // Base delay (2000ms) + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(2000);
      expect(delay).toBeLessThan(3000);
    });

    it('should calculate correct delay for retry attempt 1', () => {
      const delay = calculateNextRetryDelay(1);

      // 2000 * 2^1 = 4000ms + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(4000);
      expect(delay).toBeLessThan(5000);
    });

    it('should calculate correct delay for retry attempt 2', () => {
      const delay = calculateNextRetryDelay(2);

      // 2000 * 2^2 = 8000ms + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(8000);
      expect(delay).toBeLessThan(9000);
    });

    it('should calculate correct delay for retry attempt 3', () => {
      const delay = calculateNextRetryDelay(3);

      // 2000 * 2^3 = 16000ms + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(16000);
      expect(delay).toBeLessThan(17000);
    });

    it('should cap delay at MAX_DELAY_MS', () => {
      const delay = calculateNextRetryDelay(10); // Would be 2000 * 2^10 = 2,048,000ms

      // Should be capped at 60000ms + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(60000);
      expect(delay).toBeLessThan(61000);
    });

    it('should add jitter to prevent thundering herd', () => {
      const delays = [];

      // Calculate delay 100 times for same retry count
      for (let i = 0; i < 100; i++) {
        delays.push(calculateNextRetryDelay(1));
      }

      // All delays should be within expected range
      delays.forEach(delay => {
        expect(delay).toBeGreaterThanOrEqual(4000);
        expect(delay).toBeLessThan(5000);
      });

      // Delays should vary (jitter is random)
      const uniqueDelays = new Set(delays);
      expect(uniqueDelays.size).toBeGreaterThan(50); // At least 50% unique values
    });

    it('should use BASE_DELAY_MS from environment', () => {
      // Note: Environment variables are read at module import time,
      // so this test verifies the current configuration
      const delay = calculateNextRetryDelay(0);

      // Default base (2000ms) + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(2000);
      expect(delay).toBeLessThan(3000);
    });

    it('should use MAX_DELAY_MS from environment', () => {
      // Note: Environment variables are read at module import time
      const delay = calculateNextRetryDelay(10);

      // Should be capped at default 60000ms + jitter (0-1000ms)
      expect(delay).toBeGreaterThanOrEqual(60000);
      expect(delay).toBeLessThan(61000);
    });

    it('should handle retry count 0', () => {
      const delay = calculateNextRetryDelay(0);
      expect(delay).toBeGreaterThanOrEqual(2000);
      expect(delay).toBeLessThan(3000);
    });

    it('should handle large retry counts without overflow', () => {
      const delay = calculateNextRetryDelay(100);

      // Should be capped, not overflow
      expect(delay).toBeGreaterThanOrEqual(60000);
      expect(delay).toBeLessThan(61000);
      expect(delay).toBeLessThan(Infinity);
    });
  });

  describe('calculateNextRetryTime', () => {
    it('should return a future Date object', () => {
      const now = Date.now();
      const nextRetryTime = calculateNextRetryTime(1);

      expect(nextRetryTime).toBeInstanceOf(Date);
      expect(nextRetryTime.getTime()).toBeGreaterThan(now);
    });

    it('should return date approximately BASE_DELAY + jitter in future for retry 0', () => {
      const now = Date.now();
      const nextRetryTime = calculateNextRetryTime(0);

      const delta = nextRetryTime.getTime() - now;

      // Should be ~2000-3000ms in future
      expect(delta).toBeGreaterThanOrEqual(1900); // Small tolerance for execution time
      expect(delta).toBeLessThan(3100);
    });

    it('should return date approximately 4s + jitter in future for retry 1', () => {
      const now = Date.now();
      const nextRetryTime = calculateNextRetryTime(1);

      const delta = nextRetryTime.getTime() - now;

      // Should be ~4000-5000ms in future
      expect(delta).toBeGreaterThanOrEqual(3900);
      expect(delta).toBeLessThan(5100);
    });
  });

  describe('getRetrySchedule', () => {
    it('should return array of delays for all retry attempts', () => {
      const schedule = getRetrySchedule(3);

      expect(schedule).toHaveLength(3);
      expect(schedule[0]).toBeGreaterThanOrEqual(2000); // Retry 0
      expect(schedule[1]).toBeGreaterThanOrEqual(4000); // Retry 1
      expect(schedule[2]).toBeGreaterThanOrEqual(8000); // Retry 2
    });

    it('should return empty array for maxRetries 0', () => {
      const schedule = getRetrySchedule(0);
      expect(schedule).toHaveLength(0);
    });

    it('should return schedule with increasing delays', () => {
      const schedule = getRetrySchedule(5);

      // Verify general exponential growth pattern
      // Due to jitter, we check that later delays are significantly larger
      expect(schedule[4]).toBeGreaterThan(schedule[0] * 5); // Last should be much larger than first
      expect(schedule[2]).toBeGreaterThan(schedule[0] * 2); // Middle should be larger
    });

    it('should cap delays at MAX_DELAY_MS in schedule', () => {
      const schedule = getRetrySchedule(15);

      // Later retries should all be capped
      const lastFewDelays = schedule.slice(-5);
      lastFewDelays.forEach(delay => {
        expect(delay).toBeGreaterThanOrEqual(60000);
        expect(delay).toBeLessThan(61000);
      });
    });
  });

  describe('Exponential Growth Verification', () => {
    it('should follow exponential pattern: delay_n ≈ BASE * 2^n', () => {
      const baseDelay = 2000;

      for (let retryCount = 0; retryCount < 5; retryCount++) {
        const delay = calculateNextRetryDelay(retryCount);
        const expectedMin = baseDelay * Math.pow(2, retryCount);
        const expectedMax = expectedMin + 1000; // jitter

        expect(delay).toBeGreaterThanOrEqual(expectedMin);
        expect(delay).toBeLessThan(expectedMax);
      }
    });

    it('should demonstrate exponential growth over multiple retries', () => {
      const delays = [];

      for (let i = 0; i < 6; i++) {
        delays.push(calculateNextRetryDelay(i));
      }

      // Each delay should roughly double (accounting for jitter)
      expect(delays[1]).toBeGreaterThan(delays[0] * 1.5);
      expect(delays[2]).toBeGreaterThan(delays[1] * 1.5);
      expect(delays[3]).toBeGreaterThan(delays[2] * 1.5);
      expect(delays[4]).toBeGreaterThan(delays[3] * 1.5);
      expect(delays[5]).toBeGreaterThan(delays[4] * 1.5);
    });
  });

  describe('Thundering Herd Prevention', () => {
    it('should produce different delays with jitter', () => {
      const delays = new Set();

      // Generate 50 delays for same retry count
      for (let i = 0; i < 50; i++) {
        delays.add(calculateNextRetryDelay(2));
      }

      // With random jitter, most should be unique
      expect(delays.size).toBeGreaterThan(30); // At least 60% unique
    });

    it('should distribute delays evenly within jitter range', () => {
      const delays = [];

      for (let i = 0; i < 1000; i++) {
        delays.push(calculateNextRetryDelay(0));
      }

      // Calculate average delay
      const avgDelay = delays.reduce((sum, d) => sum + d, 0) / delays.length;

      // Average should be around midpoint: 2000 + 500 (half of max jitter)
      expect(avgDelay).toBeGreaterThan(2400); // 2500 - 100 tolerance
      expect(avgDelay).toBeLessThan(2600); // 2500 + 100 tolerance
    });
  });
});
