/**
 * Rate Limiter
 *
 * Implements token bucket algorithm for SMS rate limiting.
 * Features:
 * - Token bucket algorithm (configurable rate)
 * - Priority bypass (CRITICAL notifications skip rate limit)
 * - Queue management for low-priority messages
 * - Thread-safe token management
 */

import { logger } from './observability';
import { NotificationPriority } from './repository';

// =============================================================================
// TYPES
// =============================================================================

export interface RateLimiterConfig {
  tokensPerMinute: number;  // How many tokens refilled per minute
  maxTokens: number;        // Maximum bucket capacity
  refillIntervalMs: number; // How often to refill tokens
}

export interface QueuedItem<T> {
  item: T;
  priority: NotificationPriority;
  queuedAt: Date;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const SMS_RATE_LIMIT_PER_MINUTE = parseInt(process.env.SMS_RATE_LIMIT_PER_MINUTE || '10', 10);
const EMAIL_RATE_LIMIT_PER_MINUTE = parseInt(process.env.EMAIL_RATE_LIMIT_PER_MINUTE || '100', 10);

// =============================================================================
// TOKEN BUCKET RATE LIMITER
// =============================================================================

export class TokenBucketRateLimiter {
  private tokens: number;
  private maxTokens: number;
  private tokensPerMinute: number;
  private refillIntervalMs: number;
  private lastRefillTime: number;
  private refillIntervalId: NodeJS.Timeout | null = null;
  private name: string;

  constructor(name: string, config: RateLimiterConfig) {
    this.name = name;
    this.maxTokens = config.maxTokens;
    this.tokensPerMinute = config.tokensPerMinute;
    this.refillIntervalMs = config.refillIntervalMs;
    this.tokens = this.maxTokens; // Start with full bucket
    this.lastRefillTime = Date.now();

    logger.info(
      {
        name: this.name,
        max_tokens: this.maxTokens,
        tokens_per_minute: this.tokensPerMinute,
        refill_interval_ms: this.refillIntervalMs,
      },
      'Rate limiter initialized'
    );
  }

  /**
   * Start automatic token refill
   */
  start(): void {
    if (this.refillIntervalId) {
      logger.warn({ name: this.name }, 'Rate limiter already started');
      return;
    }

    this.refillIntervalId = setInterval(() => {
      this.refillTokens();
    }, this.refillIntervalMs);

    logger.info({ name: this.name }, 'Rate limiter started');
  }

  /**
   * Stop automatic token refill
   */
  stop(): void {
    if (this.refillIntervalId) {
      clearInterval(this.refillIntervalId);
      this.refillIntervalId = null;
      logger.info({ name: this.name }, 'Rate limiter stopped');
    }
  }

  /**
   * Refill tokens based on elapsed time
   */
  private refillTokens(): void {
    const now = Date.now();
    const elapsedMs = now - this.lastRefillTime;
    const elapsedMinutes = elapsedMs / 60000;

    // Calculate tokens to add based on elapsed time
    const tokensToAdd = Math.floor(elapsedMinutes * this.tokensPerMinute);

    if (tokensToAdd > 0) {
      const oldTokens = this.tokens;
      this.tokens = Math.min(this.tokens + tokensToAdd, this.maxTokens);
      this.lastRefillTime = now;

      logger.debug(
        {
          name: this.name,
          old_tokens: oldTokens,
          new_tokens: this.tokens,
          added_tokens: tokensToAdd,
        },
        'Tokens refilled'
      );
    }
  }

  /**
   * Try to acquire a token (non-blocking)
   *
   * @param priority - Notification priority (CRITICAL bypasses rate limit)
   * @returns true if token acquired, false otherwise
   */
  tryAcquire(priority: NotificationPriority): boolean {
    // CRITICAL priority bypasses rate limit
    if (priority === NotificationPriority.CRITICAL) {
      logger.debug({ name: this.name, priority }, 'CRITICAL priority bypasses rate limit');
      return true;
    }

    // Refill tokens before checking availability
    this.refillTokens();

    if (this.tokens >= 1) {
      this.tokens -= 1;
      logger.debug(
        {
          name: this.name,
          remaining_tokens: this.tokens,
          priority,
        },
        'Token acquired'
      );
      return true;
    }

    logger.debug(
      {
        name: this.name,
        remaining_tokens: this.tokens,
        priority,
      },
      'Token acquisition failed - rate limit exceeded'
    );
    return false;
  }

  /**
   * Wait until a token is available (blocking with timeout)
   *
   * @param priority - Notification priority
   * @param timeoutMs - Maximum wait time in milliseconds
   * @returns true if token acquired, false if timeout
   */
  async waitForToken(priority: NotificationPriority, timeoutMs = 60000): Promise<boolean> {
    // CRITICAL priority bypasses rate limit
    if (priority === NotificationPriority.CRITICAL) {
      return true;
    }

    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      if (this.tryAcquire(priority)) {
        return true;
      }

      // Wait before retrying (exponential backoff)
      const elapsedMs = Date.now() - startTime;
      const waitMs = Math.min(1000, elapsedMs / 10);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    logger.warn(
      {
        name: this.name,
        priority,
        timeout_ms: timeoutMs,
      },
      'Token acquisition timeout'
    );
    return false;
  }

  /**
   * Get current token count
   */
  getAvailableTokens(): number {
    this.refillTokens();
    return this.tokens;
  }

  /**
   * Get rate limiter stats
   */
  getStats(): {
    name: string;
    available_tokens: number;
    max_tokens: number;
    tokens_per_minute: number;
  } {
    return {
      name: this.name,
      available_tokens: this.getAvailableTokens(),
      max_tokens: this.maxTokens,
      tokens_per_minute: this.tokensPerMinute,
    };
  }
}

// =============================================================================
// PRIORITY QUEUE (for low-priority batching)
// =============================================================================

export class PriorityQueue<T> {
  private queue: QueuedItem<T>[] = [];
  private name: string;

  constructor(name: string) {
    this.name = name;
  }

  /**
   * Add item to queue
   */
  enqueue(item: T, priority: NotificationPriority): void {
    this.queue.push({
      item,
      priority,
      queuedAt: new Date(),
    });

    // Sort by priority (CRITICAL > HIGH > NORMAL > LOW)
    this.queue.sort((a, b) => {
      const priorityOrder = {
        [NotificationPriority.CRITICAL]: 4,
        [NotificationPriority.HIGH]: 3,
        [NotificationPriority.NORMAL]: 2,
        [NotificationPriority.LOW]: 1,
      };

      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });

    logger.debug(
      {
        name: this.name,
        queue_size: this.queue.length,
        priority,
      },
      'Item enqueued'
    );
  }

  /**
   * Remove and return highest priority item
   */
  dequeue(): QueuedItem<T> | null {
    const item = this.queue.shift();

    if (item) {
      logger.debug(
        {
          name: this.name,
          queue_size: this.queue.length,
          priority: item.priority,
          wait_time_ms: Date.now() - item.queuedAt.getTime(),
        },
        'Item dequeued'
      );
    }

    return item || null;
  }

  /**
   * Get queue size
   */
  size(): number {
    return this.queue.length;
  }

  /**
   * Check if queue is empty
   */
  isEmpty(): boolean {
    return this.queue.length === 0;
  }

  /**
   * Clear queue
   */
  clear(): void {
    const size = this.queue.length;
    this.queue = [];
    logger.info({ name: this.name, cleared_items: size }, 'Queue cleared');
  }
}

// =============================================================================
// GLOBAL RATE LIMITERS (Singletons)
// =============================================================================

/**
 * SMS rate limiter (10 SMS/minute by default)
 */
export const smsRateLimiter = new TokenBucketRateLimiter('sms', {
  tokensPerMinute: SMS_RATE_LIMIT_PER_MINUTE,
  maxTokens: SMS_RATE_LIMIT_PER_MINUTE * 2, // Allow 2x burst
  refillIntervalMs: 6000, // Refill every 6 seconds (10 times per minute)
});

/**
 * Email rate limiter (100 emails/minute by default)
 */
export const emailRateLimiter = new TokenBucketRateLimiter('email', {
  tokensPerMinute: EMAIL_RATE_LIMIT_PER_MINUTE,
  maxTokens: EMAIL_RATE_LIMIT_PER_MINUTE * 2, // Allow 2x burst
  refillIntervalMs: 6000, // Refill every 6 seconds
});

/**
 * SMS queue for low-priority batching
 */
export const smsQueue = new PriorityQueue<any>('sms-queue');

/**
 * Email queue for low-priority batching
 */
export const emailQueue = new PriorityQueue<any>('email-queue');

// =============================================================================
// LIFECYCLE MANAGEMENT
// =============================================================================

/**
 * Start all rate limiters
 */
export function startRateLimiters(): void {
  smsRateLimiter.start();
  emailRateLimiter.start();
  logger.info('All rate limiters started');
}

/**
 * Stop all rate limiters
 */
export function stopRateLimiters(): void {
  smsRateLimiter.stop();
  emailRateLimiter.stop();
  logger.info('All rate limiters stopped');
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  TokenBucketRateLimiter,
  PriorityQueue,
  smsRateLimiter,
  emailRateLimiter,
  smsQueue,
  emailQueue,
  startRateLimiters,
  stopRateLimiters,
};
