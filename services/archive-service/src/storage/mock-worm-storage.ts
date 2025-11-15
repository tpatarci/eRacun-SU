/**
 * Mock WORM Storage Implementation
 *
 * In-memory simulation of S3 Object Lock (compliance mode) for development and testing.
 * Enforces 11-year retention and prevents deletion/modification.
 *
 * Production: Replace with S3WORMStorage using DigitalOcean Spaces + AWS Glacier.
 */

import { createHash } from 'crypto';
import {
  IWORMStorage,
  StorageMetadata,
  StoreOptions,
  RetrieveOptions,
  RetrieveResult,
  StorageObject,
} from './interfaces';

export interface MockWORMStorageConfig {
  /** Simulate retrieval delays (ms) */
  hotLatencyMs?: number;
  warmLatencyMs?: number;
  coldRestoreMs?: number;

  /** Simulate failure rate (0-1) */
  failureRate?: number;
}

export class MockWORMStorage implements IWORMStorage {
  private readonly objects = new Map<string, StorageObject>();
  private readonly restoreRequests = new Map<string, { initiatedAt: Date; tier: string }>();

  private readonly hotLatency: number;
  private readonly warmLatency: number;
  private readonly coldRestore: number;
  private readonly failureRate: number;

  constructor(config?: MockWORMStorageConfig) {
    this.hotLatency = config?.hotLatencyMs ?? 10;
    this.warmLatency = config?.warmLatencyMs ?? 100;
    this.coldRestore = config?.coldRestoreMs ?? 3600000; // 1 hour default
    this.failureRate = config?.failureRate ?? 0;
  }

  async store(objectId: string, content: Buffer, options: StoreOptions): Promise<StorageMetadata> {
    // Simulate storage latency
    await this.simulateDelay(options.tier);

    // Simulate random failures
    if (Math.random() < this.failureRate) {
      throw new Error('Simulated storage failure');
    }

    // Verify hash
    const actualHash = this.computeSHA512(content);
    if (actualHash !== options.sha512) {
      throw new Error(`Hash mismatch: expected ${options.sha512}, got ${actualHash}`);
    }

    // Check if object already exists (idempotency)
    if (this.objects.has(objectId)) {
      const existing = this.objects.get(objectId)!;
      if (existing.metadata.sha512 === options.sha512) {
        // Idempotent store - return existing metadata
        return existing.metadata;
      }
      throw new Error(`Object ${objectId} already exists with different content`);
    }

    // Calculate retention expiration (11 years + 30 days grace period)
    const retentionYears = options.retentionYears ?? 11;
    const storedAt = new Date();
    const retentionUntil = new Date(storedAt);
    retentionUntil.setFullYear(retentionUntil.getFullYear() + retentionYears);
    retentionUntil.setDate(retentionUntil.getDate() + 30); // Grace period

    // Create storage metadata
    const metadata: StorageMetadata = {
      tier: options.tier,
      sha512: actualHash,
      contentLength: content.length,
      storedAt: storedAt.toISOString(),
      retentionUntil: retentionUntil.toISOString(),
      objectLockMode: 'COMPLIANCE',
      bucket: this.getBucketName(options.tier),
      key: `invoices/${objectId}.xml`,
    };

    // Store object in memory
    this.objects.set(objectId, {
      objectId,
      content,
      metadata,
    });

    return metadata;
  }

  async retrieve(objectId: string, options?: RetrieveOptions): Promise<RetrieveResult> {
    const obj = this.objects.get(objectId);
    if (!obj) {
      throw new Error(`Object not found: ${objectId}`);
    }

    // HOT tier: Immediately available
    if (obj.metadata.tier === 'HOT') {
      await this.simulateDelay('HOT');
      return {
        available: true,
        content: obj.content,
        metadata: obj.metadata,
      };
    }

    // WARM tier: Slightly delayed but available
    if (obj.metadata.tier === 'WARM') {
      await this.simulateDelay('WARM');
      return {
        available: true,
        content: obj.content,
        metadata: obj.metadata,
      };
    }

    // COLD tier: Requires restore
    const restoreRequest = this.restoreRequests.get(objectId);

    if (!restoreRequest) {
      // No restore initiated yet
      if (options?.initiateRestore) {
        // Initiate restore
        this.restoreRequests.set(objectId, {
          initiatedAt: new Date(),
          tier: options.restoreTier ?? 'STANDARD',
        });

        const estimatedCompletion = new Date();
        const restoreMs = this.getRestoreTime(options.restoreTier ?? 'STANDARD');
        estimatedCompletion.setTime(estimatedCompletion.getTime() + restoreMs);

        return {
          available: false,
          metadata: obj.metadata,
          restoreStatus: {
            inProgress: true,
            estimatedCompletionTime: estimatedCompletion.toISOString(),
          },
        };
      }

      // Not available and restore not initiated
      return {
        available: false,
        metadata: obj.metadata,
        restoreStatus: {
          inProgress: false,
        },
      };
    }

    // Check if restore is complete
    const elapsed = Date.now() - restoreRequest.initiatedAt.getTime();
    const restoreMs = this.getRestoreTime(restoreRequest.tier);

    if (elapsed >= restoreMs) {
      // Restore complete
      return {
        available: true,
        content: obj.content,
        metadata: obj.metadata,
        restoreStatus: {
          inProgress: false,
          expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24 hours
        },
      };
    }

    // Restore in progress
    const estimatedCompletion = new Date(restoreRequest.initiatedAt.getTime() + restoreMs);
    return {
      available: false,
      metadata: obj.metadata,
      restoreStatus: {
        inProgress: true,
        estimatedCompletionTime: estimatedCompletion.toISOString(),
      },
    };
  }

  async verifyIntegrity(objectId: string): Promise<boolean> {
    const obj = this.objects.get(objectId);
    if (!obj) {
      throw new Error(`Object not found: ${objectId}`);
    }

    const actualHash = this.computeSHA512(obj.content);
    return actualHash === obj.metadata.sha512;
  }

  async isLocked(objectId: string): Promise<boolean> {
    const obj = this.objects.get(objectId);
    if (!obj) {
      throw new Error(`Object not found: ${objectId}`);
    }

    const now = new Date();
    const retentionUntil = new Date(obj.metadata.retentionUntil);
    return now < retentionUntil;
  }

  async getMetadata(objectId: string): Promise<StorageMetadata> {
    const obj = this.objects.get(objectId);
    if (!obj) {
      throw new Error(`Object not found: ${objectId}`);
    }

    return obj.metadata;
  }

  async getPresignedUrl(objectId: string, expiresInSeconds = 3600): Promise<string> {
    const obj = this.objects.get(objectId);
    if (!obj) {
      throw new Error(`Object not found: ${objectId}`);
    }

    if (obj.metadata.tier === 'COLD') {
      throw new Error('Cannot generate presigned URL for COLD tier objects');
    }

    // Simulate presigned URL (in production, use S3 SDK)
    const expires = Math.floor(Date.now() / 1000) + expiresInSeconds;
    const signature = this.computeSignature(objectId, expires);

    return `https://mock-storage.eracun.internal/${obj.metadata.bucket}/${obj.metadata.key}?expires=${expires}&signature=${signature}`;
  }

  async close(): Promise<void> {
    // Cleanup (in production, close S3 client)
    this.objects.clear();
    this.restoreRequests.clear();
  }

  // --- Test Helpers ---

  /**
   * Get all stored object IDs (for testing)
   */
  getStoredObjectIds(): string[] {
    return Array.from(this.objects.keys());
  }

  /**
   * Get object count by tier (for testing)
   */
  getObjectCountByTier(): Record<string, number> {
    const counts = { HOT: 0, WARM: 0, COLD: 0 };
    for (const obj of this.objects.values()) {
      counts[obj.metadata.tier]++;
    }
    return counts;
  }

  /**
   * Simulate time passage (for testing retention expiry)
   */
  simulateTimePassage(years: number): void {
    for (const obj of this.objects.values()) {
      const retentionUntil = new Date(obj.metadata.retentionUntil);
      retentionUntil.setFullYear(retentionUntil.getFullYear() - years);
      obj.metadata.retentionUntil = retentionUntil.toISOString();
    }
  }

  /**
   * Attempt to delete locked object (for testing - should fail)
   */
  async attemptDelete(objectId: string): Promise<void> {
    const locked = await this.isLocked(objectId);
    if (locked) {
      throw new Error(`Cannot delete object ${objectId}: retention lock active`);
    }

    // After retention expires, deletion allowed
    this.objects.delete(objectId);
  }

  // --- Private Methods ---

  private computeSHA512(data: Buffer): string {
    return createHash('sha512').update(data).digest('hex');
  }

  private computeSignature(objectId: string, expires: number): string {
    const data = `${objectId}:${expires}`;
    return createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  private getBucketName(tier: 'HOT' | 'WARM' | 'COLD'): string {
    const buckets = {
      HOT: 'eracun-archive-hot-eu',
      WARM: 'eracun-archive-warm-eu',
      COLD: 'eracun-archive-cold-eu',
    };
    return buckets[tier];
  }

  private async simulateDelay(tier: 'HOT' | 'WARM' | 'COLD'): Promise<void> {
    const delays = {
      HOT: this.hotLatency,
      WARM: this.warmLatency,
      COLD: 0, // No delay for COLD (requires restore)
    };

    const delay = delays[tier];
    if (delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  private getRestoreTime(tier: string): number {
    const base = this.coldRestore;
    const times = {
      EXPEDITED: Math.max(600000, Math.floor(base / 3)),
      STANDARD: base,
      BULK: base * 3,
    };
    return times[tier as keyof typeof times] ?? base;
  }
}
