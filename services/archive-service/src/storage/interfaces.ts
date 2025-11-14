/**
 * WORM Storage Interfaces
 *
 * Abstractions for Write-Once-Read-Many object storage with
 * retention enforcement (Object Lock compliance mode).
 *
 * Croatian fiscalization requires 11-year retention minimum.
 * See: CLAUDE.md §5.4, ADR-004
 */

export interface StorageMetadata {
  /** Storage tier (determines retrieval latency and cost) */
  tier: 'HOT' | 'WARM' | 'COLD';

  /** Content hash for integrity verification */
  sha512: string;

  /** Size in bytes */
  contentLength: number;

  /** Storage timestamp (RFC3339) */
  storedAt: string;

  /** Retention lock expiration (11 years + 30 days grace period) */
  retentionUntil: string;

  /** Object Lock mode (compliance mode prevents deletion by anyone) */
  objectLockMode: 'COMPLIANCE' | 'GOVERNANCE';

  /** Storage location (bucket + key) */
  bucket: string;
  key: string;
}

export interface StorageObject {
  /** Unique identifier */
  objectId: string;

  /** Raw content (XML bytes) */
  content: Buffer;

  /** Storage metadata */
  metadata: StorageMetadata;
}

export interface StoreOptions {
  /** Target storage tier */
  tier: 'HOT' | 'WARM' | 'COLD';

  /** Content hash (must match actual hash) */
  sha512: string;

  /** Retention period in years (default: 11) */
  retentionYears?: number;

  /** Additional metadata */
  tags?: Record<string, string>;
}

export interface RetrieveOptions {
  /** For COLD tier: initiate restore if not available */
  initiateRestore?: boolean;

  /** Restore tier for COLD objects */
  restoreTier?: 'EXPEDITED' | 'STANDARD' | 'BULK';
}

export interface RetrieveResult {
  /** Whether object is immediately available */
  available: boolean;

  /** Object content (only if available) */
  content?: Buffer;

  /** Storage metadata */
  metadata: StorageMetadata;

  /** Restore status for COLD tier */
  restoreStatus?: {
    inProgress: boolean;
    expiresAt?: string;
    estimatedCompletionTime?: string;
  };
}

export interface IWORMStorage {
  /**
   * Store object with WORM retention lock
   *
   * @param objectId - Unique identifier (invoice_id)
   * @param content - Raw XML bytes
   * @param options - Storage configuration
   * @returns Storage metadata
   * @throws Error if hash mismatch or storage failure
   */
  store(objectId: string, content: Buffer, options: StoreOptions): Promise<StorageMetadata>;

  /**
   * Retrieve object (with optional restore for COLD tier)
   *
   * @param objectId - Unique identifier
   * @param options - Retrieval configuration
   * @returns Retrieve result with content and metadata
   * @throws Error if object not found
   */
  retrieve(objectId: string, options?: RetrieveOptions): Promise<RetrieveResult>;

  /**
   * Verify object integrity
   *
   * @param objectId - Unique identifier
   * @returns True if hash matches stored hash
   */
  verifyIntegrity(objectId: string): Promise<boolean>;

  /**
   * Check if object is locked (within retention period)
   *
   * @param objectId - Unique identifier
   * @returns True if object is retention-locked
   */
  isLocked(objectId: string): Promise<boolean>;

  /**
   * Get storage metadata without retrieving content
   *
   * @param objectId - Unique identifier
   * @returns Storage metadata
   * @throws Error if object not found
   */
  getMetadata(objectId: string): Promise<StorageMetadata>;

  /**
   * Generate presigned URL for direct download (HOT/WARM only)
   *
   * @param objectId - Unique identifier
   * @param expiresInSeconds - URL validity duration (default: 3600)
   * @returns Presigned URL
   * @throws Error if object is COLD tier
   */
  getPresignedUrl(objectId: string, expiresInSeconds?: number): Promise<string>;

  /**
   * Close storage client and release resources
   */
  close(): Promise<void>;
}

/**
 * Factory function to create WORM storage instance
 *
 * @param type - Storage backend type
 * @param config - Storage configuration
 * @returns IWORMStorage implementation
 */
export function createWORMStorage(
  type: 'mock' | 's3',
  config?: Record<string, unknown>
): IWORMStorage {
  if (type === 'mock') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { MockWORMStorage } = require('./mock-worm-storage');
    return new MockWORMStorage(config);
  }

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { S3WORMStorage } = require('./s3-worm-storage');
  return new S3WORMStorage(config);
}
