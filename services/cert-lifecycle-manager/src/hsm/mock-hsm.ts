/**
 * Mock HSM Implementation
 *
 * Simulates Hardware Security Module for development and testing
 * Provides all HSM operations without requiring actual hardware
 */

import { createSign, generateKeyPairSync, randomBytes } from 'crypto';
import type { IHSM, KeyMetadata, SigningResult } from './interfaces.js';

/**
 * Mock key storage entry
 */
interface MockKeyEntry {
  metadata: KeyMetadata;
  privateKey: string; // PEM format
  certificate?: string; // PEM format
}

/**
 * Mock HSM Implementation
 *
 * Features:
 * - In-memory key storage
 * - RSA and ECDSA key generation
 * - Signing operations
 * - Key import/export
 * - No actual hardware required
 */
export class MockHSM implements IHSM {
  private keys: Map<string, MockKeyEntry> = new Map();
  private initialized = false;

  /**
   * Initialize mock HSM
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      throw new Error('HSM already initialized');
    }

    // Simulate initialization delay
    await this.delay(50);

    this.initialized = true;
    console.log('[MockHSM] Initialized successfully');
  }

  /**
   * Generate new key pair
   */
  async generateKeyPair(
    keyId: string,
    algorithm: string,
    exportable: boolean
  ): Promise<KeyMetadata> {
    this.ensureInitialized();

    // Check if key already exists
    if (this.keys.has(keyId)) {
      throw new Error(`Key with ID ${keyId} already exists`);
    }

    // Parse algorithm
    const { type, keySize } = this.parseAlgorithm(algorithm);

    // Generate key pair
    const keyPair = generateKeyPairSync(type, {
      modulusLength: keySize,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    // Create metadata
    const metadata: KeyMetadata = {
      keyId,
      algorithm,
      keySize,
      usage: 'signing',
      createdAt: new Date(),
      exportable,
    };

    // Store key
    this.keys.set(keyId, {
      metadata,
      privateKey: keyPair.privateKey,
    });

    console.log(`[MockHSM] Generated key pair: ${keyId} (${algorithm})`);

    // Simulate HSM delay
    await this.delay(100);

    return metadata;
  }

  /**
   * Import existing key
   */
  async importKey(
    keyId: string,
    privateKey: string,
    certificate: string
  ): Promise<KeyMetadata> {
    this.ensureInitialized();

    // Check if key already exists
    if (this.keys.has(keyId)) {
      throw new Error(`Key with ID ${keyId} already exists`);
    }

    // Extract key information (simplified)
    const algorithm = privateKey.includes('BEGIN RSA') ? 'RSA-2048' : 'ECDSA-P256';
    const keySize = algorithm.includes('RSA') ? 2048 : 256;

    // Create metadata
    const metadata: KeyMetadata = {
      keyId,
      algorithm,
      keySize,
      usage: 'signing',
      createdAt: new Date(),
      exportable: true,
    };

    // Store key
    this.keys.set(keyId, {
      metadata,
      privateKey,
      certificate,
    });

    console.log(`[MockHSM] Imported key: ${keyId}`);

    // Simulate HSM delay
    await this.delay(80);

    return metadata;
  }

  /**
   * Sign data using HSM key
   */
  async sign(
    keyId: string,
    data: Buffer | string,
    algorithm: string = 'RSA-SHA256'
  ): Promise<SigningResult> {
    this.ensureInitialized();

    // Get key
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key ${keyId} not found in HSM`);
    }

    // Convert data to Buffer
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

    // Sign data
    const signer = createSign('RSA-SHA256');
    signer.update(dataBuffer);
    const signature = signer.sign(keyEntry.privateKey, 'base64');

    console.log(`[MockHSM] Signed data with key: ${keyId}`);

    // Simulate HSM signing delay
    await this.delay(30);

    return {
      signature,
      algorithm,
      keyId,
      timestamp: new Date(),
    };
  }

  /**
   * Get key metadata
   */
  async getKey(keyId: string): Promise<KeyMetadata | null> {
    this.ensureInitialized();

    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      return null;
    }

    return { ...keyEntry.metadata };
  }

  /**
   * List all keys
   */
  async listKeys(): Promise<KeyMetadata[]> {
    this.ensureInitialized();

    return Array.from(this.keys.values()).map((entry) => ({
      ...entry.metadata,
    }));
  }

  /**
   * Delete key
   */
  async deleteKey(keyId: string): Promise<void> {
    this.ensureInitialized();

    if (!this.keys.has(keyId)) {
      throw new Error(`Key ${keyId} not found in HSM`);
    }

    this.keys.delete(keyId);
    console.log(`[MockHSM] Deleted key: ${keyId}`);

    // Simulate HSM delay
    await this.delay(50);
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    // Mock HSM is always healthy if initialized
    return this.initialized;
  }

  /**
   * Close connection
   */
  async close(): Promise<void> {
    if (!this.initialized) {
      return;
    }

    this.initialized = false;
    console.log('[MockHSM] Connection closed');

    // Simulate disconnection delay
    await this.delay(30);
  }

  /**
   * Parse algorithm string
   */
  private parseAlgorithm(algorithm: string): { type: 'rsa' | 'ec'; keySize: number } {
    const upper = algorithm.toUpperCase();

    if (upper.includes('RSA-2048')) {
      return { type: 'rsa', keySize: 2048 };
    }
    if (upper.includes('RSA-4096')) {
      return { type: 'rsa', keySize: 4096 };
    }
    if (upper.includes('ECDSA') || upper.includes('EC')) {
      return { type: 'ec', keySize: 256 };
    }

    // Default to RSA-2048
    return { type: 'rsa', keySize: 2048 };
  }

  /**
   * Ensure HSM is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('HSM not initialized. Call initialize() first.');
    }
  }

  /**
   * Simulate HSM operation delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Get key count (for testing/debugging)
   */
  getKeyCount(): number {
    return this.keys.size;
  }

  /**
   * Export private key (only if exportable)
   * For testing purposes only - real HSM would not allow this
   */
  async exportPrivateKey(keyId: string): Promise<string> {
    this.ensureInitialized();

    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key ${keyId} not found`);
    }

    if (!keyEntry.metadata.exportable) {
      throw new Error(`Key ${keyId} is not exportable`);
    }

    return keyEntry.privateKey;
  }
}

/**
 * Create mock HSM instance
 */
export function createMockHSM(): IHSM {
  return new MockHSM();
}
