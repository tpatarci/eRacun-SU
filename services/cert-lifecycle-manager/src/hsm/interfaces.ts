/**
 * HSM (Hardware Security Module) Interface
 *
 * Defines the contract for hardware security modules
 * Both real HSM and mock implementations must implement this interface
 */

/**
 * Key metadata
 */
export interface KeyMetadata {
  /** Key identifier */
  keyId: string;
  /** Key algorithm (RSA, ECDSA, etc.) */
  algorithm: string;
  /** Key size in bits */
  keySize: number;
  /** Key usage (signing, encryption, etc.) */
  usage: 'signing' | 'encryption' | 'both';
  /** Creation timestamp */
  createdAt: Date;
  /** Expiration date (if applicable) */
  expiresAt?: Date;
  /** Is key exportable */
  exportable: boolean;
}

/**
 * HSM signing result
 */
export interface SigningResult {
  /** Signature (base64-encoded) */
  signature: string;
  /** Algorithm used */
  algorithm: string;
  /** Key ID used for signing */
  keyId: string;
  /** Timestamp */
  timestamp: Date;
}

/**
 * HSM operations interface
 */
export interface IHSM {
  /**
   * Initialize HSM connection
   */
  initialize(): Promise<void>;

  /**
   * Generate new key pair in HSM
   * @param keyId - Identifier for the key
   * @param algorithm - Key algorithm (RSA-2048, RSA-4096, ECDSA-P256, etc.)
   * @param exportable - Whether key can be exported
   * @returns Key metadata
   */
  generateKeyPair(
    keyId: string,
    algorithm: string,
    exportable: boolean
  ): Promise<KeyMetadata>;

  /**
   * Import existing key into HSM
   * @param keyId - Identifier for the key
   * @param privateKey - Private key (PEM format)
   * @param certificate - Associated certificate (PEM format)
   * @returns Key metadata
   */
  importKey(
    keyId: string,
    privateKey: string,
    certificate: string
  ): Promise<KeyMetadata>;

  /**
   * Sign data using HSM key
   * @param keyId - Key identifier
   * @param data - Data to sign (Buffer or string)
   * @param algorithm - Signature algorithm (RSA-SHA256, ECDSA-SHA256, etc.)
   * @returns Signing result
   */
  sign(
    keyId: string,
    data: Buffer | string,
    algorithm?: string
  ): Promise<SigningResult>;

  /**
   * Get key metadata
   * @param keyId - Key identifier
   * @returns Key metadata or null if not found
   */
  getKey(keyId: string): Promise<KeyMetadata | null>;

  /**
   * List all keys in HSM
   * @returns Array of key metadata
   */
  listKeys(): Promise<KeyMetadata[]>;

  /**
   * Delete key from HSM
   * @param keyId - Key identifier
   */
  deleteKey(keyId: string): Promise<void>;

  /**
   * Health check - verify HSM is accessible
   * @returns True if HSM is healthy
   */
  healthCheck(): Promise<boolean>;

  /**
   * Close HSM connection
   */
  close(): Promise<void>;
}
