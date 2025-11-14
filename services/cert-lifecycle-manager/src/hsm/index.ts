/**
 * HSM Module
 *
 * Hardware Security Module abstractions and implementations
 */

export type { IHSM, KeyMetadata, SigningResult } from './interfaces.js';
export { MockHSM, createMockHSM } from './mock-hsm.js';

import { createMockHSM } from './mock-hsm.js';
import type { IHSM } from './interfaces.js';

/**
 * HSM factory configuration
 */
export interface HSMConfig {
  /** HSM type */
  type: 'mock' | 'pkcs11' | 'aws-kms' | 'azure-keyvault';
  /** Connection configuration (type-specific) */
  config?: Record<string, unknown>;
}

/**
 * Create HSM instance based on configuration
 */
export function createHSM(hsmConfig: HSMConfig): IHSM {
  switch (hsmConfig.type) {
    case 'mock':
      return createMockHSM();
    case 'pkcs11':
      // TODO: Implement PKCS#11 HSM adapter
      throw new Error('PKCS#11 HSM not yet implemented');
    case 'aws-kms':
      // TODO: Implement AWS KMS adapter
      throw new Error('AWS KMS not yet implemented');
    case 'azure-keyvault':
      // TODO: Implement Azure Key Vault adapter
      throw new Error('Azure Key Vault not yet implemented');
    default:
      throw new Error(`Unknown HSM type: ${hsmConfig.type}`);
  }
}

/**
 * Get default HSM (mock for development)
 */
let defaultHSM: IHSM | null = null;

export async function getDefaultHSM(): Promise<IHSM> {
  if (!defaultHSM) {
    const hsmType = (process.env.HSM_TYPE as HSMConfig['type']) || 'mock';
    defaultHSM = createHSM({ type: hsmType });
    await defaultHSM.initialize();
  }
  return defaultHSM;
}
