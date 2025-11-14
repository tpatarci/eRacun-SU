/**
 * Tests for Mock HSM Implementation
 */

import { MockHSM } from '../../../src/hsm/mock-hsm';
import { IHSM, KeyMetadata } from '../../../src/hsm/interfaces';

describe('MockHSM', () => {
  let hsm: IHSM;

  beforeEach(async () => {
    hsm = new MockHSM();
    await hsm.initialize();
  });

  afterEach(async () => {
    await hsm.destroy();
  });

  describe('initialize', () => {
    it('should initialize successfully', async () => {
      const newHsm = new MockHSM();
      await expect(newHsm.initialize()).resolves.not.toThrow();
      await newHsm.destroy();
    });

    it('should fail if initialized twice', async () => {
      await expect(hsm.initialize()).rejects.toThrow('HSM already initialized');
    });
  });

  describe('generateKeyPair', () => {
    it('should generate RSA-2048 key pair', async () => {
      const keyId = 'test-rsa-key';
      const metadata = await hsm.generateKeyPair(keyId, 'RSA-2048', true);

      expect(metadata.keyId).toBe(keyId);
      expect(metadata.algorithm).toBe('RSA-2048');
      expect(metadata.exportable).toBe(true);
      expect(metadata.createdAt).toBeInstanceOf(Date);
      expect(metadata.publicKey).toBeDefined();
      expect(metadata.publicKey.length).toBeGreaterThan(0);
    });

    it('should generate ECDSA-P256 key pair', async () => {
      const keyId = 'test-ecdsa-key';
      const metadata = await hsm.generateKeyPair(keyId, 'ECDSA-P256', true);

      expect(metadata.keyId).toBe(keyId);
      expect(metadata.algorithm).toBe('ECDSA-P256');
      expect(metadata.exportable).toBe(true);
      expect(metadata.publicKey).toBeDefined();
    });

    it('should fail if key ID already exists', async () => {
      const keyId = 'duplicate-key';
      await hsm.generateKeyPair(keyId, 'RSA-2048', true);

      await expect(hsm.generateKeyPair(keyId, 'RSA-2048', true)).rejects.toThrow(
        'Key with ID duplicate-key already exists'
      );
    });

    it('should fail with unsupported algorithm', async () => {
      await expect(hsm.generateKeyPair('test', 'RSA-1024', true)).rejects.toThrow(
        'Unsupported algorithm: RSA-1024'
      );
    });

    it('should generate non-exportable key', async () => {
      const keyId = 'non-exportable-key';
      const metadata = await hsm.generateKeyPair(keyId, 'RSA-2048', false);

      expect(metadata.exportable).toBe(false);
    });
  });

  describe('sign', () => {
    beforeEach(async () => {
      await hsm.generateKeyPair('sign-test-key', 'RSA-2048', true);
    });

    it('should sign data with RSA-SHA256', async () => {
      const data = Buffer.from('Hello, World!');
      const result = await hsm.sign('sign-test-key', data);

      expect(result.signature).toBeDefined();
      expect(result.signature.length).toBeGreaterThan(0);
      expect(result.algorithm).toBe('RSA-SHA256');
      expect(result.keyId).toBe('sign-test-key');
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should sign string data', async () => {
      const data = 'Hello, World!';
      const result = await hsm.sign('sign-test-key', data);

      expect(result.signature).toBeDefined();
      expect(result.algorithm).toBe('RSA-SHA256');
    });

    it('should fail if key does not exist', async () => {
      await expect(hsm.sign('nonexistent-key', Buffer.from('data'))).rejects.toThrow(
        'Key nonexistent-key not found'
      );
    });

    it('should produce different signatures for different data', async () => {
      const data1 = Buffer.from('Data 1');
      const data2 = Buffer.from('Data 2');

      const sig1 = await hsm.sign('sign-test-key', data1);
      const sig2 = await hsm.sign('sign-test-key', data2);

      expect(sig1.signature).not.toBe(sig2.signature);
    });

    it('should produce consistent signatures for same data', async () => {
      const data = Buffer.from('Consistent data');

      const sig1 = await hsm.sign('sign-test-key', data);
      const sig2 = await hsm.sign('sign-test-key', data);

      // With RSA-SHA256, same data + same key = same signature
      expect(sig1.signature).toBe(sig2.signature);
    });
  });

  describe('getKey', () => {
    it('should retrieve existing key metadata', async () => {
      await hsm.generateKeyPair('retrieve-test', 'RSA-2048', true);

      const metadata = await hsm.getKey('retrieve-test');

      expect(metadata).toBeDefined();
      expect(metadata!.keyId).toBe('retrieve-test');
      expect(metadata!.algorithm).toBe('RSA-2048');
    });

    it('should return null for nonexistent key', async () => {
      const metadata = await hsm.getKey('does-not-exist');

      expect(metadata).toBeNull();
    });
  });

  describe('listKeys', () => {
    it('should list all keys', async () => {
      await hsm.generateKeyPair('key1', 'RSA-2048', true);
      await hsm.generateKeyPair('key2', 'ECDSA-P256', true);
      await hsm.generateKeyPair('key3', 'RSA-2048', false);

      const keys = await hsm.listKeys();

      expect(keys).toHaveLength(3);
      expect(keys.map((k) => k.keyId)).toContain('key1');
      expect(keys.map((k) => k.keyId)).toContain('key2');
      expect(keys.map((k) => k.keyId)).toContain('key3');
    });

    it('should return empty array when no keys exist', async () => {
      const keys = await hsm.listKeys();

      expect(keys).toHaveLength(0);
    });
  });

  describe('deleteKey', () => {
    it('should delete existing key', async () => {
      await hsm.generateKeyPair('delete-test', 'RSA-2048', true);

      await hsm.deleteKey('delete-test');

      const metadata = await hsm.getKey('delete-test');
      expect(metadata).toBeNull();
    });

    it('should fail to delete nonexistent key', async () => {
      await expect(hsm.deleteKey('does-not-exist')).rejects.toThrow(
        'Key does-not-exist not found'
      );
    });

    it('should remove key from list after deletion', async () => {
      await hsm.generateKeyPair('key1', 'RSA-2048', true);
      await hsm.generateKeyPair('key2', 'RSA-2048', true);

      await hsm.deleteKey('key1');

      const keys = await hsm.listKeys();
      expect(keys).toHaveLength(1);
      expect(keys[0].keyId).toBe('key2');
    });
  });

  describe('importKey', () => {
    it('should import RSA private key and certificate', async () => {
      const keyId = 'imported-key';
      const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1+fWIcPm15A8vMkgpycR2sdC2xZJvvXeD6LjJgEp4+E6gG
-----END PRIVATE KEY-----`;
      const certificate = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgK1Y4rWMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCFRl
c3QgQ2VydDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBMxETAPBgNV
-----END CERTIFICATE-----`;

      const metadata = await hsm.importKey(keyId, privateKey, certificate);

      expect(metadata.keyId).toBe(keyId);
      expect(metadata.algorithm).toContain('RSA');
      expect(metadata.exportable).toBe(true);
    });

    it('should fail if key ID already exists', async () => {
      await hsm.generateKeyPair('existing-key', 'RSA-2048', true);

      await expect(
        hsm.importKey('existing-key', 'private-key', 'certificate')
      ).rejects.toThrow('Key with ID existing-key already exists');
    });
  });

  describe('exportPrivateKey', () => {
    it('should export private key for exportable key', async () => {
      await hsm.generateKeyPair('exportable-key', 'RSA-2048', true);

      const privateKey = await hsm.exportPrivateKey('exportable-key');

      expect(privateKey).toBeDefined();
      expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(privateKey).toContain('-----END PRIVATE KEY-----');
    });

    it('should fail to export non-exportable key', async () => {
      await hsm.generateKeyPair('non-exportable', 'RSA-2048', false);

      await expect(hsm.exportPrivateKey('non-exportable')).rejects.toThrow(
        'Key non-exportable is not exportable'
      );
    });

    it('should fail to export nonexistent key', async () => {
      await expect(hsm.exportPrivateKey('does-not-exist')).rejects.toThrow(
        'Key does-not-exist not found'
      );
    });
  });

  describe('destroy', () => {
    it('should destroy HSM and clear all keys', async () => {
      await hsm.generateKeyPair('key1', 'RSA-2048', true);
      await hsm.generateKeyPair('key2', 'RSA-2048', true);

      await hsm.destroy();

      // HSM should be uninitialized now
      await expect(hsm.getKey('key1')).rejects.toThrow('HSM not initialized');
    });
  });

  describe('performance', () => {
    it('should simulate HSM delays for key generation', async () => {
      const start = Date.now();
      await hsm.generateKeyPair('perf-test', 'RSA-2048', true);
      const duration = Date.now() - start;

      // Should take at least 100ms (simulated delay)
      expect(duration).toBeGreaterThanOrEqual(50); // Allow some margin
    });

    it('should simulate HSM delays for signing', async () => {
      await hsm.generateKeyPair('sign-perf', 'RSA-2048', true);

      const start = Date.now();
      await hsm.sign('sign-perf', Buffer.from('test'));
      const duration = Date.now() - start;

      // Should take at least 30ms (simulated delay)
      expect(duration).toBeGreaterThanOrEqual(15); // Allow some margin
    });
  });

  describe('error handling', () => {
    it('should throw error for operations on uninitialized HSM', async () => {
      const uninitializedHsm = new MockHSM();

      await expect(
        uninitializedHsm.generateKeyPair('test', 'RSA-2048', true)
      ).rejects.toThrow('HSM not initialized');

      await expect(uninitializedHsm.getKey('test')).rejects.toThrow(
        'HSM not initialized'
      );

      await expect(uninitializedHsm.listKeys()).rejects.toThrow('HSM not initialized');
    });
  });
});
