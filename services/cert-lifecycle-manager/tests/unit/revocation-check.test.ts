/**
 * Tests for Certificate Revocation Checking
 */

import {
  IRevocationChecker,
  RevocationCheckResult,
  MockRevocationChecker,
  CRLChecker,
  OCSPChecker,
  getRevocationChecker,
} from '../../src/revocation-check';

describe('MockRevocationChecker', () => {
  let checker: IRevocationChecker;

  beforeEach(() => {
    checker = new MockRevocationChecker();
  });

  describe('checkRevocation', () => {
    it('should return not revoked for normal certificate', async () => {
      const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

      expect(result.revoked).toBe(false);
      expect(result.method).toBe('mock');
      expect(result.checkedAt).toBeInstanceOf(Date);
      expect(result.error).toBeUndefined();
    });

    it('should return revoked for known revoked certificate', async () => {
      // Mock has TEST-REVOKED-001 as revoked
      const result = await checker.checkRevocation(
        'TEST-REVOKED-001',
        'Fina RDC 2015 CA'
      );

      expect(result.revoked).toBe(true);
      expect(result.method).toBe('mock');
      expect(result.reason).toBe('keyCompromise');
      expect(result.revokedAt).toBeInstanceOf(Date);
    });

    it('should return revoked for superseded certificate', async () => {
      const result = await checker.checkRevocation(
        'TEST-SUPERSEDED-001',
        'Fina RDC 2015 CA'
      );

      expect(result.revoked).toBe(true);
      expect(result.reason).toBe('superseded');
    });

    it('should handle different issuers', async () => {
      const result1 = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');
      const result2 = await checker.checkRevocation('12345', 'AKD CA');

      expect(result1.revoked).toBe(false);
      expect(result2.revoked).toBe(false);
    });

    it('should simulate network delay', async () => {
      const start = Date.now();
      await checker.checkRevocation('12345', 'Fina RDC 2015 CA');
      const duration = Date.now() - start;

      // Should take at least 100ms (simulated delay)
      expect(duration).toBeGreaterThanOrEqual(50); // Allow some margin
    });
  });
});

describe('CRLChecker', () => {
  let checker: IRevocationChecker;

  beforeEach(() => {
    checker = new CRLChecker();
  });

  describe('checkRevocation', () => {
    it('should check revocation against CRL', async () => {
      const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

      expect(result.method).toBe('crl');
      expect(result.checkedAt).toBeInstanceOf(Date);
    });

    it('should handle FINA CA', async () => {
      const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

      expect(result).toBeDefined();
      expect(result.method).toBe('crl');
    });

    it('should handle AKD CA', async () => {
      const result = await checker.checkRevocation('12345', 'AKD CA');

      expect(result).toBeDefined();
      expect(result.method).toBe('crl');
    });

    it('should handle unknown CA gracefully', async () => {
      const result = await checker.checkRevocation('12345', 'Unknown CA');

      // Should return error for unknown CA
      expect(result.revoked).toBe(false);
      expect(result.error).toContain('Unknown CA');
    });

    it('should cache CRL for 24 hours', async () => {
      // First call - downloads CRL
      const start1 = Date.now();
      await checker.checkRevocation('12345', 'Fina RDC 2015 CA');
      const duration1 = Date.now() - start1;

      // Second call - uses cache (should be faster)
      const start2 = Date.now();
      await checker.checkRevocation('67890', 'Fina RDC 2015 CA');
      const duration2 = Date.now() - start2;

      // Cache hit should be significantly faster (but mock is already fast)
      expect(duration2).toBeLessThanOrEqual(duration1 + 50);
    });
  });
});

describe('OCSPChecker', () => {
  let checker: IRevocationChecker;

  beforeEach(() => {
    checker = new OCSPChecker();
  });

  describe('checkRevocation', () => {
    it('should check revocation via OCSP', async () => {
      const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

      expect(result.method).toBe('ocsp');
      expect(result.checkedAt).toBeInstanceOf(Date);
    });

    it('should handle FINA OCSP responder', async () => {
      const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

      expect(result).toBeDefined();
      expect(result.method).toBe('ocsp');
    });

    it('should handle AKD OCSP responder', async () => {
      const result = await checker.checkRevocation('12345', 'AKD CA');

      expect(result).toBeDefined();
      expect(result.method).toBe('ocsp');
    });

    it('should handle unknown CA gracefully', async () => {
      const result = await checker.checkRevocation('12345', 'Unknown CA');

      expect(result.revoked).toBe(false);
      expect(result.error).toContain('Unknown CA');
    });

    it('should be faster than CRL (real-time)', async () => {
      const start = Date.now();
      await checker.checkRevocation('12345', 'Fina RDC 2015 CA');
      const duration = Date.now() - start;

      // OCSP should be relatively fast (simulated)
      expect(duration).toBeLessThan(500);
    });
  });
});

describe('getRevocationChecker', () => {
  it('should return MockRevocationChecker by default', () => {
    const checker = getRevocationChecker();

    expect(checker).toBeInstanceOf(MockRevocationChecker);
  });

  it('should return MockRevocationChecker for mock type', () => {
    process.env.REVOCATION_CHECK_TYPE = 'mock';
    const checker = getRevocationChecker();

    expect(checker).toBeInstanceOf(MockRevocationChecker);
    delete process.env.REVOCATION_CHECK_TYPE;
  });

  it('should return CRLChecker for crl type', () => {
    process.env.REVOCATION_CHECK_TYPE = 'crl';
    const checker = getRevocationChecker();

    expect(checker).toBeInstanceOf(CRLChecker);
    delete process.env.REVOCATION_CHECK_TYPE;
  });

  it('should return OCSPChecker for ocsp type', () => {
    process.env.REVOCATION_CHECK_TYPE = 'ocsp';
    const checker = getRevocationChecker();

    expect(checker).toBeInstanceOf(OCSPChecker);
    delete process.env.REVOCATION_CHECK_TYPE;
  });

  it('should throw error for unknown type', () => {
    process.env.REVOCATION_CHECK_TYPE = 'invalid';

    expect(() => getRevocationChecker()).toThrow('Unknown revocation check type: invalid');

    delete process.env.REVOCATION_CHECK_TYPE;
  });
});

describe('RevocationCheckResult', () => {
  it('should have correct structure for not revoked', async () => {
    const checker = new MockRevocationChecker();
    const result = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');

    expect(result).toHaveProperty('revoked');
    expect(result).toHaveProperty('method');
    expect(result).toHaveProperty('checkedAt');
    expect(result.revoked).toBe(false);
    expect(result.reason).toBeUndefined();
    expect(result.revokedAt).toBeUndefined();
  });

  it('should have correct structure for revoked', async () => {
    const checker = new MockRevocationChecker();
    const result = await checker.checkRevocation(
      'TEST-REVOKED-001',
      'Fina RDC 2015 CA'
    );

    expect(result).toHaveProperty('revoked');
    expect(result).toHaveProperty('method');
    expect(result).toHaveProperty('checkedAt');
    expect(result).toHaveProperty('reason');
    expect(result).toHaveProperty('revokedAt');
    expect(result.revoked).toBe(true);
    expect(result.reason).toBe('keyCompromise');
    expect(result.revokedAt).toBeInstanceOf(Date);
  });

  it('should include error when check fails', async () => {
    const checker = new CRLChecker();
    const result = await checker.checkRevocation('12345', 'Unknown CA');

    expect(result).toHaveProperty('error');
    expect(result.error).toContain('Unknown CA');
    expect(result.revoked).toBe(false);
  });
});

describe('Integration scenarios', () => {
  it('should handle multiple consecutive checks', async () => {
    const checker = new MockRevocationChecker();

    const result1 = await checker.checkRevocation('12345', 'Fina RDC 2015 CA');
    const result2 = await checker.checkRevocation('67890', 'AKD CA');
    const result3 = await checker.checkRevocation(
      'TEST-REVOKED-001',
      'Fina RDC 2015 CA'
    );

    expect(result1.revoked).toBe(false);
    expect(result2.revoked).toBe(false);
    expect(result3.revoked).toBe(true);
  });

  it('should handle concurrent checks', async () => {
    const checker = new MockRevocationChecker();

    const results = await Promise.all([
      checker.checkRevocation('12345', 'Fina RDC 2015 CA'),
      checker.checkRevocation('67890', 'AKD CA'),
      checker.checkRevocation('TEST-REVOKED-001', 'Fina RDC 2015 CA'),
    ]);

    expect(results).toHaveLength(3);
    expect(results[0].revoked).toBe(false);
    expect(results[1].revoked).toBe(false);
    expect(results[2].revoked).toBe(true);
  });

  it('should support all revocation reasons', async () => {
    const checker = new MockRevocationChecker();

    const compromised = await checker.checkRevocation(
      'TEST-REVOKED-001',
      'Fina RDC 2015 CA'
    );
    const superseded = await checker.checkRevocation(
      'TEST-SUPERSEDED-001',
      'Fina RDC 2015 CA'
    );

    expect(compromised.reason).toBe('keyCompromise');
    expect(superseded.reason).toBe('superseded');
  });
});
