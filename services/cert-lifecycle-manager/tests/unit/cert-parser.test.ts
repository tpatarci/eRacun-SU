import {
  parseCertificate,
  calculateDaysUntilExpiration,
  formatFingerprint,
} from '../../src/cert-parser';

describe('cert-parser', () => {
  describe('calculateDaysUntilExpiration', () => {
    it('should calculate positive days for future expiration', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 30);

      const days = calculateDaysUntilExpiration(futureDate);

      expect(days).toBeGreaterThanOrEqual(29);
      expect(days).toBeLessThanOrEqual(30);
    });

    it('should calculate zero for today expiration', () => {
      const today = new Date();

      const days = calculateDaysUntilExpiration(today);

      expect(days).toBe(0);
    });

    it('should calculate negative days for past expiration', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 10);

      const days = calculateDaysUntilExpiration(pastDate);

      expect(days).toBeLessThan(0);
      expect(days).toBeGreaterThanOrEqual(-11);
      expect(days).toBeLessThanOrEqual(-9);
    });

    it('should handle far future dates', () => {
      const farFuture = new Date();
      farFuture.setFullYear(farFuture.getFullYear() + 5);

      const days = calculateDaysUntilExpiration(farFuture);

      expect(days).toBeGreaterThan(1800); // ~5 years
    });
  });

  describe('formatFingerprint', () => {
    it('should format fingerprint with colons', () => {
      const fingerprint =
        'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890';

      const formatted = formatFingerprint(fingerprint);

      expect(formatted).toContain(':');
      expect(formatted.split(':').length).toBe(32); // 64 chars / 2 = 32 pairs
    });

    it('should handle short fingerprints', () => {
      const fingerprint = 'ABCD';

      const formatted = formatFingerprint(fingerprint);

      expect(formatted).toBe('AB:CD');
    });

    it('should handle empty fingerprints', () => {
      const formatted = formatFingerprint('');

      expect(formatted).toBe('');
    });
  });

  describe('parseCertificate', () => {
    it('should throw error for invalid password', async () => {
      // Create a mock .p12 buffer (invalid certificate)
      const invalidBuffer = Buffer.from('invalid p12 data');

      await expect(
        parseCertificate(invalidBuffer, 'wrong-password')
      ).rejects.toThrow();
    });

    it('should throw error for empty buffer', async () => {
      const emptyBuffer = Buffer.from('');

      await expect(
        parseCertificate(emptyBuffer, 'password')
      ).rejects.toThrow();
    });

    it('should throw error for non-PKCS#12 data', async () => {
      const invalidBuffer = Buffer.from('not a certificate');

      await expect(
        parseCertificate(invalidBuffer, 'password')
      ).rejects.toThrow();
    });

    // Note: Testing actual certificate parsing requires a valid .p12 file
    // For comprehensive testing, create a test certificate in tests/fixtures/
  });
});
