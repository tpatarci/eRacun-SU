import { maskEmail, maskToken } from '../../src/observability';

describe('Observability - PII Masking', () => {
  describe('maskEmail', () => {
    it('should mask email addresses correctly', () => {
      expect(maskEmail('admin@example.com')).toBe('ad***@example.com');
      expect(maskEmail('user123@test.org')).toBe('us***@test.org');
      expect(maskEmail('a@example.com')).toBe('a***@example.com');
    });

    it('should handle invalid emails', () => {
      expect(maskEmail('not-an-email')).toBe('INVALID_EMAIL');
      expect(maskEmail('')).toBe('INVALID_EMAIL');
    });
  });

  describe('maskToken', () => {
    it('should mask JWT tokens correctly', () => {
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.signature';
      const masked = maskToken(token);
      expect(masked).toBe('eyJhbGci***');
      expect(masked.length).toBeLessThan(token.length);
    });

    it('should handle invalid tokens', () => {
      expect(maskToken('short')).toBe('INVALID_TOKEN');
      expect(maskToken('')).toBe('INVALID_TOKEN');
    });
  });
});
