import {
  finaConfigSchema,
  imapConfigSchema,
  validateUserConfig,
} from '../../../src/shared/tenant-config';

describe('Tenant Config', () => {

  describe('finaConfigSchema', () => {
    it('should validate correct FINA config', () => {
      const validConfig = {
        wsdlUrl: 'https://fina.example.com/wsdl',
        certPath: '/path/to/cert.p12',
        certPassphrase: 'secret123',
      };

      const result = finaConfigSchema.safeParse(validConfig);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.wsdlUrl).toBe('https://fina.example.com/wsdl');
        expect(result.data.certPath).toBe('/path/to/cert.p12');
        expect(result.data.certPassphrase).toBe('secret123');
      }
    });

    it('should reject invalid URL', () => {
      const invalidConfig = {
        wsdlUrl: 'not-a-valid-url',
        certPath: '/path/to/cert.p12',
        certPassphrase: 'secret123',
      };

      const result = finaConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'wsdlUrl')).toBe(true);
      }
    });

    it('should reject empty certPath', () => {
      const invalidConfig = {
        wsdlUrl: 'https://fina.example.com/wsdl',
        certPath: '',
        certPassphrase: 'secret123',
      };

      const result = finaConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'certPath')).toBe(true);
      }
    });

    it('should reject missing required field', () => {
      const invalidConfig = {
        wsdlUrl: 'https://fina.example.com/wsdl',
        certPath: '/path/to/cert.p12',
        // certPassphrase is missing
      };

      const result = finaConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'certPassphrase')).toBe(true);
      }
    });
  });

  describe('imapConfigSchema', () => {
    it('should validate correct IMAP config', () => {
      const validConfig = {
        host: 'imap.example.com',
        port: 993,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = imapConfigSchema.safeParse(validConfig);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.host).toBe('imap.example.com');
        expect(result.data.port).toBe(993);
        expect(result.data.user).toBe('user@example.com');
        expect(result.data.password).toBe('password123');
      }
    });

    it('should reject empty host', () => {
      const invalidConfig = {
        host: '',
        port: 993,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = imapConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'host')).toBe(true);
      }
    });

    it('should reject invalid port (too low)', () => {
      const invalidConfig = {
        host: 'imap.example.com',
        port: 0,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = imapConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'port')).toBe(true);
      }
    });

    it('should reject invalid port (too high)', () => {
      const invalidConfig = {
        host: 'imap.example.com',
        port: 70000,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = imapConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'port')).toBe(true);
      }
    });

    it('should reject non-integer port', () => {
      const invalidConfig = {
        host: 'imap.example.com',
        port: 993.5,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = imapConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'port')).toBe(true);
      }
    });

    it('should reject missing required field', () => {
      const invalidConfig = {
        host: 'imap.example.com',
        port: 993,
        user: 'user@example.com',
        // password is missing
      };

      const result = imapConfigSchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path.join('.') === 'password')).toBe(true);
      }
    });
  });

  describe('validateUserConfig', () => {
    it('should validate valid FINA config', () => {
      const config = {
        wsdlUrl: 'https://fina.example.com/wsdl',
        certPath: '/path/to/cert.p12',
        certPassphrase: 'secret123',
      };

      const result = validateUserConfig('fina', config);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.wsdlUrl).toBe('https://fina.example.com/wsdl');
      }
    });

    it('should validate valid IMAP config', () => {
      const config = {
        host: 'imap.example.com',
        port: 993,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = validateUserConfig('imap', config);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.host).toBe('imap.example.com');
      }
    });

    it('should return errors for invalid FINA config', () => {
      const config = {
        wsdlUrl: 'invalid-url',
        certPath: '/path/to/cert.p12',
        certPassphrase: 'secret123',
      };

      const result = validateUserConfig('fina', config);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.errors[0]).toContain('wsdlUrl');
      }
    });

    it('should return errors for invalid IMAP config', () => {
      const config = {
        host: '',
        port: 993,
        user: 'user@example.com',
        password: 'password123',
      };

      const result = validateUserConfig('imap', config);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.errors[0]).toContain('host');
      }
    });
  });
});
