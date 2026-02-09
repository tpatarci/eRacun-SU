import { loadConfig, configSchema } from '../../src/shared/config';

describe('Config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should load valid config', () => {
    process.env.DATABASE_URL = 'postgresql://user:pass@localhost:5432/test';
    process.env.FINA_WSDL_URL = 'https://test.example.com/wsdl';
    process.env.FINA_CERT_PATH = './cert.p12';

    const result = configSchema.safeParse(process.env);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.DATABASE_URL).toBe('postgresql://user:pass@localhost:5432/test');
      expect(result.data.FINA_WSDL_URL).toBe('https://test.example.com/wsdl');
      expect(result.data.FINA_CERT_PATH).toBe('./cert.p12');
    }
  });

  it('should reject missing required field', () => {
    delete process.env.DATABASE_URL;
    process.env.FINA_WSDL_URL = 'https://test.example.com/wsdl';
    process.env.FINA_CERT_PATH = './cert.p12';

    const result = configSchema.safeParse(process.env);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path.join('.') === 'DATABASE_URL')).toBe(true);
    }
  });

  it('should use defaults for optional fields', () => {
    process.env.DATABASE_URL = 'postgresql://user:pass@localhost:5432/test';
    process.env.FINA_WSDL_URL = 'https://test.example.com/wsdl';
    process.env.FINA_CERT_PATH = './cert.p12';
    delete process.env.REDIS_URL;
    delete process.env.PORT;

    const result = configSchema.safeParse(process.env);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.REDIS_URL).toBe('redis://localhost:6379');
      expect(result.data.PORT).toBe(3000);
      expect(result.data.LOG_LEVEL).toBe('info');
      // Jest sets NODE_ENV to 'test', which is a valid enum value
      expect(['development', 'production', 'test']).toContain(result.data.NODE_ENV);
    }
  });
});
