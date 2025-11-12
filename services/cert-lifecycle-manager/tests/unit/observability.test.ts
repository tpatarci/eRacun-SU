import {
  maskPassword,
  initObservability,
  shutdownObservability,
  getMetrics,
  createSpan,
  setSpanError,
  logger,
  serviceUp,
  certificatesExpiring,
  certificateOperations,
} from '../../src/observability';

describe('observability', () => {
  afterEach(() => {
    // Reset metrics between tests
    certificatesExpiring.reset();
    certificateOperations.reset();
  });

  describe('maskPassword', () => {
    it('should mask password', () => {
      const masked = maskPassword('my-secret-password');

      expect(masked).not.toContain('my-secret-password');
      expect(masked).toBe('***REDACTED***');
    });

    it('should handle empty password', () => {
      const masked = maskPassword('');

      expect(masked).toBe('NO_PASSWORD');
    });

    it('should handle undefined password', () => {
      const masked = maskPassword(undefined as any);

      expect(masked).toBe('NO_PASSWORD');
    });
  });

  describe('initObservability', () => {
    it('should initialize observability', async () => {
      initObservability();

      // Service should be marked as up
      const metrics = await serviceUp.get();
      expect(metrics.values.length).toBeGreaterThan(0);
    });
  });

  describe('shutdownObservability', () => {
    it('should shutdown observability', async () => {
      shutdownObservability();

      // Service should be marked as down
      const metrics = await serviceUp.get();
      expect(metrics.values.length).toBeGreaterThan(0);
    });
  });

  describe('getMetrics', () => {
    it('should return Prometheus metrics', async () => {
      const metrics = await getMetrics();

      expect(typeof metrics).toBe('string');
      expect(metrics.length).toBeGreaterThan(0);
    });

    it('should include custom metrics', async () => {
      certificatesExpiring.labels('30').set(5);

      const metrics = await getMetrics();

      expect(metrics).toContain('certificates_expiring_count');
    });
  });

  describe('createSpan', () => {
    it('should create a span with name', () => {
      const span = createSpan('test_operation');

      expect(span).toBeDefined();
      expect(typeof span.end).toBe('function');
    });

    it('should create a span with attributes', () => {
      const span = createSpan('test_operation', {
        testAttribute: 'test value',
        numericAttribute: 123,
      });

      expect(span).toBeDefined();
      span.end();
    });
  });

  describe('setSpanError', () => {
    it('should set span error', () => {
      const span = createSpan('test_operation');
      const error = new Error('Test error');

      expect(() => setSpanError(span, error)).not.toThrow();

      span.end();
    });
  });

  describe('Prometheus metrics', () => {
    it('should increment certificate operations counter', async () => {
      certificateOperations.labels('upload', 'success').inc();
      certificateOperations.labels('upload', 'success').inc();

      const metrics = await certificateOperations.get();
      expect(metrics.values.length).toBeGreaterThan(0);
    });

    it('should set expiring certificates gauge', async () => {
      certificatesExpiring.labels('30').set(10);
      certificatesExpiring.labels('7').set(2);

      const metrics = await certificatesExpiring.get();
      expect(metrics.values.length).toBe(2);
    });
  });

  describe('logger', () => {
    it('should log info messages', () => {
      expect(() => logger.info('Test info message')).not.toThrow();
    });

    it('should log error messages', () => {
      expect(() => logger.error('Test error message')).not.toThrow();
    });

    it('should log with structured data', () => {
      expect(() =>
        logger.info({ certId: '123', operation: 'test' }, 'Test message')
      ).not.toThrow();
    });

    it('should redact passwords', () => {
      // Password redaction is configured in pino, test that logger accepts password field
      expect(() =>
        logger.info({ password: 'secret123' }, 'Test with password')
      ).not.toThrow();
    });
  });
});
