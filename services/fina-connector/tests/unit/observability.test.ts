import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  logger,
  maskOIB,
  maskJIR,
  fiscalizationTotal,
  fiscalizationDuration,
  finaErrors,
  retryAttempts,
  offlineQueueDepth,
  offlineQueueMaxAge,
  jirReceived,
  resetMetrics,
} from '../../src/observability';

describe('Observability', () => {
  beforeEach(() => {
    resetMetrics();
  });

  describe('Logger', () => {
    it('should have correct service name', () => {
      expect(logger.bindings().service).toBe('fina-connector');
    });

    it('should support structured logging', () => {
      expect(() => {
        logger.info({ test: 'data' }, 'Test message');
      }).not.toThrow();
    });
  });

  describe('PII Masking', () => {
    describe('maskOIB', () => {
      it('should fully mask valid OIB', () => {
        const oib = '12345678901';
        const masked = maskOIB(oib);
        expect(masked).toBe('***********');
        expect(masked).not.toContain(oib);
      });

      it('should handle invalid OIB length', () => {
        const invalidOib = '123';
        const masked = maskOIB(invalidOib);
        expect(masked).toBe('INVALID_OIB');
      });

      it('should handle empty OIB', () => {
        const masked = maskOIB('');
        expect(masked).toBe('INVALID_OIB');
      });
    });

    describe('maskJIR', () => {
      it('should abbreviate JIR for readability', () => {
        const jir = 'a1b2c3d4-e5f6-7890-1234-567890abcdef';
        const masked = maskJIR(jir);
        expect(masked).toBe('a1b2c3d4...');
        expect(masked.length).toBeLessThan(jir.length);
      });

      it('should handle short JIR', () => {
        const shortJir = 'abc123';
        const masked = maskJIR(shortJir);
        expect(masked).toBe(shortJir);
      });

      it('should handle empty JIR', () => {
        const masked = maskJIR('');
        expect(masked).toBe('NO_JIR');
      });
    });
  });

  describe('Prometheus Metrics', () => {
    it('should increment fiscalizationTotal counter', () => {
      expect(() => {
        fiscalizationTotal.inc({ operation: 'racuni', status: 'success' });
      }).not.toThrow();
    });

    it('should observe fiscalizationDuration histogram', () => {
      expect(() => {
        fiscalizationDuration.observe({ operation: 'racuni' }, 2.5);
      }).not.toThrow();
    });

    it('should increment finaErrors counter', () => {
      expect(() => {
        finaErrors.inc({ error_code: 's:001' });
      }).not.toThrow();
    });

    it('should increment retryAttempts counter', () => {
      expect(() => {
        retryAttempts.inc({ operation: 'racuni', attempt: '1' });
      }).not.toThrow();
    });

    it('should set offlineQueueDepth gauge', () => {
      expect(() => {
        offlineQueueDepth.set(5);
      }).not.toThrow();
    });

    it('should set offlineQueueMaxAge gauge', () => {
      expect(() => {
        offlineQueueMaxAge.set(3600);
      }).not.toThrow();
    });

    it('should increment jirReceived counter', () => {
      expect(() => {
        jirReceived.inc();
      }).not.toThrow();
    });
  });
});
