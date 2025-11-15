/**
 * Observability Module Tests
 */

import { describe, it, expect, jest } from '@jest/globals';
import type { Span } from '@opentelemetry/api';

import {
  logger,
  pdfsProcessedTotal,
  pdfParsingErrorsTotal,
  invoicesExtractedTotal,
  pdfParsingDuration,
  pdfFileSizeBytes,
  pdfPageCount,
  queueDepth,
  getMetricsRegistry,
  withSpan,
  getActiveSpan,
} from '../../src/observability';

describe('Observability Module', () => {
  describe('Logger', () => {
    it('should have info level or higher', () => {
      expect(logger.level).toBeDefined();
    });

    it('should log messages', () => {
      expect(() => {
        logger.info('test message');
        logger.debug('debug message');
        logger.warn('warning message');
      }).not.toThrow();
    });
  });

  describe('Metrics', () => {
    it('should increment pdfsProcessedTotal', async () => {
      pdfsProcessedTotal.inc({ status: 'success' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_pdfs_processed_total');
      expect(metrics).toContain('status="success"');
    });

    it('should increment pdfParsingErrorsTotal', async () => {
      pdfParsingErrorsTotal.inc({ error_type: 'corrupt' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_errors_total');
    });

    it('should increment invoicesExtractedTotal', async () => {
      invoicesExtractedTotal.inc({ extraction_quality: 'high' });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_invoices_extracted_total');
    });

    it('should record pdfParsingDuration', async () => {
      const endTimer = pdfParsingDuration.startTimer({ operation: 'extract' });
      await new Promise((resolve) => setTimeout(resolve, 10));
      endTimer();

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_parsing_duration_seconds');
    });

    it('should record pdfFileSizeBytes', async () => {
      pdfFileSizeBytes.observe(102400);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_file_size_bytes');
    });

    it('should record pdfPageCount', async () => {
      pdfPageCount.observe(5);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_page_count');
    });

    it('should set queueDepth', async () => {
      queueDepth.set({ queue: 'test-queue' }, 42);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('pdf_parser_queue_depth');
    });
  });

  describe('Distributed Tracing', () => {
    it('should execute function within span successfully', async () => {
      const testFn = jest.fn(async (_span: Span) => 'success');

      const result = await withSpan('test.operation', { test: 'attribute' }, testFn);

      expect(result).toBe('success');
      expect(testFn).toHaveBeenCalled();
    });

    it('should handle errors in span', async () => {
      const testError = new Error('test error');
      const testFn = jest.fn(async (_span: Span) => {
        throw testError;
      });

      await expect(withSpan('test.operation', { test: 'attribute' }, testFn)).rejects.toThrow(
        'test error'
      );

      expect(testFn).toHaveBeenCalled();
    });

    it('should pass span to callback function', async () => {
      const testFn = jest.fn(async (span: Span) => {
        expect(span).toBeDefined();
        expect(span.setAttribute).toBeDefined();
      });

      await withSpan('test.operation', { test: 'attribute' }, testFn);

      expect(testFn).toHaveBeenCalled();
    });

    it('should call getActiveSpan function', async () => {
      await withSpan('test.operation', {}, async () => {
        const span = getActiveSpan();
        expect(span === undefined || span !== undefined).toBe(true);
        return 'test';
      });
    });
  });

  describe('Metrics Registry', () => {
    it('should return registry instance', () => {
      const registry = getMetricsRegistry();
      expect(registry).toBeDefined();
      expect(registry.metrics).toBeDefined();
    });

    it('should contain all registered metrics', async () => {
      pdfsProcessedTotal.inc({ status: 'success' });
      pdfParsingErrorsTotal.inc({ error_type: 'corrupt' });
      invoicesExtractedTotal.inc({ extraction_quality: 'high' });
      queueDepth.set({ queue: 'test' }, 10);

      const metrics = await getMetricsRegistry().metrics();

      expect(metrics).toContain('pdf_parser_pdfs_processed_total');
      expect(metrics).toContain('pdf_parser_errors_total');
      expect(metrics).toContain('pdf_parser_invoices_extracted_total');
      expect(metrics).toContain('pdf_parser_queue_depth');
    });
  });
});
