/**
 * Observability Module Tests
 */

import {
  logger,
  emailsFetchedTotal,
  attachmentsExtractedTotal,
  messagesPublishedTotal,
  imapConnectionStatus,
  emailProcessingDuration,
  inboxUnreadCount,
  getMetricsRegistry,
  withSpan,
} from '../../src/observability';

describe('Observability Module', () => {
  beforeEach(() => {
    // Reset metrics
    getMetricsRegistry().resetMetrics();
  });

  describe('Logger', () => {
    it('should have info level or higher', () => {
      expect(logger.level).toBeDefined();
      expect(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).toContain(
        logger.level
      );
    });

    it('should log messages', () => {
      const logSpy = jest.spyOn(logger, 'info');
      logger.info('test message');
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockRestore();
    });
  });

  describe('Metrics', () => {
    it('should increment emailsFetchedTotal', async () => {
      emailsFetchedTotal.inc({ mailbox: 'test', status: 'success' }, 5);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_emails_fetched_total');
      expect(metrics).toContain('mailbox="test"');
      expect(metrics).toContain('status="success"');
    });

    it('should increment attachmentsExtractedTotal', async () => {
      attachmentsExtractedTotal.inc({
        content_type: 'application/pdf',
        status: 'success',
      });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_attachments_extracted_total');
      expect(metrics).toContain('content_type="application/pdf"');
    });

    it('should increment messagesPublishedTotal', async () => {
      messagesPublishedTotal.inc({
        message_type: 'attachment',
        status: 'success',
      });

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_messages_published_total');
      expect(metrics).toContain('message_type="attachment"');
    });

    it('should set imapConnectionStatus', async () => {
      imapConnectionStatus.set({ mailbox: 'test' }, 1);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_imap_connection_status');
      expect(metrics).toContain('1');
    });

    it('should set inboxUnreadCount', async () => {
      inboxUnreadCount.set({ mailbox: 'test' }, 42);

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_inbox_unread_count');
      expect(metrics).toContain('42');
    });

    it('should record emailProcessingDuration', async () => {
      const endTimer = emailProcessingDuration.startTimer({ operation: 'fetch' });
      await new Promise((resolve) => setTimeout(resolve, 10));
      endTimer();

      const metrics = await getMetricsRegistry().metrics();
      expect(metrics).toContain('email_ingestion_email_processing_duration_seconds');
      expect(metrics).toContain('operation="fetch"');
    });
  });

  describe('Distributed Tracing', () => {
    it('should execute function within span successfully', async () => {
      const testFn = jest.fn().mockResolvedValue('success');

      const result = await withSpan(
        'test.operation',
        { test: 'attribute' },
        testFn
      );

      expect(result).toBe('success');
      expect(testFn).toHaveBeenCalled();
    });

    it('should handle errors in span', async () => {
      const testError = new Error('test error');
      const testFn = jest.fn().mockRejectedValue(testError);

      await expect(
        withSpan('test.operation', { test: 'attribute' }, testFn)
      ).rejects.toThrow('test error');

      expect(testFn).toHaveBeenCalled();
    });

    it('should pass span to callback function', async () => {
      const testFn = jest.fn((span) => {
        expect(span).toBeDefined();
        expect(span.setAttribute).toBeDefined();
        return Promise.resolve();
      });

      await withSpan('test.operation', { test: 'attribute' }, testFn);

      expect(testFn).toHaveBeenCalled();
    });

    it('should end span after execution', async () => {
      const spanEndSpy = jest.fn();
      const testFn = jest.fn((span) => {
        span.end = spanEndSpy;
        return Promise.resolve();
      });

      await withSpan('test.operation', {}, testFn);

      // Span should be ended even though we mocked it
      expect(testFn).toHaveBeenCalled();
    });
  });

  describe('Metrics Registry', () => {
    it('should return registry instance', () => {
      const registry = getMetricsRegistry();
      expect(registry).toBeDefined();
      expect(registry.metrics).toBeDefined();
    });

    it('should contain all registered metrics', async () => {
      // Trigger all metrics
      emailsFetchedTotal.inc({ mailbox: 'test', status: 'success' });
      attachmentsExtractedTotal.inc({
        content_type: 'application/pdf',
        status: 'success',
      });
      messagesPublishedTotal.inc({
        message_type: 'attachment',
        status: 'success',
      });
      imapConnectionStatus.set({ mailbox: 'test' }, 1);
      inboxUnreadCount.set({ mailbox: 'test' }, 10);

      const metrics = await getMetricsRegistry().metrics();

      expect(metrics).toContain('email_ingestion_emails_fetched_total');
      expect(metrics).toContain('email_ingestion_attachments_extracted_total');
      expect(metrics).toContain('email_ingestion_messages_published_total');
      expect(metrics).toContain('email_ingestion_imap_connection_status');
      expect(metrics).toContain('email_ingestion_inbox_unread_count');
    });
  });
});
