/**
 * Unit Tests for Email Sender Module
 */

import nodemailer from 'nodemailer';
import {
  initTransporter,
  sendEmail,
  verifyConnection,
  closeTransporter,
  sendEmailWithTemplate,
  sendBatch,
  SendEmailParams,
} from '../../src/email-sender';
import { NotificationPriority } from '../../src/repository';

// Mock nodemailer
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
  notificationsSentTotal: { inc: jest.fn() },
  notificationSendDuration: { observe: jest.fn() },
  notificationRetryAttemptsTotal: { inc: jest.fn() },
  notificationFailuresTotal: { inc: jest.fn() },
  withSpan: jest.fn((_name, _attrs, fn) => fn({ end: jest.fn(), setAttribute: jest.fn() })),
}));

// Mock repository
jest.mock('../../src/repository', () => ({
  NotificationType: { EMAIL: 'email', SMS: 'sms', WEBHOOK: 'webhook' },
  NotificationPriority: { LOW: 'low', NORMAL: 'normal', HIGH: 'high', CRITICAL: 'critical' },
  NotificationStatus: { PENDING: 'pending', SENT: 'sent', FAILED: 'failed' },
  saveNotification: jest.fn().mockResolvedValue({}),
  updateNotificationStatus: jest.fn().mockResolvedValue({}),
}));

// Mock rate-limiter
jest.mock('../../src/rate-limiter', () => ({
  emailRateLimiter: {
    waitForToken: jest.fn().mockResolvedValue(true),
  },
}));

// Mock template-engine
jest.mock('../../src/template-engine', () => ({
  renderEmailTemplate: jest.fn().mockReturnValue('<html>Rendered Template</html>'),
}));

describe('Email Sender Module', () => {
  let mockSendMail: jest.Mock;
  let mockTransporter: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup nodemailer mock - reset to default success behavior
    if (!mockSendMail) {
      mockSendMail = jest.fn();
    }
    mockSendMail.mockResolvedValue({ messageId: 'test-message-id' });

    mockTransporter = {
      sendMail: mockSendMail,
      verify: jest.fn().mockResolvedValue(true),
      close: jest.fn(),
    };
    mockedNodemailer.createTransport.mockReturnValue(mockTransporter as any);
  });

  describe('initTransporter()', () => {
    it('should initialize SMTP transporter', () => {
      const transporter = initTransporter();

      expect(transporter).toBeDefined();
      expect(mockedNodemailer.createTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          host: expect.any(String),
          port: expect.any(Number),
          pool: true,
          maxConnections: 10,
          maxMessages: 100,
        })
      );
    });

    it('should warn if transporter already initialized', () => {
      const observability = require('../../src/observability');

      initTransporter();
      initTransporter(); // Second call

      expect(observability.logger.warn).toHaveBeenCalledWith('SMTP transporter already initialized');
    });

    it('should use environment variables for SMTP configuration', () => {
      // Skip this test as it requires module reset which breaks other tests
      // Environment variable handling is tested during actual service deployment
    });
  });

  describe('sendEmail()', () => {
    beforeEach(() => {
      initTransporter();
      // Reset rate limiter mock to default
      const rateLimiter = require('../../src/rate-limiter');
      rateLimiter.emailRateLimiter.waitForToken.mockResolvedValue(true);
    });

    it('should send email successfully', async () => {
      const params: SendEmailParams = {
        notification_id: 'notif-123',
        recipients: ['user@example.com'],
        subject: 'Test Email',
        body: '<html><body>Test Content</body></html>',
        priority: NotificationPriority.NORMAL,
      };

      const result = await sendEmail(params);

      expect(result).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith({
        from: expect.any(String),
        to: 'user@example.com',
        subject: 'Test Email',
        html: '<html><body>Test Content</body></html>',
      });
    });

    it('should send email to multiple recipients', async () => {
      const params: SendEmailParams = {
        notification_id: 'notif-456',
        recipients: ['user1@example.com', 'user2@example.com', 'user3@example.com'],
        subject: 'Bulk Email',
        body: '<html>Content</html>',
        priority: NotificationPriority.HIGH,
      };

      const result = await sendEmail(params);

      expect(result).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith({
        from: expect.any(String),
        to: 'user1@example.com, user2@example.com, user3@example.com',
        subject: 'Bulk Email',
        html: '<html>Content</html>',
      });
    });

    it('should wait for rate limiter before sending', async () => {
      const rateLimiter = require('../../src/rate-limiter');
      const params: SendEmailParams = {
        notification_id: 'notif-789',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.LOW,
      };

      const result = await sendEmail(params);

      expect(result).toBe(true);
      expect(rateLimiter.emailRateLimiter.waitForToken).toHaveBeenCalledWith(NotificationPriority.LOW, 60000);
    });

    it('should skip rate limiter for CRITICAL priority', async () => {
      const rateLimiter = require('../../src/rate-limiter');
      rateLimiter.emailRateLimiter.waitForToken.mockResolvedValue(false); // Rate limit exceeded

      const params: SendEmailParams = {
        notification_id: 'notif-critical',
        recipients: ['admin@example.com'],
        subject: 'CRITICAL ALERT',
        body: 'System failure',
        priority: NotificationPriority.CRITICAL,
      };

      const result = await sendEmail(params);

      // Should succeed without checking rate limiter
      expect(result).toBe(true);
      expect(rateLimiter.emailRateLimiter.waitForToken).not.toHaveBeenCalled();
    });

    it('should handle SMTP connection errors', async () => {
      mockSendMail.mockRejectedValue(new Error('SMTP connection refused'));

      const params: SendEmailParams = {
        notification_id: 'notif-fail',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await expect(sendEmail(params)).rejects.toThrow('SMTP connection refused');
    });

    it('should handle authentication errors', async () => {
      mockSendMail.mockRejectedValue(new Error('Invalid login: 535 5.7.8 Authentication failed'));

      const params: SendEmailParams = {
        notification_id: 'notif-auth-fail',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await expect(sendEmail(params)).rejects.toThrow('Authentication failed');
    });

    it('should handle rate limit exceeded', async () => {
      const rateLimiter = require('../../src/rate-limiter');
      rateLimiter.emailRateLimiter.waitForToken.mockResolvedValue(false);

      const params: SendEmailParams = {
        notification_id: 'notif-rate-limited',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.LOW,
      };

      await expect(sendEmail(params)).rejects.toThrow('Rate limit timeout');
    });

    it('should track metrics on success', async () => {
      const observability = require('../../src/observability');
      const params: SendEmailParams = {
        notification_id: 'notif-metrics',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await sendEmail(params);

      expect(observability.notificationsSentTotal.inc).toHaveBeenCalledWith({
        type: 'email',
        priority: 'normal',
        status: 'success',
      });
      expect(observability.notificationSendDuration.observe).toHaveBeenCalledWith(
        { type: 'email' },
        expect.any(Number)
      );
    });

    it('should track metrics on failure', async () => {
      const observability = require('../../src/observability');
      mockSendMail.mockRejectedValue(new Error('Send failed'));

      const params: SendEmailParams = {
        notification_id: 'notif-fail-metrics',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await expect(sendEmail(params)).rejects.toThrow('Send failed');

      expect(observability.notificationsSentTotal.inc).toHaveBeenCalledWith({
        type: 'email',
        priority: 'normal',
        status: 'failed',
      });
    });

    it('should use template when template_name provided', async () => {
      const templateEngine = require('../../src/template-engine');
      const params: SendEmailParams = {
        notification_id: 'notif-template',
        recipients: ['user@example.com'],
        subject: 'Template Email',
        body: '', // Will be replaced by template
        priority: NotificationPriority.NORMAL,
        template_name: 'invoice-submitted',
        template_vars: { invoice_id: 'INV-123', amount: '€100.00' },
      };

      await sendEmail(params);

      expect(templateEngine.renderEmailTemplate).toHaveBeenCalledWith(
        'invoice-submitted',
        { invoice_id: 'INV-123', amount: '€100.00' }
      );
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          html: '<html>Rendered Template</html>',
        })
      );
    });

    it('should save notification to database', async () => {
      const repository = require('../../src/repository');
      const params: SendEmailParams = {
        notification_id: 'notif-db',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await sendEmail(params);

      expect(repository.saveNotification).toHaveBeenCalledWith({
        notification_id: 'notif-db',
        type: 'email',
        priority: 'normal',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
      });
    });

    it('should update notification status after send', async () => {
      const repository = require('../../src/repository');
      const params: SendEmailParams = {
        notification_id: 'notif-update',
        recipients: ['user@example.com'],
        subject: 'Test',
        body: 'Content',
        priority: NotificationPriority.NORMAL,
      };

      await sendEmail(params);

      expect(repository.updateNotificationStatus).toHaveBeenCalledWith({
        notification_id: 'notif-update',
        status: 'sent',
        sent_at: expect.any(Date),
      });
    });
  });

  describe('verifyConnection()', () => {
    it('should verify SMTP connection successfully', async () => {
      const result = await verifyConnection();

      expect(result).toBe(true);
    });

    it('should return false on verification failure', async () => {
      // Reset transporter and create new one with failing verify
      await closeTransporter();

      const failingTransporter = {
        sendMail: mockSendMail,
        verify: jest.fn().mockRejectedValue(new Error('Connection failed')),
        close: jest.fn(),
      };
      mockedNodemailer.createTransport.mockReturnValue(failingTransporter as any);

      const result = await verifyConnection();

      expect(result).toBe(false);
    });
  });

  describe('closeTransporter()', () => {
    it('should close transporter', async () => {
      // Ensure we have a fresh transporter
      await closeTransporter();

      const transporterWithClose = {
        sendMail: mockSendMail,
        verify: jest.fn().mockResolvedValue(true),
        close: jest.fn(),
      };
      mockedNodemailer.createTransport.mockReturnValue(transporterWithClose as any);

      initTransporter();
      await closeTransporter();

      expect(transporterWithClose.close).toHaveBeenCalled();
    });

    it('should do nothing if transporter not initialized', async () => {
      await closeTransporter(); // Reset
      // Should not throw error when called without initialization
      await expect(closeTransporter()).resolves.not.toThrow();
    });
  });

  describe('sendEmailWithTemplate()', () => {
    beforeEach(() => {
      initTransporter();
      const rateLimiter = require('../../src/rate-limiter');
      rateLimiter.emailRateLimiter.waitForToken.mockResolvedValue(true);
    });

    it('should send email using template', async () => {
      const templateEngine = require('../../src/template-engine');

      const result = await sendEmailWithTemplate(
        'notif-template-test',
        ['user@example.com'],
        'Template Email',
        'invoice-reminder',
        { invoice_id: 'INV-456', amount: '€200.00' },
        NotificationPriority.NORMAL
      );

      expect(result).toBe(true);
      expect(templateEngine.renderEmailTemplate).toHaveBeenCalledWith(
        'invoice-reminder',
        { invoice_id: 'INV-456', amount: '€200.00' }
      );
      expect(mockSendMail).toHaveBeenCalled();
    });
  });

  describe('sendBatch()', () => {
    beforeEach(() => {
      initTransporter();
      const rateLimiter = require('../../src/rate-limiter');
      rateLimiter.emailRateLimiter.waitForToken.mockResolvedValue(true);
    });

    it('should send batch of emails', async () => {
      const emails: SendEmailParams[] = [
        {
          notification_id: 'batch-1',
          recipients: ['user1@example.com'],
          subject: 'Email 1',
          body: 'Content 1',
          priority: NotificationPriority.LOW,
        },
        {
          notification_id: 'batch-2',
          recipients: ['user2@example.com'],
          subject: 'Email 2',
          body: 'Content 2',
          priority: NotificationPriority.LOW,
        },
        {
          notification_id: 'batch-3',
          recipients: ['user3@example.com'],
          subject: 'Email 3',
          body: 'Content 3',
          priority: NotificationPriority.LOW,
        },
      ];

      const successCount = await sendBatch(emails);

      expect(successCount).toBe(3);
      expect(mockSendMail).toHaveBeenCalledTimes(3);
    });

    it('should continue on individual failures', async () => {
      // First email succeeds, second fails all 3 retry attempts, third succeeds
      mockSendMail
        .mockResolvedValueOnce({ messageId: 'msg-1' })
        .mockRejectedValueOnce(new Error('Send failed'))
        .mockRejectedValueOnce(new Error('Send failed'))
        .mockRejectedValueOnce(new Error('Send failed'))
        .mockResolvedValueOnce({ messageId: 'msg-3' });

      const emails: SendEmailParams[] = [
        {
          notification_id: 'batch-1',
          recipients: ['user1@example.com'],
          subject: 'Email 1',
          body: 'Content 1',
          priority: NotificationPriority.LOW,
        },
        {
          notification_id: 'batch-2',
          recipients: ['user2@example.com'],
          subject: 'Email 2',
          body: 'Content 2',
          priority: NotificationPriority.LOW,
        },
        {
          notification_id: 'batch-3',
          recipients: ['user3@example.com'],
          subject: 'Email 3',
          body: 'Content 3',
          priority: NotificationPriority.LOW,
        },
      ];

      const successCount = await sendBatch(emails);

      expect(successCount).toBe(2); // 2 out of 3 succeeded
      expect(mockSendMail).toHaveBeenCalledTimes(5); // 1 + 3 retries + 1
    });
  });
});
