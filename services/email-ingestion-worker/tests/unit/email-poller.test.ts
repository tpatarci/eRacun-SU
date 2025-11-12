/**
 * Email Poller Module Tests
 */

import { EmailPoller, EmailPollerConfig } from '../../src/email-poller';
import { ImapClient } from '../../src/imap-client';
import { EventEmitter } from 'events';

// Mock ImapClient
jest.mock('../../src/imap-client');

describe('EmailPoller', () => {
  let mockImapClient: jest.Mocked<ImapClient>;
  let mockProcessor: jest.Mock;
  let config: EmailPollerConfig;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Create mock IMAP client
    mockImapClient = new (EventEmitter as any)() as jest.Mocked<ImapClient>;
    mockImapClient.getConnectionStatus = jest.fn().mockReturnValue(true);
    mockImapClient.openMailbox = jest.fn().mockResolvedValue({
      name: 'INBOX',
      messages: {
        total: 10,
        unseen: 5,
        new: 2,
      },
    });
    mockImapClient.searchMessages = jest.fn().mockResolvedValue([1, 2, 3, 4, 5]);
    mockImapClient.markAsSeen = jest.fn().mockResolvedValue(undefined);
    mockImapClient.connect = jest.fn().mockResolvedValue(undefined);

    // Create mock processor
    mockProcessor = jest.fn().mockResolvedValue(undefined);

    // Default config
    config = {
      schedule: '*/5 * * * *',
      mailbox: 'INBOX',
      batchSize: 10,
      enabled: true,
    };
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Constructor', () => {
    it('should create EmailPoller instance', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      expect(poller).toBeInstanceOf(EmailPoller);
    });

    it('should store configuration', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      const storedConfig = poller.getConfig();
      expect(storedConfig).toEqual(config);
    });
  });

  describe('start', () => {
    it('should start polling with valid cron schedule', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();
      expect(poller.isRunning()).toBe(true);
    });

    it('should not start if already running', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();
      const firstStart = poller.isRunning();
      poller.start(); // Second start attempt
      expect(firstStart).toBe(true);
      expect(poller.isRunning()).toBe(true);
    });

    it('should not start if polling is disabled', () => {
      const disabledConfig = { ...config, enabled: false };
      const poller = new EmailPoller(disabledConfig, mockImapClient, mockProcessor);
      poller.start();
      expect(poller.isRunning()).toBe(false);
    });

    it('should throw error for invalid cron expression', () => {
      const invalidConfig = { ...config, schedule: 'invalid cron' };
      const poller = new EmailPoller(invalidConfig, mockImapClient, mockProcessor);
      expect(() => poller.start()).toThrow('Invalid cron expression');
    });

    it('should run initial poll immediately', async () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();

      // Wait for setImmediate
      await new Promise((resolve) => setImmediate(resolve));

      expect(mockImapClient.openMailbox).toHaveBeenCalled();
    });
  });

  describe('stop', () => {
    it('should stop polling', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();
      expect(poller.isRunning()).toBe(true);

      poller.stop();
      expect(poller.isRunning()).toBe(false);
    });

    it('should handle stop when not running', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      expect(() => poller.stop()).not.toThrow();
    });
  });

  describe('poll', () => {
    it('should poll inbox and process unread messages', async () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      expect(mockImapClient.openMailbox).toHaveBeenCalledWith('INBOX', false);
      expect(mockImapClient.searchMessages).toHaveBeenCalledWith(['UNSEEN']);
      expect(mockProcessor).toHaveBeenCalledTimes(5);
      expect(mockProcessor).toHaveBeenCalledWith(1);
      expect(mockProcessor).toHaveBeenCalledWith(5);
    });

    it('should skip poll if already in progress', async () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      // Start first poll
      const firstPoll = poller.poll();

      // Try to start second poll
      const secondPoll = poller.poll();

      await Promise.all([firstPoll, secondPoll]);

      // Should only open mailbox once
      expect(mockImapClient.openMailbox).toHaveBeenCalledTimes(1);
    });

    it('should connect IMAP client if not connected', async () => {
      mockImapClient.getConnectionStatus.mockReturnValue(false);
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      expect(mockImapClient.connect).toHaveBeenCalled();
    });

    it('should not process emails if none are unread', async () => {
      mockImapClient.openMailbox.mockResolvedValue({
        name: 'INBOX',
        messages: {
          total: 10,
          unseen: 0,
          new: 0,
        },
      } as any);

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      expect(mockImapClient.searchMessages).not.toHaveBeenCalled();
      expect(mockProcessor).not.toHaveBeenCalled();
    });

    it('should limit batch size', async () => {
      const smallBatchConfig = { ...config, batchSize: 2 };
      const poller = new EmailPoller(smallBatchConfig, mockImapClient, mockProcessor);

      await poller.poll();

      // Should only process first 2 UIDs
      expect(mockProcessor).toHaveBeenCalledTimes(2);
      expect(mockProcessor).toHaveBeenCalledWith(1);
      expect(mockProcessor).toHaveBeenCalledWith(2);
      expect(mockProcessor).not.toHaveBeenCalledWith(3);
    });

    it('should mark successfully processed emails as seen', async () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      expect(mockImapClient.markAsSeen).toHaveBeenCalledTimes(5);
      expect(mockImapClient.markAsSeen).toHaveBeenCalledWith(1);
      expect(mockImapClient.markAsSeen).toHaveBeenCalledWith(5);
    });

    it('should not mark failed emails as seen', async () => {
      mockProcessor.mockRejectedValueOnce(new Error('Processing failed'));

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      // First email failed, so only 4 should be marked as seen
      expect(mockImapClient.markAsSeen).toHaveBeenCalledTimes(4);
    });

    it('should continue processing after individual email failure', async () => {
      mockProcessor
        .mockResolvedValueOnce(undefined) // UID 1: success
        .mockRejectedValueOnce(new Error('Failed')) // UID 2: failure
        .mockResolvedValueOnce(undefined) // UID 3: success
        .mockResolvedValueOnce(undefined) // UID 4: success
        .mockResolvedValueOnce(undefined); // UID 5: success

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      // All 5 should be attempted
      expect(mockProcessor).toHaveBeenCalledTimes(5);
      // Only 4 successful should be marked as seen
      expect(mockImapClient.markAsSeen).toHaveBeenCalledTimes(4);
    });

    it('should handle empty search results', async () => {
      mockImapClient.searchMessages.mockResolvedValue([]);

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await poller.poll();

      expect(mockProcessor).not.toHaveBeenCalled();
    });

    it('should handle IMAP connection errors', async () => {
      mockImapClient.connect.mockRejectedValue(new Error('Connection failed'));
      mockImapClient.getConnectionStatus.mockReturnValue(false);

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await expect(poller.poll()).rejects.toThrow('Connection failed');
    });

    it('should handle mailbox open errors', async () => {
      mockImapClient.openMailbox.mockRejectedValue(
        new Error('Mailbox not found')
      );

      const poller = new EmailPoller(config, mockImapClient, mockProcessor);

      await expect(poller.poll()).rejects.toThrow('Mailbox not found');
    });
  });

  describe('isRunning', () => {
    it('should return false when not started', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      expect(poller.isRunning()).toBe(false);
    });

    it('should return true when started', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();
      expect(poller.isRunning()).toBe(true);
    });

    it('should return false after stopped', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      poller.start();
      poller.stop();
      expect(poller.isRunning()).toBe(false);
    });
  });

  describe('getConfig', () => {
    it('should return configuration copy', () => {
      const poller = new EmailPoller(config, mockImapClient, mockProcessor);
      const retrievedConfig = poller.getConfig();

      expect(retrievedConfig).toEqual(config);
      expect(retrievedConfig).not.toBe(config); // Should be a copy
    });
  });
});
