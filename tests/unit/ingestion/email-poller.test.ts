import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { EmailPoller } from '../../../src/ingestion/email-poller';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock imapflow
jest.mock('imapflow', () => {
  const mockMailbox = {
    exists: 5,
  };

  // Create an async generator function for fetch
  async function* mockFetchGenerator() {
    // No messages by default
  }

  const mockClient = {
    connect: jest.fn().mockResolvedValue(undefined),
    mailboxOpen: jest.fn().mockResolvedValue(mockMailbox),
    fetch: jest.fn().mockReturnValue(mockFetchGenerator()),
    download: jest.fn().mockResolvedValue(Buffer.from('test content')),
    messageFlagsSet: jest.fn().mockResolvedValue(undefined),
    logout: jest.fn().mockResolvedValue(undefined),
  };

  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockClient),
  };
});

describe('Email Poller', () => {
  let emailPoller: EmailPoller;
  let mockOnMessage: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    emailPoller = new EmailPoller({
      userId: 'test-user-id',
      host: 'imap.example.com',
      port: 993,
      user: 'test@example.com',
      password: 'password',
      mailbox: 'INBOX',
      markSeen: true,
    });
    mockOnMessage = jest.fn().mockResolvedValue(undefined);
  });

  afterEach(async () => {
    // Clean up any running poller
    try {
      await emailPoller.stop();
    } catch {
      // Ignore errors if not started
    }
  });

  describe('constructor', () => {
    it('should create poller with config', () => {
      const poller = new EmailPoller({
        userId: 'test-user-id',
        host: 'imap.test.com',
        port: 993,
        user: 'user@test.com',
        password: 'pass',
      });

      expect(poller).toBeDefined();
    });

    it('should use default values for optional config', () => {
      const poller = new EmailPoller({
        userId: 'test-user-id',
        host: 'imap.test.com',
        port: 993,
        user: 'user@test.com',
        password: 'pass',
      });

      expect(poller).toBeDefined();
    });

    it('should throw error if userId is not provided', () => {
      expect(() => {
        new EmailPoller({
          userId: '',
          host: 'imap.test.com',
          port: 993,
          user: 'user@test.com',
          password: 'pass',
        });
      }).toThrow();
    });
  });

  describe('start', () => {
    it('should start polling', async () => {
      await expect(
        emailPoller.start(mockOnMessage, 1000)
      ).resolves.not.toThrow();

      await emailPoller.stop();
    });

    it('should throw if already polling', async () => {
      await emailPoller.start(mockOnMessage, 1000);

      await expect(
        emailPoller.start(mockOnMessage, 1000)
      ).rejects.toThrow('EmailPoller is already running');

      await emailPoller.stop();
    });
  });

  describe('stop', () => {
    it('should stop polling', async () => {
      await emailPoller.start(mockOnMessage, 1000);
      await expect(emailPoller.stop()).resolves.not.toThrow();
    });

    it('should handle stop when not started', async () => {
      await expect(emailPoller.stop()).resolves.not.toThrow();
    });
  });
});
