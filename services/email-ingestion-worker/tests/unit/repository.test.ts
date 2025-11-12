/**
 * Repository Module Tests
 */

import { EmailRepository } from '../../src/repository';

// Mock pg module
jest.mock('pg', () => {
  const mockClient = {
    query: jest.fn(),
    release: jest.fn(),
  };

  const mockPool = {
    connect: jest.fn(() => Promise.resolve(mockClient)),
    query: jest.fn(),
    end: jest.fn(),
    on: jest.fn(),
  };

  return {
    Pool: jest.fn(() => mockPool),
  };
});

describe('EmailRepository', () => {
  let repository: EmailRepository;
  let mockPool: any;
  let mockClient: any;

  beforeEach(() => {
    jest.clearAllMocks();

    repository = new EmailRepository({
      host: 'localhost',
      port: 5432,
      database: 'test',
      user: 'test',
      password: 'test',
    });

    mockPool = (repository as any).pool;
    mockClient = {
      query: jest.fn(),
      release: jest.fn(),
    };

    mockPool.connect.mockResolvedValue(mockClient);
  });

  describe('initialize', () => {
    it('should create database schema successfully', async () => {
      mockClient.query.mockResolvedValue({ rows: [], rowCount: 0 });

      await repository.initialize();

      expect(mockClient.query).toHaveBeenCalledWith('BEGIN');
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('CREATE TABLE IF NOT EXISTS processed_emails')
      );
      expect(mockClient.query).toHaveBeenCalledWith(
        expect.stringContaining('CREATE TABLE IF NOT EXISTS processed_attachments')
      );
      expect(mockClient.query).toHaveBeenCalledWith('COMMIT');
      expect(mockClient.release).toHaveBeenCalled();
    });

    it('should rollback on error', async () => {
      mockClient.query
        .mockResolvedValueOnce({ rows: [], rowCount: 0 }) // BEGIN
        .mockRejectedValueOnce(new Error('Schema creation failed'));

      await expect(repository.initialize()).rejects.toThrow(
        'Schema creation failed'
      );

      expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK');
      expect(mockClient.release).toHaveBeenCalled();
    });
  });

  describe('isEmailProcessed', () => {
    it('should return true if email exists', async () => {
      mockPool.query.mockResolvedValue({
        rows: [{ id: 1 }],
        rowCount: 1,
      });

      const result = await repository.isEmailProcessed(123);

      expect(result).toBe(true);
      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT 1 FROM processed_emails WHERE uid = $1',
        [123]
      );
    });

    it('should return false if email does not exist', async () => {
      mockPool.query.mockResolvedValue({
        rows: [],
        rowCount: 0,
      });

      const result = await repository.isEmailProcessed(123);

      expect(result).toBe(false);
    });
  });

  describe('isMessageIdProcessed', () => {
    it('should return true if message ID exists', async () => {
      mockPool.query.mockResolvedValue({
        rows: [{ id: 1 }],
        rowCount: 1,
      });

      const result = await repository.isMessageIdProcessed('<test@example.com>');

      expect(result).toBe(true);
      expect(mockPool.query).toHaveBeenCalledWith(
        'SELECT 1 FROM processed_emails WHERE message_id = $1',
        ['<test@example.com>']
      );
    });

    it('should return false if message ID does not exist', async () => {
      mockPool.query.mockResolvedValue({
        rows: [],
        rowCount: 0,
      });

      const result = await repository.isMessageIdProcessed('<test@example.com>');

      expect(result).toBe(false);
    });
  });

  describe('saveProcessedEmail', () => {
    it('should save processed email successfully', async () => {
      mockPool.query.mockResolvedValue({
        rows: [{ id: 42 }],
        rowCount: 1,
      });

      const emailId = await repository.saveProcessedEmail(
        123,
        '<test@example.com>',
        'Test Subject',
        'sender@example.com',
        ['recipient@example.com'],
        new Date('2024-01-01'),
        2,
        'success'
      );

      expect(emailId).toBe(42);
      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO processed_emails'),
        expect.arrayContaining([
          123,
          '<test@example.com>',
          'Test Subject',
          'sender@example.com',
          ['recipient@example.com'],
          expect.any(Date),
          2,
          'success',
          undefined,
        ])
      );
    });

    it('should save error status', async () => {
      mockPool.query.mockResolvedValue({
        rows: [{ id: 43 }],
        rowCount: 1,
      });

      const emailId = await repository.saveProcessedEmail(
        124,
        '<error@example.com>',
        'Error Email',
        'sender@example.com',
        [],
        new Date('2024-01-01'),
        0,
        'error',
        'Processing failed'
      );

      expect(emailId).toBe(43);
      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO processed_emails'),
        expect.arrayContaining(['error', 'Processing failed'])
      );
    });

    it('should handle database errors', async () => {
      mockPool.query.mockRejectedValue(new Error('Database error'));

      await expect(
        repository.saveProcessedEmail(
          123,
          '<test@example.com>',
          'Test',
          'from@example.com',
          [],
          new Date(),
          0
        )
      ).rejects.toThrow('Database error');
    });
  });

  describe('saveProcessedAttachment', () => {
    it('should save attachment successfully', async () => {
      mockPool.query.mockResolvedValue({
        rows: [],
        rowCount: 1,
      });

      await repository.saveProcessedAttachment(
        42,
        'attachment-id-123',
        'invoice.pdf',
        'application/pdf',
        1024,
        'abc123'
      );

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO processed_attachments'),
        [42, 'attachment-id-123', 'invoice.pdf', 'application/pdf', 1024, 'abc123']
      );
    });

    it('should handle database errors', async () => {
      mockPool.query.mockRejectedValue(new Error('Database error'));

      await expect(
        repository.saveProcessedAttachment(
          42,
          'attachment-id',
          'file.pdf',
          'application/pdf',
          1024,
          'checksum'
        )
      ).rejects.toThrow('Database error');
    });
  });

  describe('getProcessedEmailByUid', () => {
    it('should return processed email when found', async () => {
      mockPool.query.mockResolvedValue({
        rows: [
          {
            id: 1,
            uid: 123,
            message_id: '<test@example.com>',
            subject: 'Test Subject',
            from: 'sender@example.com',
            to: ['recipient@example.com'],
            date: new Date('2024-01-01'),
            attachment_count: 2,
            processed_at: new Date('2024-01-01T12:00:00Z'),
            status: 'success',
            error_message: null,
          },
        ],
        rowCount: 1,
      });

      const email = await repository.getProcessedEmailByUid(123);

      expect(email).not.toBeNull();
      expect(email?.uid).toBe(123);
      expect(email?.messageId).toBe('<test@example.com>');
      expect(email?.subject).toBe('Test Subject');
      expect(email?.status).toBe('success');
    });

    it('should return null when not found', async () => {
      mockPool.query.mockResolvedValue({
        rows: [],
        rowCount: 0,
      });

      const email = await repository.getProcessedEmailByUid(999);

      expect(email).toBeNull();
    });
  });

  describe('getRecentProcessedEmails', () => {
    it('should return recent emails', async () => {
      mockPool.query.mockResolvedValue({
        rows: [
          {
            id: 1,
            uid: 123,
            message_id: '<test1@example.com>',
            subject: 'Email 1',
            from: 'sender@example.com',
            to: [],
            date: new Date('2024-01-01'),
            attachment_count: 0,
            processed_at: new Date('2024-01-01T12:00:00Z'),
            status: 'success',
            error_message: null,
          },
          {
            id: 2,
            uid: 124,
            message_id: '<test2@example.com>',
            subject: 'Email 2',
            from: 'sender@example.com',
            to: [],
            date: new Date('2024-01-02'),
            attachment_count: 1,
            processed_at: new Date('2024-01-02T12:00:00Z'),
            status: 'success',
            error_message: null,
          },
        ],
        rowCount: 2,
      });

      const emails = await repository.getRecentProcessedEmails(100);

      expect(emails).toHaveLength(2);
      expect(emails[0].uid).toBe(123);
      expect(emails[1].uid).toBe(124);
    });

    it('should use custom limit', async () => {
      mockPool.query.mockResolvedValue({
        rows: [],
        rowCount: 0,
      });

      await repository.getRecentProcessedEmails(50);

      expect(mockPool.query).toHaveBeenCalledWith(
        expect.any(String),
        [50]
      );
    });
  });

  describe('getAttachmentsForEmail', () => {
    it('should return attachments for email', async () => {
      mockPool.query.mockResolvedValue({
        rows: [
          {
            id: 1,
            email_id: 42,
            attachment_id: 'att-1',
            filename: 'file1.pdf',
            content_type: 'application/pdf',
            size: 1024,
            checksum: 'abc123',
            published_at: new Date('2024-01-01T12:00:00Z'),
          },
        ],
        rowCount: 1,
      });

      const attachments = await repository.getAttachmentsForEmail(42);

      expect(attachments).toHaveLength(1);
      expect(attachments[0].attachmentId).toBe('att-1');
      expect(attachments[0].filename).toBe('file1.pdf');
    });
  });

  describe('getStatistics', () => {
    it('should return processing statistics', async () => {
      mockPool.query
        .mockResolvedValueOnce({
          rows: [
            {
              total: '100',
              successful: '95',
              failed: '5',
            },
          ],
          rowCount: 1,
        })
        .mockResolvedValueOnce({
          rows: [
            {
              total: '200',
            },
          ],
          rowCount: 1,
        });

      const stats = await repository.getStatistics();

      expect(stats.totalEmails).toBe(100);
      expect(stats.successfulEmails).toBe(95);
      expect(stats.failedEmails).toBe(5);
      expect(stats.totalAttachments).toBe(200);
    });
  });

  describe('close', () => {
    it('should close database connection pool', async () => {
      await repository.close();

      expect(mockPool.end).toHaveBeenCalled();
    });
  });
});
