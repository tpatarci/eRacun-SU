import IFlow from 'imapflow';
import { logger } from '../shared/logger.js';
import type { Config } from '../shared/config.js';
import type { UserConfig } from '../shared/types.js';

/**
 * Attachment found in email
 */
export interface EmailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}

/**
 * Email message with attachments
 */
export interface EmailMessage {
  messageId: string;
  subject: string;
  from: string;
  to: string;
  date: Date;
  attachments: EmailAttachment[];
}

/**
 * Email poller configuration
 */
export interface EmailPollerConfig {
  userId: string;
  host: string;
  port: number;
  user: string;
  password: string;
  mailbox?: string;
  markSeen?: boolean;
}

/**
 * Email poller for invoice ingestion
 */
class EmailPoller {
  private client: IFlow | null = null;
  private config: EmailPollerConfig;
  private polling = false;
  private pollInterval: NodeJS.Timeout | null = null;

  constructor(config: EmailPollerConfig) {
    if (!config.userId) {
      throw new Error('userId is required for EmailPoller');
    }
    this.config = {
      mailbox: 'INBOX',
      markSeen: true,
      ...config,
    };
  }

  /**
   * Start polling for emails
   */
  async start(
    onMessage: (message: EmailMessage) => Promise<void>,
    intervalMs = 60000 // Default: poll every minute
  ): Promise<void> {
    if (this.polling) {
      throw new Error('EmailPoller is already running');
    }

    this.polling = true;

    // Connect to IMAP server
    this.client = new IFlow({
      host: this.config.host,
      port: this.config.port,
      secure: true, // IMAPS
      auth: {
        user: this.config.user,
        pass: this.config.password,
      },
      logger: false, // Disable imapflow's internal logging
    });

    try {
      await this.client.connect();
      logger.info({
        userId: this.config.userId,
        host: this.config.host,
        mailbox: this.config.mailbox,
      }, 'Connected to IMAP server');

      // Select mailbox
      const mailbox = await this.client.mailboxOpen(this.config.mailbox!);
      logger.info({
        userId: this.config.userId,
        mailbox: this.config.mailbox,
        totalMessages: mailbox.exists,
      }, 'Mailbox opened');

      // Poll immediately on start
      await this.poll(onMessage);

      // Set up recurring polling
      this.pollInterval = setInterval(() => {
        this.poll(onMessage).catch((error) => {
          logger.error({
            userId: this.config.userId,
            error: error instanceof Error ? error.message : String(error),
          }, 'Error during email poll');
        });
      }, intervalMs);

      logger.info({
        userId: this.config.userId,
        intervalMs,
      }, 'Email polling started');
    } catch (error) {
      this.polling = false;
      await this.disconnect();
      throw error;
    }
  }

  /**
   * Poll for new emails
   */
  private async poll(
    onMessage: (message: EmailMessage) => Promise<void>
  ): Promise<void> {
    if (!this.client) {
      throw new Error('IMAP client not connected');
    }

    try {
      // Search for unread messages
      const searchCriteria = { seen: false };

      for await (const message of this.client.fetch(searchCriteria, {
        source: true,
        envelope: true,
        bodyStructure: true,
      })) {
        try {
          const emailMessage = await this.parseMessage(message);

          if (emailMessage.attachments.length > 0) {
            logger.info({
              userId: this.config.userId,
              messageId: emailMessage.messageId,
              attachmentCount: emailMessage.attachments.length,
            }, 'Found email with attachments');

            await onMessage(emailMessage);
          }

          // Mark as read if configured
          if (this.config.markSeen) {
            await this.client.messageFlagsSet(message.uid, ['\\Seen'], true);
          }
        } catch (error) {
          logger.error({
            userId: this.config.userId,
            messageId: message.envelope?.messageId,
            error: error instanceof Error ? error.message : String(error),
          }, 'Error processing email message');
        }
      }
    } catch (error) {
      logger.error({
        userId: this.config.userId,
        error: error instanceof Error ? error.message : String(error),
      }, 'Error fetching emails');
      throw error;
    }
  }

  /**
   * Parse IMAP message into EmailMessage
   */
  private async parseMessage(
    message: any
  ): Promise<EmailMessage> {
    const attachments: EmailAttachment[] = [];

    // Recursively extract attachments from message structure
    const extractAttachments = async (node: any): Promise<void> => {
      if (!node) return;

      // If this node has a filename and disposition, it's likely an attachment
      if (node.disposition?.type === 'attachment' || node.filename) {
        const filename = node.filename || 'attachment';
        const contentType = node.contentType || 'application/octet-stream';

        try {
          // Download attachment content
          const content = await this.client!.download(message.uid, node.part);
          if (content) {
            attachments.push({
              filename,
              content: Buffer.from(content),
              contentType,
            });
          }
        } catch (error) {
          logger.warn({
            userId: this.config.userId,
            filename,
            error: error instanceof Error ? error.message : String(error),
          }, 'Failed to download attachment');
        }
      }

      // Recursively process child nodes
      if (node.childNodes) {
        for (const child of node.childNodes) {
          await extractAttachments(child);
        }
      }
    };

    await extractAttachments(message.bodyStructure);

    return {
      messageId: message.envelope?.messageId || 'unknown',
      subject: message.envelope?.subject || '',
      from: message.envelope?.from?.[0]?.address || '',
      to: message.envelope?.to?.[0]?.address || '',
      date: message.envelope?.date ? new Date(message.envelope.date) : new Date(),
      attachments,
    };
  }

  /**
   * Stop polling and disconnect
   */
  async stop(): Promise<void> {
    this.polling = false;

    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }

    await this.disconnect();

    logger.info({
      userId: this.config.userId,
    }, 'Email polling stopped');
  }

  /**
   * Disconnect from IMAP server
   */
  private async disconnect(): Promise<void> {
    if (this.client) {
      try {
        await this.client.logout();
      } catch (error) {
        logger.error({
          userId: this.config.userId,
          error: error instanceof Error ? error.message : String(error),
        }, 'Error during IMAP logout');
      }
      this.client = null;
    }
  }
}

/**
 * Create email poller from global configuration
 * @deprecated Use createEmailPollerForUser instead for multi-user support
 */
export function createEmailPoller(config: Config, userId = 'default'): EmailPoller {
  if (!config.IMAP_HOST || !config.IMAP_USER || !config.IMAP_PASS) {
    throw new Error('IMAP configuration is incomplete. Set IMAP_HOST, IMAP_USER, and IMAP_PASS');
  }

  return new EmailPoller({
    userId,
    host: config.IMAP_HOST,
    port: config.IMAP_PORT,
    user: config.IMAP_USER,
    password: config.IMAP_PASS,
    mailbox: 'INBOX',
    markSeen: true,
  });
}

/**
 * Create email poller for a specific user from their stored configuration
 *
 * @param userConfig - User's IMAP configuration from database
 * @returns EmailPoller instance configured for the specific user
 * @throws Error if required IMAP fields are missing from user config
 */
export function createEmailPollerForUser(userConfig: UserConfig): EmailPoller {
  if (userConfig.serviceName !== 'imap') {
    throw new Error(`Expected 'imap' service name, got '${userConfig.serviceName}'`);
  }

  const imapConfig = userConfig.config as Record<string, unknown>;

  if (!imapConfig.host || !imapConfig.user || !imapConfig.password) {
    throw new Error('IMAP configuration is incomplete. Required: host, user, password');
  }

  return new EmailPoller({
    userId: userConfig.userId,
    host: imapConfig.host as string,
    port: (imapConfig.port as number) ?? 993,
    user: imapConfig.user as string,
    password: imapConfig.password as string,
    mailbox: (imapConfig.mailbox as string | undefined) ?? 'INBOX',
    markSeen: (imapConfig.markSeen as boolean | undefined) ?? true,
  });
}

export { EmailPoller };
