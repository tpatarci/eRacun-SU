/**
 * IMAP Client Module
 *
 * Manages IMAP connection lifecycle for email monitoring.
 * - Connection management with automatic reconnection
 * - Exponential backoff retry logic
 * - Mailbox operations (select, search, fetch)
 * - Connection status monitoring
 */

import Imap from 'imap';
import { EventEmitter } from 'events';
import {
  logger,
  imapConnectionStatus,
  emailsFetchedTotal,
  withSpan,
} from './observability';

/**
 * IMAP connection configuration
 */
export interface ImapConfig {
  user: string;
  password: string;
  host: string;
  port: number;
  tls: boolean;
  tlsOptions?: {
    rejectUnauthorized: boolean;
  };
  authTimeout?: number;
  connTimeout?: number;
  keepalive?: {
    interval: number;
    idleInterval: number;
    forceNoop: boolean;
  };
}

/**
 * Email message metadata
 */
export interface EmailMessage {
  uid: number;
  flags: string[];
  date: Date;
  subject?: string;
  from?: string;
  to?: string;
  messageId?: string;
  hasAttachments: boolean;
}

/**
 * IMAP Client with connection management and error handling
 */
export class ImapClient extends EventEmitter {
  private config: ImapConfig;
  private connection: Imap | null = null;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectBaseDelay = 2000; // 2 seconds
  private reconnectTimer: NodeJS.Timeout | null = null;
  private currentMailbox: string | null = null;

  constructor(config: ImapConfig) {
    super();
    this.config = config;
  }

  /**
   * Connect to IMAP server
   */
  async connect(): Promise<void> {
    return withSpan(
      'imap.connect',
      {
        host: this.config.host,
        port: this.config.port,
      },
      async () => {
        if (this.isConnected) {
          logger.info('IMAP client already connected');
          return;
        }

        logger.info({ host: this.config.host, port: this.config.port }, 'Connecting to IMAP server');

        this.connection = new Imap(this.config);

        return new Promise<void>((resolve, reject) => {
          if (!this.connection) {
            reject(new Error('Failed to create IMAP connection'));
            return;
          }

          // Connection ready event
          this.connection.once('ready', () => {
            this.isConnected = true;
            this.reconnectAttempts = 0;
            imapConnectionStatus.set({ mailbox: this.config.user }, 1);
            logger.info('IMAP connection established');
            this.emit('ready');
            resolve();
          });

          // Connection error event
          this.connection.once('error', (err: Error) => {
            logger.error({ err, host: this.config.host }, 'IMAP connection error');
            this.isConnected = false;
            imapConnectionStatus.set({ mailbox: this.config.user }, 0);
            this.emit('error', err);
            reject(err);
          });

          // Connection end event
          this.connection.once('end', () => {
            logger.info('IMAP connection ended');
            this.isConnected = false;
            imapConnectionStatus.set({ mailbox: this.config.user }, 0);
            this.emit('end');
            this.scheduleReconnect();
          });

          // Connection close event
          this.connection.once('close', (hadError: boolean) => {
            logger.info({ hadError }, 'IMAP connection closed');
            this.isConnected = false;
            imapConnectionStatus.set({ mailbox: this.config.user }, 0);
            this.emit('close', hadError);
          });

          // Initiate connection
          this.connection.connect();
        });
      }
    );
  }

  /**
   * Disconnect from IMAP server
   */
  async disconnect(): Promise<void> {
    logger.info('Disconnecting from IMAP server');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.connection && this.isConnected) {
      this.connection.end();
    }

    this.isConnected = false;
    this.connection = null;
    this.currentMailbox = null;
    imapConnectionStatus.set({ mailbox: this.config.user }, 0);
  }

  /**
   * Schedule automatic reconnection with exponential backoff
   */
  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error(
        { attempts: this.reconnectAttempts },
        'Max reconnection attempts reached'
      );
      this.emit('maxReconnectAttemptsReached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1);
    const jitter = Math.random() * 1000; // Add jitter to prevent thundering herd

    logger.info(
      { attempt: this.reconnectAttempts, delayMs: delay + jitter },
      'Scheduling IMAP reconnection'
    );

    this.reconnectTimer = setTimeout(() => {
      this.connect().catch((err) => {
        logger.error({ err }, 'Reconnection attempt failed');
      });
    }, delay + jitter);
  }

  /**
   * Open a mailbox
   */
  async openMailbox(mailboxName: string, readOnly = false): Promise<Imap.Box> {
    return withSpan(
      'imap.openMailbox',
      {
        mailbox: mailboxName,
        readOnly: readOnly ? 1 : 0,
      },
      async () => {
        if (!this.connection || !this.isConnected) {
          throw new Error('IMAP client not connected');
        }

        logger.info({ mailbox: mailboxName, readOnly }, 'Opening mailbox');

        return new Promise<Imap.Box>((resolve, reject) => {
          if (!this.connection) {
            reject(new Error('IMAP connection lost'));
            return;
          }

          this.connection.openBox(mailboxName, readOnly, (err, box) => {
            if (err) {
              logger.error({ err, mailbox: mailboxName }, 'Failed to open mailbox');
              reject(err);
              return;
            }

            this.currentMailbox = mailboxName;
            logger.info(
              { mailbox: mailboxName, messages: box.messages.total },
              'Mailbox opened successfully'
            );
            resolve(box);
          });
        });
      }
    );
  }

  /**
   * Search for messages matching criteria
   */
  async searchMessages(criteria: (string | string[])[]): Promise<number[]> {
    return withSpan(
      'imap.searchMessages',
      {
        mailbox: this.currentMailbox || 'unknown',
      },
      async () => {
        if (!this.connection || !this.isConnected) {
          throw new Error('IMAP client not connected');
        }

        if (!this.currentMailbox) {
          throw new Error('No mailbox currently selected');
        }

        logger.info({ criteria }, 'Searching messages');

        return new Promise<number[]>((resolve, reject) => {
          if (!this.connection) {
            reject(new Error('IMAP connection lost'));
            return;
          }

          this.connection.search(criteria, (err, uids) => {
            if (err) {
              logger.error({ err, criteria }, 'Message search failed');
              emailsFetchedTotal.inc({ mailbox: this.config.user, status: 'error' });
              reject(err);
              return;
            }

            logger.info({ count: uids.length }, 'Messages found');
            emailsFetchedTotal.inc({
              mailbox: this.config.user,
              status: 'success',
            }, uids.length);
            resolve(uids);
          });
        });
      }
    );
  }

  /**
   * Fetch message by UID
   */
  fetchMessage(uid: number, options: Imap.FetchOptions = {}): Imap.ImapFetch {
    if (!this.connection || !this.isConnected) {
      throw new Error('IMAP client not connected');
    }

    logger.info({ uid, options }, 'Fetching message');

    const fetch = this.connection.fetch(uid, options);
    return fetch;
  }

  /**
   * Mark message as seen
   */
  async markAsSeen(uid: number): Promise<void> {
    if (!this.connection || !this.isConnected) {
      throw new Error('IMAP client not connected');
    }

    return new Promise<void>((resolve, reject) => {
      if (!this.connection) {
        reject(new Error('IMAP connection lost'));
        return;
      }

      this.connection.addFlags(uid, ['\\Seen'], (err) => {
        if (err) {
          logger.error({ err, uid }, 'Failed to mark message as seen');
          reject(err);
          return;
        }

        logger.debug({ uid }, 'Message marked as seen');
        resolve();
      });
    });
  }

  /**
   * Get connection status
   */
  getConnectionStatus(): boolean {
    return this.isConnected;
  }

  /**
   * Get current mailbox name
   */
  getCurrentMailbox(): string | null {
    return this.currentMailbox;
  }
}

/**
 * Create IMAP client from environment variables
 */
export function createImapClientFromEnv(): ImapClient {
  const config: ImapConfig = {
    user: process.env.IMAP_USER || '',
    password: process.env.IMAP_PASSWORD || '',
    host: process.env.IMAP_HOST || '',
    port: parseInt(process.env.IMAP_PORT || '993', 10),
    tls: process.env.IMAP_TLS !== 'false',
    tlsOptions: {
      rejectUnauthorized: process.env.IMAP_TLS_REJECT_UNAUTHORIZED !== 'false',
    },
    authTimeout: 10000,
    connTimeout: 10000,
    keepalive: {
      interval: 10000,
      idleInterval: 300000,
      forceNoop: true,
    },
  };

  // Validate required configuration
  if (!config.user || !config.password || !config.host) {
    throw new Error(
      'Missing required IMAP configuration: IMAP_USER, IMAP_PASSWORD, IMAP_HOST'
    );
  }

  logger.info(
    { host: config.host, port: config.port, user: config.user },
    'Creating IMAP client'
  );

  return new ImapClient(config);
}
