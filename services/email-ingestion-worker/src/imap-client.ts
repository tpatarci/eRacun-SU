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
  imapConnectionErrors,
  imapMailArrivals,
  imapReconnectionAttempts,
} from './observability';

/**
 * IMAP connection configuration
 *
 * IMPROVEMENT-047: All configuration values support environment variable overrides
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
  // IMPROVEMENT-047: Reconnection configuration (previously hard-coded)
  maxReconnectAttempts?: number;
  reconnectBaseDelayMs?: number;
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
  // IMPROVEMENT-047: Use configuration-based values instead of hard-coded defaults
  private maxReconnectAttempts: number;
  private reconnectBaseDelay: number;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private currentMailbox: string | null = null;
  private connectionId = ''; // IMPROVEMENT-003: Connection ID for debugging
  private reconnectionScheduled = false; // IMPROVEMENT-003: Prevent duplicate reconnection schedules

  constructor(config: ImapConfig) {
    super();
    this.config = config;
    // IMPROVEMENT-047: Initialize reconnection settings from config with safe defaults
    this.maxReconnectAttempts = config.maxReconnectAttempts ?? 5;
    this.reconnectBaseDelay = config.reconnectBaseDelayMs ?? 2000;
  }

  /**
   * Generate unique connection ID for debugging (IMPROVEMENT-003)
   */
  private generateConnectionId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Register event listeners on current IMAP connection (IMPROVEMENT-003)
   *
   * Removes any stale listeners from previous connections and registers
   * fresh listeners on the current connection instance.
   */
  private registerEventListeners(): void {
    if (!this.connection) {
      throw new Error('Connection not initialized');
    }

    const connectionId = this.connectionId;

    // Remove any stale listeners first
    this.connection.removeAllListeners('ready');
    this.connection.removeAllListeners('error');
    this.connection.removeAllListeners('end');
    this.connection.removeAllListeners('mail');
    this.connection.removeAllListeners('close');

    // Ready event (fires once when connected)
    this.connection.once('ready', () => {
      logger.debug('IMAP ready', { connectionId });
      this.isConnected = true;
      this.emit('ready');
    });

    // Error event (fires on errors)
    this.connection.on('error', (err: Error) => {
      logger.error(
        {
          error: err,
          code: (err as any).code,
          connectionId,
        },
        'IMAP error'
      );
      this.isConnected = false;
      imapConnectionStatus.set({ mailbox: this.config.user }, 0);
      imapConnectionErrors.inc({
        error_type: (err as any).code || 'unknown',
      });
      this.emit('error', err);
    });

    // End event (fires when connection closes)
    this.connection.once('end', () => {
      logger.info('IMAP connection ended', { connectionId });
      this.isConnected = false;
      imapConnectionStatus.set({ mailbox: this.config.user }, 0);
      this.emit('end');
      // Trigger automatic reconnection
      this.scheduleReconnection();
    });

    // Close event (fires when connection is fully closed)
    this.connection.once('close', (hadError: boolean) => {
      logger.info('IMAP connection closed', { hadError, connectionId });
      this.isConnected = false;
      imapConnectionStatus.set({ mailbox: this.config.user }, 0);
      this.emit('close', hadError);
    });

    // Mail arrival event
    this.connection.on('mail', (numNewEmails: number) => {
      if (numNewEmails > 0) {
        logger.debug('Mail arrived', { count: numNewEmails, connectionId });
        imapMailArrivals.inc();
      }
    });
  }

  /**
   * Connect to IMAP server (IMPROVEMENT-003: Added listener re-registration and timeout)
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

        logger.info(
          { host: this.config.host, port: this.config.port, previousConnectionId: this.connectionId },
          'Connecting to IMAP server'
        );

        // Generate unique ID for this connection attempt
        this.connectionId = this.generateConnectionId();

        // Create new connection instance
        this.connection = new Imap(this.config);

        // IMPROVEMENT-003: Immediately register all event listeners on new instance
        this.registerEventListeners();

        return new Promise<void>((resolve, reject) => {
          if (!this.connection) {
            reject(new Error('Failed to create IMAP connection'));
            return;
          }

          // IMPROVEMENT-047: Wait for 'ready' event using configured connection timeout
          const timeoutMs = this.config.connTimeout ?? 10000;
          const timeout = setTimeout(() => {
            reject(new Error(`IMAP connection timeout after ${timeoutMs}ms`));
          }, timeoutMs);

          const handleReady = () => {
            clearTimeout(timeout);
            this.connection?.removeListener('ready', handleReady);
            this.isConnected = true;
            this.reconnectAttempts = 0;
            imapConnectionStatus.set({ mailbox: this.config.user }, 1);
            logger.info('IMAP connection established', { connectionId: this.connectionId });
            this.emit('ready');
            resolve();
          };

          this.connection.once('ready', handleReady);

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
   * Schedule automatic reconnection with exponential backoff (IMPROVEMENT-003)
   */
  private scheduleReconnection(): void {
    if (this.reconnectionScheduled) {
      logger.debug('Reconnection already scheduled');
      return;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error(
        { attempts: this.reconnectAttempts },
        'Max reconnection attempts reached'
      );
      this.emit('maxReconnectAttemptsReached');
      return;
    }

    this.reconnectionScheduled = true;
    this.reconnectAttempts++;
    const delay = this.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1);
    const jitter = Math.random() * 1000; // Add jitter to prevent thundering herd

    logger.info(
      { attempt: this.reconnectAttempts, delayMs: delay + jitter },
      'Scheduling IMAP reconnection'
    );

    imapReconnectionAttempts.inc();

    this.reconnectTimer = setTimeout(() => {
      this.connect()
        .catch((err) => {
          logger.error({ err }, 'Reconnection attempt failed');
        })
        .finally(() => {
          this.reconnectionScheduled = false;
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
    // IMPROVEMENT-047: Make connection timeouts configurable via environment variables
    authTimeout: parseInt(process.env.IMAP_AUTH_TIMEOUT || '10000', 10),
    connTimeout: parseInt(process.env.IMAP_CONN_TIMEOUT || '10000', 10),
    // IMPROVEMENT-047: Make keepalive configuration flexible
    keepalive: {
      interval: parseInt(process.env.IMAP_KEEPALIVE_INTERVAL || '10000', 10),
      idleInterval: parseInt(process.env.IMAP_KEEPALIVE_IDLE_INTERVAL || '300000', 10),
      forceNoop: process.env.IMAP_KEEPALIVE_FORCE_NOOP !== 'false',
    },
    // IMPROVEMENT-047: Make reconnection strategy configurable
    maxReconnectAttempts: parseInt(process.env.IMAP_MAX_RECONNECT_ATTEMPTS || '5', 10),
    reconnectBaseDelayMs: parseInt(process.env.IMAP_RECONNECT_BASE_DELAY_MS || '2000', 10),
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
