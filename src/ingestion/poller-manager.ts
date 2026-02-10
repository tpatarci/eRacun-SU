import { logger } from '../shared/logger.js';
import type { UserConfig } from '../shared/types.js';
import { EmailPoller, type EmailMessage, createEmailPollerForUser } from './email-poller.js';

/**
 * Poller manager entry - tracks a poller instance and its metadata
 */
interface PollerEntry {
  /** Email poller instance */
  poller: EmailPoller;
  /** User configuration */
  userConfig: UserConfig;
  /** Whether the poller is currently running */
  isRunning: boolean;
  /** When the poller was started */
  startedAt?: Date;
}

/**
 * Poller manager configuration
 */
export interface PollerManagerConfig {
  /** Default polling interval in milliseconds (default: 60000 = 1 minute) */
  defaultPollIntervalMs?: number;
}

/**
 * Message handler callback for incoming email messages
 */
export type MessageHandler = (message: EmailMessage, userId: string) => Promise<void>;

/**
 * Poller Manager for Multi-User Email Polling
 *
 * Manages multiple email pollers, one per user, allowing independent
 * start/stop control for each user's email polling.
 */
class PollerManager {
  /** Map of userId to poller entry */
  private pollers = new Map<string, PollerEntry>();
  /** Default polling interval */
  private defaultPollIntervalMs: number;
  /** Global message handler */
  private messageHandler?: MessageHandler;

  constructor(config?: PollerManagerConfig) {
    this.defaultPollIntervalMs = config?.defaultPollIntervalMs ?? 60000;
  }

  /**
   * Set the global message handler for all pollers
   *
   * @param handler - Function to call when new email messages arrive
   */
  setMessageHandler(handler: MessageHandler): void {
    this.messageHandler = handler;
  }

  /**
   * Start a poller for a specific user
   *
   * @param userConfig - User's IMAP configuration
   * @param messageHandler - Optional user-specific message handler
   * @param pollIntervalMs - Optional custom poll interval (uses default if not provided)
   * @throws Error if user config is invalid or poller is already running
   */
  async startPollerForUser(
    userConfig: UserConfig,
    messageHandler?: MessageHandler,
    pollIntervalMs?: number
  ): Promise<void> {
    const userId = userConfig.userId;

    // Check if poller already exists and is running
    const existingEntry = this.pollers.get(userId);
    if (existingEntry?.isRunning) {
      throw new Error(`Poller for user '${userId}' is already running`);
    }

    try {
      // Create new poller if it doesn't exist
      if (!existingEntry) {
        const poller = createEmailPollerForUser(userConfig);
        this.pollers.set(userId, {
          poller,
          userConfig,
          isRunning: false,
        });
      }

      const entry = this.pollers.get(userId)!;
      const handler = messageHandler ?? this.messageHandler;

      if (!handler) {
        throw new Error('No message handler configured. Set a global handler via setMessageHandler or provide a user-specific handler');
      }

      // Start the poller
      const intervalMs = pollIntervalMs ?? this.defaultPollIntervalMs;
      await entry.poller.start(
        async (message) => handler(message, userId),
        intervalMs
      );

      // Update entry state
      entry.isRunning = true;
      entry.startedAt = new Date();

      logger.info({
        userId,
        pollIntervalMs: intervalMs,
      }, 'Started email poller for user');
    } catch (error) {
      // Clean up on error
      this.pollers.delete(userId);
      throw error;
    }
  }

  /**
   * Stop a poller for a specific user
   *
   * @param userId - User ID to stop polling for
   * @throws Error if user has no active poller
   */
  async stopPollerForUser(userId: string): Promise<void> {
    const entry = this.pollers.get(userId);

    if (!entry) {
      throw new Error(`No poller found for user '${userId}'`);
    }

    if (!entry.isRunning) {
      logger.warn({
        userId,
      }, 'Attempted to stop poller that is not running');
      return;
    }

    try {
      await entry.poller.stop();
      entry.isRunning = false;
      entry.startedAt = undefined;

      logger.info({
        userId,
      }, 'Stopped email poller for user');
    } catch (error) {
      logger.error({
        userId,
        error: error instanceof Error ? error.message : String(error),
      }, 'Error stopping poller for user');
      throw error;
    }
  }

  /**
   * Get list of active poller user IDs
   *
   * @returns Array of user IDs with running pollers
   */
  getActivePollers(): string[] {
    const activePollers: string[] = [];

    for (const [userId, entry] of Array.from(this.pollers.entries())) {
      if (entry.isRunning) {
        activePollers.push(userId);
      }
    }

    return activePollers;
  }

  /**
   * Get all registered poller user IDs (including stopped ones)
   *
   * @returns Array of all registered user IDs
   */
  getAllPollers(): string[] {
    return Array.from(this.pollers.keys());
  }

  /**
   * Check if a poller exists for a specific user
   *
   * @param userId - User ID to check
   * @returns true if poller exists, false otherwise
   */
  hasPoller(userId: string): boolean {
    return this.pollers.has(userId);
  }

  /**
   * Check if a poller is running for a specific user
   *
   * @param userId - User ID to check
   * @returns true if poller is running, false otherwise
   */
  isPollerRunning(userId: string): boolean {
    const entry = this.pollers.get(userId);
    return entry?.isRunning ?? false;
  }

  /**
   * Get poller status information
   *
   * @param userId - User ID to get status for
   * @returns Status object or undefined if user has no poller
   */
  getPollerStatus(userId: string): { isRunning: boolean; startedAt?: Date } | undefined {
    const entry = this.pollers.get(userId);
    if (!entry) {
      return undefined;
    }
    return {
      isRunning: entry.isRunning,
      startedAt: entry.startedAt,
    };
  }

  /**
   * Remove a poller for a specific user
   *
   * Stops the poller if running and removes it from the manager.
   *
   * @param userId - User ID to remove poller for
   */
  async removePoller(userId: string): Promise<void> {
    const entry = this.pollers.get(userId);

    if (!entry) {
      return;
    }

    if (entry.isRunning) {
      await this.stopPollerForUser(userId);
    }

    this.pollers.delete(userId);

    logger.info({
      userId,
    }, 'Removed email poller for user');
  }

  /**
   * Stop all running pollers
   *
   * Useful for graceful shutdown
   */
  async stopAll(): Promise<void> {
    const stopPromises: Promise<void>[] = [];

    for (const [userId, entry] of Array.from(this.pollers.entries())) {
      if (entry.isRunning) {
        stopPromises.push(this.stopPollerForUser(userId));
      }
    }

    await Promise.all(stopPromises);

    logger.info({
      count: stopPromises.length,
    }, 'Stopped all email pollers');
  }

  /**
   * Remove all pollers
   *
   * Stops all running pollers and removes them from the manager.
   */
  async removeAll(): Promise<void> {
    await this.stopAll();
    this.pollers.clear();

    logger.info('Removed all email pollers');
  }
}

/**
 * Create a new poller manager instance
 *
 * @param config - Optional manager configuration
 * @returns PollerManager instance
 */
export function createPollerManager(config?: PollerManagerConfig): PollerManager {
  return new PollerManager(config);
}

export { PollerManager };
