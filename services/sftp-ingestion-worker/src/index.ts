/**
 * SFTP Ingestion Worker
 * Main service entry point
 */

import pino from 'pino';
import cron from 'node-cron';
import { SFTPClientWrapper } from './sftp-client';
import { FileProcessor } from './file-processor';
import { SFTPConfig } from './types';

const logger = pino({ name: 'sftp-ingestion-worker' });

export { SFTPClientWrapper, FileProcessor };
export * from './types';

export class SFTPIngestionWorker {
  private readonly sftpClient: SFTPClientWrapper;
  private readonly fileProcessor: FileProcessor;
  private readonly config: SFTPConfig;
  private cronJob?: cron.ScheduledTask;

  constructor(config: SFTPConfig) {
    this.config = config;
    this.sftpClient = new SFTPClientWrapper(config);
    this.fileProcessor = new FileProcessor(config.host);
  }

  async start(): Promise<void> {
    logger.info('Starting SFTP Ingestion Worker');

    try {
      // Initial connection
      await this.sftpClient.connect();

      // Schedule polling
      const cronExpression = `*/${this.config.pollIntervalSeconds} * * * * *`;
      this.cronJob = cron.schedule(cronExpression, async () => {
        await this.poll();
      });

      logger.info(
        { interval: this.config.pollIntervalSeconds },
        'SFTP Ingestion Worker started'
      );
    } catch (error) {
      logger.error({ error }, 'Failed to start SFTP Ingestion Worker');
      throw error;
    }
  }

  private async poll(): Promise<void> {
    try {
      // List files
      const files = await this.sftpClient.listFiles();

      if (files.length === 0) {
        logger.debug('No files found');
        return;
      }

      logger.info({ count: files.length }, 'Found files to download');

      // Download and process files
      for (const file of files) {
        const download = await this.sftpClient.downloadFile(file);
        const message = await this.fileProcessor.processDownload(download);

        if (message) {
          logger.info({ fileId: message.fileId }, 'File ready for publishing');
          // In real implementation, publish to RabbitMQ here
        }
      }
    } catch (error) {
      logger.error({ error }, 'Polling failed');
    }
  }

  async stop(): Promise<void> {
    logger.info('Stopping SFTP Ingestion Worker');

    if (this.cronJob) {
      this.cronJob.stop();
    }

    await this.sftpClient.disconnect();

    logger.info('SFTP Ingestion Worker stopped');
  }

  async healthCheck(): Promise<boolean> {
    return this.sftpClient.isConnected();
  }
}

// Start service if run directly
if (require.main === module) {
  const config: SFTPConfig = {
    host: process.env.SFTP_HOST || 'localhost',
    port: parseInt(process.env.SFTP_PORT || '22', 10),
    username: process.env.SFTP_USERNAME || 'user',
    password: process.env.SFTP_PASSWORD,
    remotePath: process.env.SFTP_REMOTE_PATH || '/invoices',
    pollIntervalSeconds: parseInt(process.env.POLL_INTERVAL_SECONDS || '60', 10),
    maxConcurrentDownloads: parseInt(process.env.MAX_CONCURRENT_DOWNLOADS || '3', 10)
  };

  const worker = new SFTPIngestionWorker(config);
  worker.start().catch(error => {
    logger.fatal({ error }, 'Worker crashed');
    process.exit(1);
  });
}
