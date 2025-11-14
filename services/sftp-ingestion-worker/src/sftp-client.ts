/**
 * SFTP Client
 * Handles SFTP connections and file operations
 */

import SFTPClient from 'ssh2-sftp-client';
import pino from 'pino';
import { SFTPConfig, RemoteFile, DownloadResult } from './types';

const logger = pino({ name: 'sftp-client' });

export class SFTPClientWrapper {
  private client: SFTPClient;
  private config: SFTPConfig;
  private connected = false;

  constructor(config: SFTPConfig) {
    this.config = config;
    this.client = new SFTPClient();
  }

  async connect(): Promise<void> {
    try {
      await this.client.connect({
        host: this.config.host,
        port: this.config.port,
        username: this.config.username,
        password: this.config.password,
        privateKey: this.config.privateKey,
        passphrase: this.config.passphrase
      });

      this.connected = true;
      logger.info({ host: this.config.host }, 'SFTP connection established');
    } catch (error) {
      logger.error({ error, host: this.config.host }, 'SFTP connection failed');
      throw error;
    }
  }

  async listFiles(remotePath?: string): Promise<RemoteFile[]> {
    const path = remotePath || this.config.remotePath;

    try {
      const fileList = await this.client.list(path);

      return fileList
        .filter(file => file.type === '-') // Only files
        .map(file => ({
          name: file.name,
          path: `${path}/${file.name}`,
          size: file.size,
          modifyTime: new Date(file.modifyTime),
          type: 'file' as const
        }));
    } catch (error) {
      logger.error({ error, path }, 'Failed to list files');
      throw error;
    }
  }

  async downloadFile(remoteFile: RemoteFile): Promise<DownloadResult> {
    const startTime = Date.now();

    try {
      const buffer = await this.client.get(remoteFile.path);

      return {
        success: true,
        file: remoteFile,
        buffer: buffer as Buffer,
        downloadTime: Date.now() - startTime
      };
    } catch (error) {
      logger.error({ error, file: remoteFile.name }, 'File download failed');
      return {
        success: false,
        file: remoteFile,
        error: String(error),
        downloadTime: Date.now() - startTime
      };
    }
  }

  async deleteFile(remotePath: string): Promise<boolean> {
    try {
      await this.client.delete(remotePath);
      logger.info({ path: remotePath }, 'File deleted from SFTP server');
      return true;
    } catch (error) {
      logger.error({ error, path: remotePath }, 'File deletion failed');
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      await this.client.end();
      this.connected = false;
      logger.info('SFTP connection closed');
    } catch (error) {
      logger.error({ error }, 'Error closing SFTP connection');
    }
  }

  isConnected(): boolean {
    return this.connected;
  }
}
