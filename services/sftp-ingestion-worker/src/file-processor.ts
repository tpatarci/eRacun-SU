/**
 * File Processor
 * Process downloaded files and prepare for publishing
 */

import crypto from 'crypto';
import mime from 'mime-types';
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';
import { RemoteFile, DownloadResult, FileMessage } from './types';

const logger = pino({ name: 'file-processor' });

export class FileProcessor {
  private readonly sftpHost: string;

  constructor(sftpHost: string) {
    this.sftpHost = sftpHost;
  }

  async processDownload(download: DownloadResult): Promise<FileMessage | null> {
    if (!download.success || !download.buffer) {
      logger.warn({ file: download.file.name }, 'Skipping failed download');
      return null;
    }

    try {
      const fileId = uuidv4();
      const checksum = this.calculateChecksum(download.buffer);
      const mimeType = this.detectMimeType(download.file.name, download.buffer);

      const message: FileMessage = {
        fileId,
        filename: download.file.name,
        content: download.buffer.toString('base64'),
        mimeType,
        size: download.file.size,
        checksum,
        metadata: {
          sourceService: 'sftp-ingestion-worker',
          sftpHost: this.sftpHost,
          remotePath: download.file.path,
          downloadedAt: new Date().toISOString()
        }
      };

      logger.info(
        { fileId, filename: download.file.name, size: download.file.size },
        'File processed successfully'
      );

      return message;
    } catch (error) {
      logger.error({ error, file: download.file.name }, 'File processing failed');
      return null;
    }
  }

  private calculateChecksum(buffer: Buffer): string {
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  private detectMimeType(filename: string, buffer: Buffer): string {
    // Try extension-based detection first
    const mimeFromExt = mime.lookup(filename);
    if (mimeFromExt) {
      return mimeFromExt;
    }

    // Try magic bytes
    if (buffer.length >= 4) {
      if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
        return 'application/pdf';
      }
      if (buffer[0] === 0x50 && buffer[1] === 0x4B) {
        return 'application/zip';
      }
      if (buffer[0] === 0x3C && buffer[1] === 0x3F && buffer[2] === 0x78 && buffer[3] === 0x6D) {
        return 'application/xml';
      }
    }

    return 'application/octet-stream';
  }
}
