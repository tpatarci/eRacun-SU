/**
 * Type Definitions for SFTP Ingestion Worker
 */

export interface SFTPConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: Buffer | string;
  passphrase?: string;
  remotePath: string;
  pollIntervalSeconds: number;
  maxConcurrentDownloads: number;
}

export interface RemoteFile {
  name: string;
  path: string;
  size: number;
  modifyTime: Date;
  type: 'file' | 'directory' | 'symlink';
}

export interface DownloadResult {
  success: boolean;
  file: RemoteFile;
  localPath?: string;
  buffer?: Buffer;
  error?: string;
  downloadTime: number;
}

export interface ProcessedFile {
  id: string;
  filename: string;
  path: string;
  size: number;
  checksum: string;
  processedAt: Date;
  status: 'success' | 'failed';
  errorMessage?: string;
}

export interface FileMessage {
  fileId: string;
  filename: string;
  content: string; // base64
  mimeType: string;
  size: number;
  checksum: string;
  metadata: {
    sourceService: string;
    sftpHost: string;
    remotePath: string;
    downloadedAt: string;
  };
}
