/**
 * Email Types for Mock Email Client
 * Provides structures for simulating IMAP email behavior
 */

export interface Attachment {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  content?: Buffer;
}

export interface EmailMessage {
  id: string;
  from: string;
  to: string;
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  htmlBody?: string;
  date: Date;
  read: boolean;
  processed: boolean;
  attachments: Attachment[];
  labels: string[];
  headers: Record<string, string>;
  priority?: 'low' | 'normal' | 'high';
  inReplyTo?: string;
  references?: string[];
}

export interface EmailClientConfig {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  mailbox?: string;
  pollInterval?: number;
}

export interface FetchOptions {
  limit?: number;
  since?: Date;
  before?: Date;
  withAttachments?: boolean;
  unreadOnly?: boolean;
}
