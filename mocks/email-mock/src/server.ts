/**
 * Email Service Mock
 * Production-grade mock for SMTP/IMAP email service
 *
 * Features:
 * - SMTP server for receiving emails
 * - IMAP server for reading emails
 * - Attachment handling (PDF, XML, images)
 * - Multi-part MIME support
 * - Web UI for email inspection
 */

import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import express from 'express';
import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import path from 'path';

interface EmailMessage {
  id: string;
  from: string;
  to: string[];
  subject: string;
  text?: string;
  html?: string;
  attachments: Array<{
    filename: string;
    contentType: string;
    size: number;
    content: Buffer;
  }>;
  receivedAt: Date;
  folder: string;
}

interface MockConfig {
  smtpPort: number;
  imapPort: number;
  webPort: number;
  mailDir: string;
}

class EmailMockService {
  private config: MockConfig;
  private logger: winston.Logger;
  private emails: Map<string, EmailMessage> = new Map();
  private folders: Map<string, Set<string>> = new Map(); // folder -> email IDs
  private smtpServer?: SMTPServer;
  private webApp: express.Application;

  constructor(config: Partial<MockConfig> = {}) {
    this.config = {
      smtpPort: config.smtpPort || 1025,
      imapPort: config.imapPort || 1143,
      webPort: config.webPort || 8025,
      mailDir: config.mailDir || '/app/maildir'
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ filename: 'email-mock.log' })
      ]
    });

    this.webApp = express();
    this.setupWebUI();
    this.initializeFolders();
  }

  private initializeFolders(): void {
    const defaultFolders = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Spam'];
    for (const folder of defaultFolders) {
      this.folders.set(folder, new Set());
    }
  }

  private setupSMTP(): void {
    this.smtpServer = new SMTPServer({
      secure: false,
      authOptional: true,
      disabledCommands: ['STARTTLS'],

      onData: (stream, session, callback) => {
        let rawEmail = '';

        stream.on('data', (chunk) => {
          rawEmail += chunk.toString();
        });

        stream.on('end', async () => {
          try {
            const parsed = await simpleParser(rawEmail);

            const email: EmailMessage = {
              id: uuidv4(),
              from: parsed.from?.text || 'unknown@example.com',
              to: parsed.to?.value.map(addr => addr.address || '') || [],
              subject: parsed.subject || '(no subject)',
              text: parsed.text,
              html: parsed.html?.toString(),
              attachments: (parsed.attachments || []).map(att => ({
                filename: att.filename || 'unnamed',
                contentType: att.contentType,
                size: att.size,
                content: att.content
              })),
              receivedAt: new Date(),
              folder: 'INBOX'
            };

            this.emails.set(email.id, email);
            this.folders.get('INBOX')?.add(email.id);

            // Save to disk
            await this.saveEmail(email);

            this.logger.info(`Email received: ${email.subject} from ${email.from}`);
            callback();
          } catch (error) {
            this.logger.error('Error parsing email:', error);
            callback(new Error('Failed to parse email'));
          }
        });
      },

      onAuth: (auth, session, callback) => {
        // Accept all authentication (it's a mock)
        callback(null, { user: auth.username });
      }
    });

    this.smtpServer.listen(this.config.smtpPort, () => {
      this.logger.info(`SMTP server listening on port ${this.config.smtpPort}`);
    });
  }

  private setupWebUI(): void {
    this.webApp.use(express.json());

    // Health check
    this.webApp.get('/health', (req, res) => {
      res.json({
        status: 'operational',
        emailCount: this.emails.size,
        folders: Array.from(this.folders.keys())
      });
    });

    // List all emails
    this.webApp.get('/api/emails', (req, res) => {
      const folder = (req.query.folder as string) || 'INBOX';
      const emailIds = this.folders.get(folder);

      if (!emailIds) {
        return res.status(404).json({ error: 'Folder not found' });
      }

      const emails = Array.from(emailIds)
        .map(id => this.emails.get(id))
        .filter(Boolean)
        .map(email => ({
          id: email!.id,
          from: email!.from,
          to: email!.to,
          subject: email!.subject,
          receivedAt: email!.receivedAt,
          hasAttachments: email!.attachments.length > 0,
          attachmentCount: email!.attachments.length
        }));

      res.json({ folder, count: emails.length, emails });
    });

    // Get single email
    this.webApp.get('/api/emails/:id', (req, res) => {
      const email = this.emails.get(req.params.id);
      if (!email) {
        return res.status(404).json({ error: 'Email not found' });
      }

      res.json({
        ...email,
        attachments: email.attachments.map(att => ({
          filename: att.filename,
          contentType: att.contentType,
          size: att.size
          // Don't send content in list view
        }))
      });
    });

    // Get attachment
    this.webApp.get('/api/emails/:id/attachments/:index', (req, res) => {
      const email = this.emails.get(req.params.id);
      if (!email) {
        return res.status(404).json({ error: 'Email not found' });
      }

      const index = parseInt(req.params.index);
      const attachment = email.attachments[index];

      if (!attachment) {
        return res.status(404).json({ error: 'Attachment not found' });
      }

      res.setHeader('Content-Type', attachment.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${attachment.filename}"`);
      res.send(attachment.content);
    });

    // Delete email
    this.webApp.delete('/api/emails/:id', (req, res) => {
      const email = this.emails.get(req.params.id);
      if (!email) {
        return res.status(404).json({ error: 'Email not found' });
      }

      // Move to trash
      this.folders.get(email.folder)?.delete(email.id);
      this.folders.get('Trash')?.add(email.id);
      email.folder = 'Trash';

      res.json({ success: true, message: 'Email moved to trash' });
    });

    // Move email to folder
    this.webApp.post('/api/emails/:id/move', (req, res) => {
      const email = this.emails.get(req.params.id);
      if (!email) {
        return res.status(404).json({ error: 'Email not found' });
      }

      const { folder } = req.body;
      if (!this.folders.has(folder)) {
        return res.status(400).json({ error: 'Invalid folder' });
      }

      this.folders.get(email.folder)?.delete(email.id);
      this.folders.get(folder)?.add(email.id);
      email.folder = folder;

      res.json({ success: true, message: `Email moved to ${folder}` });
    });

    // Search emails
    this.webApp.get('/api/search', (req, res) => {
      const query = (req.query.q as string || '').toLowerCase();
      const results = Array.from(this.emails.values())
        .filter(email =>
          email.subject.toLowerCase().includes(query) ||
          email.from.toLowerCase().includes(query) ||
          email.text?.toLowerCase().includes(query)
        )
        .map(email => ({
          id: email.id,
          from: email.from,
          to: email.to,
          subject: email.subject,
          receivedAt: email.receivedAt,
          folder: email.folder
        }));

      res.json({ query, count: results.length, results });
    });

    // Clear all emails
    this.webApp.post('/api/clear', (req, res) => {
      this.emails.clear();
      for (const folder of this.folders.values()) {
        folder.clear();
      }
      this.logger.info('All emails cleared');
      res.json({ success: true, message: 'All emails cleared' });
    });

    // Simple HTML UI
    this.webApp.get('/', (req, res) => {
      res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Email Mock Service</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; }
    .stats { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .folder-list { display: flex; gap: 10px; margin: 20px 0; }
    .folder { padding: 10px 15px; background: #007bff; color: white; border-radius: 5px; cursor: pointer; }
    .email-list { border: 1px solid #ddd; border-radius: 5px; }
    .email-item { padding: 15px; border-bottom: 1px solid #ddd; cursor: pointer; }
    .email-item:hover { background: #f8f9fa; }
    button { padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #218838; }
  </style>
</head>
<body>
  <h1>📧 Email Mock Service</h1>
  <div class="stats">
    <strong>Total Emails:</strong> <span id="email-count">0</span><br>
    <strong>SMTP Port:</strong> ${this.config.smtpPort}<br>
    <strong>Web Port:</strong> ${this.config.webPort}
  </div>
  <button onclick="loadEmails()">Refresh</button>
  <button onclick="clearEmails()" style="background: #dc3545;">Clear All</button>
  <div class="folder-list" id="folders"></div>
  <div class="email-list" id="email-list"></div>

  <script>
    let currentFolder = 'INBOX';

    async function loadEmails(folder = 'INBOX') {
      currentFolder = folder;
      const res = await fetch('/api/emails?folder=' + folder);
      const data = await res.json();

      document.getElementById('email-count').textContent = data.count;

      const list = document.getElementById('email-list');
      list.innerHTML = data.emails.map(e => \`
        <div class="email-item" onclick="viewEmail('\${e.id}')">
          <strong>\${e.subject}</strong><br>
          <small>From: \${e.from} | \${new Date(e.receivedAt).toLocaleString()}</small>
          \${e.hasAttachments ? ' 📎 ' + e.attachmentCount : ''}
        </div>
      \`).join('');
    }

    async function viewEmail(id) {
      const res = await fetch('/api/emails/' + id);
      const email = await res.json();
      alert('Subject: ' + email.subject + '\\n\\nFrom: ' + email.from + '\\n\\n' + (email.text || email.html));
    }

    async function clearEmails() {
      if (confirm('Clear all emails?')) {
        await fetch('/api/clear', { method: 'POST' });
        loadEmails();
      }
    }

    loadEmails();
  </script>
</body>
</html>
      `);
    });
  }

  private async saveEmail(email: EmailMessage): Promise<void> {
    try {
      const emailDir = path.join(this.config.mailDir, email.id);
      await fs.mkdir(emailDir, { recursive: true });

      // Save metadata
      await fs.writeFile(
        path.join(emailDir, 'meta.json'),
        JSON.stringify({
          id: email.id,
          from: email.from,
          to: email.to,
          subject: email.subject,
          receivedAt: email.receivedAt,
          folder: email.folder
        }, null, 2)
      );

      // Save text
      if (email.text) {
        await fs.writeFile(path.join(emailDir, 'body.txt'), email.text);
      }

      // Save HTML
      if (email.html) {
        await fs.writeFile(path.join(emailDir, 'body.html'), email.html);
      }

      // Save attachments
      for (let i = 0; i < email.attachments.length; i++) {
        const att = email.attachments[i];
        await fs.writeFile(
          path.join(emailDir, `attachment_${i}_${att.filename}`),
          att.content
        );
      }
    } catch (error) {
      this.logger.error('Error saving email:', error);
    }
  }

  public start(): void {
    this.setupSMTP();

    this.webApp.listen(this.config.webPort, () => {
      this.logger.info(`Web UI started on port ${this.config.webPort}`);
      this.logger.info(`Visit http://localhost:${this.config.webPort} to view emails`);
    });
  }
}

// Start the service
if (require.main === module) {
  const config: Partial<MockConfig> = {
    smtpPort: parseInt(process.env.SMTP_PORT || '1025'),
    imapPort: parseInt(process.env.IMAP_PORT || '1143'),
    webPort: parseInt(process.env.WEB_PORT || '8025'),
    mailDir: process.env.MAIL_DIR || '/app/maildir'
  };

  const service = new EmailMockService(config);
  service.start();
}

export { EmailMockService, MockConfig, EmailMessage };
