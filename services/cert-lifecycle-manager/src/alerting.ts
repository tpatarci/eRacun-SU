import axios, { AxiosInstance } from 'axios';
import { Certificate } from './repository';
import { AlertHandler } from './expiration-monitor';
import { formatFingerprint } from './cert-parser';
import { logger, createSpan, setSpanError } from './observability';

/**
 * Notification Service Client
 *
 * Integrates with notification-service to send expiration alerts
 * via email, SMS, and webhooks.
 */
export class NotificationServiceClient implements AlertHandler {
  private httpClient: AxiosInstance;
  private serviceUrl: string;

  constructor(serviceUrl?: string) {
    this.serviceUrl =
      serviceUrl ||
      process.env.NOTIFICATION_SERVICE_URL ||
      'http://notification-service:8080';

    this.httpClient = axios.create({
      baseURL: this.serviceUrl,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    logger.info(
      { notificationServiceUrl: this.serviceUrl },
      'Notification service client initialized'
    );
  }

  /**
   * Send expiration alert via notification service
   *
   * @param cert - Certificate that is expiring
   * @param severity - Alert severity (info, warning, critical, urgent)
   * @param daysUntilExpiry - Number of days until expiration
   */
  async sendAlert(
    cert: Certificate,
    severity: 'info' | 'warning' | 'critical' | 'urgent',
    daysUntilExpiry: number
  ): Promise<void> {
    const span = createSpan('send_expiration_alert', {
      certId: cert.certId,
      severity,
      daysUntilExpiry,
    });

    try {
      logger.info(
        {
          certId: cert.certId,
          serialNumber: cert.serialNumber,
          severity,
          daysUntilExpiry,
        },
        'Sending certificate expiration alert'
      );

      // Determine notification channels based on severity
      const channels = this.getChannelsForSeverity(severity);

      // Build notification payload
      const notification = {
        templateName: this.getTemplateName(daysUntilExpiry),
        channels,
        recipients: this.getRecipients(severity),
        subject: this.buildSubject(cert, daysUntilExpiry, severity),
        variables: {
          certificate_serial_number: cert.serialNumber,
          certificate_issuer: cert.issuer,
          certificate_subject: cert.subjectDn,
          certificate_type: cert.certType,
          not_after: cert.notAfter.toISOString(),
          not_after_formatted: cert.notAfter.toLocaleDateString(),
          days_until_expiry: daysUntilExpiry,
          severity_level: severity.toUpperCase(),
          fingerprint: formatFingerprint(cert.fingerprint),
          expiration_status: this.getExpirationStatus(daysUntilExpiry),
          renewal_url: this.getRenewalUrl(),
          alert_timestamp: new Date().toISOString(),
        },
      };

      // Send notification
      const response = await this.httpClient.post(
        '/api/v1/notifications',
        notification
      );

      logger.info(
        {
          certId: cert.certId,
          notificationId: response.data.notificationId,
          channels,
          severity,
        },
        'Certificate expiration alert sent successfully'
      );

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error(
        {
          error,
          certId: cert.certId,
          severity,
        },
        'Failed to send certificate expiration alert'
      );

      // Re-throw to allow retry logic
      throw error;
    }
  }

  /**
   * Get notification channels based on severity
   *
   * @param severity - Alert severity
   * @returns Array of notification channels
   */
  private getChannelsForSeverity(
    severity: 'info' | 'warning' | 'critical' | 'urgent'
  ): string[] {
    switch (severity) {
      case 'urgent':
        return ['email', 'sms', 'webhook']; // All channels for urgent
      case 'critical':
        return ['email', 'sms']; // Email + SMS for critical
      case 'warning':
        return ['email']; // Email only for warning
      case 'info':
        return ['email']; // Email only for info
      default:
        return ['email'];
    }
  }

  /**
   * Get recipients based on severity
   *
   * @param severity - Alert severity
   * @returns Recipients object
   */
  private getRecipients(
    severity: 'info' | 'warning' | 'critical' | 'urgent'
  ): {
    email?: string[];
    sms?: string[];
    webhook?: string[];
  } {
    // TODO: Load recipients from environment variables or configuration
    const adminEmails =
      process.env.ADMIN_EMAILS?.split(',') || ['admin@eracun.hr'];
    const adminPhones =
      process.env.ADMIN_PHONES?.split(',') || ['+385991234567'];
    const webhookUrls =
      process.env.ALERT_WEBHOOKS?.split(',') || ['https://example.com/webhook'];

    switch (severity) {
      case 'urgent':
        return {
          email: adminEmails,
          sms: adminPhones,
          webhook: webhookUrls,
        };
      case 'critical':
        return {
          email: adminEmails,
          sms: adminPhones,
        };
      case 'warning':
      case 'info':
        return {
          email: adminEmails,
        };
      default:
        return {
          email: adminEmails,
        };
    }
  }

  /**
   * Get template name based on days until expiry
   *
   * @param daysUntilExpiry - Number of days until expiration
   * @returns Template name
   */
  private getTemplateName(daysUntilExpiry: number): string {
    if (daysUntilExpiry <= 0) {
      return 'certificate_expired';
    } else if (daysUntilExpiry <= 1) {
      return 'certificate_expiring_1day';
    } else if (daysUntilExpiry <= 7) {
      return 'certificate_expiring_7days';
    } else if (daysUntilExpiry <= 14) {
      return 'certificate_expiring_14days';
    } else {
      return 'certificate_expiring_30days';
    }
  }

  /**
   * Build alert subject line
   *
   * @param cert - Certificate
   * @param daysUntilExpiry - Days until expiration
   * @param severity - Alert severity
   * @returns Subject string
   */
  private buildSubject(
    cert: Certificate,
    daysUntilExpiry: number,
    severity: 'info' | 'warning' | 'critical' | 'urgent'
  ): string {
    const severityPrefix = severity === 'urgent' ? '[URGENT] ' : '';

    if (daysUntilExpiry <= 0) {
      return `${severityPrefix}Certificate EXPIRED - ${cert.serialNumber}`;
    } else if (daysUntilExpiry === 1) {
      return `${severityPrefix}Certificate expires in 1 DAY - ${cert.serialNumber}`;
    } else {
      return `${severityPrefix}Certificate expires in ${daysUntilExpiry} days - ${cert.serialNumber}`;
    }
  }

  /**
   * Get expiration status text
   *
   * @param daysUntilExpiry - Days until expiration
   * @returns Status text
   */
  private getExpirationStatus(daysUntilExpiry: number): string {
    if (daysUntilExpiry <= 0) {
      return 'EXPIRED';
    } else if (daysUntilExpiry <= 1) {
      return 'EXPIRES_IN_1_DAY';
    } else if (daysUntilExpiry <= 7) {
      return 'EXPIRES_IN_7_DAYS';
    } else if (daysUntilExpiry <= 14) {
      return 'EXPIRES_IN_14_DAYS';
    } else {
      return 'EXPIRES_IN_30_DAYS';
    }
  }

  /**
   * Get FINA certificate renewal URL
   *
   * @returns Renewal URL
   */
  private getRenewalUrl(): string {
    return 'https://cms.fina.hr';
  }

  /**
   * Test notification service connectivity
   *
   * @returns true if service is reachable
   */
  async testConnection(): Promise<boolean> {
    try {
      const response = await this.httpClient.get('/health');
      return response.status === 200;
    } catch (error) {
      logger.error(
        { error, serviceUrl: this.serviceUrl },
        'Notification service health check failed'
      );
      return false;
    }
  }
}

/**
 * Console Alert Handler (for testing)
 *
 * Logs alerts to console instead of sending via notification service.
 * Useful for development and testing.
 */
export class ConsoleAlertHandler implements AlertHandler {
  async sendAlert(
    cert: Certificate,
    severity: 'info' | 'warning' | 'critical' | 'urgent',
    daysUntilExpiry: number
  ): Promise<void> {
    const message = `[${severity.toUpperCase()}] Certificate ${
      cert.serialNumber
    } expires in ${daysUntilExpiry} days`;

    switch (severity) {
      case 'urgent':
      case 'critical':
        logger.error({ cert, daysUntilExpiry }, message);
        break;
      case 'warning':
        logger.warn({ cert, daysUntilExpiry }, message);
        break;
      case 'info':
        logger.info({ cert, daysUntilExpiry }, message);
        break;
    }
  }
}

/**
 * Create alert handler based on environment
 *
 * @param notificationServiceUrl - Optional notification service URL
 * @returns AlertHandler instance
 */
export function createAlertHandler(
  notificationServiceUrl?: string
): AlertHandler {
  // Use console handler in test/development
  if (process.env.NODE_ENV === 'test' || process.env.USE_CONSOLE_ALERTS === 'true') {
    logger.info('Using console alert handler (development mode)');
    return new ConsoleAlertHandler();
  }

  // Use notification service in production
  return new NotificationServiceClient(notificationServiceUrl);
}
