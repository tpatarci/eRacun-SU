import cron from 'node-cron';
import { CertificateRepository, Certificate } from './repository';
import { calculateDaysUntilExpiration } from './cert-parser';
import {
  logger,
  certificatesExpiring,
  certificateExpirationAlerts,
  createSpan,
  setSpanError,
} from './observability';

/**
 * Expiration check result
 */
export interface ExpirationCheckResult {
  totalChecked: number;
  expiring1Day: number;
  expiring7Days: number;
  expiring14Days: number;
  expiring30Days: number;
  expired: number;
  alertsSent: number;
}

/**
 * Alert handler interface
 *
 * Implement this interface to send alerts via different channels
 * (email, SMS, Slack, etc.)
 */
export interface AlertHandler {
  sendAlert(
    cert: Certificate,
    severity: 'info' | 'warning' | 'critical' | 'urgent',
    daysUntilExpiry: number
  ): Promise<void>;
}

/**
 * Certificate Expiration Monitor
 *
 * Monitors certificate expiration dates and triggers alerts.
 * Runs as a scheduled cron job (daily at 9 AM by default).
 *
 * Alert Thresholds:
 * - 30 days: INFO level alert
 * - 14 days: WARNING level alert
 * - 7 days: CRITICAL level alert
 * - 1 day: URGENT level alert
 * - 0 days (expired): URGENT level alert
 */
export class ExpirationMonitor {
  private repository: CertificateRepository;
  private alertHandler?: AlertHandler;
  private cronJob?: cron.ScheduledTask;
  private isRunning: boolean = false;

  constructor(repository: CertificateRepository, alertHandler?: AlertHandler) {
    this.repository = repository;
    this.alertHandler = alertHandler;
  }

  /**
   * Start expiration monitoring with cron schedule
   *
   * @param schedule - Cron schedule (default: daily at 9 AM)
   */
  start(schedule: string = '0 9 * * *'): void {
    if (this.isRunning) {
      logger.warn('Expiration monitor already running');
      return;
    }

    logger.info({ schedule }, 'Starting expiration monitor');

    this.cronJob = cron.schedule(schedule, async () => {
      try {
        await this.checkCertificateExpiration();
      } catch (error) {
        logger.error({ error }, 'Expiration check failed');
      }
    });

    this.isRunning = true;
    logger.info('Expiration monitor started successfully');
  }

  /**
   * Stop expiration monitoring
   */
  stop(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = undefined;
    }

    this.isRunning = false;
    logger.info('Expiration monitor stopped');
  }

  /**
   * Check certificate expiration (can be called manually or via cron)
   *
   * This is the main function that:
   * 1. Retrieves all active certificates
   * 2. Checks expiration dates
   * 3. Updates certificate status
   * 4. Triggers alerts via notification service
   * 5. Updates Prometheus metrics
   *
   * @returns ExpirationCheckResult with statistics
   */
  async checkCertificateExpiration(): Promise<ExpirationCheckResult> {
    const span = createSpan('check_certificate_expiration');
    const startTime = Date.now();

    try {
      logger.info('Starting certificate expiration check');

      // Get all active certificates
      const certificates = await this.repository.getAllActiveCertificates();

      logger.info(
        { certificateCount: certificates.length },
        'Retrieved active certificates'
      );

      const result: ExpirationCheckResult = {
        totalChecked: certificates.length,
        expiring1Day: 0,
        expiring7Days: 0,
        expiring14Days: 0,
        expiring30Days: 0,
        expired: 0,
        alertsSent: 0,
      };

      // Check each certificate
      for (const cert of certificates) {
        await this.checkSingleCertificate(cert, result);
      }

      // Update Prometheus metrics
      this.updateMetrics(result);

      const durationSeconds = (Date.now() - startTime) / 1000;

      logger.info(
        {
          totalChecked: result.totalChecked,
          expired: result.expired,
          expiring1Day: result.expiring1Day,
          expiring7Days: result.expiring7Days,
          expiring14Days: result.expiring14Days,
          expiring30Days: result.expiring30Days,
          alertsSent: result.alertsSent,
          durationSeconds,
        },
        'Certificate expiration check completed'
      );

      span.end();
      return result;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Certificate expiration check failed');
      throw error;
    }
  }

  /**
   * Check a single certificate and trigger alerts if necessary
   *
   * @param cert - Certificate to check
   * @param result - Result object to update
   */
  private async checkSingleCertificate(
    cert: Certificate,
    result: ExpirationCheckResult
  ): Promise<void> {
    const span = createSpan('check_single_certificate', {
      certId: cert.certId,
      serialNumber: cert.serialNumber,
    });

    try {
      const daysUntilExpiry = calculateDaysUntilExpiration(cert.notAfter);

      logger.debug(
        {
          certId: cert.certId,
          serialNumber: cert.serialNumber,
          notAfter: cert.notAfter.toISOString(),
          daysUntilExpiry,
        },
        'Checking certificate expiration'
      );

      // Determine alert level and update status
      let newStatus: 'active' | 'expiring_soon' | 'expired' | 'revoked' = cert.status;
      let shouldAlert = false;
      let alertSeverity: 'info' | 'warning' | 'critical' | 'urgent' = 'info';

      if (daysUntilExpiry <= 0) {
        // Expired
        newStatus = 'expired';
        shouldAlert = true;
        alertSeverity = 'urgent';
        result.expired++;

        logger.error(
          {
            certId: cert.certId,
            serialNumber: cert.serialNumber,
            expiredDaysAgo: Math.abs(daysUntilExpiry),
          },
          'Certificate EXPIRED'
        );
      } else if (daysUntilExpiry <= 1) {
        // Expires in 1 day
        newStatus = 'expiring_soon';
        shouldAlert = true;
        alertSeverity = 'urgent';
        result.expiring1Day++;

        logger.error(
          {
            certId: cert.certId,
            serialNumber: cert.serialNumber,
            daysUntilExpiry,
          },
          'Certificate expires in 1 day - URGENT'
        );
      } else if (daysUntilExpiry <= 7) {
        // Expires in 7 days
        newStatus = 'expiring_soon';
        shouldAlert = true;
        alertSeverity = 'critical';
        result.expiring7Days++;

        logger.warn(
          {
            certId: cert.certId,
            serialNumber: cert.serialNumber,
            daysUntilExpiry,
          },
          'Certificate expires in 7 days - CRITICAL'
        );
      } else if (daysUntilExpiry <= 14) {
        // Expires in 14 days
        newStatus = 'expiring_soon';
        shouldAlert = true;
        alertSeverity = 'warning';
        result.expiring14Days++;

        logger.warn(
          {
            certId: cert.certId,
            serialNumber: cert.serialNumber,
            daysUntilExpiry,
          },
          'Certificate expires in 14 days - WARNING'
        );
      } else if (daysUntilExpiry <= 30) {
        // Expires in 30 days
        newStatus = 'expiring_soon';
        shouldAlert = true;
        alertSeverity = 'info';
        result.expiring30Days++;

        logger.info(
          {
            certId: cert.certId,
            serialNumber: cert.serialNumber,
            daysUntilExpiry,
          },
          'Certificate expires in 30 days - INFO'
        );
      } else {
        // More than 30 days - still active
        newStatus = 'active';
      }

      // Update certificate status if changed
      if (newStatus !== cert.status) {
        await this.repository.updateCertificateStatus(cert.certId, newStatus);

        logger.info(
          {
            certId: cert.certId,
            oldStatus: cert.status,
            newStatus,
          },
          'Certificate status updated'
        );
      }

      // Send alert if necessary
      if (shouldAlert && this.alertHandler) {
        try {
          await this.alertHandler.sendAlert(cert, alertSeverity, daysUntilExpiry);

          result.alertsSent++;
          certificateExpirationAlerts.labels(alertSeverity).inc();

          logger.info(
            {
              certId: cert.certId,
              severity: alertSeverity,
              daysUntilExpiry,
            },
            'Expiration alert sent'
          );
        } catch (error) {
          logger.error(
            {
              error,
              certId: cert.certId,
              severity: alertSeverity,
            },
            'Failed to send expiration alert'
          );
        }
      }

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error(
        {
          error,
          certId: cert.certId,
        },
        'Failed to check certificate'
      );
    }
  }

  /**
   * Update Prometheus metrics based on check results
   *
   * @param result - Expiration check result
   */
  private updateMetrics(result: ExpirationCheckResult): void {
    // Reset metrics
    certificatesExpiring.reset();

    // Set expiring certificate counts
    certificatesExpiring.labels('1').set(result.expiring1Day);
    certificatesExpiring.labels('7').set(result.expiring7Days);
    certificatesExpiring.labels('14').set(result.expiring14Days);
    certificatesExpiring.labels('30').set(result.expiring30Days);

    logger.debug('Prometheus metrics updated');
  }

  /**
   * Check if monitor is running
   *
   * @returns true if running
   */
  isMonitorRunning(): boolean {
    return this.isRunning;
  }
}

/**
 * Create default expiration monitor with standard configuration
 *
 * @param repository - Certificate repository
 * @param alertHandler - Optional alert handler
 * @returns Configured ExpirationMonitor instance
 */
export function createExpirationMonitor(
  repository: CertificateRepository,
  alertHandler?: AlertHandler
): ExpirationMonitor {
  return new ExpirationMonitor(repository, alertHandler);
}
