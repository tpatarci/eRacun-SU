/**
 * Reporting Service
 *
 * Generate compliance reports and analytics
 */

import { pino } from 'pino';
import type { ReportRequest, ReportResult } from './types/index.js';
import { generateComplianceReport } from './generators/compliance-report.js';
import { exportToCSV, flattenObject } from './exporters/csv-exporter.js';

const logger = pino({
  name: 'reporting-service',
  level: process.env.LOG_LEVEL || 'info',
});

/**
 * Generate report based on request
 */
export async function generateReport(request: ReportRequest): Promise<ReportResult> {
  try {
    logger.info({ type: request.type, format: request.format }, 'Generating report');

    // Generate report data based on type
    let reportData;
    switch (request.type) {
      case 'COMPLIANCE_SUMMARY':
        reportData = await generateComplianceReport(request);
        break;
      default:
        return {
          success: false,
          error: `Unsupported report type: ${request.type}`,
        };
    }

    // Export to requested format
    let exportedData: Buffer | string | Record<string, unknown>;
    switch (request.format) {
      case 'JSON':
        exportedData = JSON.stringify(reportData, null, 2);
        break;
      case 'CSV':
        // Flatten nested structure for CSV
        const flattened = reportData.breakdown.byMonth.map((item) =>
          flattenObject(item)
        );
        exportedData = exportToCSV(flattened);
        break;
      default:
        return {
          success: false,
          error: `Unsupported format: ${request.format}`,
        };
    }

    logger.info(
      {
        reportId: reportData.metadata.id,
        recordCount: reportData.metadata.recordCount,
      },
      'Report generated successfully'
    );

    return {
      success: true,
      metadata: reportData.metadata,
      data: exportedData,
    };
  } catch (error) {
    logger.error({ error, request }, 'Failed to generate report');
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// Export types
export type * from './types/index.js';

// Main entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  logger.info('Reporting Service started');

  // Example: Generate a compliance report
  const exampleRequest: ReportRequest = {
    type: 'COMPLIANCE_SUMMARY',
    startDate: '2025-01-01',
    endDate: '2025-11-14',
    format: 'JSON',
  };

  generateReport(exampleRequest)
    .then((result) => {
      if (result.success) {
        logger.info('Example report generated');
        console.log(result.data);
      } else {
        logger.error('Example report failed', result.error);
      }
    })
    .catch((error) => {
      logger.error({ error }, 'Unexpected error');
    });
}
