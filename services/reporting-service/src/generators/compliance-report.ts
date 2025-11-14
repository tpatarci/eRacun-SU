/**
 * Compliance Summary Report Generator
 */

import type { ComplianceSummaryReport, ReportMetadata, ReportRequest } from '../types/index.js';

/**
 * Generate compliance summary report
 */
export async function generateComplianceReport(
  request: ReportRequest
): Promise<ComplianceSummaryReport> {
  // Mock data for now - will connect to archive-service in production
  const mockData = generateMockComplianceData(request.startDate, request.endDate);

  const metadata: ReportMetadata = {
    id: generateReportId(),
    type: 'COMPLIANCE_SUMMARY',
    generatedAt: new Date().toISOString(),
    period: {
      start: request.startDate,
      end: request.endDate,
    },
    recordCount: mockData.totalInvoices,
    format: request.format,
  };

  return {
    metadata,
    summary: {
      totalInvoices: mockData.totalInvoices,
      fiscalized: mockData.fiscalized,
      pending: mockData.pending,
      failed: mockData.failed,
      complianceRate: (mockData.fiscalized / mockData.totalInvoices) * 100,
    },
    breakdown: {
      byStatus: {
        fiscalized: mockData.fiscalized,
        pending: mockData.pending,
        failed: mockData.failed,
      },
      byMonth: mockData.byMonth,
    },
  };
}

/**
 * Generate mock compliance data
 */
function generateMockComplianceData(startDate: string, endDate: string) {
  const start = new Date(startDate);
  const end = new Date(endDate);
  const months: Array<{ month: string; count: number; complianceRate: number }> = [];

  let currentMonth = new Date(start.getFullYear(), start.getMonth(), 1);
  while (currentMonth <= end) {
    const monthStr = currentMonth.toISOString().substring(0, 7);
    const count = Math.floor(Math.random() * 1000) + 500;
    const complianceRate = 95 + Math.random() * 5;

    months.push({
      month: monthStr,
      count,
      complianceRate,
    });

    currentMonth.setMonth(currentMonth.getMonth() + 1);
  }

  const totalInvoices = months.reduce((sum, m) => sum + m.count, 0);
  const avgCompliance = months.reduce((sum, m) => sum + m.complianceRate, 0) / months.length;
  const fiscalized = Math.floor(totalInvoices * (avgCompliance / 100));
  const failed = Math.floor(totalInvoices * 0.02);
  const pending = totalInvoices - fiscalized - failed;

  return {
    totalInvoices,
    fiscalized,
    pending,
    failed,
    byMonth: months,
  };
}

/**
 * Generate unique report ID
 */
function generateReportId(): string {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  return `RPT-${timestamp}-${random}`;
}
