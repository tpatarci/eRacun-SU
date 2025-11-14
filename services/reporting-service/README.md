# Reporting Service

Generate compliance reports and analytics for eRačun platform.

## Purpose

Provides comprehensive reporting and analytics:
- Compliance summary reports
- Fiscal monthly reports
- VAT summaries
- Invoice volume analysis
- Error analysis
- Archive status reports

## Features

- ✅ **Multiple Report Types** - Compliance, VAT, volume, errors, archive
- ✅ **Multiple Formats** - JSON, CSV, XLSX, PDF
- ✅ **Type-Safe** - Full TypeScript with strict mode
- ✅ **Performant** - Optimized queries and caching
- ✅ **Scheduled** - Automated report generation

## Usage

### Generate Report

```typescript
import { generateReport } from '@eracun/reporting-service';

const request = {
  type: 'COMPLIANCE_SUMMARY',
  startDate: '2025-01-01',
  endDate: '2025-11-30',
  format: 'CSV',
  filters: {
    status: 'fiscalized',
  },
};

const result = await generateReport(request);
if (result.success) {
  console.log('Report ID:', result.metadata?.id);
  console.log('Data:', result.data);
}
```

### Report Types

#### Compliance Summary
```typescript
{
  type: 'COMPLIANCE_SUMMARY',
  startDate: '2025-01-01',
  endDate: '2025-11-30',
  format: 'JSON'
}
```

Returns:
- Total invoices processed
- Fiscalization success rate
- Breakdown by status
- Monthly trends

#### VAT Summary
```typescript
{
  type: 'VAT_SUMMARY',
  startDate: '2025-01-01',
  endDate: '2025-11-30',
  format: 'XLSX'
}
```

Returns:
- Total base amounts by VAT rate
- Total VAT collected
- Invoice counts per rate
- Compliance with Croatian VAT law

#### Invoice Volume
```typescript
{
  type: 'INVOICE_VOLUME',
  startDate: '2025-11-01',
  endDate: '2025-11-30',
  format: 'CSV'
}
```

Returns:
- Daily invoice counts
- Hourly distribution
- Peak times
- Volume trends

## Supported Formats

### JSON
Structured data suitable for API consumption.

### CSV
Comma-separated values for Excel/spreadsheet import.

### XLSX
Native Excel format with formatting.

### PDF
Human-readable reports with charts and formatting.

## Configuration

Environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `LOG_LEVEL` - Logging level (debug/info/warn/error)
- `REPORT_CACHE_TTL` - Cache TTL in seconds (default: 300)

## Report Scheduling

Automated report generation via cron or systemd timers:

```bash
# Daily compliance report at 2 AM
0 2 * * * /opt/eracun/bin/generate-report --type=COMPLIANCE_SUMMARY
```

## Performance

Target metrics:
- Report generation: <5s (p95)
- Data retrieval: <1s
- Format export: <2s
- Cache hit rate: >80%

## Related Services

- `archive-service` - Source data for reports
- `fina-connector` - Fiscalization status
- `porezna-connector` - Tax submissions

## Testing

```bash
# Run tests
npm test

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

---

**Service Owner:** Team 3 (External Integration & Compliance)
**Status:** Production Ready
**Coverage:** Target 100%
