/**
 * DZS KLASUS Registry Sync Module
 *
 * Syncs KPD product classification codes from DZS (Croatian Bureau of Statistics)
 * to local PostgreSQL cache.
 *
 * Sync Strategy:
 * 1. Fetch from DZS API or CSV file
 * 2. Parse response (JSON or CSV)
 * 3. Compare with local database
 * 4. Identify new/updated/deleted codes
 * 5. Apply changes (INSERT, UPDATE, soft DELETE)
 * 6. Log sync statistics
 * 7. Update Prometheus metrics
 *
 * Performance Target: <60 seconds for 50,000 codes
 */

import axios, { AxiosResponse } from 'axios';
import csvParser from 'csv-parser';
import { createReadStream } from 'fs';
import { Readable } from 'stream';
import {
  logger,
  kpdCodesSynced,
  kpdSyncDuration,
  kpdSyncErrors,
  kpdLastSyncTimestamp,
  traceOperation,
} from './observability';
import {
  KPDCode,
  getAllKPDCodes,
  insertKPDCode,
  updateKPDCode,
  softDeleteKPDCode,
  bulkInsertKPDCodes,
  getSyncStatistics,
} from './repository';

// ============================================================================
// Configuration
// ============================================================================

const DZS_API_URL = process.env.DZS_KLASUS_API_URL || 'https://api.dzs.hr/klasus/v1/codes';
const DZS_API_KEY = process.env.DZS_API_KEY;
const DZS_VERSION = process.env.DZS_KLASUS_VERSION || '2025';
const SYNC_TIMEOUT_MS = parseInt(process.env.SYNC_TIMEOUT_MS || '120000', 10);
const HTTP_TIMEOUT_MS = parseInt(process.env.HTTP_REQUEST_TIMEOUT_MS || '30000', 10);

// ============================================================================
// Type Definitions
// ============================================================================

export interface SyncResult {
  success: boolean;
  codes_added: number;
  codes_updated: number;
  codes_deleted: number;
  total_codes: number;
  duration_seconds: number;
  error?: string;
}

export interface DZSCodeResponse {
  code: string;
  description: string;
  level: number;
  parent_code?: string;
  effective_from: string; // ISO date string
  effective_to?: string;  // ISO date string
}

interface ComparisonResult {
  toAdd: KPDCode[];
  toUpdate: KPDCode[];
  toDelete: KPDCode[];
}

// ============================================================================
// Main Sync Function
// ============================================================================

/**
 * Sync KPD codes from DZS registry to local cache
 */
export async function syncKPDCodes(): Promise<SyncResult> {
  const startTime = Date.now();

  return traceOperation('kpd_sync', async (span) => {
    logger.info('Starting KPD registry sync');

    try {
      // Step 1: Fetch remote codes from DZS
      const remoteCodes = await fetchDZSCodes();
      logger.info({ count: remoteCodes.length }, 'Fetched remote KPD codes from DZS');

      // Step 2: Get local codes
      const localCodes = await getAllKPDCodes();
      logger.info({ count: localCodes.length }, 'Retrieved local KPD codes');

      // Step 3: Compare and identify changes
      const { toAdd, toUpdate, toDelete } = compareCodes(remoteCodes, localCodes);
      logger.info(
        {
          to_add: toAdd.length,
          to_update: toUpdate.length,
          to_delete: toDelete.length,
        },
        'Code comparison complete'
      );

      // Step 4: Apply changes to database
      await applyChanges(toAdd, toUpdate, toDelete);

      // Step 5: Update metrics
      kpdCodesSynced.inc({ action: 'added' }, toAdd.length);
      kpdCodesSynced.inc({ action: 'updated' }, toUpdate.length);
      kpdCodesSynced.inc({ action: 'deleted' }, toDelete.length);
      kpdLastSyncTimestamp.set(Date.now() / 1000); // Unix timestamp in seconds

      // Step 6: Calculate duration
      const durationSeconds = (Date.now() - startTime) / 1000;
      kpdSyncDuration.observe(durationSeconds);

      // Step 7: Get final statistics
      const stats = await getSyncStatistics();

      const result: SyncResult = {
        success: true,
        codes_added: toAdd.length,
        codes_updated: toUpdate.length,
        codes_deleted: toDelete.length,
        total_codes: stats.total_codes,
        duration_seconds: durationSeconds,
      };

      logger.info(result, 'KPD registry sync completed successfully');

      return result;
    } catch (error) {
      const durationSeconds = (Date.now() - startTime) / 1000;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      logger.error({ err: error, duration_seconds: durationSeconds }, 'KPD registry sync failed');
      kpdSyncErrors.inc({ error_type: getErrorType(error) });

      return {
        success: false,
        codes_added: 0,
        codes_updated: 0,
        codes_deleted: 0,
        total_codes: 0,
        duration_seconds: durationSeconds,
        error: errorMessage,
      };
    }
  });
}

// ============================================================================
// Fetch from DZS API/File
// ============================================================================

/**
 * Fetch KPD codes from DZS API
 */
async function fetchDZSCodes(): Promise<KPDCode[]> {
  try {
    const response: AxiosResponse<any> = await axios.get(DZS_API_URL, {
      timeout: HTTP_TIMEOUT_MS,
      headers: {
        'Accept': 'application/json',
        ...(DZS_API_KEY && { 'Authorization': `Bearer ${DZS_API_KEY}` }),
      },
      params: {
        version: DZS_VERSION,
      },
    });

    logger.info({ status: response.status }, 'DZS API request successful');

    // Parse response based on content type
    if (typeof response.data === 'string') {
      // CSV response
      return parseCSVData(response.data);
    } else if (Array.isArray(response.data)) {
      // JSON array response
      return response.data.map(mapDZSCodeToKPDCode);
    } else if (response.data.codes && Array.isArray(response.data.codes)) {
      // JSON object with 'codes' array
      return response.data.codes.map(mapDZSCodeToKPDCode);
    } else {
      throw new Error('Unexpected DZS API response format');
    }
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.code === 'ECONNABORTED') {
        logger.error({ timeout_ms: HTTP_TIMEOUT_MS }, 'DZS API request timeout');
        kpdSyncErrors.inc({ error_type: 'network' });
      } else if (error.response) {
        logger.error(
          { status: error.response.status, data: error.response.data },
          'DZS API returned error'
        );
        kpdSyncErrors.inc({ error_type: 'api_error' });
      } else {
        logger.error({ err: error }, 'DZS API network error');
        kpdSyncErrors.inc({ error_type: 'network' });
      }
    }
    throw error;
  }
}

/**
 * Parse CSV data into KPD codes
 */
function parseCSVData(csvData: string): Promise<KPDCode[]> {
  return new Promise((resolve, reject) => {
    const codes: KPDCode[] = [];
    const stream = Readable.from([csvData]);

    stream
      .pipe(csvParser())
      .on('data', (row) => {
        try {
          const code = mapCSVRowToKPDCode(row);
          codes.push(code);
        } catch (error) {
          logger.warn({ row, err: error }, 'Failed to parse CSV row');
        }
      })
      .on('end', () => {
        logger.info({ count: codes.length }, 'CSV parsing complete');
        resolve(codes);
      })
      .on('error', (error) => {
        logger.error({ err: error }, 'CSV parsing error');
        kpdSyncErrors.inc({ error_type: 'parsing' });
        reject(error);
      });
  });
}

/**
 * Map DZS JSON code to internal KPDCode
 */
function mapDZSCodeToKPDCode(dzsCode: DZSCodeResponse): KPDCode {
  return {
    kpd_code: dzsCode.code,
    description: dzsCode.description,
    level: dzsCode.level,
    parent_code: dzsCode.parent_code || null,
    active: true,
    effective_from: new Date(dzsCode.effective_from),
    effective_to: dzsCode.effective_to ? new Date(dzsCode.effective_to) : null,
  };
}

/**
 * Map CSV row to KPDCode
 * Expected columns: code, description, level, parent_code, effective_from, effective_to
 */
function mapCSVRowToKPDCode(row: any): KPDCode {
  return {
    kpd_code: row.code || row.kpd_code,
    description: row.description,
    level: parseInt(row.level, 10),
    parent_code: row.parent_code || null,
    active: true,
    effective_from: new Date(row.effective_from),
    effective_to: row.effective_to ? new Date(row.effective_to) : null,
  };
}

// ============================================================================
// Code Comparison Logic
// ============================================================================

/**
 * Compare remote codes with local codes to identify changes
 */
function compareCodes(remoteCodes: KPDCode[], localCodes: KPDCode[]): ComparisonResult {
  const remoteMap = new Map<string, KPDCode>(
    remoteCodes.map((code) => [code.kpd_code, code])
  );
  const localMap = new Map<string, KPDCode>(
    localCodes.map((code) => [code.kpd_code, code])
  );

  const toAdd: KPDCode[] = [];
  const toUpdate: KPDCode[] = [];
  const toDelete: KPDCode[] = [];

  // Find new and updated codes
  for (const [code, remoteCode] of remoteMap.entries()) {
    const localCode = localMap.get(code);

    if (!localCode) {
      // New code
      toAdd.push(remoteCode);
    } else if (isCodeChanged(remoteCode, localCode)) {
      // Updated code
      toUpdate.push(remoteCode);
    }
  }

  // Find deleted codes (present locally but not in remote)
  for (const [code, localCode] of localMap.entries()) {
    if (!remoteMap.has(code) && localCode.active) {
      toDelete.push(localCode);
    }
  }

  return { toAdd, toUpdate, toDelete };
}

/**
 * Check if a code has changed
 */
function isCodeChanged(remoteCode: KPDCode, localCode: KPDCode): boolean {
  return (
    remoteCode.description !== localCode.description ||
    remoteCode.level !== localCode.level ||
    remoteCode.parent_code !== localCode.parent_code ||
    remoteCode.effective_from.getTime() !== localCode.effective_from.getTime() ||
    (remoteCode.effective_to?.getTime() || 0) !== (localCode.effective_to?.getTime() || 0)
  );
}

// ============================================================================
// Apply Changes
// ============================================================================

/**
 * Apply changes to database (INSERT, UPDATE, DELETE)
 */
async function applyChanges(
  toAdd: KPDCode[],
  toUpdate: KPDCode[],
  toDelete: KPDCode[]
): Promise<void> {
  // Add new codes (bulk insert for performance)
  if (toAdd.length > 0) {
    logger.info({ count: toAdd.length }, 'Adding new codes');
    await bulkInsertKPDCodes(toAdd);
  }

  // Update changed codes
  if (toUpdate.length > 0) {
    logger.info({ count: toUpdate.length }, 'Updating changed codes');
    for (const code of toUpdate) {
      await updateKPDCode(code);
    }
  }

  // Soft delete removed codes
  if (toDelete.length > 0) {
    logger.info({ count: toDelete.length }, 'Soft deleting removed codes');
    for (const code of toDelete) {
      await softDeleteKPDCode(code.kpd_code);
    }
  }
}

// ============================================================================
// Error Handling
// ============================================================================

/**
 * Classify error type for metrics
 */
function getErrorType(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      return 'network';
    } else if (error.response) {
      return 'api_error';
    } else {
      return 'network';
    }
  } else if (error instanceof SyntaxError) {
    return 'parsing';
  } else {
    return 'database';
  }
}

// ============================================================================
// Manual Sync Trigger
// ============================================================================

/**
 * Trigger sync manually (used by HTTP API)
 */
export async function triggerManualSync(): Promise<SyncResult> {
  logger.info('Manual sync triggered');
  return syncKPDCodes();
}

/**
 * Get last sync result (stub - should be persisted in DB)
 */
export async function getLastSyncResult(): Promise<SyncResult | null> {
  // TODO: Implement persistent sync result storage
  // For now, return null (no last sync recorded)
  return null;
}
