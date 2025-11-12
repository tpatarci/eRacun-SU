/**
 * gRPC Server for KPD Code Lookups
 *
 * Provides gRPC API for KPD code validation and lookup.
 * Used by kpd-validator service for fast invoice line item validation.
 *
 * Performance Target: <5ms p95 latency
 *
 * Port: 50052
 */

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { resolve } from 'path';
import { logger, kpdLookupRequests, kpdLookupDuration, traceOperation } from './observability';
import { getKPDCode, searchKPDCodes, KPDCode } from './repository';

// ============================================================================
// Configuration
// ============================================================================

const GRPC_PORT = parseInt(process.env.GRPC_PORT || '50052', 10);
const PROTO_PATH = resolve(__dirname, '../proto/kpd-lookup.proto');

// ============================================================================
// Type Definitions (from proto)
// ============================================================================

interface LookupCodeRequest {
  kpd_code: string;
}

interface LookupCodeResponse {
  found: boolean;
  code_info?: KPDCodeInfo;
}

interface KPDCodeInfo {
  kpd_code: string;
  description: string;
  level: number;
  parent_code: string;
  active: boolean;
  effective_from: string;
  effective_to: string;
}

interface ValidateCodeRequest {
  kpd_code: string;
}

interface ValidateCodeResponse {
  valid: boolean;
  error_message: string;
}

interface SearchCodesRequest {
  query: string;
  limit: number;
}

interface SearchCodesResponse {
  codes: KPDCodeInfo[];
  total_results: number;
}

// ============================================================================
// gRPC Service Implementation
// ============================================================================

/**
 * LookupCode RPC - Find a KPD code by code value
 */
async function lookupCode(
  call: grpc.ServerUnaryCall<LookupCodeRequest, LookupCodeResponse>,
  callback: grpc.sendUnaryData<LookupCodeResponse>
): Promise<void> {
  const startTime = Date.now();
  const { kpd_code } = call.request;

  logger.debug({ kpd_code }, 'LookupCode RPC called');

  try {
    const code = await traceOperation('grpc.lookup_code', async (span) => {
      span.setAttribute('kpd_code', kpd_code);
      return getKPDCode(kpd_code);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);

    if (code) {
      kpdLookupRequests.inc({ status: 'found' });
      callback(null, {
        found: true,
        code_info: mapKPDCodeToGRPC(code),
      });
    } else {
      kpdLookupRequests.inc({ status: 'not_found' });
      callback(null, {
        found: false,
      });
    }
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, kpd_code }, 'LookupCode RPC failed');
    callback({
      code: grpc.status.INTERNAL,
      message: error instanceof Error ? error.message : 'Internal server error',
    });
  }
}

/**
 * ValidateCode RPC - Check if a KPD code exists and is active
 */
async function validateCode(
  call: grpc.ServerUnaryCall<ValidateCodeRequest, ValidateCodeResponse>,
  callback: grpc.sendUnaryData<ValidateCodeResponse>
): Promise<void> {
  const startTime = Date.now();
  const { kpd_code } = call.request;

  logger.debug({ kpd_code }, 'ValidateCode RPC called');

  try {
    const code = await traceOperation('grpc.validate_code', async (span) => {
      span.setAttribute('kpd_code', kpd_code);
      return getKPDCode(kpd_code);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);

    if (!code) {
      kpdLookupRequests.inc({ status: 'not_found' });
      callback(null, {
        valid: false,
        error_message: `KPD code '${kpd_code}' not found in registry`,
      });
    } else if (!code.active) {
      kpdLookupRequests.inc({ status: 'not_found' });
      callback(null, {
        valid: false,
        error_message: `KPD code '${kpd_code}' is inactive (effective_to: ${code.effective_to})`,
      });
    } else {
      kpdLookupRequests.inc({ status: 'found' });
      callback(null, {
        valid: true,
        error_message: '',
      });
    }
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, kpd_code }, 'ValidateCode RPC failed');
    callback({
      code: grpc.status.INTERNAL,
      message: error instanceof Error ? error.message : 'Internal server error',
    });
  }
}

/**
 * SearchCodes RPC - Search KPD codes by description
 */
async function searchCodes(
  call: grpc.ServerUnaryCall<SearchCodesRequest, SearchCodesResponse>,
  callback: grpc.sendUnaryData<SearchCodesResponse>
): Promise<void> {
  const startTime = Date.now();
  const { query, limit } = call.request;
  const searchLimit = limit > 0 ? limit : 100;

  logger.debug({ query, limit: searchLimit }, 'SearchCodes RPC called');

  try {
    const codes = await traceOperation('grpc.search_codes', async (span) => {
      span.setAttribute('query', query);
      span.setAttribute('limit', searchLimit);
      return searchKPDCodes(query, searchLimit);
    });

    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'found' });

    callback(null, {
      codes: codes.map(mapKPDCodeToGRPC),
      total_results: codes.length,
    });
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    kpdLookupDuration.observe(duration);
    kpdLookupRequests.inc({ status: 'error' });

    logger.error({ err: error, query }, 'SearchCodes RPC failed');
    callback({
      code: grpc.status.INTERNAL,
      message: error instanceof Error ? error.message : 'Internal server error',
    });
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Map internal KPDCode to gRPC KPDCodeInfo
 */
function mapKPDCodeToGRPC(code: KPDCode): KPDCodeInfo {
  return {
    kpd_code: code.kpd_code,
    description: code.description,
    level: code.level,
    parent_code: code.parent_code || '',
    active: code.active,
    effective_from: code.effective_from.toISOString().split('T')[0], // YYYY-MM-DD
    effective_to: code.effective_to ? code.effective_to.toISOString().split('T')[0] : '',
  };
}

// ============================================================================
// Server Lifecycle
// ============================================================================

let server: grpc.Server | null = null;

/**
 * Start gRPC server
 */
export function startGRPCServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    // Load proto file
    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition) as any;
    const kpdProto = protoDescriptor.kpd;

    // Create gRPC server
    server = new grpc.Server();

    // Add service implementation
    server.addService(kpdProto.KPDLookupService.service, {
      LookupCode: lookupCode,
      ValidateCode: validateCode,
      SearchCodes: searchCodes,
    });

    // Bind server to port
    const bindAddress = `0.0.0.0:${GRPC_PORT}`;
    server.bindAsync(
      bindAddress,
      grpc.ServerCredentials.createInsecure(), // Use TLS in production
      (error, port) => {
        if (error) {
          logger.error({ err: error }, 'Failed to bind gRPC server');
          reject(error);
          return;
        }

        server!.start();
        logger.info({ port }, 'gRPC server started');
        resolve();
      }
    );
  });
}

/**
 * Stop gRPC server (graceful shutdown)
 */
export function stopGRPCServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      server.tryShutdown(() => {
        logger.info('gRPC server shut down');
        server = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

/**
 * Force stop gRPC server (immediate shutdown)
 */
export function forceStopGRPCServer(): void {
  if (server) {
    server.forceShutdown();
    logger.warn('gRPC server force shut down');
    server = null;
  }
}
