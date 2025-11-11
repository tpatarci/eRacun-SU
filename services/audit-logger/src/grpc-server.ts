import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';
import { getAuditTrail, queryAuditEvents, AuditEvent } from './writer';
import { verifyIntegrity } from './integrity';
import {
  logger,
  auditGrpcRequests,
  createSpan,
  setSpanError,
} from './observability';

let server: grpc.Server | null = null;

/**
 * Load protocol buffer definition
 */
function loadProto() {
  const PROTO_PATH = path.join(__dirname, '../proto/audit.proto');

  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });

  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  return (protoDescriptor.eracun as any).auditlogger;
}

/**
 * gRPC Handler: GetAuditTrail
 */
async function handleGetAuditTrail(
  call: grpc.ServerUnaryCall<any, any>,
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  const span = createSpan('grpc.GetAuditTrail', {
    'invoice.id': call.request.invoice_id,
  });

  try {
    const invoiceId = call.request.invoice_id;

    if (!invoiceId) {
      auditGrpcRequests.inc({ method: 'GetAuditTrail', status: 'error' });
      span.end();
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'invoice_id is required',
      });
    }

    logger.debug({ invoice_id: invoiceId }, 'gRPC GetAuditTrail request');

    const events = await getAuditTrail(invoiceId);

    const response = {
      events: events.map(event => ({
        event_id: event.event_id,
        invoice_id: event.invoice_id,
        service_name: event.service_name,
        event_type: event.event_type,
        timestamp_ms: event.timestamp_ms.toString(),
        user_id: event.user_id || '',
        request_id: event.request_id,
        metadata: JSON.stringify(event.metadata),
        previous_hash: event.previous_hash || '',
        event_hash: event.event_hash || '',
      })),
      total_events: events.length,
    };

    auditGrpcRequests.inc({ method: 'GetAuditTrail', status: 'success' });
    span.end();

    callback(null, response);

  } catch (error) {
    auditGrpcRequests.inc({ method: 'GetAuditTrail', status: 'error' });
    setSpanError(span, error as Error);
    span.end();

    logger.error({ err: error }, 'gRPC GetAuditTrail failed');

    callback({
      code: grpc.status.INTERNAL,
      message: (error as Error).message,
    });
  }
}

/**
 * gRPC Handler: QueryAuditEvents
 */
async function handleQueryAuditEvents(
  call: grpc.ServerUnaryCall<any, any>,
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  const span = createSpan('grpc.QueryAuditEvents');

  try {
    const filters = {
      service_name: call.request.service_name || undefined,
      event_type: call.request.event_type || undefined,
      start_timestamp_ms: call.request.start_timestamp_ms ? parseInt(call.request.start_timestamp_ms) : undefined,
      end_timestamp_ms: call.request.end_timestamp_ms ? parseInt(call.request.end_timestamp_ms) : undefined,
      limit: call.request.limit || 100,
      offset: call.request.offset || 0,
    };

    logger.debug({ filters }, 'gRPC QueryAuditEvents request');

    const result = await queryAuditEvents(filters);

    const response = {
      events: result.events.map(event => ({
        event_id: event.event_id,
        invoice_id: event.invoice_id,
        service_name: event.service_name,
        event_type: event.event_type,
        timestamp_ms: event.timestamp_ms.toString(),
        user_id: event.user_id || '',
        request_id: event.request_id,
        metadata: JSON.stringify(event.metadata),
        previous_hash: event.previous_hash || '',
        event_hash: event.event_hash || '',
      })),
      total_count: result.total,
    };

    auditGrpcRequests.inc({ method: 'QueryAuditEvents', status: 'success' });
    span.end();

    callback(null, response);

  } catch (error) {
    auditGrpcRequests.inc({ method: 'QueryAuditEvents', status: 'error' });
    setSpanError(span, error as Error);
    span.end();

    logger.error({ err: error }, 'gRPC QueryAuditEvents failed');

    callback({
      code: grpc.status.INTERNAL,
      message: (error as Error).message,
    });
  }
}

/**
 * gRPC Handler: VerifyIntegrity
 */
async function handleVerifyIntegrity(
  call: grpc.ServerUnaryCall<any, any>,
  callback: grpc.sendUnaryData<any>
): Promise<void> {
  const span = createSpan('grpc.VerifyIntegrity');

  try {
    const startTimeMs = parseInt(call.request.start_timestamp_ms);
    const endTimeMs = parseInt(call.request.end_timestamp_ms);

    if (!startTimeMs || !endTimeMs) {
      auditGrpcRequests.inc({ method: 'VerifyIntegrity', status: 'error' });
      span.end();
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'start_timestamp_ms and end_timestamp_ms are required',
      });
    }

    logger.info({ start_time_ms: startTimeMs, end_time_ms: endTimeMs }, 'gRPC VerifyIntegrity request');

    const result = await verifyIntegrity(startTimeMs, endTimeMs);

    const response = {
      integrity_valid: result.valid,
      total_events: result.total_events,
      broken_chains: result.broken_chains,
      verification_time_ms: result.verification_time_ms.toString(),
    };

    auditGrpcRequests.inc({ method: 'VerifyIntegrity', status: 'success' });
    span.end();

    callback(null, response);

  } catch (error) {
    auditGrpcRequests.inc({ method: 'VerifyIntegrity', status: 'error' });
    setSpanError(span, error as Error);
    span.end();

    logger.error({ err: error }, 'gRPC VerifyIntegrity failed');

    callback({
      code: grpc.status.INTERNAL,
      message: (error as Error).message,
    });
  }
}

/**
 * Start gRPC server
 */
export async function startGrpcServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      const port = process.env.GRPC_PORT || '50051';
      const host = process.env.GRPC_HOST || '0.0.0.0';

      const proto = loadProto();

      server = new grpc.Server();

      // Register service implementation
      server.addService(proto.AuditLogService.service, {
        GetAuditTrail: handleGetAuditTrail,
        QueryAuditEvents: handleQueryAuditEvents,
        VerifyIntegrity: handleVerifyIntegrity,
      });

      // Bind and start
      server.bindAsync(
        `${host}:${port}`,
        grpc.ServerCredentials.createInsecure(),
        (error, port) => {
          if (error) {
            logger.error({ err: error }, 'Failed to bind gRPC server');
            return reject(error);
          }

          server!.start();
          logger.info({ port, host }, 'gRPC server started');
          resolve();
        }
      );

    } catch (error) {
      logger.error({ err: error }, 'Failed to start gRPC server');
      reject(error);
    }
  });
}

/**
 * Stop gRPC server gracefully
 */
export async function stopGrpcServer(): Promise<void> {
  return new Promise((resolve) => {
    if (server) {
      logger.info('Stopping gRPC server');
      server.tryShutdown(() => {
        logger.info('gRPC server stopped');
        server = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

/**
 * Get gRPC server instance (for testing)
 */
export function getGrpcServer(): grpc.Server | null {
  return server;
}
