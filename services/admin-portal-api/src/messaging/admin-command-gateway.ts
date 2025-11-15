import { randomUUID } from 'crypto';
import { RequestContext } from '../generated/common';
import {
  AdminPortalCertificateQuery,
  AdminPortalCertificateQueryCodec,
  CertificateQueryResponse,
  CertificateQueryResponseCodec,
  CertificateQueryType,
  CertificateUploadCommandCodec,
  CertificateUploadResponse,
  CertificateUploadResponseCodec,
  CertificateUploadCommand,
  CertificateMetadata,
  DeadLetterFilter,
  DeadLetterReviewAction,
  DeadLetterReviewCommand,
  DeadLetterReviewCommandCodec,
  DeadLetterReviewResponse,
  DeadLetterReviewResponseCodec,
  DeadLetterStats,
  HealthDashboardQuery,
  HealthDashboardQueryCodec,
  HealthDashboardResponse,
  HealthDashboardResponseCodec,
  HealthSection,
} from '../generated/admin_portal';
import { RpcClient } from './rpc-client';
import { downstreamCalls, logger } from '../observability';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface GatewayConfig {
  certificateQueryRoutingKey: string;
  certificateUploadRoutingKey: string;
  deadLetterRoutingKey: string;
  healthRoutingKey: string;
  defaultTimeoutMs: number;
  maxRetries: number;
}

const DEFAULT_CONFIG: GatewayConfig = {
  certificateQueryRoutingKey: process.env.CERTIFICATE_QUERY_ROUTING_KEY || 'cert-lifecycle.commands',
  certificateUploadRoutingKey:
    process.env.CERTIFICATE_UPLOAD_ROUTING_KEY || 'cert-lifecycle.commands.upload',
  deadLetterRoutingKey: process.env.DEAD_LETTER_ROUTING_KEY || 'dead-letter-handler.commands',
  healthRoutingKey: process.env.HEALTH_MONITOR_ROUTING_KEY || 'health-monitor.dashboard',
  defaultTimeoutMs: parseInt(process.env.ADMIN_RPC_TIMEOUT_MS || '5000', 10),
  maxRetries: parseInt(process.env.ADMIN_RPC_MAX_RETRIES || '1', 10),
};

interface RequestParams<TRequest, TResponse> {
  operation: string;
  routingKey: string;
  message: TRequest;
  encode: (message: TRequest) => Uint8Array;
  decode: (payload: Uint8Array) => TResponse;
  context: RequestContext;
  timeoutMs?: number;
  targetService: string;
}

export class AdminPortalCommandGateway {
  constructor(private readonly rpcClient: RpcClient, private readonly config: GatewayConfig = DEFAULT_CONFIG) {}

  async listCertificates(context: RequestContext): Promise<CertificateMetadata[]> {
    const response = await this.requestWithRetry<AdminPortalCertificateQuery, CertificateQueryResponse>({
      operation: 'certificates.list',
      routingKey: this.config.certificateQueryRoutingKey,
      message: {
        context,
        queryType: CertificateQueryType.CERTIFICATE_QUERY_TYPE_ALL,
      },
      encode: AdminPortalCertificateQueryCodec.encode,
      decode: CertificateQueryResponseCodec.decode,
      context,
      targetService: 'cert-lifecycle-manager',
    });

    return response.certificates ?? [];
  }

  async getExpiringCertificates(context: RequestContext, days: number): Promise<CertificateMetadata[]> {
    const response = await this.requestWithRetry<AdminPortalCertificateQuery, CertificateQueryResponse>({
      operation: 'certificates.expiring',
      routingKey: this.config.certificateQueryRoutingKey,
      message: {
        context,
        queryType: CertificateQueryType.CERTIFICATE_QUERY_TYPE_EXPIRING_ONLY,
        expiringWithinDays: days,
      },
      encode: AdminPortalCertificateQueryCodec.encode,
      decode: CertificateQueryResponseCodec.decode,
      context,
      targetService: 'cert-lifecycle-manager',
    });

    return response.certificates ?? [];
  }

  async uploadCertificate(context: RequestContext, payload: CertificateUploadCommand): Promise<CertificateUploadResponse> {
    return this.requestWithRetry<CertificateUploadCommand, CertificateUploadResponse>({
      operation: 'certificates.upload',
      routingKey: this.config.certificateUploadRoutingKey,
      message: {
        ...payload,
        context,
      },
      encode: CertificateUploadCommandCodec.encode,
      decode: CertificateUploadResponseCodec.decode,
      context,
      targetService: 'cert-lifecycle-manager',
      timeoutMs: this.config.defaultTimeoutMs * 2,
    });
  }

  async listDeadLetterErrors(context: RequestContext, filters: DeadLetterFilter[]): Promise<DeadLetterReviewResponse> {
    return this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.list',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_LIST,
        filters,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
    });
  }

  async getDeadLetterError(context: RequestContext, errorId: string): Promise<DeadLetterReviewResponse> {
    return this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.get',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_GET,
        errorId,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
    });
  }

  async resolveDeadLetter(context: RequestContext, errorId: string): Promise<DeadLetterReviewResponse> {
    return this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.resolve',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_RESOLVE,
        errorId,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
    });
  }

  async resubmitDeadLetter(context: RequestContext, errorId: string): Promise<DeadLetterReviewResponse> {
    return this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.resubmit',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_RESUBMIT,
        errorId,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
    });
  }

  async bulkResolveDeadLetters(context: RequestContext, errorIds: string[]): Promise<DeadLetterReviewResponse> {
    return this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.bulk-resolve',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_BULK_RESOLVE,
        errorIds,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
      timeoutMs: this.config.defaultTimeoutMs * 2,
    });
  }

  async deadLetterStats(context: RequestContext): Promise<DeadLetterStats | undefined> {
    const response = await this.requestWithRetry<DeadLetterReviewCommand, DeadLetterReviewResponse>({
      operation: 'dlq.stats',
      routingKey: this.config.deadLetterRoutingKey,
      message: {
        context,
        action: DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_STATS,
      },
      encode: DeadLetterReviewCommandCodec.encode,
      decode: DeadLetterReviewResponseCodec.decode,
      context,
      targetService: 'dead-letter-handler',
    });

    return response.stats;
  }

  async fetchHealthDashboard(context: RequestContext): Promise<HealthDashboardResponse> {
    return this.requestHealth(context, [
      HealthSection.HEALTH_SECTION_DASHBOARD,
      HealthSection.HEALTH_SECTION_DEAD_LETTERS,
      HealthSection.HEALTH_SECTION_CERTIFICATES,
    ]);
  }

  async fetchServiceStatuses(context: RequestContext): Promise<HealthDashboardResponse> {
    return this.requestHealth(context, [HealthSection.HEALTH_SECTION_SERVICES]);
  }

  async fetchExternalStatuses(context: RequestContext): Promise<HealthDashboardResponse> {
    return this.requestHealth(context, [HealthSection.HEALTH_SECTION_EXTERNAL]);
  }

  async fetchCircuitBreakers(context: RequestContext): Promise<HealthDashboardResponse> {
    return this.requestHealth(context, [HealthSection.HEALTH_SECTION_CIRCUIT_BREAKERS]);
  }

  private async requestHealth(context: RequestContext, sections: HealthSection[]): Promise<HealthDashboardResponse> {
    return this.requestWithRetry<HealthDashboardQuery, HealthDashboardResponse>({
      operation: 'health.snapshot',
      routingKey: this.config.healthRoutingKey,
      message: {
        context,
        sections,
      },
      encode: HealthDashboardQueryCodec.encode,
      decode: HealthDashboardResponseCodec.decode,
      context,
      targetService: 'health-monitor',
    });
  }

  private buildCorrelationId(context: RequestContext, operation: string, attempt: number): string {
    const requestId = context.requestId || randomUUID();
    return `${requestId}:${operation}:attempt-${attempt}`;
  }

  private async requestWithRetry<TRequest, TResponse>(params: RequestParams<TRequest, TResponse>): Promise<TResponse> {
    const { operation, routingKey, message, encode, decode, context, timeoutMs, targetService } = params;
    const attempts = this.config.maxRetries + 1;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const correlationId = this.buildCorrelationId(context, operation, attempt);
      try {
        const responseBuffer = await this.rpcClient.request({
          routingKey,
          payload: encode(message),
          correlationId,
          timeoutMs: timeoutMs ?? this.config.defaultTimeoutMs,
          headers: {
            'x-request-id': context.requestId ?? correlationId,
            'x-operation': operation,
            'x-user-id': context.userId,
          },
          messageId: context.requestId,
        });

        downstreamCalls.inc({ service: targetService, operation, status: 'success' });
        return decode(responseBuffer);
      } catch (error) {
        lastError = error as Error;
        downstreamCalls.inc({ service: targetService, operation, status: 'error' });
        logger.warn(
          {
            request_id: context.requestId,
            routingKey,
            operation,
            attempt,
            maxAttempts: attempts,
            error: lastError.message,
          },
          'Admin portal RPC request failed'
        );

        if (attempt >= attempts) {
          break;
        }

        await sleep(50 * attempt);
      }
    }

    throw lastError ?? new Error(`RPC request failed for operation ${params.operation}`);
  }
}
