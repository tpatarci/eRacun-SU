import axios, { AxiosInstance } from 'axios';
import { logger, downstreamCalls } from '../observability';

/**
 * Dead Letter Handler Client
 *
 * Queries dead-letter-handler service for manual review queue
 */
export class DeadLetterHandlerClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor(baseURL?: string) {
    this.baseURL = baseURL || process.env.DEAD_LETTER_HANDLER_URL || 'http://dead-letter-handler:8081';

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * List errors in manual review queue
   */
  async listErrors(requestId?: string, filters?: any): Promise<any> {
    try {
      const response = await this.client.get('/api/v1/errors', {
        params: filters,
      });

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'listErrors',
        status: 'success',
      });

      logger.debug({
        request_id: requestId,
        service: 'dead-letter-handler',
        operation: 'listErrors',
        count: response.data.errors?.length,
        msg: 'Errors list retrieved',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'listErrors',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error: error.message,
        msg: 'Errors list retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Get error details
   */
  async getError(errorId: string, requestId?: string): Promise<any> {
    try {
      const response = await this.client.get(`/api/v1/errors/${errorId}`);

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'getError',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'getError',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_id: errorId,
        error: error.message,
        msg: 'Error details retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Resolve error
   */
  async resolveError(errorId: string, requestId?: string): Promise<any> {
    try {
      const response = await this.client.post(`/api/v1/errors/${errorId}/resolve`);

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'resolveError',
        status: 'success',
      });

      logger.info({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_id: errorId,
        msg: 'Error resolved',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'resolveError',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_id: errorId,
        error: error.message,
        msg: 'Error resolution failed',
      });

      throw error;
    }
  }

  /**
   * Resubmit error to original queue
   */
  async resubmitError(errorId: string, requestId?: string): Promise<any> {
    try {
      const response = await this.client.post(`/api/v1/errors/${errorId}/resubmit`);

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'resubmitError',
        status: 'success',
      });

      logger.info({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_id: errorId,
        msg: 'Error resubmitted',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'resubmitError',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_id: errorId,
        error: error.message,
        msg: 'Error resubmission failed',
      });

      throw error;
    }
  }

  /**
   * Bulk resolve errors
   */
  async bulkResolve(errorIds: string[], requestId?: string): Promise<any> {
    try {
      const response = await this.client.post('/api/v1/errors/bulk-resolve', {
        error_ids: errorIds,
      });

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'bulkResolve',
        status: 'success',
      });

      logger.info({
        request_id: requestId,
        service: 'dead-letter-handler',
        error_count: errorIds.length,
        msg: 'Errors bulk resolved',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'bulkResolve',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error: error.message,
        msg: 'Bulk resolve failed',
      });

      throw error;
    }
  }

  /**
   * Get error statistics
   */
  async getErrorStats(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/api/v1/errors/stats');

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'getErrorStats',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'dead-letter-handler',
        operation: 'getErrorStats',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'dead-letter-handler',
        error: error.message,
        msg: 'Error stats retrieval failed',
      });

      throw error;
    }
  }
}

// Singleton instance
let deadLetterHandlerClient: DeadLetterHandlerClient | null = null;

export function getDeadLetterHandlerClient(): DeadLetterHandlerClient {
  if (!deadLetterHandlerClient) {
    deadLetterHandlerClient = new DeadLetterHandlerClient();
  }
  return deadLetterHandlerClient;
}
