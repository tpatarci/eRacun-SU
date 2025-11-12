import axios, { AxiosInstance } from 'axios';
import { logger, downstreamCalls } from '../observability';

/**
 * Health Monitor Client
 *
 * Queries health-monitor service for system health data
 */
export class HealthMonitorClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor(baseURL?: string) {
    this.baseURL = baseURL || process.env.HEALTH_MONITOR_URL || 'http://health-monitor:8084';

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Get system-wide health dashboard data
   */
  async getDashboard(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/health/dashboard');

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getDashboard',
        status: 'success',
      });

      logger.debug({
        request_id: requestId,
        service: 'health-monitor',
        operation: 'getDashboard',
        msg: 'Health dashboard retrieved',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getDashboard',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'health-monitor',
        operation: 'getDashboard',
        error: error.message,
        msg: 'Health dashboard retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Get all services status
   */
  async getServicesStatus(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/health/services');

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getServicesStatus',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getServicesStatus',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'health-monitor',
        error: error.message,
        msg: 'Services status retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Get external dependencies status
   */
  async getExternalStatus(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/health/external');

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getExternalStatus',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getExternalStatus',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'health-monitor',
        error: error.message,
        msg: 'External status retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Get circuit breaker states
   */
  async getCircuitBreakers(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/health/circuit-breakers');

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getCircuitBreakers',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'health-monitor',
        operation: 'getCircuitBreakers',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'health-monitor',
        error: error.message,
        msg: 'Circuit breakers retrieval failed',
      });

      throw error;
    }
  }
}

// Singleton instance
let healthMonitorClient: HealthMonitorClient | null = null;

export function getHealthMonitorClient(): HealthMonitorClient {
  if (!healthMonitorClient) {
    healthMonitorClient = new HealthMonitorClient();
  }
  return healthMonitorClient;
}
