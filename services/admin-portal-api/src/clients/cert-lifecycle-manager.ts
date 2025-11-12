import axios, { AxiosInstance } from 'axios';
import { logger, downstreamCalls } from '../observability';

/**
 * Certificate Lifecycle Manager Client
 *
 * Queries cert-lifecycle-manager service for certificate inventory
 */
export class CertLifecycleManagerClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor(baseURL?: string) {
    this.baseURL = baseURL || process.env.CERT_MANAGER_URL || 'http://cert-lifecycle-manager:8087';

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * List all certificates
   */
  async listCertificates(requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/api/v1/certificates');

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'listCertificates',
        status: 'success',
      });

      logger.debug({
        request_id: requestId,
        service: 'cert-lifecycle-manager',
        count: response.data.certificates?.length,
        msg: 'Certificates list retrieved',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'listCertificates',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'cert-lifecycle-manager',
        error: error.message,
        msg: 'Certificates list retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Get expiring certificates
   */
  async getExpiringCertificates(days: number = 30, requestId?: string): Promise<any> {
    try {
      const response = await this.client.get('/api/v1/certificates/expiring', {
        params: { days },
      });

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'getExpiringCertificates',
        status: 'success',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'getExpiringCertificates',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'cert-lifecycle-manager',
        error: error.message,
        msg: 'Expiring certificates retrieval failed',
      });

      throw error;
    }
  }

  /**
   * Upload new certificate
   */
  async uploadCertificate(formData: FormData, requestId?: string): Promise<any> {
    try {
      const response = await this.client.post('/api/v1/certificates/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'uploadCertificate',
        status: 'success',
      });

      logger.info({
        request_id: requestId,
        service: 'cert-lifecycle-manager',
        msg: 'Certificate uploaded',
      });

      return response.data;
    } catch (err) {
      const error = err as Error;

      downstreamCalls.inc({
        service: 'cert-lifecycle-manager',
        operation: 'uploadCertificate',
        status: 'error',
      });

      logger.error({
        request_id: requestId,
        service: 'cert-lifecycle-manager',
        error: error.message,
        msg: 'Certificate upload failed',
      });

      throw error;
    }
  }
}

// Singleton instance
let certLifecycleManagerClient: CertLifecycleManagerClient | null = null;

export function getCertLifecycleManagerClient(): CertLifecycleManagerClient {
  if (!certLifecycleManagerClient) {
    certLifecycleManagerClient = new CertLifecycleManagerClient();
  }
  return certLifecycleManagerClient;
}
