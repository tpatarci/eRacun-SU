import { AdminPortalCommandGateway } from '../../src/messaging/admin-command-gateway';
import { InMemoryRpcClient } from '../../src/messaging';
import { RequestContext } from '../../src/generated/common';
import {
  AdminPortalCertificateQueryCodec,
  CertificateQueryResponseCodec,
  CertificateQueryType,
  DeadLetterReviewAction,
  DeadLetterReviewCommandCodec,
  DeadLetterReviewResponseCodec,
  HealthDashboardResponseCodec,
} from '../../src/generated/admin_portal';

describe('Admin portal messaging gateway', () => {
  const baseContext: RequestContext = {
    requestId: 'req-test',
    userId: '7',
    timestampMs: Date.now(),
  };

  const gatewayConfig = {
    certificateQueryRoutingKey: 'cert.test',
    certificateUploadRoutingKey: 'cert.upload.test',
    deadLetterRoutingKey: 'dlq.test',
    healthRoutingKey: 'health.test',
    defaultTimeoutMs: 250,
    maxRetries: 1,
  };

  let rpcClient: InMemoryRpcClient;
  let gateway: AdminPortalCommandGateway;

  beforeEach(() => {
    rpcClient = new InMemoryRpcClient();
    gateway = new AdminPortalCommandGateway(rpcClient, gatewayConfig);
  });

  afterEach(async () => {
    await rpcClient.close();
  });

  it('returns certificate inventory over the bus', async () => {
    rpcClient.registerHandler('cert.test', async (payload) => {
      const query = AdminPortalCertificateQueryCodec.decode(payload);
      expect(query.queryType).toBe(CertificateQueryType.CERTIFICATE_QUERY_TYPE_ALL);
      return CertificateQueryResponseCodec.encode({
        certificates: [
          {
            certificateId: 'cert-123',
            commonName: 'FINA Test Cert',
            isActive: true,
          },
        ],
      });
    });

    const certificates = await gateway.listCertificates(baseContext);
    expect(certificates).toHaveLength(1);
    expect(certificates[0]?.certificateId).toBe('cert-123');
  });

  it('retries dashboard query before succeeding', async () => {
    let attempts = 0;
    rpcClient.registerHandler('health.test', async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error('Transient broker error');
      }
      return HealthDashboardResponseCodec.encode({
        services: [
          { name: 'cert-lifecycle-manager', status: 'healthy' },
        ],
      });
    });

    const snapshot = await gateway.fetchHealthDashboard(baseContext);
    expect(snapshot.services).toHaveLength(1);
    expect(attempts).toBe(2);
  });

  it('sends DLQ commands with encoded filters', async () => {
    rpcClient.registerHandler('dlq.test', async (payload) => {
      const command = DeadLetterReviewCommandCodec.decode(payload);
      expect(command.action).toBe(DeadLetterReviewAction.DEAD_LETTER_REVIEW_ACTION_LIST);
      expect(command.filters).toEqual([{ key: 'queue', value: 'retry' }]);
      return DeadLetterReviewResponseCodec.encode({
        errors: [{ errorId: 'dlq-1', originalQueue: 'retry' }],
      });
    });

    const response = await gateway.listDeadLetterErrors(baseContext, [{ key: 'queue', value: 'retry' }]);
    expect(response.errors?.[0]?.errorId).toBe('dlq-1');
  });
});
