import { AdminPortalCommandGateway } from './admin-command-gateway';
import { RabbitMQRpcClient } from './rabbitmq-client';
import { RpcClient } from './rpc-client';
import { InMemoryRpcClient } from './in-memory-rpc-client';

let gatewayInstance: AdminPortalCommandGateway | null = null;
let rpcClient: RpcClient | null = null;

function shouldUseInMemoryBus(): boolean {
  if (process.env.ADMIN_PORTAL_FORCE_IN_MEMORY_BUS === 'true') {
    return true;
  }
  if (process.env.ADMIN_PORTAL_FORCE_IN_MEMORY_BUS === 'false') {
    return false;
  }
  return process.env.NODE_ENV === 'test';
}

export function getAdminCommandGateway(): AdminPortalCommandGateway {
  if (!gatewayInstance) {
    rpcClient = shouldUseInMemoryBus() ? new InMemoryRpcClient() : new RabbitMQRpcClient();
    gatewayInstance = new AdminPortalCommandGateway(rpcClient);
  }

  return gatewayInstance;
}

export async function shutdownMessaging(): Promise<void> {
  if (rpcClient) {
    await rpcClient.close();
  }
  gatewayInstance = null;
  rpcClient = null;
}

export type { RpcClient } from './rpc-client';
export { InMemoryRpcClient } from './in-memory-rpc-client';
