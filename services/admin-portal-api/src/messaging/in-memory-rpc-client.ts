import { setTimeout as delay } from 'timers/promises';
import { RpcClient, RpcHandler, RpcRequest } from './rpc-client';

interface PendingRequest {
  resolve: (payload: Uint8Array) => void;
  reject: (error: Error) => void;
  timeoutHandle: NodeJS.Timeout;
}

/**
 * Lightweight RPC client used for tests and as a safety fallback when RabbitMQ
 * is unavailable. It mimics AMQP correlation semantics by routing requests to
 * locally registered handlers.
 */
export class InMemoryRpcClient implements RpcClient {
  private readonly handlers = new Map<string, RpcHandler>();
  private readonly pending = new Map<string, PendingRequest>();
  private closed = false;

  registerHandler(routingKey: string, handler: RpcHandler) {
    this.handlers.set(routingKey, handler);
  }

  async request(request: RpcRequest): Promise<Uint8Array> {
    if (this.closed) {
      throw new Error('RPC client closed');
    }

    const handler = this.handlers.get(request.routingKey);
    if (!handler) {
      throw new Error(`No handler registered for ${request.routingKey}`);
    }

    const timeoutMs = request.timeoutMs ?? 5000;
    return new Promise<Uint8Array>((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        this.pending.delete(request.correlationId);
        reject(new Error(`RPC timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(request.correlationId, { resolve, reject, timeoutHandle });

      Promise.resolve(handler(request.payload, request))
        .then(async (response) => {
          await delay(0); // ensure async boundary for parity with RabbitMQ
          const pending = this.pending.get(request.correlationId);
          if (!pending) {
            return;
          }
          clearTimeout(pending.timeoutHandle);
          this.pending.delete(request.correlationId);
          pending.resolve(response instanceof Uint8Array ? response : new Uint8Array(response));
        })
        .catch((err) => {
          const pending = this.pending.get(request.correlationId);
          if (!pending) {
            return;
          }
          clearTimeout(pending.timeoutHandle);
          this.pending.delete(request.correlationId);
          pending.reject(err as Error);
        });
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeoutHandle);
      pending.reject(new Error('RPC client closed'));
    }
    this.pending.clear();
    this.handlers.clear();
  }
}
