export interface RpcRequest {
  routingKey: string;
  payload: Uint8Array;
  correlationId: string;
  timeoutMs?: number;
  headers?: Record<string, string | undefined>;
  messageId?: string;
}

export interface RpcClient {
  request(request: RpcRequest): Promise<Uint8Array>;
  close(): Promise<void>;
}

export type RpcHandler = (payload: Uint8Array, meta: RpcRequest) => Promise<Uint8Array> | Uint8Array;
