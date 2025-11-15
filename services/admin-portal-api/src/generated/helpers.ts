import { Buffer } from 'buffer';

/**
 * Minimal helper utilities to serialize/deserialize proto-compatible payloads.
 *
 * Until we can run ts-proto inside CI, we encode the strongly typed objects as
 * JSON buffers. This keeps the transport binary-safe and still allows us to
 * enforce schema compatibility through the `.proto` contracts that live under
 * docs/api-contracts/protobuf.
 */
export function encodeMessage<T>(message: T): Uint8Array {
  const json = JSON.stringify(message ?? {});
  return Buffer.from(json, 'utf-8');
}

export function decodeMessage<T>(payload: Uint8Array): T {
  const text = Buffer.from(payload).toString('utf-8');
  return JSON.parse(text) as T;
}
