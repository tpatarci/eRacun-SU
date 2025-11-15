import { decodeMessage, encodeMessage } from './helpers';

export enum InvoiceType {
  INVOICE_TYPE_UNSPECIFIED = 0,
  B2C = 1,
  B2B = 2,
  B2G = 3,
}

export interface RequestContext {
  requestId?: string;
  userId?: string;
  timestampMs?: number;
  invoiceType?: InvoiceType;
}

export interface ErrorDetail {
  code?: string;
  message?: string;
  field?: string;
  details?: string[];
}

export const RequestContextCodec = {
  encode(context: RequestContext): Uint8Array {
    return encodeMessage(context);
  },
  decode(payload: Uint8Array): RequestContext {
    return decodeMessage<RequestContext>(payload);
  },
};

export const ErrorDetailCodec = {
  encode(error: ErrorDetail): Uint8Array {
    return encodeMessage(error);
  },
  decode(payload: Uint8Array): ErrorDetail {
    return decodeMessage<ErrorDetail>(payload);
  },
};
