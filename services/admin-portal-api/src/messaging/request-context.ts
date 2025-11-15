import { randomUUID } from 'crypto';
import { AuthenticatedRequest } from '../auth/types';
import { InvoiceType, RequestContext } from '../generated/common';

export function createRequestContext(req: AuthenticatedRequest): RequestContext {
  return {
    requestId: req.requestId || randomUUID(),
    userId: req.user?.userId ? String(req.user.userId) : undefined,
    timestampMs: Date.now(),
    invoiceType: InvoiceType.INVOICE_TYPE_UNSPECIFIED,
  };
}
