import { decodeMessage, encodeMessage } from './helpers';
import { RequestContext } from './common';

export enum CertificateQueryType {
  CERTIFICATE_QUERY_TYPE_UNSPECIFIED = 0,
  CERTIFICATE_QUERY_TYPE_ALL = 1,
  CERTIFICATE_QUERY_TYPE_EXPIRING_ONLY = 2,
}

export interface AdminPortalCertificateQuery {
  context?: RequestContext;
  queryType?: CertificateQueryType;
  expiringWithinDays?: number;
}

export interface CertificateMetadata {
  certificateId?: string;
  commonName?: string;
  serialNumber?: string;
  issuer?: string;
  validFromMs?: number;
  validUntilMs?: number;
  isActive?: boolean;
}

export interface CertificateQueryResponse {
  certificates?: CertificateMetadata[];
}

export interface CertificateUploadCommand {
  context?: RequestContext;
  filename?: string;
  /**
   * Raw PKCS#12 payload encoded as base64.
   */
  pkcs12Bundle?: string;
  password?: string;
  label?: string;
}

export interface CertificateUploadResponse {
  certificateId?: string;
  status?: string;
  message?: string;
}

export enum DeadLetterReviewAction {
  DEAD_LETTER_REVIEW_ACTION_UNSPECIFIED = 0,
  DEAD_LETTER_REVIEW_ACTION_LIST = 1,
  DEAD_LETTER_REVIEW_ACTION_GET = 2,
  DEAD_LETTER_REVIEW_ACTION_RESOLVE = 3,
  DEAD_LETTER_REVIEW_ACTION_RESUBMIT = 4,
  DEAD_LETTER_REVIEW_ACTION_BULK_RESOLVE = 5,
  DEAD_LETTER_REVIEW_ACTION_STATS = 6,
}

export interface DeadLetterFilter {
  key?: string;
  value?: string;
}

export interface DeadLetterItem {
  errorId?: string;
  originalQueue?: string;
  reason?: string;
  payloadPreview?: string;
  failedAtMs?: number;
  status?: string;
  tags?: string[];
}

export interface DeadLetterStats {
  total?: number;
  pending?: number;
  resolved?: number;
  byQueue?: Record<string, number>;
}

export interface DeadLetterReviewCommand {
  context?: RequestContext;
  action?: DeadLetterReviewAction;
  errorId?: string;
  errorIds?: string[];
  filters?: DeadLetterFilter[];
}

export interface DeadLetterReviewResponse {
  errors?: DeadLetterItem[];
  error?: DeadLetterItem;
  stats?: DeadLetterStats;
  status?: string;
}

export enum HealthSection {
  HEALTH_SECTION_UNSPECIFIED = 0,
  HEALTH_SECTION_DASHBOARD = 1,
  HEALTH_SECTION_SERVICES = 2,
  HEALTH_SECTION_EXTERNAL = 3,
  HEALTH_SECTION_CIRCUIT_BREAKERS = 4,
  HEALTH_SECTION_DEAD_LETTERS = 5,
  HEALTH_SECTION_CERTIFICATES = 6,
}

export interface HealthDashboardQuery {
  context?: RequestContext;
  sections?: HealthSection[];
}

export interface ServiceHealth {
  name?: string;
  status?: string;
  latencyMs?: number;
  region?: string;
  lastError?: string;
  updatedAtMs?: number;
}

export interface ExternalDependencyHealth {
  name?: string;
  status?: string;
  latencyMs?: number;
  endpoint?: string;
  checkedAtMs?: number;
}

export interface CircuitBreakerState {
  name?: string;
  state?: string;
  reason?: string;
  updatedAtMs?: number;
}

export interface HealthDashboardResponse {
  services?: ServiceHealth[];
  dependencies?: ExternalDependencyHealth[];
  circuitBreakers?: CircuitBreakerState[];
  deadLetterStats?: DeadLetterStats;
  expiringCertificates?: CertificateMetadata[];
}

export const AdminPortalCertificateQueryCodec = {
  encode(message: AdminPortalCertificateQuery): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): AdminPortalCertificateQuery {
    return decodeMessage<AdminPortalCertificateQuery>(payload);
  },
};

export const CertificateQueryResponseCodec = {
  encode(message: CertificateQueryResponse): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): CertificateQueryResponse {
    return decodeMessage<CertificateQueryResponse>(payload);
  },
};

export const CertificateUploadCommandCodec = {
  encode(message: CertificateUploadCommand): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): CertificateUploadCommand {
    return decodeMessage<CertificateUploadCommand>(payload);
  },
};

export const CertificateUploadResponseCodec = {
  encode(message: CertificateUploadResponse): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): CertificateUploadResponse {
    return decodeMessage<CertificateUploadResponse>(payload);
  },
};

export const DeadLetterReviewCommandCodec = {
  encode(message: DeadLetterReviewCommand): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): DeadLetterReviewCommand {
    return decodeMessage<DeadLetterReviewCommand>(payload);
  },
};

export const DeadLetterReviewResponseCodec = {
  encode(message: DeadLetterReviewResponse): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): DeadLetterReviewResponse {
    return decodeMessage<DeadLetterReviewResponse>(payload);
  },
};

export const HealthDashboardQueryCodec = {
  encode(message: HealthDashboardQuery): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): HealthDashboardQuery {
    return decodeMessage<HealthDashboardQuery>(payload);
  },
};

export const HealthDashboardResponseCodec = {
  encode(message: HealthDashboardResponse): Uint8Array {
    return encodeMessage(message);
  },
  decode(payload: Uint8Array): HealthDashboardResponse {
    return decodeMessage<HealthDashboardResponse>(payload);
  },
};
