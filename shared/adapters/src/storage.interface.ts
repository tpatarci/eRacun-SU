/**
 * Storage Service Adapter Interface
 * Abstracts document storage and archiving
 */

export interface IStorageService {
  /**
   * Store document (invoice, XML, PDF)
   */
  store(request: StorageRequest): Promise<StorageResponse>;

  /**
   * Retrieve document by ID
   */
  retrieve(documentId: string): Promise<Document | null>;

  /**
   * Delete document (with retention policy check)
   */
  delete(documentId: string): Promise<boolean>;

  /**
   * List documents by criteria
   */
  list(criteria: StorageCriteria): Promise<Document[]>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

export interface StorageRequest {
  documentId: string;
  content: Buffer | string;
  contentType: string;            // application/xml, application/pdf, etc.
  metadata: {
    invoiceId: string;
    invoiceNumber: string;
    supplierOIB: string;
    retentionUntil: string;       // ISO 8601 (11 years from now)
    encrypted?: boolean;
    signature?: string;
  };
}

export interface StorageResponse {
  success: boolean;
  documentId: string;
  location: string;
  size: number;                   // bytes
  checksum: string;               // SHA-256
  error?: string;
}

export interface Document {
  documentId: string;
  invoiceId: string;
  content: Buffer;
  contentType: string;
  size: number;
  checksum: string;
  storedAt: string;
  retentionUntil: string;
  metadata: Record<string, any>;
}

export interface StorageCriteria {
  invoiceId?: string;
  supplierOIB?: string;
  fromDate?: string;
  toDate?: string;
  limit?: number;
  offset?: number;
}

export interface IArchiveService {
  /**
   * Archive invoice with all related documents
   */
  archive(archiveRequest: ArchiveRequest): Promise<ArchiveResponse>;

  /**
   * Retrieve archived invoice
   */
  retrieve(archiveId: string): Promise<ArchivedInvoice | null>;

  /**
   * Verify archive integrity
   */
  verifyIntegrity(archiveId: string): Promise<IntegrityCheckResult>;
}

export interface ArchiveRequest {
  invoiceId: string;
  documents: {
    originalXML: string;
    signedXML: string;
    pdf?: string;
    finaConfirmation?: string;
  };
  metadata: Record<string, any>;
}

export interface ArchiveResponse {
  success: boolean;
  archiveId: string;
  retentionUntil: string;         // 11 years from now
  location: string;
  error?: string;
}

export interface ArchivedInvoice {
  archiveId: string;
  invoiceId: string;
  documents: Map<string, Buffer>;
  archivedAt: string;
  retentionUntil: string;
  integrityHash: string;
}

export interface IntegrityCheckResult {
  valid: boolean;
  archiveId: string;
  checkedAt: string;
  signatureValid?: boolean;
  checksumValid?: boolean;
  error?: string;
}
